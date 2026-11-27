/**
 * ScopeGuard v2.0 — Stateless GCS-Backed Governance Portal Frontend
 * Zero external JavaScript dependencies; reads versioned run envelopes from server.py.
 */

(function () {
  "use strict";

  const state = {
    bucket: "",
    projects: [],
    currentProject: "",
    currentRun: "latest",
    runs: [],
    envelope: null,
    fleetScope: "all",
    fleetData: null,
    inheritanceCutoverSimulated: false,
    activeArtifactTab: "rollback",
    activeArchDesignIdx: 0,
    activeArchTab: "main_tf",
    activeTab: "view-overview",
    roleView: "all",
    fleetSort: { key: "findings_critical", dir: "desc" },
    fleetGroupByFolder: false,
  };

  /** Insights module (findings queue, overview, drawer, plans, exports); optional. */
  const insights = window.ScopeGuardInsights || null;
  const VALID_TABS = new Set([
    "view-fleet", "view-overview", "view-findings", "view-scorecard", "view-inheritance",
    "view-compression", "view-guardrails", "view-architect", "view-compliance",
  ]);
  const ROLE_VIEW_STORAGE_KEY = "scopeguard_role_view";
  const ROLE_VIEW_TABS = {
    all: VALID_TABS,
    devops: new Set(["view-overview", "view-findings", "view-compression", "view-guardrails", "view-architect"]),
    secops: new Set(["view-fleet", "view-overview", "view-findings", "view-scorecard", "view-inheritance", "view-compliance"]),
  };
  const RUN_DELIVERABLE_FILES = [
    "EXECUTIVE_SUMMARY.md",
    "REMEDIATION_PLAN.md",
    "EVIDENCE.md",
    "scopeguard.sarif.json",
    "scc_findings_import.json",
    "findings.csv",
    "manifest.json",
  ];

  function escapeHtml(value) {
    const str = value === null || value === undefined ? "" : String(value);
    return str
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function formatNumber(num) {
    const n = Number(num || 0);
    return Number.isFinite(n) ? n.toLocaleString("en-US") : "0";
  }

  function shortPrincipal(member) {
    if (!member) return "";
    const raw = String(member).replace(/^(user:|serviceAccount:|group:|domain:)/, "");
    const atIdx = raw.indexOf("@");
    return atIdx > 0 ? raw.slice(0, atIdx) : raw;
  }

  /**
   * Renders an accessible ⓘ tooltip (UI-3). Keyboard-focusable; the definition
   * is exposed through both title (hover) and aria-label (screen readers).
   * @param {string} text Definition text; empty returns "".
   * @return {string} Escaped HTML snippet.
   */
  function infoTip(text) {
    if (!text) return "";
    const t = escapeHtml(text);
    // Uses data-tooltip (rendered by the instant #sg-tooltip popover) rather
    // than native title= so hover, click, and keyboard focus all work instantly
    // without browser delay or container overflow clipping.
    return ` <span class="info-tip" tabindex="0" role="button" data-tooltip="${t}" aria-label="${t}">&#9432;</span>`;
  }

  /**
   * Mirrors findings_engine.replay_confidence() so simulator rows show how much
   * a PASS verdict can be trusted (UI-4). Zero replayed calls is a vacuous pass.
   * @param {Object} r Principal replay record.
   * @param {Object} summary Simulator module summary.
   * @return {{level:string,reason:string}}
   */
  function replayConfidence(r, summary) {
    const calls = Number(r?.replayed_api_calls || 0);
    const src = String(summary?.telemetry_source || "");
    if (calls <= 0) return { level: "Low", reason: "No API calls replayed in the window: PASS is vacuous." };
    if (r?.log_limit_hit || summary?.log_limit_hit) {
      return { level: "Low", reason: "Log page limit hit: replay may be truncated." };
    }
    if (src.startsWith("bigquery")) return { level: "High", reason: "100% BigQuery Log Analytics telemetry." };
    if (calls >= 20) return { level: "Medium", reason: `${calls} calls replayed from paginated Cloud Logging.` };
    return { level: "Low", reason: `Only ${calls} calls replayed.` };
  }

  function confidenceChip(conf) {
    const cls = conf.level === "High" ? "conf-high" : conf.level === "Medium" ? "conf-med" : "conf-low";
    return `<span class="chip ${cls}" title="${escapeHtml(conf.reason)}">${escapeHtml(conf.level)}</span>`;
  }

  /**
   * Extracts simulator audit-log confidence, cutover recommendation, and any
   * services missing DATA_READ/DATA_WRITE audit logs from the breakglass module.
   */
  function simAuditConfidence(simMod) {
    const mod = simMod || state.envelope?.modules?.breakglass_simulator || {};
    const sum = mod.summary || {};
    const pay = mod.payload || {};
    const dig = state.envelope?.recommendation_digest?.executive_kpis || {};
    const level = String(
      pay.audit_log_confidence || sum.audit_log_confidence || dig.audit_log_confidence || ""
    ).toUpperCase();
    const cutover = String(
      pay.recommended_cutover || sum.recommended_cutover || dig.recommended_cutover || ""
    ).toUpperCase();
    const missingRaw =
      pay.missing_data_access_services || sum.missing_data_access_services || [];
    const missing = Array.isArray(missingRaw) ? missingRaw.filter(Boolean) : [];
    const warning = String(
      pay.audit_log_confidence_warning || sum.audit_log_confidence_warning || ""
    );
    return { level, cutover, missing, warning };
  }

  /**
   * Renders the audit-log confidence badge (green for HIGH, amber for MEDIUM/LOW)
   * with tooltip listing missing_data_access_services and recommended cutover.
   */
  function renderSimConfidenceBadge(info) {
    const c = info || simAuditConfidence();
    if (!c.level && !c.cutover) return "";
    const tipParts = [];
    if (c.level) tipParts.push(`Audit-log confidence: ${c.level}`);
    if (c.cutover) tipParts.push(`Recommended cutover: ${c.cutover}`);
    if (c.missing.length) {
      tipParts.push(`Missing Data Access audit logs: ${c.missing.join(", ")}`);
    }
    if (c.warning) tipParts.push(c.warning);
    const tip = tipParts.join(" • ");
    const parts = [];
    if (c.level) {
      const cls = c.level === "HIGH" ? "badge-green" : "badge-amber";
      parts.push(
        `<span class="badge ${cls}" tabindex="0" data-tooltip="${escapeHtml(tip)}" aria-label="${escapeHtml(tip)}">Audit Confidence: ${escapeHtml(c.level)}</span>`
      );
    }
    if (c.cutover) {
      const cutCls =
        c.cutover === "DIRECT"
          ? "badge-green"
          : c.cutover === "HOLD"
          ? "badge-crimson"
          : "badge-amber";
      const cutLabel =
        c.cutover === "CANARY_DUAL_BIND"
          ? "Canary Dual-Bind"
          : c.cutover === "DIRECT"
          ? "Direct Cutover"
          : c.cutover;
      parts.push(
        `<span class="badge ${cutCls}" tabindex="0" data-tooltip="${escapeHtml(tip)}" aria-label="${escapeHtml(tip)}">${escapeHtml(cutLabel)}</span>`
      );
    }
    return parts.join(" ");
  }

  async function copyTextToClipboard(text) {
    const str = String(text || "");
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(str);
        return true;
      }
    } catch (_err) {
      // Fallback below
    }
    const ta = document.createElement("textarea");
    ta.value = str;
    ta.setAttribute("readonly", "");
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    let ok = false;
    try {
      ok = document.execCommand("copy");
    } catch (_err) {
      ok = false;
    }
    document.body.removeChild(ta);
    return ok;
  }

  function applyRoleView(view, opts = {}) {
    const normalized = ROLE_VIEW_TABS[view] ? view : "all";
    state.roleView = normalized;
    const allowed = ROLE_VIEW_TABS[normalized];
    if (opts.persist !== false) {
      try {
        window.localStorage.setItem(ROLE_VIEW_STORAGE_KEY, normalized);
      } catch (_err) {
        // Ignore storage errors in restricted contexts
      }
    }
    document.querySelectorAll("[data-role-view]").forEach((btn) => {
      const on = btn.dataset.roleView === normalized;
      btn.classList.toggle("active", on);
      btn.setAttribute("aria-pressed", on ? "true" : "false");
    });
    document.querySelectorAll(".nav-tab").forEach((tabBtn) => {
      const visible = allowed.has(tabBtn.dataset.tab);
      tabBtn.classList.toggle("hidden", !visible);
      tabBtn.hidden = !visible;
    });
    if (!allowed.has(state.activeTab) && opts.ensureVisible !== false) {
      switchToTab("view-overview", { focus: false });
    }
  }

  function openYamlRole(roleId) {
    if (!roleId) return;
    if (!ROLE_VIEW_TABS[state.roleView]?.has("view-compression")) {
      applyRoleView("all", { ensureVisible: false });
    }
    switchToTab("view-compression", { focus: false });
    const sel = document.getElementById("yaml-file-select");
    const viewer = document.getElementById("yaml-code-viewer");
    if (!sel || !viewer) return;
    const needle = String(roleId).toLowerCase();
    const matchOpt = Array.from(sel.options).find((opt) => {
      const val = opt.value.toLowerCase();
      const txt = opt.textContent.toLowerCase();
      return (
        val === needle ||
        val.endsWith(`/${needle}.yaml`) ||
        val.endsWith(`/${needle}.yml`) ||
        txt === needle ||
        txt === `${needle}.yaml` ||
        val.includes(needle)
      );
    });
    if (matchOpt) {
      sel.value = matchOpt.value;
      sel.dispatchEvent(new Event("change"));
    }
    viewer.scrollIntoView({ behavior: "smooth", block: "center" });
  }

  function renderOverviewDeliverablesBar() {
    const host = document.getElementById("overview-deliverables-bar");
    if (!host) return;
    const pid = state.currentProject || "";
    const run = state.currentRun || "latest";
    if (!pid) {
      host.innerHTML = `<span class="muted">Select a project to download run deliverables.</span>`;
      return;
    }
    host.innerHTML = RUN_DELIVERABLE_FILES.map((file) => {
      const href = `/api/artifact?project=${encodeURIComponent(pid)}&run=${encodeURIComponent(
        run
      )}&file=${encodeURIComponent(file)}`;
      return `<a class="deliverable-pill" href="${escapeHtml(href)}" download="${escapeHtml(
        file
      )}" title="Download ${escapeHtml(file)} for ${escapeHtml(pid)} (${escapeHtml(run)})">&#8595; ${escapeHtml(
        file
      )}</a>`;
    }).join("");
  }

  function showToast(message, isError = false) {
    const el = document.getElementById("toast-banner");
    if (!el) return;
    el.textContent = message;
    el.classList.toggle("error", Boolean(isError));
    el.classList.remove("hidden");
    window.clearTimeout(el._hideTimer);
    el._hideTimer = window.setTimeout(() => {
      el.classList.add("hidden");
    }, 6000);
  }

  function triggerDownload(filename, content, mimeType = "text/plain;charset=utf-8") {
    const blob = new Blob([content || ""], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  /* ------------------------------------------------------------------------ */
  /* Initialization & GCS Sync                                                */
  /* ------------------------------------------------------------------------ */

  async function initApp() {
    bindNavigationEvents();
    bindActionEvents();

    const params = new URLSearchParams(window.location.search);
    const urlProj = params.get("project");
    const urlRun = params.get("run");
    const urlTab = params.get("tab");
    if (urlProj) state.currentProject = urlProj;
    if (urlRun) state.currentRun = urlRun;

    if (insights) {
      insights.init({
        state, escapeHtml, formatNumber, shortPrincipal, showToast, triggerDownload,
        switchToTab, loadAssessment, replayConfidence, confidenceChip, infoTip,
        simAuditConfidence, renderSimConfidenceBadge, openYamlRole,
      });
    }

    let savedRoleView = "all";
    try {
      savedRoleView = window.localStorage.getItem(ROLE_VIEW_STORAGE_KEY) || "all";
    } catch (_err) {
      savedRoleView = "all";
    }
    applyRoleView(savedRoleView, { persist: false, ensureVisible: false });

    await syncFromGcs({ initial: true });

    // UI-1: honour ?tab=; otherwise land on Fleet when several projects exist
    // and no specific project was requested, else on the project Overview.
    const allowedInitial = ROLE_VIEW_TABS[state.roleView] || VALID_TABS;
    if (urlTab && VALID_TABS.has(urlTab) && allowedInitial.has(urlTab)) {
      switchToTab(urlTab, { focus: false });
    } else if (!urlProj && state.projects.length > 1 && allowedInitial.has("view-fleet")) {
      switchToTab("view-fleet", { focus: false });
    } else {
      switchToTab("view-overview", { focus: false });
    }
  }

  async function syncFromGcs(opts = {}) {
    try {
      const healthRes = await fetch("/api/health");
      const health = await healthRes.json();
      state.bucket = health.gcs_store?.bucket || "";
      state.projects = health.projects || [];

      if (!opts.initial || !new URLSearchParams(window.location.search).get("project")) {
        if (
          state.projects.length > 0 &&
          !state.projects.some((p) => p.project_id === state.currentProject)
        ) {
          state.currentProject = health.default_project || state.projects[0].project_id;
        }
      }

      renderHeaderControls(health.runtime, health.gcs_store);
      await loadAssessment(state.currentProject, state.currentRun);
      if (!opts.initial) {
        showToast(`Synced latest folders and run history from gs://${state.bucket}.`);
      }
    } catch (err) {
      showToast(`GCS sync failed: ${err.message}`, true);
    }
  }

  function renderHeaderControls(runtime, gcsStore) {
    const pillText = document.getElementById("runtime-pill-text");
    if (pillText) {
      const bkt = gcsStore?.bucket ? `gs://${gcsStore.bucket}` : "Bucket Unconfigured";
      const idShort = shortPrincipal(runtime?.runtime_identity) || "gcs-viewer";
      pillText.textContent = `${bkt} • ${idShort}`;
    }

    const projSelect = document.getElementById("project-select");
    if (projSelect) {
      if (state.projects.length === 0) {
        projSelect.innerHTML = `<option value="${escapeHtml(state.currentProject)}">${escapeHtml(
          state.currentProject
        )} (No runs yet)</option>`;
      } else {
        projSelect.innerHTML = state.projects
          .map((p) => {
            const sel = p.project_id === state.currentProject ? "selected" : "";
            return `<option value="${escapeHtml(p.project_id)}" ${sel}>${escapeHtml(
              p.project_id
            )} (${p.run_count} run${p.run_count === 1 ? "" : "s"})</option>`;
          })
          .join("");
      }
    }
  }

  function renderRunSelector() {
    const runSelect = document.getElementById("run-select");
    if (!runSelect) return;

    const options = [
      `<option value="latest" ${
        state.currentRun === "latest" ? "selected" : ""
      }>Latest Snapshot (${state.runs.length ? escapeHtml(state.runs[0].trigger_mode) : "auto"})</option>`,
    ];

    state.runs.forEach((r) => {
      const sel = state.currentRun === r.run_id ? "selected" : "";
      const tsDisplay = r.updated ? r.updated.replace("T", " ").slice(0, 19) + "Z" : r.compact_timestamp;
      options.push(
        `<option value="${escapeHtml(r.run_id)}" ${sel}>${escapeHtml(tsDisplay)} — ${escapeHtml(
          r.trigger_mode
        )} (${escapeHtml(r.run_id.slice(-6))})</option>`
      );
    });
    runSelect.innerHTML = options.join("");
  }

  /**
   * Shows (or clears) a load-error banner with a Retry button (UI-13) so a
   * failed GCS read is not just a transient toast.
   */
  function renderLoadError(message, retryFn) {
    const host = document.getElementById("global-alerts");
    if (!host) return;
    host.querySelector(".alert-load-error")?.remove();
    if (!message) return;
    const div = document.createElement("div");
    div.className = "alert alert-error alert-load-error";
    div.setAttribute("role", "alert");
    div.innerHTML = `<div><strong>Could not load assessment.</strong> ${escapeHtml(
      message
    )} Check that the portal identity has <code>roles/storage.objectViewer</code> on the bucket.</div>
      <button type="button" class="btn btn-secondary btn-sm">Retry</button>`;
    div.querySelector("button").addEventListener("click", () => retryFn && retryFn());
    host.prepend(div);
  }

  async function loadAssessment(projectId, runRef = "latest") {
    const url = `/api/assessment?project=${encodeURIComponent(
      projectId
    )}&run=${encodeURIComponent(runRef)}`;
    let res;
    let data;
    try {
      res = await fetch(url);
      data = await res.json();
    } catch (err) {
      renderLoadError(`Network error: ${err.message}`, () => loadAssessment(projectId, runRef));
      throw err;
    }
    if (!res.ok) {
      const msg = data.details || data.error || "Failed to load GCS assessment";
      renderLoadError(msg, () => loadAssessment(projectId, runRef));
      throw new Error(msg);
    }
    renderLoadError(null);

    const emptyBanner = document.getElementById("empty-gcs-state");
    const mainWs = document.getElementById("main-workspace");

    if (data.status !== "OK" || !data.envelope) {
      if (emptyBanner) {
        emptyBanner.classList.remove("hidden");
        document.getElementById("empty-gcs-message").textContent =
          data.message || "Run ScopeGuard in Antigravity to publish your first assessment.";
      }
      if (mainWs) mainWs.classList.add("hidden");
      return;
    }

    if (emptyBanner) emptyBanner.classList.add("hidden");
    if (mainWs) mainWs.classList.remove("hidden");

    state.currentProject = projectId;
    state.currentRun = runRef;
    state.runs = data.runs || [];
    state.envelope = data.envelope;
    state.activeArchDesignIdx = 0;

    renderRunSelector();
    renderAllViews();
    if (insights) {
      try {
        await insights.onAssessmentLoaded();
      } catch (err) {
        console.error("ScopeGuard insights render failed", err);
        showToast(`Findings view failed to load: ${err.message}`, true);
      }
    }
  }

  /* ------------------------------------------------------------------------ */
  /* Freshness / Carried-Forward Staleness Banner Helper                      */
  /* ------------------------------------------------------------------------ */

  function renderFreshnessBanner(containerId, moduleKeys) {
    const container = document.getElementById(containerId);
    if (!container || !state.envelope) return;
    const mods = state.envelope.modules || {};

    const items = moduleKeys.map((k) => mods[k]).filter(Boolean);
    if (!items.length) {
      container.innerHTML = "";
      return;
    }

    const driftItem = items.find((m) => m.freshness === "STALE_POLICY_DRIFT");
    const staleItem = items.find((m) => m.is_potentially_stale);
    const notRunItem = items.find((m) => m.status === "NOT_RUN");

    if (driftItem) {
      container.innerHTML = `
        <div class="freshness-bar drift">
          <div><strong>&#9888; Policy Drift Warning (Probably Stale):</strong> ${escapeHtml(
            driftItem.stale_warning
          )}</div>
          <span class="mono">Source Run: ${escapeHtml(driftItem.source_run_id || "--")}</span>
        </div>`;
    } else if (staleItem) {
      const staleNames = items
        .filter((m) => m.is_potentially_stale)
        .map((m) => m.skill_name)
        .join(", ");
      container.innerHTML = `
        <div class="freshness-bar stale">
          <div><strong>&#9888; Carried Forward (Probably Stale):</strong> <code>${escapeHtml(
            staleNames
          )}</code> was not re-executed in run <code>${escapeHtml(
        state.envelope.run_id
      )}</code> (showing output from <code>${escapeHtml(
        staleItem.generated_at || "prior run"
      )}</code>).</div>
          <span class="mono">Trigger Mode: ${escapeHtml(state.envelope.trigger_mode)}</span>
        </div>`;
    } else if (notRunItem && items.every((m) => m.status === "NOT_RUN")) {
      container.innerHTML = `
        <div class="freshness-bar not-run">
          <div><strong>Module Not Yet Executed:</strong> Run <code>${escapeHtml(
            notRunItem.skill_name
          )}</code> or <code>scopeguard-orchestrator</code> in Antigravity to populate this section.</div>
        </div>`;
    } else {
      const skillNames = items.map((m) => m.skill_name).join(" + ");
      container.innerHTML = `
        <div class="freshness-bar fresh">
          <div><strong>&#10003; Current Snapshot:</strong> Evaluated in selected run (<code>${escapeHtml(
            state.envelope.timestamp_utc
          )}</code>) via <code>${escapeHtml(skillNames)}</code>.</div>
          <span class="mono">Run ID: ${escapeHtml(state.envelope.run_id)}</span>
        </div>`;
    }
  }

  /* ------------------------------------------------------------------------ */
  /* Master Render Dispatch                                                   */
  /* ------------------------------------------------------------------------ */

  function renderAllViews() {
    const env = state.envelope;
    if (!env) return;
    const mods = env.modules || {};

    const auditMod = mods.recommender_audit?.payload || {};
    const analysis = auditMod.analysis || {};

    renderGatesRibbon(env, analysis);
    renderOverviewDeliverablesBar();

    renderFreshnessBanner("freshness-scorecard", [
      "recommender_audit",
      "org_hierarchy_auditor",
    ]);
    renderScorecardAndOrgView(analysis, mods.org_hierarchy_auditor?.payload || {});
    renderPrincipalsTable(analysis);

    renderFreshnessBanner("freshness-inheritance", [
      "recommender_audit",
      "federation_architect",
    ]);
    renderInheritanceAndWifView(analysis, mods.federation_architect?.payload || {});

    renderFreshnessBanner("freshness-compression", [
      "recommender_audit",
      "breakglass_simulator",
    ]);
    renderCompressionAndSimulatorView(
      analysis,
      auditMod.artifacts || {},
      mods.breakglass_simulator || {}
    );

    renderFreshnessBanner("freshness-guardrails", [
      "jit_pam_architect",
      "deny_policy_architect",
    ]);
    renderGuardrailsView(
      mods.jit_pam_architect?.payload || {},
      mods.deny_policy_architect?.payload || {}
    );

    renderFreshnessBanner("freshness-architect", [
      "role_architect",
      "gitops_pr_guardrail",
    ]);
    renderArchitectAndGitopsView(
      mods.role_architect?.payload || {},
      mods.gitops_pr_guardrail || {}
    );

    renderFreshnessBanner("freshness-compliance", ["compliance_mapper"]);
    renderComplianceView(mods.compliance_mapper?.payload || {});
  }

  function renderGatesRibbon(env, analysis) {
    const container = document.getElementById("gates-container");
    if (!container) return;
    const gates = analysis.verification_gates || {};
    const g1 = gates.gate_1_zero_hallucination || {};
    const g2 = gates.gate_2_mathematical_disjointness || {};
    const g3 = gates.gate_3_principal_accounting || {};
    const simDenials =
      env.modules?.breakglass_simulator?.summary?.simulated_403_denials ?? 0;
    const staleCount = (env.freshness_overview?.potentially_stale_modules || []).length;

    const chips = [
      {
        ok: true,
        text: `Project: ${env.project_id} (${env.trigger_mode})`,
      },
      {
        ok: g1.passed !== false,
        text: `Testable Perms Verified (${formatNumber(
          g1.testable_permissions_catalog_size || 9140
        )})`,
      },
      {
        ok: g2.passed !== false,
        text: `Disjoint Rᵢ ∩ Rⱼ = ∅ (Overlap: ${g2.pairwise_overlap_count ?? 0})`,
      },
      {
        ok: g3.passed !== false,
        text: `${g3.mapped_principals || 0}/${g3.input_principals || 0} Principals Accounted`,
      },
      {
        ok: simDenials === 0,
        text: `Audit Log Replay: ${simDenials} Simulated 403s`,
      },
      {
        ok: staleCount === 0,
        text:
          staleCount === 0
            ? "All 9 Modules Fresh"
            : `${staleCount} Module(s) Carried Forward (Stale)`,
      },
    ];

    container.innerHTML = chips
      .map(
        (it) =>
          `<span class="gate-chip ${it.ok ? "pass" : ""}">${
            it.ok ? "&#10003;" : "&#9888;"
          } ${escapeHtml(it.text)}</span>`
      )
      .join("");
  }

  /* ------------------------------------------------------------------------ */
  /* View 1: Executive Scorecard + Org Hierarchy                              */
  /* ------------------------------------------------------------------------ */

  /**
   * Groups role YAML artifacts for the explorer: personas (Model A default),
   * capability roles (Model B), and the bundles manifest. Each group carries a
   * folder prefix so identically named files across groups never collide.
   * @param {Object} artifacts recommender_audit payload.artifacts (name -> content).
   * @return {Array<{label:string,prefix:string,files:Object}>}
   */
  function collectRoleYamls(artifacts) {
    const art = artifacts || {};
    const bundles = {};
    if (art.bundles_yaml) bundles["bundles.yaml"] = art.bundles_yaml;
    return [
      { label: "Persona roles (Model A · default)", prefix: "personas/", files: art.model_a_role_yamls || {} },
      { label: "Capability roles (Model B)", prefix: "capabilities/", files: art.disjoint_role_yamls || {} },
      { label: "Model B bundles", prefix: "", files: bundles },
    ];
  }

  /** Flattens collectRoleYamls() output into one prefixed name -> content map. */
  function flattenRoleYamls(groups) {
    const flat = {};
    (groups || []).forEach((g) => {
      Object.keys(g.files).forEach((k) => {
        flat[g.prefix + k] = g.files[k];
      });
    });
    return flat;
  }

  /**
   * Summarises the custom-role design for KPI tiles and badges.
   * Reads the v2.1 keys (model_b_verification) and falls back to legacy
   * envelopes (executive_kpis.disjoint_roles_count / gate_2) so old runs render.
   */
  function roleDesignCounts(analysis) {
    const kpis = analysis.executive_kpis || {};
    const summary = analysis.summary || {};
    const ver = analysis.model_b_verification || {};
    const g2 = (analysis.verification_gates || {}).gate_2_mathematical_disjointness || {};
    const persona =
      summary.persona_roles_count ?? Object.keys(analysis.custom_roles_model_a || {}).length;
    const capability =
      ver.capability_count ??
      summary.capability_roles_count ??
      kpis.disjoint_roles_count ??
      Object.keys(analysis.custom_roles_model_b_disjoint || {}).length;
    const overlap = ver.pairwise_overlap ?? g2.pairwise_overlap_count ?? 0;
    // Legacy envelopes have no exact-cover proof; treat as unknown (false).
    const exact = ver.exact_cover === true;
    return { persona, capability, overlap, exact, verified: "exact_cover" in ver };
  }

  function renderScorecardAndOrgView(analysis, orgPayload) {
    const kpis = analysis.executive_kpis || {};
    const summary = analysis.summary || {};
    const meta = analysis.metadata || {};
    const roleCounts = roleDesignCounts(analysis);

    const kpiGrid = document.getElementById("kpi-grid");
    if (kpiGrid) {
      const cards = [
        {
          label: "Permission grants (principal × permission)",
          tip: "Sum over every principal of the distinct permissions its bound roles grant (current), versus the permissions the proposed least-privilege roles grant. One permission held by 10 principals counts 10 times.",
          value: `${formatNumber(kpis.total_permissions_before)} → ${formatNumber(
            kpis.total_permissions_after
          )}`,
          delta: `-${kpis.permissions_reduction_pct ?? 0}%`,
          deltaClass: "good",
          foot: "Proposed target, not applied. Based on 90-day IAM Recommender and audit-log usage.",
        },
        {
          label: "Over-scoped identities",
          tip: "Share of actionable principals (Google-managed service agents excluded) holding permissions they did not use in the last 90 days, now versus after the proposed cutover.",
          value: `${kpis.overprivileged_percentage_before ?? 0}% → ${
            kpis.overprivileged_percentage_after ?? 0
          }%`,
          delta: `${kpis.actionable_non_agent_principals || 0} Actionable`,
          deltaClass: "good",
          foot: `${kpis.total_principals || 0} total principals (Service Agents isolated)`,
        },
        {
          label: "Role compression",
          tip: "Distinct predefined roles bound today versus the persona custom roles proposed (Model A, the default). The footer shows the alternative capability-role design (Model B): zero-overlap building blocks whose bundles grant exactly what each persona needs.",
          value: `${kpis.predefined_roles_before_count || 0} → ${roleCounts.persona} Roles`,
          // v2.1 runs carry an exact-cover proof; legacy runs only report overlap.
          delta: roleCounts.verified
            ? roleCounts.exact && roleCounts.overlap === 0
              ? "Exact cover · 0 overlap"
              : "Bundle mismatch — review"
            : `${roleCounts.overlap} Overlap`,
          deltaClass:
            roleCounts.overlap === 0 && (!roleCounts.verified || roleCounts.exact) ? "good" : "warn",
          foot: `Persona roles (Model A) · alt: ${roleCounts.capability} capability roles (Model B)`,
        },
        {
          label: "Escalation paths (open → after plan)",
          tip: "Transitive actAs / getAccessToken / setIamPolicy chains detected now. The 'after' value is what remains if every P1 proposal is applied; nothing has been changed yet.",
          value: `${kpis.escalation_chains_count || 0} → ${Math.max(
            0,
            (kpis.escalation_chains_count || 0) - (kpis.escalation_chains_closed_count || 0)
          )}`,
          delta: `${kpis.escalation_chains_closed_count || 0} closable`,
          deltaClass: (kpis.escalation_chains_count || 0) > 0 ? "warn" : "good",
          foot: "Project & SA-level actAs / getAccessToken edges (proposal)",
        },
        {
          label: "Dormant SAs & past-window conditions",
          tip: "Service accounts with zero authentications in 90 days, and IAM conditions whose time window has already expired. Both are observed now and are P0 hygiene items.",
          value: `${kpis.inactive_sa_count || 0} SAs / ${
            kpis.expired_conditions_count || 0
          } Cond`,
          delta: "Phase P0",
          deltaClass: "warn",
          foot: "Two-stage disablement prior to removal",
        },
      ];

      kpiGrid.innerHTML = cards
        .map(
          (c) => `
          <div class="kpi-card">
            <div class="kpi-label">${escapeHtml(c.label)}${infoTip(c.tip)}</div>
            <div class="kpi-value-row">
              <span class="kpi-value">${escapeHtml(c.value)}</span>
              <span class="kpi-delta ${c.deltaClass}">${escapeHtml(c.delta)}</span>
            </div>
            <div class="kpi-foot">${escapeHtml(c.foot)}</div>
          </div>`
        )
        .join("");
    }

    const modeBadge = document.getElementById("telemetry-mode-badge");
    if (modeBadge) modeBadge.textContent = meta.telemetry_mode || "live_gcp_telemetry";

    const etagBadge = document.getElementById("etag-badge");
    if (etagBadge) {
      etagBadge.textContent = `etag: ${state.envelope?.live_policy_etag || meta.policy_etag || "--"}`;
    }

    const fc = summary.findings_counts || {};
    const fMeta = [
      { key: "F1_basic_roles", code: "F1 — Legacy Basic Roles (Owner / Editor)", color: "#dc2626" },
      { key: "F2_overprivileged_principals", code: "F2 — Broad Predefined Roles vs. 90d Usage", color: "#ea580c" },
      { key: "F3_privilege_escalation_risks", code: "F3 — Transitive SA Attachment & Admin Paths", color: "#d97706" },
      { key: "F4_inactive_service_accounts", code: "F4 — Dormant Service Accounts (90d Zero Auth)", color: "#7c3aed" },
      { key: "F5_expired_conditional_bindings", code: "F5 — Past-Window Conditional IAM Expressions", color: "#2563eb" },
      { key: "F6_overprivileged_service_agents", code: "F6 — Service Agents with Extra Admin Roles", color: "#0d9488" },
      { key: "F7_role_sprawl_redundancy", code: "F7 — Overlapping Multi-Role Sprawl", color: "#475569" },
    ];
    const maxCount = Math.max(1, ...fMeta.map((m) => Number(fc[m.key] || 0)));
    const barsEl = document.getElementById("findings-bars");
    if (barsEl) {
      barsEl.innerHTML = fMeta
        .map((m) => {
          const val = Number(fc[m.key] || 0);
          const pct = Math.max(val > 0 ? 8 : 2, Math.round((val / maxCount) * 100));
          return `
            <div class="finding-row">
              <div class="finding-row-top">
                <span class="finding-code">${escapeHtml(m.code)}</span>
                <span class="mono"><strong>${val}</strong> finding${val === 1 ? "" : "s"}</span>
              </div>
              <div class="finding-track">
                <div class="finding-fill" style="width:${pct}%; background:${m.color};"></div>
              </div>
            </div>`;
        })
        .join("");
    }

    // Ancestry Chain from gcp-iam-org-hierarchy-auditor
    const ancEl = document.getElementById("ancestry-chain-box");
    if (ancEl) {
      const nodes = orgPayload.ancestry_nodes || [];
      if (nodes.length) {
        ancEl.innerHTML = nodes
          .map(
            (n, idx) =>
              `<span class="ancestry-node">${escapeHtml(n.type.toUpperCase())}: <code>${escapeHtml(
                n.id
              )}</code></span>${
                idx < nodes.length - 1 ? '<span class="ancestry-arrow">&rarr;</span>' : ""
              }`
          )
          .join("");
      } else {
        ancEl.innerHTML = `<span class="ancestry-node">PROJECT: <code>${escapeHtml(
          state.currentProject
        )}</code></span>`;
      }
    }

    const taxEl = document.getElementById("taxonomy-list");
    if (taxEl) {
      const tc = summary.taxonomy_counts || {};
      taxEl.innerHTML = Object.entries(tc)
        .map(
          ([name, count]) => `
          <div class="tax-item">
            <span class="tax-name">${escapeHtml(name)}</span>
            <span class="tax-count">${formatNumber(count)}</span>
          </div>`
        )
        .join("");
    }

    const orgConstEl = document.getElementById("org-constraints-summary");
    if (orgConstEl) {
      const constraints = orgPayload.org_policy_constraints || [];
      orgConstEl.innerHTML = constraints
        .map(
          (c) => `
          <div style="display:flex;justify-content:space-between;align-items:center;padding:6px 0;border-top:1px solid #f1f5f9;font-size:0.78rem;">
            <span><code>${escapeHtml(c.constraint.replace("constraints/", ""))}</code></span>
            <span class="badge ${c.enforced ? "badge-green" : "badge-amber"}">${escapeHtml(
            c.status
          )}</span>
          </div>`
        )
        .join("");
    }
  }

  function renderPrincipalsTable(analysis) {
    const tbody = document.getElementById("principals-tbody");
    if (!tbody) return;
    const searchVal = (document.getElementById("principal-search")?.value || "")
      .trim()
      .toLowerCase();
    const taxFilter = document.getElementById("taxonomy-filter")?.value || "ALL";

    const rows = (analysis.principal_mappings || []).filter((pm) => {
      const cat = pm.category || pm.taxonomy || "";
      if (taxFilter === "NON_AGENT" && cat === "Google-Managed Service Agents") return false;
      if (taxFilter !== "ALL" && taxFilter !== "NON_AGENT" && cat !== taxFilter) return false;
      if (!searchVal) return true;
      const hay = [
        pm.principal,
        cat,
        (pm.current_roles || []).join(" "),
        pm.target_mapping || pm.model_a_custom_role || "",
        pm.recommended_action || pm.remediation_action || "",
      ]
        .join(" ")
        .toLowerCase();
      return hay.includes(searchVal);
    });

    if (!rows.length) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;color:#64748b;">No principals match filter.</td></tr>`;
      return;
    }

    tbody.innerHTML = rows
      .map((pm) => {
        const cat = pm.category || pm.taxonomy || "";
        // Prefer the bare persona role ID (sg_persona_*) for readability; fall back to legacy fields.
        const targetStr = pm.persona_role_id || pm.target_mapping || pm.model_a_custom_role || "Retain Current";
        const noteStr = pm.recommended_action || pm.remediation_action || pm.notes || "";
        const bundleList = pm.disjoint_model_b_bundle || pm.model_b_disjoint_roles || [];

        const rolesHtml = (pm.current_roles || [])
          .map((r) => {
            const isHigh =
              r === "roles/owner" ||
              r === "roles/editor" ||
              r.toLowerCase().endsWith("admin");
            const isCustom = r.startsWith("projects/");
            return `<span class="role-pill ${
              isCustom ? "good" : isHigh ? "high" : ""
            }">${escapeHtml(r)}</span>`;
          })
          .join("");

        const bundleHtml = bundleList
          .map((b) => `<span class="role-pill good">${escapeHtml(b)}</span>`)
          .join("");

        let actionBadge = `<span class="badge badge-blue">Phase ${escapeHtml(
          pm.remediation_phase || "P2"
        )}</span>`;
        if (String(targetStr).includes("Compliant")) {
          actionBadge = `<span class="badge badge-green">Compliant LP</span>`;
        } else if (cat === "Google-Managed Service Agents") {
          actionBadge = `<span class="badge badge-neutral">Protected Agent</span>`;
        }

        return `
          <tr>
            <td class="mono" style="font-weight:600;"><button type="button" class="link-btn" data-principal="${escapeHtml(pm.principal)}" title="Open identity details">${escapeHtml(pm.principal)}</button></td>
            <td><span class="badge badge-neutral">${escapeHtml(cat)}</span></td>
            <td><div class="role-pill-list">${rolesHtml}</div></td>
            <td>
              <div style="font-weight:600;">${escapeHtml(targetStr)}</div>
              <div style="font-size:0.75rem;color:#64748b;margin-top:2px;">${escapeHtml(noteStr)}</div>
            </td>
            <td><div class="role-pill-list">${bundleHtml || "—"}</div></td>
            <td>${actionBadge}</td>
          </tr>`;
      })
      .join("");
  }

  /* ------------------------------------------------------------------------ */
  /* View 2: Transitive Inheritance + Workload Federation (WIF)               */
  /* ------------------------------------------------------------------------ */

  function renderInheritanceAndWifView(analysis, wifPayload) {
    const stage = document.getElementById("inheritance-svg-stage");
    const cardsEl = document.getElementById("inheritance-cards");
    const paths = analysis.transitive_paths || [];
    const cutover = state.inheritanceCutoverSimulated;
    const projectId = analysis.metadata?.project_id || state.currentProject;

    if (stage) {
      const primary = paths[0] || {
        source_principal: `serviceAccount:cicd-deployer-sa@${projectId}.iam.gserviceaccount.com`,
        edge_permission: "iam.serviceAccounts.actAs / getAccessToken",
        intermediate_principal: `serviceAccount:platform-automation-sa@${projectId}.iam.gserviceaccount.com`,
        terminal_capability: "resourcemanager.projects.setIamPolicy",
        target_project: projectId,
      };
      const edgeColor = cutover ? "#16a34a" : "#dc2626";
      const edgeDash = cutover ? 'stroke-dasharray="6,6"' : "";
      const boxFill = cutover ? "#f0fdf4" : "#fff1f2";
      const statusHeader = cutover
        ? "POST-PHASE P1 CUTOVER: Transitive Inheritance Severed & Roles Right-Sized"
        : "CURRENT BROWNFIELD STATE: Active 2-Hop Administrative Role Inheritance Path";

      stage.innerHTML = `
        <svg viewBox="0 0 980 220" width="100%" height="220" role="img">
          <defs>
            <marker id="arrow-active" markerWidth="10" markerHeight="8" refX="9" refY="4" orient="auto">
              <path d="M0,0 L10,4 L0,8 Z" fill="${edgeColor}" />
            </marker>
          </defs>
          <text x="24" y="28" font-size="13" font-weight="700" fill="${edgeColor}">${escapeHtml(
        statusHeader
      )}</text>
          <rect x="24" y="54" width="250" height="118" rx="10" fill="#ffffff" stroke="#1a73e8" stroke-width="2"/>
          <text x="40" y="80" font-size="11" font-weight="700" fill="#1a73e8">WORKLOAD IDENTITY (HOP 0)</text>
          <text x="40" y="104" font-size="13" font-weight="700" fill="#0f172a">${escapeHtml(
            shortPrincipal(primary.source_principal)
          )}</text>
          <text x="40" y="126" font-size="11" fill="#475569">${
            cutover ? "Scoped Custom Role" : "Holds SA Impersonation Edge"
          }</text>

          <line x1="274" y1="113" x2="368" y2="113" stroke="${edgeColor}" stroke-width="2.5" ${edgeDash} marker-end="url(#arrow-active)" />
          <text x="321" y="98" text-anchor="middle" font-size="10.5" font-weight="700" fill="${edgeColor}">${
        cutover ? "Edge Removed (P1)" : "actAs + getAccessToken"
      }</text>

          <rect x="372" y="54" width="265" height="118" rx="10" fill="${boxFill}" stroke="${edgeColor}" stroke-width="2"/>
          <text x="388" y="80" font-size="11" font-weight="700" fill="${edgeColor}">INTERMEDIATE SA (HOP 1)</text>
          <text x="388" y="104" font-size="13" font-weight="700" fill="#0f172a">${escapeHtml(
            shortPrincipal(primary.intermediate_principal)
          )}</text>
          <text x="388" y="126" font-size="11" fill="#475569">${
            cutover ? "Zero setIamPolicy Perms" : "Holds Project IAM Admin"
          }</text>

          <line x1="637" y1="113" x2="725" y2="113" stroke="${edgeColor}" stroke-width="2.5" ${edgeDash} marker-end="url(#arrow-active)" />
          <rect x="729" y="54" width="228" height="118" rx="10" fill="#ffffff" stroke="${edgeColor}" stroke-width="2"/>
          <text x="745" y="80" font-size="11" font-weight="700" fill="#475569">TARGET PROJECT</text>
          <text x="745" y="104" font-size="14" font-weight="800" fill="#0f172a">${escapeHtml(
            primary.target_project || projectId
          )}</text>
          <text x="745" y="126" font-size="11" fill="${edgeColor}" font-weight="600">${
        cutover ? "Least-Privilege Enforced" : escapeHtml(primary.terminal_capability)
      }</text>
        </svg>`;
    }

    if (cardsEl) {
      cardsEl.innerHTML = paths
        .map(
          (p) => `
          <div class="chain-card">
            <span class="badge ${cutover ? "badge-green" : "badge-crimson"}">${
            cutover ? "Closed in " + p.remediation_phase : "Active Transitive Path"
          }</span>
            <div style="font-weight:700;margin:6px 0 4px;">${escapeHtml(
              shortPrincipal(p.source_principal)
            )} &rarr; ${escapeHtml(shortPrincipal(p.intermediate_principal))}</div>
            <div style="font-size:0.78rem;color:#475569;">Capability: <code>${escapeHtml(
              p.terminal_capability
            )}</code></div>
          </div>`
        )
        .join("");
    }

    // WIF Service Account Key Table & Terraform
    const wifTbody = document.getElementById("wif-sa-tbody");
    if (wifTbody) {
      const sas = wifPayload.service_accounts || [];
      wifTbody.innerHTML =
        sas
          .map((sa) => {
            const badgeCls =
              sa.user_managed_key_count > 0
                ? "badge-crimson"
                : sa.posture_status.includes("WIF")
                ? "badge-blue"
                : "badge-green";
            return `
              <tr>
                <td class="mono" style="font-size:0.77rem;">${escapeHtml(sa.email)}</td>
                <td class="mono"><strong>${sa.user_managed_key_count}</strong></td>
                <td><span class="badge ${badgeCls}">${escapeHtml(sa.posture_status)}</span></td>
                <td style="font-size:0.77rem;">${escapeHtml(sa.recommended_federation)}</td>
              </tr>`;
          })
          .join("") || `<tr><td colspan="4">No Service Accounts audited.</td></tr>`;
    }
    const wifViewer = document.getElementById("wif-tf-viewer");
    if (wifViewer) {
      wifViewer.textContent =
        wifPayload.wif_terraform_hcl || "# No WIF Terraform generated yet.";
    }
    // Only surface CI snippet downloads that the federation architect emitted.
    const snippets = wifPayload.ci_snippets || {};
    [
      ["btn-dl-wif-gha", snippets.github_actions],
      ["btn-dl-wif-gitlab", snippets.gitlab_ci],
    ].forEach(([id, content]) => {
      const btn = document.getElementById(id);
      if (btn) btn.style.display = content ? "" : "none";
    });

    // Existing WIF Provider Hygiene Audit table (when present)
    const wifAuditEl = document.getElementById("wif-existing-audit-section");
    if (wifAuditEl) {
      const auditFindings = wifPayload.existing_wif_audit?.findings || [];
      if (auditFindings.length) {
        wifAuditEl.innerHTML = `
          <h3 style="margin:0 0 8px;font-size:0.9rem;">Existing WIF Provider Hygiene Audit (${auditFindings.length} finding${auditFindings.length === 1 ? "" : "s"})</h3>
          <div class="table-scroll">
            <table class="data-table">
              <thead>
                <tr>
                  <th>Rule</th>
                  <th>Severity</th>
                  <th>Pool / Provider</th>
                  <th>Issuer URI</th>
                  <th>Finding Detail</th>
                </tr>
              </thead>
              <tbody>
                ${auditFindings
                  .map((f) => {
                    const sev = String(f.severity || "HIGH").toUpperCase();
                    const sevCls =
                      sev === "CRITICAL"
                        ? "badge-crimson"
                        : sev === "HIGH" || sev === "MEDIUM"
                        ? "badge-amber"
                        : "badge-neutral";
                    const poolProv = [f.pool_id, f.provider_id].filter(Boolean).join(" / ") || f.provider_name || "--";
                    return `<tr>
                      <td><span class="badge badge-mono">${escapeHtml(f.rule_id || "WIF_AUDIT")}</span></td>
                      <td><span class="badge ${sevCls}">${escapeHtml(sev)}</span></td>
                      <td class="mono" style="font-size:0.76rem;">${escapeHtml(poolProv)}</td>
                      <td class="mono" style="font-size:0.74rem;word-break:break-all;">${escapeHtml(f.issuer_uri || "--")}</td>
                      <td style="font-size:0.78rem;">${escapeHtml(f.detail || "")}</td>
                    </tr>`;
                  })
                  .join("")}
              </tbody>
            </table>
          </div>`;
      } else {
        wifAuditEl.innerHTML = "";
      }
    }

    // F5 & F6
    const condEl = document.getElementById("conditional-and-scope-list");
    if (condEl) {
      const f5 = analysis.findings?.F5_expired_conditional_bindings || [];
      const f6 =
        analysis.findings?.F6_overprivileged_service_agents ||
        analysis.findings?.F6_excess_service_agent_roles ||
        [];
      const items = [];
      f5.forEach((c) => {
        items.push(`
          <div class="detail-item">
            <span class="badge badge-amber">F5 Expired Condition</span>
            <div style="font-weight:700;margin-top:6px;">${escapeHtml(c.role)}</div>
            <div class="mono" style="font-size:0.75rem;color:#475569;">${escapeHtml(
              c.condition_title || ""
            )} — ${escapeHtml(c.condition_expression || c.expression || "")}</div>
          </div>`);
      });
      f6.forEach((sa) => {
        const extra = sa.excess_non_service_agent_roles || sa.high_risk_roles || [];
        items.push(`
          <div class="detail-item">
            <span class="badge badge-blue">F6 Service Agent Scope</span>
            <div style="font-weight:700;margin-top:6px;">${escapeHtml(sa.principal)}</div>
            <div style="font-size:0.78rem;color:#475569;">Extra Roles: <code>${escapeHtml(
              extra.join(", ")
            )}</code></div>
          </div>`);
      });
      condEl.innerHTML = items.join("") || `<div class="detail-item">Clean.</div>`;
    }

    // F4
    const f4El = document.getElementById("inactive-sa-list");
    if (f4El) {
      const f4 = analysis.findings?.F4_inactive_service_accounts || [];
      f4El.innerHTML =
        f4
          .map(
            (s) => `
          <div class="detail-item">
            <span class="badge badge-purple">Phase P0 — Disable Dormant SA</span>
            <div class="mono" style="font-weight:700;margin-top:6px;">${escapeHtml(s.email)}</div>
            <div class="mono" style="font-size:0.74rem;color:#64748b;">uniqueId: ${escapeHtml(
              s.service_account_id || s.unique_id || "captured"
            )}</div>
          </div>`
          )
          .join("") || `<div class="detail-item">No dormant SAs.</div>`;
    }
  }

  /* ------------------------------------------------------------------------ */
  /* View 3: Disjoint Compression + Breakglass Simulator                      */
  /* ------------------------------------------------------------------------ */

  function renderCompressionAndSimulatorView(analysis, artifacts, simModule) {
    const stage = document.getElementById("compression-svg-stage");
    const modelA = Object.entries(analysis.custom_roles_model_a || {});
    const modelB = Object.entries(analysis.custom_roles_model_b_disjoint || {});
    const kpis = analysis.executive_kpis || {};

    // Proof badge reflects the computed partition instead of a static "0".
    const proofBadge = document.getElementById("disjoint-proof-badge");
    if (proofBadge) {
      const rc = roleDesignCounts(analysis);
      const ok = rc.overlap === 0 && (!rc.verified || rc.exact);
      proofBadge.textContent = rc.verified
        ? `Overlap: ${rc.overlap} · Exact cover: ${rc.exact ? "yes" : "no"}`
        : `Pairwise Overlap: ${rc.overlap}`;
      proofBadge.className = `badge ${ok ? "badge-green" : "badge-amber"}`;
    }

    if (stage) {
      const height = Math.max(230, modelB.length * 34 + 60);
      const modelBNodes = modelB
        .slice(0, 8)
        .map(([slug, spec], idx) => {
          const y = 52 + idx * 32;
          const pCount = (spec.includedPermissions || []).length;
          return `
            <g>
              <line x1="550" y1="130" x2="640" y2="${y + 11}" stroke="#0d9488" stroke-width="1.5" stroke-opacity="0.55" />
              <rect x="640" y="${y}" width="310" height="24" rx="5" fill="#f0fdfa" stroke="#0d9488" stroke-width="1.3" />
              <text x="650" y="${y + 16}" font-size="11" font-weight="600" fill="#0f172a">${escapeHtml(
            spec.role_id || spec.roleId || slug
          )} (${pCount} perms)${spec.sensitive ? " ⚠" : ""}</text>
            </g>`;
        })
        .join("");

      stage.innerHTML = `
        <svg viewBox="0 0 980 ${height}" width="100%" height="${height}">
          <rect x="22" y="50" width="235" height="155" rx="10" fill="#fff1f2" stroke="#dc2626" stroke-width="1.8" />
          <text x="40" y="78" font-size="11" font-weight="700" fill="#991b1b">BEFORE: PREDEFINED SPRAWL</text>
          <text x="40" y="112" font-size="24" font-weight="800" fill="#0f172a">${formatNumber(
            kpis.predefined_roles_before_count || 21
          )} Roles</text>
          <text x="40" y="138" font-size="13" font-weight="700" fill="#dc2626">${formatNumber(
            kpis.total_permissions_before || 0
          )} Granted Perms</text>
          <line x1="257" y1="130" x2="325" y2="130" stroke="#1a73e8" stroke-width="2.5" />
          <rect x="325" y="50" width="225" height="155" rx="10" fill="#e8f0fe" stroke="#1a73e8" stroke-width="1.8" />
          <text x="342" y="78" font-size="11" font-weight="700" fill="#1557b0">MODEL A: PERSONA ROLES</text>
          <text x="342" y="112" font-size="24" font-weight="800" fill="#0f172a">${modelA.length} Roles</text>
          <text x="342" y="138" font-size="13" font-weight="700" fill="#1557b0">${formatNumber(
            kpis.total_permissions_after || 0
          )} Exercised Perms</text>
          <text x="640" y="34" font-size="11.5" font-weight="700" fill="#115e59">MODEL B: CAPABILITY ROLES (Rᵢ ∩ Rⱼ = ∅)${modelB.length > 8 ? ` · showing 8 of ${modelB.length}` : ""}</text>
          ${modelBNodes}
        </svg>`;
    }

    // Simulator Table
    const simVerdictBadge = document.getElementById("sim-verdict-badge");
    const simSummary = simModule.summary || {};
    const simPayload = simModule.payload || {};
    if (simVerdictBadge) {
      const v = simSummary.cutover_verdict || "NOT_RUN";
      simVerdictBadge.textContent = `${v} (${simSummary.simulated_403_denials ?? 0} Simulated 403s)`;
      simVerdictBadge.className = `badge ${
        (simSummary.simulated_403_denials ?? 0) === 0 ? "badge-green" : "badge-amber"
      }`;
    }
    const simConfBadge = document.getElementById("sim-confidence-badge");
    if (simConfBadge) {
      simConfBadge.innerHTML = renderSimConfidenceBadge(simAuditConfidence(simModule));
    }
    const simTbody = document.getElementById("simulator-tbody");
    if (simTbody) {
      const replays = simPayload.principal_replays || [];
      simTbody.innerHTML =
        replays
          .map(
            (r) => `
          <tr>
            <td class="mono" style="font-weight:600;"><button type="button" class="link-btn" data-principal="${escapeHtml(r.principal)}" title="Open identity details">${escapeHtml(r.principal)}</button></td>
            <td><span class="badge badge-neutral">${escapeHtml(r.remediation_phase)}</span></td>
            <td class="mono" style="font-size:0.76rem;">${escapeHtml(r.proposed_model_a_role)}</td>
            <td class="mono">${formatNumber(r.replayed_api_calls)}</td>
            <td class="mono"><strong>${r.simulated_403_denials}</strong></td>
            <td class="mono">${r.replay_coverage_pct}%</td>
            <td><span class="badge ${
              r.simulated_403_denials === 0 ? "badge-green" : "badge-crimson"
            }">${escapeHtml(r.verdict)}</span></td>
            <td>${confidenceChip(replayConfidence(r, simSummary))}</td>
          </tr>`
          )
          .join("") || `<tr><td colspan="8">No replay data available.</td></tr>`;
    }
    const covNote = document.getElementById("sim-coverage-note");
    if (covNote) {
      const src = simSummary.telemetry_source || "";
      const note = simSummary.sampling_coverage_note || "";
      covNote.innerHTML = src || note
        ? `<strong>Telemetry:</strong> <code>${escapeHtml(src || "unspecified")}</code>${
            note ? ` &mdash; ${escapeHtml(note)}` : ""
          }`
        : "Telemetry source not recorded in this run. Treat PASS verdicts with zero replayed calls as unverified.";
    }

    // Phases
    const phaseEl = document.getElementById("phase-timeline");
    if (phaseEl) {
      const phases = [
        { cls: "p0", title: "Phase P0 — Hygiene", desc: "Disable 90d dormant SAs & remove past-window conditions.", meta: `${kpis.inactive_sa_count || 0} SAs` },
        { cls: "p1", title: "Phase P1 — Sever Impersonation", desc: "Remove broad SA-level actAs/getAccessToken edges.", meta: `${kpis.escalation_chains_closed_count || 0} Paths` },
        { cls: "p2", title: "Phase P2 — Custom Role Cutover", desc: "Bind verified Model A / Disjoint Model B custom roles.", meta: simSummary.cutover_verdict
          ? `${formatNumber(simSummary.simulated_403_denials ?? 0)} Simulated 403s · ${simSummary.cutover_verdict}`
          : "Simulator not run" },
        { cls: "p3", title: "Phase P3 — PAM & Guardrails", desc: "Move humans to JIT PAM & enforce IAM v2 Deny Policies.", meta: "etag Rollback Armed" },
      ];
      phaseEl.innerHTML = phases
        .map(
          (p) => `
          <div class="phase-card ${p.cls}">
            <h3 class="phase-title">${escapeHtml(p.title)}</h3>
            <p class="phase-desc">${escapeHtml(p.desc)}</p>
            <span class="badge badge-neutral">${escapeHtml(p.meta)}</span>
          </div>`
        )
        .join("");
    }

    // YAML Explorer: persona roles (Model A default) first, then capability
    // roles and the per-principal bundles manifest (Model B alternative).
    const yamlGroups = collectRoleYamls(artifacts);
    const yamlFiles = flattenRoleYamls(yamlGroups);
    const yamlSelect = document.getElementById("yaml-file-select");
    const yamlViewer = document.getElementById("yaml-code-viewer");
    const keys = Object.keys(yamlFiles);
    if (yamlSelect && yamlViewer) {
      yamlSelect.innerHTML = yamlGroups
        .filter((g) => Object.keys(g.files).length)
        .map(
          (g) =>
            `<optgroup label="${escapeHtml(g.label)}">${Object.keys(g.files)
              .map(
                (k) =>
                  `<option value="${escapeHtml(g.prefix + k)}">${escapeHtml(k)}</option>`
              )
              .join("")}</optgroup>`
        )
        .join("");
      yamlViewer.textContent = keys.length ? yamlFiles[keys[0]] : "# No YAML files.";
    }

    // Persona evidence caveats: personas built purely from role definitions
    // (no Recommender/audit-log usage) are not least-privilege and must be
    // flagged so admins do not mistake them for right-sized roles.
    const caveatEl = document.getElementById("role-evidence-caveat");
    if (caveatEl) {
      const noUsage = analysis.summary?.no_usage_data_personas || [];
      const traceCount = Object.keys(analysis.role_traceability || {}).length;
      const parts = [];
      if (traceCount) {
        parts.push(
          `<span class="badge badge-blue">Traceability: ${traceCount} role(s) with per-permission evidence</span>`
        );
      }
      if (noUsage.length) {
        parts.push(
          `<span class="badge badge-amber" title="${escapeHtml(noUsage.join(", "))}">⚠ ${noUsage.length} persona(s) built without usage data — review before adoption</span>`
        );
      }
      caveatEl.innerHTML = parts.join(" ");
      caveatEl.style.display = parts.length ? "" : "none";
    }

    renderTriageMatrix(analysis);
    renderSelectedAuditArtifact();
  }

  function renderTriageMatrix(analysis) {
    const tbody = document.getElementById("triage-tbody");
    if (!tbody) return;
    const q = (document.getElementById("triage-search")?.value || "")
      .trim()
      .toLowerCase();
    const rows = (analysis.triage_matrix || []).filter((tr) => {
      if (!q) return true;
      return [tr.phase, tr.symptom, tr.principal, tr.rollback_command]
        .join(" ")
        .toLowerCase()
        .includes(q);
    });
    tbody.innerHTML =
      rows
        .map(
          (tr) => `
        <tr>
          <td><span class="badge badge-amber">${escapeHtml(tr.phase)}</span></td>
          <td style="font-weight:600;">${escapeHtml(tr.symptom)}</td>
          <td class="mono"><button type="button" class="link-btn" data-principal="${escapeHtml(tr.principal)}">${escapeHtml(tr.principal)}</button></td>
          <td><code style="font-size:0.74rem;word-break:break-all;">${escapeHtml(
            tr.rollback_command
          )}</code></td>
        </tr>`
        )
        .join("") || `<tr><td colspan="4">No matching triage entries.</td></tr>`;
  }

  function renderSelectedAuditArtifact() {
    const viewer = document.getElementById("artifact-code-viewer");
    if (!viewer || !state.envelope) return;
    const art = state.envelope.modules?.recommender_audit?.payload?.artifacts || {};
    const tab = state.activeArtifactTab;
    if (tab === "rollback") {
      viewer.textContent = art.rollback_runbook_sh || "# Rollback runbook unavailable";
    } else if (tab === "scc") {
      viewer.textContent = JSON.stringify(art.scc_findings || {}, null, 2);
    } else if (tab === "sarif") {
      viewer.textContent = JSON.stringify(art.sarif || {}, null, 2);
    } else if (tab === "report") {
      viewer.textContent = art.report_markdown || "# Report unavailable";
    }
  }

  /* ------------------------------------------------------------------------ */
  /* View 4: JIT PAM & IAM v2 Deny Policies                                   */
  /* ------------------------------------------------------------------------ */

  function renderGuardrailsView(pamPayload, denyPayload) {
    const pamList = document.getElementById("pam-entitlements-list");
    if (pamList) {
      const ents = pamPayload.entitlements || [];
      pamList.innerHTML =
        ents
          .map(
            (e) => `
          <div class="scope-card">
            <div style="display:flex;justify-content:space-between;align-items:center;">
              <span class="badge badge-purple">${escapeHtml(e.tier)}</span>
              <span class="mono" style="font-size:0.76rem;">Max: ${escapeHtml(
                e.max_request_duration
              )}</span>
            </div>
            <div style="font-weight:700;margin-top:6px;">${escapeHtml(
              e.entitlement_id
            )} &mdash; <code>${escapeHtml(e.eligible_requester)}</code></div>
            <div style="font-size:0.78rem;color:#475569;margin-top:4px;">
              Removes Standing: <code>${escapeHtml(
                (e.standing_roles_removed || []).join(", ")
              )}</code> &rarr; Grants JIT: <code>${escapeHtml(
              (e.jit_granted_roles || []).join(", ")
            )}</code>
            </div>
            <div style="font-size:0.75rem;color:#64748b;margin-top:4px;">Approver: <code>${escapeHtml(
              e.approver_principal
            )}</code></div>
          </div>`
          )
          .join("") || `<div class="detail-item">No standing human admin grants found.</div>`;
    }
    const pamViewer = document.getElementById("pam-tf-viewer");
    if (pamViewer) pamViewer.textContent = pamPayload.pam_terraform_hcl || "";

    const denyList = document.getElementById("deny-rules-list");
    if (denyList) {
      const rules = denyPayload.rules || [];
      denyList.innerHTML = rules
        .map(
          (r) => `
          <div class="scope-card" style="border-left-color:#dc2626;">
            <span class="badge badge-crimson">${escapeHtml(r.rule_id)}</span>
            <div style="font-weight:700;margin-top:6px;">${escapeHtml(r.description)}</div>
            <div class="role-pill-list" style="margin-top:6px;">
              ${(r.denied_permissions || [])
                .map((p) => `<span class="role-pill high">${escapeHtml(p)}</span>`)
                .join("")}
            </div>
          </div>`
        )
        .join("");
    }
    const denyViewer = document.getElementById("deny-tf-viewer");
    if (denyViewer) denyViewer.textContent = denyPayload.deny_policy_terraform_hcl || "";
  }

  /* ------------------------------------------------------------------------ */
  /* View 5: Shift-Left Role Architect + GitOps PR Guardrail                  */
  /* ------------------------------------------------------------------------ */

  function renderArchitectAndGitopsView(archPayload, gitopsModule) {
    const designs = archPayload.designs || [];
    const chipsEl = document.getElementById("architect-design-chips");
    if (chipsEl) {
      chipsEl.innerHTML = designs
        .map(
          (d, idx) =>
            `<button type="button" class="preset-chip ${
              idx === state.activeArchDesignIdx ? "active" : ""
            }" data-design-idx="${idx}">${escapeHtml(d.id)}: ${escapeHtml(
              (d.title || "").slice(0, 48)
            )}...</button>`
        )
        .join("");

      chipsEl.querySelectorAll("[data-design-idx]").forEach((btn) => {
        btn.addEventListener("click", () => {
          state.activeArchDesignIdx = Number(btn.dataset.designIdx);
          renderArchitectAndGitopsView(archPayload, gitopsModule);
        });
      });
    }

    const active = designs[state.activeArchDesignIdx] || archPayload.primary_design;
    if (active && active.spec) {
      renderSelectedArchitectBlueprint(active);
    }

    // GitOps PR Guardrail
    const gitSummary = gitopsModule.summary || {};
    const gitPayload = gitopsModule.payload || {};
    const verdictEl = document.getElementById("gitops-verdict-badge");
    if (verdictEl) {
      const v = gitSummary.pr_gate_verdict || "NOT_RUN";
      verdictEl.textContent = `${v} (${gitSummary.total_violations ?? 0} Violations)`;
      verdictEl.className = `badge ${
        v === "APPROVE_CLEAN" ? "badge-green" : "badge-crimson"
      }`;
    }

    const gitTbody = document.getElementById("gitops-tbody");
    if (gitTbody) {
      const viols = gitPayload.violations || [];
      gitTbody.innerHTML =
        viols
          .map(
            (v) => `
          <tr>
            <td><span class="badge badge-mono">${escapeHtml(v.rule_id)}</span></td>
            <td><span class="badge ${
              v.severity === "CRITICAL" ? "badge-crimson" : "badge-amber"
            }">${escapeHtml(v.severity)}</span></td>
            <td class="mono">${escapeHtml(v.file)}:${v.line}</td>
            <td class="mono" style="font-size:0.76rem;">${escapeHtml(
              v.resource
            )}<br/><code>${escapeHtml(v.role)}</code></td>
            <td>
              <div style="font-weight:600;">${escapeHtml(v.message)}</div>
              <div style="font-size:0.76rem;color:#475569;margin-top:2px;"><strong>Fix:</strong> ${escapeHtml(
                v.remediation
              )}</div>
            </td>
          </tr>`
          )
          .join("") || `<tr><td colspan="5">Zero Terraform IAM drift violations detected.</td></tr>`;
    }

    const patchEl = document.getElementById("gitops-patch-viewer");
    if (patchEl) {
      patchEl.textContent =
        gitPayload.remediated_hcl || "# No Terraform drift violations requiring auto-patch.";
    }
    const prCommentBtn = document.getElementById("btn-dl-gitops-pr-md");
    if (prCommentBtn) {
      prCommentBtn.style.display = gitPayload.pr_comment_md ? "" : "none";
    }

    // Inbound SCC & Wiz Finding-to-Fix Co-Pilot
    const remMod = state.envelope?.modules?.finding_remediator || {};
    const remPayload = remMod.payload || {};
    const plans = remPayload.remediation_plans || [];
    const remBadge = document.getElementById("remediator-count-badge");
    if (remBadge) {
      remBadge.textContent = `${plans.length} SCC/Wiz Alert(s) Remediated`;
    }
    const remCards = document.getElementById("remediator-cards");
    if (remCards) {
      // UI-5: show the real per-plan replay outcome and reconcile it with the
      // full-cutover simulator, which scopes differently (all proposed roles at once).
      const simReplays = state.envelope?.modules?.breakglass_simulator?.payload?.principal_replays || [];
      const simByPrincipal = new Map(simReplays.map((r) => [r.principal, r]));
      const globalCanary = Boolean(remPayload.canary_mode || remMod.summary?.canary_mode);
      remCards.innerHTML =
        plans
          .map((rp) => {
            const planDenials = rp.simulated_403_denials;
            const planLabel =
              planDenials === undefined || planDenials === null
                ? rp.simulated_403_display || "Fix replay: not recorded"
                : `Fix replay: ${formatNumber(planDenials)} 403s`;
            const simRow = simByPrincipal.get(rp.principal);
            const simNote =
              simRow && Number(simRow.simulated_403_denials || 0) !== Number(planDenials || 0)
                ? `<div class="scope-note">Full-cutover simulator: <strong>${formatNumber(
                    simRow.simulated_403_denials
                  )}</strong> 403s for this principal (different scope: all proposed roles applied together).</div>`
                : "";
            const isCanary = Boolean(rp.canary_recommended || rp.canary_mode || globalCanary);
            const ap = rp.attack_path_summary;
            let chokeHtml = "";
            if (ap) {
              if (typeof ap === "string") {
                chokeHtml = `<div class="choke-box"><strong>Attack-Path Choke-Point:</strong> ${escapeHtml(ap)}</div>`;
              } else {
                const edge = ap.choke_point_edge || ap.choke_point || "";
                const strat = ap.choke_point_strategy || "";
                const rat = ap.rationale || ap.summary || ap.description || "";
                const hops = ap.hop_count ? `${ap.hop_count}-hop path` : "";
                const metaLine = [hops, strat, edge].filter(Boolean).join(" • ");
                chokeHtml = `<div class="choke-box">
                  <div><strong>Attack-Path Choke-Point${metaLine ? ` (${escapeHtml(metaLine)})` : ""}:</strong> ${escapeHtml(rat || "Targeted choke-point remediation.")}</div>
                </div>`;
              }
            }
            return `
          <div class="chain-card">
            <div style="display:flex;justify-content:space-between;align-items:center;gap:6px;flex-wrap:wrap;margin-bottom:6px;">
              <span class="badge badge-blue">${escapeHtml(rp.source_platform)}</span>
              <span class="badge ${
                rp.severity === "CRITICAL" ? "badge-crimson" : "badge-amber"
              }">${escapeHtml(rp.severity)}</span>
              <span class="tag tag-simulated" title="Simulated against 90-day audit logs for this single fix">${escapeHtml(planLabel)}</span>
              ${rp.status ? `<span class="badge ${rp.status === "READY" ? "badge-green" : "badge-amber"}" title="Remediation plan status">${escapeHtml(rp.status)}</span>` : ""}
              ${ap ? `<span class="badge badge-purple" title="Attack-path choke-point identified">Choke-Point</span>` : ""}
              ${isCanary ? `<span class="badge badge-amber" title="Dual-bind canary cutover recommended before removing legacy role">Canary Cutover</span>` : ""}
            </div>
            <div style="font-weight:700;margin-bottom:4px;">${escapeHtml(rp.title)}</div>
            <div class="mono" style="font-size:0.74rem;margin-bottom:4px;">Finding: ${escapeHtml(
              rp.finding_id
            )}</div>
            <div style="font-size:0.78rem;color:#334155;">
              <strong>Principal:</strong> <button type="button" class="link-btn mono" data-principal="${escapeHtml(rp.principal)}">${escapeHtml(rp.principal)}</button><br/>
              <strong>Proposed Fix:</strong> <code>${escapeHtml(rp.replacement_role)}</code> (${
                rp.replacement_permissions_count || 0
              } perms)
            </div>
            ${chokeHtml}
            ${simNote}
          </div>`;
          })
          .join("") ||
        `<div class="detail-item">No inbound SCC or Wiz findings ingested in this run yet. Run <code>gcp-iam-finding-remediator</code> with an SCC or Wiz JSON export.</div>`;
    }
    const remTfEl = document.getElementById("remediator-tf-viewer");
    if (remTfEl) {
      remTfEl.textContent =
        remPayload.remediation_terraform_hcl ||
        "# Run gcp-iam-finding-remediator to generate surgical SCC/Wiz Terraform patches.";
    }
  }

  function renderSelectedArchitectBlueprint(bundle) {
    const spec = bundle.spec || {};
    const metrics = spec.summary_metrics || {};

    const compEl = document.getElementById("arch-persona-comparison");
    if (compEl) {
      const predefCount = metrics.closest_predefined_permission_count || 450;
      const consoleCount = metrics.total_selected_permissions || 12;
      const headlessCount = metrics.strict_headless_permission_count || 4;
      const headlessPct = Math.max(3, Math.round((headlessCount / predefCount) * 100));
      const consolePct = Math.max(6, Math.round((consoleCount / predefCount) * 100));

      compEl.innerHTML = `
        <div class="findings-bars">
          <div class="finding-row">
            <div class="finding-row-top">
              <span>Predefined Baseline (<code>${escapeHtml(
                (metrics.closest_predefined_roles || []).join(", ")
              )}</code>)</span>
              <span class="mono"><strong>${formatNumber(predefCount)}</strong> perms</span>
            </div>
            <div class="finding-track"><div class="finding-fill" style="width:100%;background:#dc2626;"></div></div>
          </div>
          <div class="finding-row">
            <div class="finding-row-top">
              <span>Interactive Console Role</span>
              <span class="mono"><strong>${formatNumber(consoleCount)}</strong> perms</span>
            </div>
            <div class="finding-track"><div class="finding-fill" style="width:${consolePct}%;background:#1a73e8;"></div></div>
          </div>
          <div class="finding-row">
            <div class="finding-row-top">
              <span><strong>Strict Headless Workload Role</strong></span>
              <span class="mono"><strong>${formatNumber(headlessCount)}</strong> perms</span>
            </div>
            <div class="finding-track"><div class="finding-fill" style="width:${headlessPct}%;background:#16a34a;"></div></div>
          </div>
        </div>`;
    }

    const guardEl = document.getElementById("arch-guardrail-alerts");
    if (guardEl) {
      const risks =
        spec.privilege_escalation_findings ||
        spec.escalation_risks ||
        spec.escalation_findings ||
        [];
      guardEl.innerHTML = risks.length
        ? risks
            .map(
              (r) => `
          <div class="guardrail-alert">
            <strong>[${escapeHtml(r.code || r.rule_id)}]</strong> <code>${escapeHtml(
                r.permission
              )}</code>: ${escapeHtml(r.reason || r.risk || r.description || "")}
          </div>`
            )
            .join("")
        : `<div class="callout callout-info" style="margin-top:8px;"><strong>Guardrail Passed:</strong> Zero E1–E5 escalation primitives in synthesized role.</div>`;
    }

    const scopeEl = document.getElementById("arch-scope-diagram");
    if (scopeEl) {
      const roles = spec.scoped_custom_roles || spec.scoped_roles || [];
      scopeEl.innerHTML = roles
        .map(
          (r) => `
          <div class="scope-card">
            <div style="display:flex;justify-content:space-between;align-items:center;">
              <span class="badge badge-blue">Scope: ${escapeHtml(r.scope)}</span>
              <code style="font-size:0.75rem;">${escapeHtml(r.tf_binding_resource || "")}</code>
            </div>
            <div style="font-weight:700;margin-top:6px;">${escapeHtml(r.role_id)}</div>
            <div class="role-pill-list" style="margin-top:6px;">
              ${(r.included_permissions || [])
                .map((p) => `<span class="role-pill good">${escapeHtml(p)}</span>`)
                .join("")}
            </div>
          </div>`
        )
        .join("");
    }

    renderSelectedArchitectCode();
  }

  function renderSelectedArchitectCode() {
    const viewer = document.getElementById("arch-code-viewer");
    if (!viewer || !state.envelope) return;
    const archPayload = state.envelope.modules?.role_architect?.payload || {};
    const designs = archPayload.designs || [];
    const active = designs[state.activeArchDesignIdx] || archPayload.primary_design || {};
    const art = active.artifacts || {};
    const tab = state.activeArchTab;

    if (tab === "main_tf") {
      viewer.textContent = art.main_tf || "";
    } else if (tab === "yamls") {
      viewer.textContent = Object.entries(art.role_yamls || {})
        .map(([n, c]) => `# === ${n} ===\n${c}`)
        .join("\n\n");
    } else if (tab === "provision_sh") {
      viewer.textContent = art.provision_sh || "";
    } else if (tab === "rollback_sh") {
      viewer.textContent = art.rollback_sh || "";
    } else if (tab === "sarif") {
      viewer.textContent = JSON.stringify(art.sarif || {}, null, 2);
    }
  }

  /* ------------------------------------------------------------------------ */
  /* View 6: Regulatory Compliance Matrix                                     */
  /* ------------------------------------------------------------------------ */

  function renderComplianceView(compPayload) {
    const cardsEl = document.getElementById("compliance-framework-cards");
    if (cardsEl) {
      const fws = compPayload.framework_scorecards || [];
      cardsEl.innerHTML = fws
        .map(
          (fw) => `
          <div class="framework-card">
            <div style="font-weight:700;color:#475569;font-size:0.82rem;">${escapeHtml(
              fw.framework
            )}</div>
            <div class="framework-score-row">
              <span class="framework-score-now">${fw.score_before_pct}%</span>
              <span class="badge badge-green">&rarr; ${fw.score_after_pct}% Projected</span>
            </div>
            <div style="font-size:0.76rem;color:#64748b;">
              ${fw.controls_passing_before}/${fw.controls_total} passing now &bull; ${
            fw.controls_passing_after
          }/${fw.controls_total} post-remediation
            </div>
          </div>`
        )
        .join("");
    }

    renderComplianceTable(compPayload);
    const mdViewer = document.getElementById("compliance-md-viewer");
    if (mdViewer) mdViewer.textContent = compPayload.auditor_report_markdown || "";
  }

  function renderComplianceTable(compPayload) {
    const tbody = document.getElementById("compliance-tbody");
    if (!tbody) return;
    const fwFilter = document.getElementById("compliance-fw-filter")?.value || "ALL";
    const controls = (compPayload.controls || []).filter(
      (c) => fwFilter === "ALL" || c.framework === fwFilter
    );

    tbody.innerHTML =
      controls
        .map(
          (c) => `
        <tr>
          <td style="font-weight:600;">${escapeHtml(c.framework)}</td>
          <td><code>${escapeHtml(c.control_id)}</code> &mdash; ${escapeHtml(c.title)}</td>
          <td><span class="badge ${
            c.current_status === "PASS" ? "badge-green" : "badge-crimson"
          }">${escapeHtml(c.current_status)}</span></td>
          <td><span class="badge badge-green">${escapeHtml(c.projected_status)}</span></td>
          <td style="font-size:0.78rem;">${escapeHtml(c.finding_detail)}</td>
          <td><span class="badge badge-neutral">${escapeHtml(c.remediation_phase)}</span></td>
          <td class="mono" style="font-size:0.75rem;">${escapeHtml(c.evidence_artifact)}</td>
        </tr>`
        )
        .join("") || `<tr><td colspan="7">No compliance controls evaluated.</td></tr>`;
  }

  /* ------------------------------------------------------------------------ */
  /* Event Binding                                                            */
  /* ------------------------------------------------------------------------ */

  /**
   * Activates a tab (UI-13: roving tabindex + aria-selected + hidden panels)
   * and records it in the URL (UI-11) so views are shareable.
   * @param {string} targetId Panel id, e.g. "view-findings".
   * @param {{focus?: boolean}} opts focus=true moves keyboard focus to the tab.
   */
  function switchToTab(targetId, opts = {}) {
    if (!VALID_TABS.has(targetId)) targetId = "view-overview";
    state.activeTab = targetId;
    document.querySelectorAll(".nav-tab").forEach((b) => {
      const isMatch = b.dataset.tab === targetId;
      b.classList.toggle("active", isMatch);
      b.setAttribute("aria-selected", isMatch ? "true" : "false");
      b.tabIndex = isMatch ? 0 : -1;
      if (isMatch && opts.focus) b.focus();
    });
    document.querySelectorAll(".tab-panel").forEach((panel) => {
      const on = panel.id === targetId;
      panel.classList.toggle("active", on);
      panel.hidden = !on;
    });
    if (targetId === "view-fleet") {
      loadFleetView(state.fleetScope || "all");
    }
    if (insights) insights.onTabSwitched(targetId);
  }

  async function loadFleetView(scopeValue = "all") {
    state.fleetScope = scopeValue || "all";
    const tbody = document.getElementById("fleet-projects-tbody");
    if (tbody) {
      tbody.innerHTML = `<tr><td colspan="12">Loading Org / Folder fleet posture from GCS...</td></tr>`;
    }
    try {
      const res = await fetch(
        `/api/fleet?scope=${encodeURIComponent(state.fleetScope)}`,
        { cache: "no-store" }
      );
      const data = await res.json();
      if (!res.ok) throw new Error(data.details || data.error || `HTTP ${res.status}`);
      state.fleetData = data;
      renderFleetView(data);
    } catch (err) {
      if (tbody) {
        tbody.innerHTML = `<tr><td colspan="12">Failed to load fleet posture: ${escapeHtml(
          String(err)
        )} <button type="button" class="btn btn-secondary btn-sm" id="btn-fleet-retry">Retry</button></td></tr>`;
        document.getElementById("btn-fleet-retry")?.addEventListener("click", () =>
          loadFleetView(state.fleetScope || "all")
        );
      }
    }
  }

  function renderFleetView(data) {
    const scopeSel = document.getElementById("fleet-scope-select");
    const bannerEl = document.getElementById("fleet-sweep-banner");
    const kpiGrid = document.getElementById("fleet-kpi-grid");
    const tbody = document.getElementById("fleet-projects-tbody");
    const findingsRoot = document.getElementById("fleet-findings-by-project");

    if (scopeSel && Array.isArray(data.available_scopes)) {
      const prev = state.fleetScope || "all";
      scopeSel.innerHTML = data.available_scopes
        .map(
          (s) =>
            `<option value="${escapeHtml(s.value)}">${escapeHtml(s.label)}</option>`
        )
        .join("");
      scopeSel.value = data.available_scopes.some((s) => s.value === prev)
        ? prev
        : "all";
    }

    if (bannerEl) {
      const rollup = data.sweep_rollup;
      if (rollup) {
        bannerEl.innerHTML = `<div class="callout callout-info">
          <strong>Org / Folder Sweep Rollup Active:</strong>
          <code>${escapeHtml(rollup.scope_resource)}</code> &bull; Sweep <code>${escapeHtml(
            rollup.sweep_id
          )}</code> (${escapeHtml(rollup.timestamp_utc)}) &bull;
          Assessed <strong>${rollup.succeeded_count}/${rollup.discovered_count}</strong> projects.
        </div>`;
      } else {
        bannerEl.innerHTML = `<div class="callout callout-info">
          Showing live GCS snapshots grouped by GCP Organization &amp; Folder ancestry.
          To sweep all projects in an Org or Folder automatically, run
          <code>scopeguard_pipeline.py --org-id=&lt;ORG_ID&gt;</code> or <code>--folder-id=&lt;FOLDER_ID&gt;</code>.
        </div>`;
      }
    }

    const k = data.aggregate_kpis || {};
    if (kpiGrid) {
      kpiGrid.innerHTML = `
        <div class="kpi-card">
          <div class="kpi-label">Projects in Scope</div>
          <div class="kpi-value">${formatNumber(k.projects_count)}</div>
          <div class="kpi-sub">${formatNumber(k.total_principals)} total principals audited</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-label">Fleet Blast-Radius Reduction</div>
          <div class="kpi-value" style="color:#15803d;">-${k.permissions_reduction_pct || 0}%</div>
          <div class="kpi-sub">${formatNumber(k.permissions_before)} &rarr; ${formatNumber(
            k.permissions_after
          )} perms</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-label">Privilege Escalations &amp; Standing Admins</div>
          <div class="kpi-value" style="color:#b91c1c;">${formatNumber(
            k.escalation_chains_count
          )} / ${formatNumber(k.standing_privileged_humans_count)}</div>
          <div class="kpi-sub">F3 chains / PAM JIT human targets</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-label">Inbound SCC &amp; Wiz Fixes</div>
          <div class="kpi-value" style="color:#1d4ed8;">${formatNumber(
            k.inbound_findings_remediated
          )}</div>
          <div class="kpi-sub">${formatNumber(k.gitops_violations_count)} GitOps drift findings</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-label">Avg Compliance Score</div>
          <div class="kpi-value">${k.avg_compliance_before_pct || 0}% &rarr; ${
            k.avg_compliance_after_pct || 0
          }%</div>
          <div class="kpi-sub">CIS / SOC 2 / ISO 27001 / PCI-DSS</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-label">Coverage Gaps${infoTip(
            `Stale: latest run older than ${k.stale_threshold_days || 14} days. Not assessed: discovered in a sweep or present in the bucket without a usable latest.json.`
          )}</div>
          <div class="kpi-value" style="color:${
            (k.stale_projects_count || 0) + (k.not_assessed_count || 0) > 0 ? "#b45309" : "#15803d"
          };">${formatNumber(k.stale_projects_count)} / ${formatNumber(k.not_assessed_count)}</div>
          <div class="kpi-sub">stale / not-assessed projects</div>
        </div>
      `;
    }

    const projects = data.projects || [];
    if (tbody) {
      renderFleetTable(tbody, projects, data.unassessed_projects || []);
    }
    renderFleetHeatmap(projects, data.category_labels || {});
    renderFleetTopPrincipals(data.top_principals || []);

    if (findingsRoot) {
      if (!projects.length) {
        findingsRoot.innerHTML = `<div class="callout callout-info">No project findings available in this scope.</div>`;
      } else {
        findingsRoot.innerHTML = projects
          .map((p) => {
            const items = p.top_findings || [];
            return `<div class="chain-card" style="margin-bottom:14px;">
              <div style="display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:10px;flex-wrap:wrap;">
                <div>
                  <strong class="mono" style="font-size:0.95rem;">${escapeHtml(
                    p.project_id
                  )}</strong>
                  <span class="badge badge-crimson" style="margin-left:8px;">P0: ${
                    p.p0_count
                  }</span>
                  <span class="badge badge-amber" style="margin-left:4px;">P1: ${
                    p.p1_count
                  }</span>
                  <span style="font-size:0.75rem;color:#64748b;margin-left:8px;">Run: <code>${escapeHtml(
                    p.run_id
                  )}</code></span>
                </div>
                <button class="btn btn-secondary btn-inspect-project-card" type="button" data-project="${escapeHtml(
                  p.project_id
                )}">Open Full Project Report &rarr;</button>
              </div>
              ${
                items.length
                  ? `<div class="table-scroll"><table class="data-table">
                      <thead><tr><th>Phase</th><th>Skill</th><th>Target</th><th>Recommended Action</th></tr></thead>
                      <tbody>${items
                        .map(
                          (f) => `<tr>
                          <td><span class="badge ${
                            f.phase === "P0" ? "badge-crimson" : "badge-amber"
                          }">${escapeHtml(f.phase)}</span></td>
                          <td class="mono" style="font-size:0.75rem;">${escapeHtml(f.skill)}</td>
                          <td class="mono" style="font-size:0.75rem;">${escapeHtml(f.target)}</td>
                          <td style="font-size:0.8rem;">${escapeHtml(f.action)}</td>
                        </tr>`
                        )
                        .join("")}</tbody>
                    </table></div>`
                  : `<div style="font-size:0.8rem;color:#15803d;">No P0/P1 findings remaining for this project.</div>`
              }
            </div>`;
          })
          .join("");

        findingsRoot.querySelectorAll(".btn-inspect-project-card").forEach((btn) => {
          btn.addEventListener("click", async () => {
            const pid = btn.dataset.project;
            const projSel = document.getElementById("project-select");
            if (projSel) projSel.value = pid;
            state.currentRun = "latest";
            await loadAssessment(pid, "latest");
            switchToTab("view-overview");
            showToast(`Drilled into project ${pid}.`);
          });
        });
      }
    }
  }

  /** Sort value extractors for the fleet matrix (UI-8). */
  const FLEET_SORTERS = {
    project_id: (p) => p.project_id || "",
    age_days: (p) => (p.age_days === null || p.age_days === undefined ? -1 : p.age_days),
    findings_critical: (p) =>
      (p.severity_counts?.CRITICAL || 0) * 1000 + (p.severity_counts?.HIGH || 0) * 10 + (p.findings_total || 0) / 100,
    actionable_principals: (p) => p.kpis?.total_principals || 0,
    permissions_before: (p) => p.kpis?.permissions_before || 0,
    escalation_chains: (p) => p.kpis?.escalation_chains_count || 0,
    standing_admins: (p) => p.kpis?.standing_privileged_humans_count || 0,
    compliance: (p) => p.kpis?.compliance_score_before_pct || 0,
  };

  function sortFleetProjects(projects) {
    const { key, dir } = state.fleetSort;
    const get = FLEET_SORTERS[key] || FLEET_SORTERS.project_id;
    const mult = dir === "asc" ? 1 : -1;
    return projects.slice().sort((a, b) => {
      const va = get(a);
      const vb = get(b);
      if (va < vb) return -1 * mult;
      if (va > vb) return 1 * mult;
      return String(a.project_id).localeCompare(String(b.project_id));
    });
  }

  function fleetStatusCell(p) {
    if (p.status && p.status !== "OK") {
      return `<span class="badge badge-neutral" title="${escapeHtml(p.reason || "")}">${escapeHtml(
        p.status.replace(/_/g, " ")
      )}</span>`;
    }
    const age = p.age_days;
    const ageTxt = age === null || age === undefined ? "age unknown" : age === 0 ? "today" : `${age}d ago`;
    return p.is_stale
      ? `<span class="badge badge-amber" title="Latest run is older than the stale threshold">Stale &middot; ${escapeHtml(ageTxt)}</span>`
      : `<span class="badge badge-green">Fresh &middot; ${escapeHtml(ageTxt)}</span>`;
  }

  function fleetFindingsCell(p) {
    const sc = p.severity_counts || {};
    const parts = [];
    if (sc.CRITICAL) parts.push(`<span class="sev sev-critical">${sc.CRITICAL} Critical</span>`);
    if (sc.HIGH) parts.push(`<span class="sev sev-high">${sc.HIGH} High</span>`);
    const rest = (p.findings_total || 0) - (sc.CRITICAL || 0) - (sc.HIGH || 0);
    if (rest > 0) parts.push(`<span class="sev sev-low">+${rest}</span>`);
    return parts.join(" ") || `<span class="badge badge-green">None</span>`;
  }

  function fleetRowHtml(p) {
    const pk = p.kpis || {};
    const ancestryText = (p.ancestry || []).join(" → ") || "project:" + p.project_id;
    const gitBadge =
      pk.gitops_pr_verdict === "BLOCK_MERGE"
        ? `<span class="badge badge-crimson">BLOCK (${formatNumber(pk.gitops_violations_count)})</span>`
        : `<span class="badge badge-green">${escapeHtml(pk.gitops_pr_verdict || "—")}</span>`;
    return `<tr class="${p.is_stale ? "row-stale" : ""}">
      <td class="mono" style="font-weight:700;">${escapeHtml(p.project_id)}</td>
      <td class="mono" style="font-size:0.75rem;color:#475569;">${escapeHtml(ancestryText)}</td>
      <td>${fleetStatusCell(p)}</td>
      <td>${fleetFindingsCell(p)}</td>
      <td class="mono">${formatNumber(pk.total_principals)}</td>
      <td class="mono">${formatNumber(pk.permissions_before)} &rarr; ${formatNumber(
        pk.permissions_after
      )} <span class="badge badge-green">-${escapeHtml(pk.permissions_reduction_pct ?? 0)}%</span></td>
      <td class="mono">${formatNumber(pk.escalation_chains_count)}</td>
      <td class="mono">${formatNumber(pk.standing_privileged_humans_count)}</td>
      <td>${gitBadge}</td>
      <td class="mono">${formatNumber(pk.inbound_findings_remediated)}</td>
      <td class="mono">${escapeHtml(pk.compliance_score_before_pct ?? 0)}% &rarr; <strong>${escapeHtml(
        pk.compliance_score_after_pct ?? 0
      )}%</strong></td>
      <td><button class="btn btn-secondary btn-inspect-project" type="button" data-project="${escapeHtml(
        p.project_id
      )}">Inspect &rarr;</button></td>
    </tr>`;
  }

  function gapRowHtml(g) {
    return `<tr class="row-gap">
      <td class="mono" style="font-weight:700;">${escapeHtml(g.project_id)}</td>
      <td class="mono" style="font-size:0.75rem;color:#475569;">${escapeHtml(g.folder_label || "")}</td>
      <td>${fleetStatusCell(g)}</td>
      <td colspan="9" style="font-size:0.8rem;color:#64748b;">${escapeHtml(
        g.reason || "Not assessed"
      )}. Run <code>scopeguard_pipeline.py --project=${escapeHtml(g.project_id)}</code> to close this coverage gap.</td>
    </tr>`;
  }

  /**
   * Renders the fleet matrix: sorted (UI-8), optionally grouped by folder, with
   * stale and not-assessed projects listed so coverage gaps stay visible.
   */
  function renderFleetTable(tbody, projects, gaps) {
    document.querySelectorAll("#view-fleet th.sortable").forEach((th) => {
      const on = th.dataset.sort === state.fleetSort.key;
      th.setAttribute("aria-sort", on ? (state.fleetSort.dir === "asc" ? "ascending" : "descending") : "none");
    });
    if (!projects.length && !gaps.length) {
      tbody.innerHTML = `<tr><td colspan="12">No assessed projects match this Org / Folder scope yet.</td></tr>`;
      return;
    }
    const sorted = sortFleetProjects(projects);
    let html = "";
    if (state.fleetGroupByFolder) {
      const groups = new Map();
      sorted.forEach((p) => {
        const g = p.folder_label || "(no ancestry)";
        if (!groups.has(g)) groups.set(g, { rows: [], gaps: [] });
        groups.get(g).rows.push(p);
      });
      gaps.forEach((g) => {
        const lbl = g.folder_label || "(unknown)";
        if (!groups.has(lbl)) groups.set(lbl, { rows: [], gaps: [] });
        groups.get(lbl).gaps.push(g);
      });
      [...groups.keys()].sort().forEach((lbl) => {
        const grp = groups.get(lbl);
        const crit = grp.rows.reduce((a, p) => a + (p.severity_counts?.CRITICAL || 0), 0);
        html += `<tr class="group-row"><th colspan="12" scope="rowgroup">${escapeHtml(lbl)} &middot; ${
          grp.rows.length
        } assessed${grp.gaps.length ? `, ${grp.gaps.length} not assessed` : ""} &middot; ${crit} critical</th></tr>`;
        html += grp.rows.map(fleetRowHtml).join("") + grp.gaps.map(gapRowHtml).join("");
      });
    } else {
      html = sorted.map(fleetRowHtml).join("") + gaps.map(gapRowHtml).join("");
    }
    tbody.innerHTML = html;
    tbody.querySelectorAll(".btn-inspect-project").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const pid = btn.dataset.project;
        const projSel = document.getElementById("project-select");
        if (projSel) projSel.value = pid;
        state.currentRun = "latest";
        try {
          await loadAssessment(pid, "latest");
          switchToTab("view-overview");
          showToast(`Drilled into project ${pid}.`);
        } catch (err) {
          showToast(`Failed to open ${pid}: ${err.message}`, true);
        }
      });
    });
  }

  /** Projects × finding-category heatmap (UI-8). */
  function renderFleetHeatmap(projects, labels) {
    const host = document.getElementById("fleet-heatmap");
    if (!host) return;
    const cats = new Set();
    projects.forEach((p) => Object.keys(p.category_counts || {}).forEach((c) => cats.add(c)));
    const catList = [...cats].sort();
    if (!projects.length || !catList.length) {
      host.innerHTML = `<div class="empty-note">No categorized findings in this scope.</div>`;
      return;
    }
    const max = Math.max(1, ...projects.flatMap((p) => Object.values(p.category_counts || {})));
    const head = catList
      .map((c) => `<th scope="col" class="heat-col" title="${escapeHtml(labels[c] || c)}"><span>${escapeHtml(labels[c] || c)}</span></th>`)
      .join("");
    const rows = sortFleetProjects(projects)
      .map((p) => {
        const cells = catList
          .map((c) => {
            const n = (p.category_counts || {})[c] || 0;
            const lvl = n === 0 ? 0 : Math.min(4, Math.ceil((n / max) * 4));
            return `<td class="heat heat-${lvl}" title="${escapeHtml(p.project_id)} · ${escapeHtml(
              labels[c] || c
            )}: ${n}">${n || ""}</td>`;
          })
          .join("");
        return `<tr><th scope="row" class="mono">${escapeHtml(p.project_id)}</th>${cells}</tr>`;
      })
      .join("");
    host.innerHTML = `<table class="data-table heatmap"><thead><tr><th scope="col">Project</th>${head}</tr></thead><tbody>${rows}</tbody></table>`;
  }

  /** Top-10 riskiest principals across the fleet (UI-8). */
  function renderFleetTopPrincipals(list) {
    const host = document.getElementById("fleet-top-principals");
    if (!host) return;
    if (!list.length) {
      host.innerHTML = `<div class="empty-note">No principal-level findings in this scope.</div>`;
      return;
    }
    host.innerHTML = `<table class="data-table"><thead><tr>
        <th scope="col">#</th><th scope="col">Principal</th><th scope="col">Type</th>
        <th scope="col">Findings</th><th scope="col">Projects</th><th scope="col">Categories</th></tr></thead>
      <tbody>${list
        .map(
          (e, i) => `<tr>
          <td>${i + 1}</td>
          <td class="mono" style="font-size:0.76rem;">${escapeHtml(e.principal)}</td>
          <td><span class="badge badge-neutral">${escapeHtml(e.principal_type || "")}</span></td>
          <td>${e.critical ? `<span class="sev sev-critical">${e.critical} Critical</span> ` : ""}${formatNumber(e.findings)} total</td>
          <td class="mono" style="font-size:0.75rem;">${escapeHtml((e.projects || []).join(", "))}</td>
          <td style="font-size:0.75rem;">${escapeHtml((e.categories || []).join(", "))}</td>
        </tr>`
        )
        .join("")}</tbody></table>`;
  }

  /**
   * Tab clicks plus WAI-ARIA tablist keyboard support (UI-13):
   * ArrowLeft/ArrowRight cycle, Home/End jump, activation follows focus.
   */
  function bindNavigationEvents() {
    const tabs = Array.from(document.querySelectorAll(".nav-tab"));
    tabs.forEach((tabBtn) => {
      tabBtn.addEventListener("click", () => {
        switchToTab(tabBtn.dataset.tab);
      });
      tabBtn.addEventListener("keydown", (e) => {
        const visibleTabs = tabs.filter((t) => !t.hidden && !t.classList.contains("hidden"));
        const visIdx = visibleTabs.indexOf(tabBtn);
        if (visIdx < 0 || !visibleTabs.length) return;
        let next = -1;
        if (e.key === "ArrowRight") next = (visIdx + 1) % visibleTabs.length;
        else if (e.key === "ArrowLeft") next = (visIdx - 1 + visibleTabs.length) % visibleTabs.length;
        else if (e.key === "Home") next = 0;
        else if (e.key === "End") next = visibleTabs.length - 1;
        if (next >= 0) {
          e.preventDefault();
          switchToTab(visibleTabs[next].dataset.tab, { focus: true });
        }
      });
    });

    // Role view segmented toggle (All / DevOps / SecOps & GRC)
    document.querySelectorAll("[data-role-view]").forEach((btn) => {
      btn.addEventListener("click", () => {
        applyRoleView(btn.dataset.roleView);
      });
    });

    // Fleet: sortable headers + group-by-folder toggle (UI-8).
    document.querySelectorAll("#view-fleet th.sortable button").forEach((btn) => {
      btn.addEventListener("click", () => {
        const key = btn.parentElement.dataset.sort;
        if (state.fleetSort.key === key) {
          state.fleetSort.dir = state.fleetSort.dir === "asc" ? "desc" : "asc";
        } else {
          state.fleetSort = { key, dir: key === "project_id" ? "asc" : "desc" };
        }
        if (state.fleetData) renderFleetView(state.fleetData);
      });
    });
    document.getElementById("fleet-group-folder")?.addEventListener("change", (e) => {
      state.fleetGroupByFolder = e.target.checked;
      if (state.fleetData) renderFleetView(state.fleetData);
    });
  }

  function bindActionEvents() {
    document.getElementById("project-select")?.addEventListener("change", async (e) => {
      state.currentRun = "latest";
      try {
        await loadAssessment(e.target.value, "latest");
        showToast(`Loaded latest GCS snapshot for ${e.target.value}.`);
      } catch (err) {
        showToast(`Failed to load ${e.target.value}: ${err.message}`, true);
      }
    });

    document.getElementById("run-select")?.addEventListener("change", async (e) => {
      try {
        await loadAssessment(state.currentProject, e.target.value);
        showToast(`Loaded snapshot '${e.target.value}' for ${state.currentProject}.`);
      } catch (err) {
        showToast(`Failed to load snapshot: ${err.message}`, true);
      }
    });

    document.getElementById("btn-sync-gcs")?.addEventListener("click", () => {
      syncFromGcs({ initial: false });
      const fleetPanel = document.getElementById("view-fleet");
      if (fleetPanel && fleetPanel.classList.contains("active")) {
        loadFleetView(state.fleetScope || "all");
      }
    });

    document.getElementById("fleet-scope-select")?.addEventListener("change", (e) => {
      loadFleetView(e.target.value);
    });

    document.getElementById("principal-search")?.addEventListener("input", () => {
      const an = state.envelope?.modules?.recommender_audit?.payload?.analysis;
      if (an) renderPrincipalsTable(an);
    });
    document.getElementById("taxonomy-filter")?.addEventListener("change", () => {
      const an = state.envelope?.modules?.recommender_audit?.payload?.analysis;
      if (an) renderPrincipalsTable(an);
    });

    document.getElementById("btn-graph-before")?.addEventListener("click", () => {
      state.inheritanceCutoverSimulated = false;
      document.getElementById("btn-graph-before").classList.add("active");
      document.getElementById("btn-graph-after").classList.remove("active");
      renderAllViews();
    });
    document.getElementById("btn-graph-after")?.addEventListener("click", () => {
      state.inheritanceCutoverSimulated = true;
      document.getElementById("btn-graph-after").classList.add("active");
      document.getElementById("btn-graph-before").classList.remove("active");
      renderAllViews();
    });

    document.getElementById("triage-search")?.addEventListener("input", () => {
      const an = state.envelope?.modules?.recommender_audit?.payload?.analysis;
      if (an) renderTriageMatrix(an);
    });

    document.getElementById("yaml-file-select")?.addEventListener("change", (e) => {
      const art = state.envelope?.modules?.recommender_audit?.payload?.artifacts || {};
      const allYamls = flattenRoleYamls(collectRoleYamls(art));
      document.getElementById("yaml-code-viewer").textContent =
        allYamls[e.target.value] || "";
    });

    document.querySelectorAll("[data-artifact]").forEach((btn) => {
      btn.addEventListener("click", () => {
        state.activeArtifactTab = btn.dataset.artifact;
        document
          .querySelectorAll("[data-artifact]")
          .forEach((b) => b.classList.toggle("active", b === btn));
        renderSelectedAuditArtifact();
      });
    });

    document.querySelectorAll("[data-arch-tab]").forEach((btn) => {
      btn.addEventListener("click", () => {
        state.activeArchTab = btn.dataset.archTab;
        document
          .querySelectorAll("[data-arch-tab]")
          .forEach((b) => b.classList.toggle("active", b === btn));
        renderSelectedArchitectCode();
      });
    });

    document.getElementById("compliance-fw-filter")?.addEventListener("change", () => {
      const cp = state.envelope?.modules?.compliance_mapper?.payload;
      if (cp) renderComplianceTable(cp);
    });

    // Artifact Downloads
    document.getElementById("btn-dl-rollback")?.addEventListener("click", () => {
      const art = state.envelope?.modules?.recommender_audit?.payload?.artifacts || {};
      triggerDownload(`rollback_${state.currentProject}.sh`, art.rollback_runbook_sh);
    });
    document.getElementById("btn-dl-scc")?.addEventListener("click", () => {
      const art = state.envelope?.modules?.recommender_audit?.payload?.artifacts || {};
      triggerDownload(
        `scc_${state.currentProject}.json`,
        JSON.stringify(art.scc_findings || {}, null, 2),
        "application/json"
      );
    });
    document.getElementById("btn-dl-sarif")?.addEventListener("click", () => {
      const art = state.envelope?.modules?.recommender_audit?.payload?.artifacts || {};
      triggerDownload(
        `scopeguard_${state.currentProject}.sarif.json`,
        JSON.stringify(art.sarif || {}, null, 2),
        "application/sarif+json"
      );
    });
    document.getElementById("btn-dl-wif-tf")?.addEventListener("click", () => {
      const wf = state.envelope?.modules?.federation_architect?.payload || {};
      triggerDownload(`wif_federation_${state.currentProject}.tf`, wf.wif_terraform_hcl);
    });
    document.getElementById("btn-dl-key-sh")?.addEventListener("click", () => {
      const wf = state.envelope?.modules?.federation_architect?.payload || {};
      triggerDownload(
        `retire_sa_keys_${state.currentProject}.sh`,
        wf.key_retirement_runbook_sh
      );
    });
    // CI workflow snippets (ART-11): keyless auth wiring for each CI platform.
    document.getElementById("btn-dl-wif-gha")?.addEventListener("click", () => {
      const wf = state.envelope?.modules?.federation_architect?.payload || {};
      triggerDownload("github-actions-wif.yml", wf.ci_snippets?.github_actions);
    });
    document.getElementById("btn-dl-wif-gitlab")?.addEventListener("click", () => {
      const wf = state.envelope?.modules?.federation_architect?.payload || {};
      triggerDownload("gitlab-ci-wif.yml", wf.ci_snippets?.gitlab_ci);
    });
    document.getElementById("btn-dl-pam-tf")?.addEventListener("click", () => {
      const pm = state.envelope?.modules?.jit_pam_architect?.payload || {};
      triggerDownload(`pam_entitlements_${state.currentProject}.tf`, pm.pam_terraform_hcl);
    });
    document.getElementById("btn-dl-deny-tf")?.addEventListener("click", () => {
      const dn = state.envelope?.modules?.deny_policy_architect?.payload || {};
      triggerDownload(
        `deny_policies_${state.currentProject}.tf`,
        dn.deny_policy_terraform_hcl
      );
    });
    document.getElementById("btn-dl-arch-tf")?.addEventListener("click", () => {
      const ap = state.envelope?.modules?.role_architect?.payload || {};
      const active = (ap.designs || [])[state.activeArchDesignIdx] || ap.primary_design || {};
      triggerDownload("main.tf", active.artifacts?.main_tf || "");
    });
    document.getElementById("btn-dl-arch-sarif")?.addEventListener("click", () => {
      const ap = state.envelope?.modules?.role_architect?.payload || {};
      const active = (ap.designs || [])[state.activeArchDesignIdx] || ap.primary_design || {};
      triggerDownload(
        "role_architect.sarif.json",
        JSON.stringify(active.artifacts?.sarif || {}, null, 2),
        "application/sarif+json"
      );
    });
    document.getElementById("btn-dl-gitops-ci")?.addEventListener("click", () => {
      const gp = state.envelope?.modules?.gitops_pr_guardrail?.payload || {};
      triggerDownload("scopeguard-iam-guardrail.yml", gp.ci_workflow_yaml);
    });
    document.getElementById("btn-dl-gitops-patch")?.addEventListener("click", () => {
      const gp = state.envelope?.modules?.gitops_pr_guardrail?.payload || {};
      triggerDownload("gitops_remediation_patch.tf", gp.remediated_hcl || "");
    });
    document.getElementById("btn-dl-gitops-pr-md")?.addEventListener("click", () => {
      const gp = state.envelope?.modules?.gitops_pr_guardrail?.payload || {};
      triggerDownload(
        `gitops_pr_comment_${state.currentProject}.md`,
        gp.pr_comment_md || "",
        "text/markdown"
      );
    });
    // Inline Copy buttons on code viewers
    document.querySelectorAll("[data-copy-target]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const targetId = btn.dataset.copyTarget;
        const viewer = document.getElementById(targetId);
        const text = viewer?.textContent || "";
        if (!text.trim()) {
          showToast("Nothing to copy yet.", true);
          return;
        }
        const ok = await copyTextToClipboard(text);
        showToast(ok ? "Copied to clipboard." : "Copy failed; select the text manually.", !ok);
      });
    });
    document.getElementById("btn-dl-rem-tf")?.addEventListener("click", () => {
      const rm = state.envelope?.modules?.finding_remediator?.payload || {};
      triggerDownload(
        `scc_wiz_remediation_${state.currentProject}.tf`,
        rm.remediation_terraform_hcl || ""
      );
    });
    document.getElementById("btn-dl-rem-notes")?.addEventListener("click", () => {
      const rm = state.envelope?.modules?.finding_remediator?.payload || {};
      triggerDownload(
        `ticket_proposed_remediation_${state.currentProject}.md`,
        rm.ticket_proposed_remediation_md || rm.ticket_closure_notes_md || "",
        "text/markdown"
      );
    });

    // Run-to-Run Burn-Down & Drift Diff Modal
    const diffModal = document.getElementById("diff-modal");
    const diffContent = document.getElementById("diff-content");
    document.getElementById("btn-open-diff")?.addEventListener("click", async () => {
      diffModal?.classList.remove("hidden");
      if (diffContent) diffContent.innerHTML = "<p>Computing run-to-run diff from GCS...</p>";
      try {
        const res = await fetch(
          `/api/diff?project=${encodeURIComponent(state.currentProject)}&target=${encodeURIComponent(
            state.currentRun || "latest"
          )}`
        );
        const data = await res.json();
        if (data.status !== "OK") {
          diffContent.innerHTML = `<div class="callout callout-info">${escapeHtml(
            data.message || "Unable to compare runs."
          )}</div>`;
          return;
        }
        const d = data.deltas || {};
        const fmtDelta = (n, invertGood = true) => {
          if (n === 0) return `<span class="badge badge-neutral">0 (Unchanged)</span>`;
          const isGood = invertGood ? n < 0 : n > 0;
          return `<span class="badge ${isGood ? "badge-green" : "badge-crimson"}">${
            n > 0 ? "+" : ""
          }${n}</span>`;
        };
        diffContent.innerHTML = `
          <div class="callout callout-info" style="margin-bottom:14px;">
            Comparing Baseline <code>${escapeHtml(data.base.run_id)}</code> (${escapeHtml(
              data.base.timestamp_utc
            )}) &rarr; Target <code>${escapeHtml(data.target.run_id)}</code> (${escapeHtml(
              data.target.timestamp_utc
            )}) &bull; IAM Policy <code>etag</code> Changed: <strong>${
              d.etag_changed ? "YES (Live Policy Drift Detected)" : "NO"
            }</strong>
          </div>
          <div class="table-scroll" style="margin-bottom:14px;">
            <table class="data-table">
              <thead><tr><th>Governance Metric</th><th>Prior Run</th><th>Selected Run</th><th>Delta</th></tr></thead>
              <tbody>
                <tr><td>Total Granted Permissions</td><td class="mono">${formatNumber(
                  data.base.permissions_before
                )}</td><td class="mono">${formatNumber(
                  data.target.permissions_before
                )}</td><td>${fmtDelta(d.permissions_before_delta, true)}</td></tr>
                <tr><td>Target Compressed Permissions</td><td class="mono">${formatNumber(
                  data.base.permissions_after
                )}</td><td class="mono">${formatNumber(
                  data.target.permissions_after
                )}</td><td>${fmtDelta(d.permissions_after_delta, true)}</td></tr>
                <tr><td>Escalation Chains (F3)</td><td class="mono">${
                  data.base.escalation_chains
                }</td><td class="mono">${data.target.escalation_chains}</td><td>${fmtDelta(
                  d.escalation_chains_delta,
                  true
                )}</td></tr>
                <tr><td>Baseline Compliance Score</td><td class="mono">${
                  data.base.compliance_before_pct
                }%</td><td class="mono">${data.target.compliance_before_pct}%</td><td>${fmtDelta(
                  d.compliance_before_delta_pct,
                  false
                )}</td></tr>
              </tbody>
            </table>
          </div>
          <div class="two-col-grid">
            <div class="chain-card">
              <div style="font-weight:700;margin-bottom:6px;color:#b91c1c;">Newly Added Bindings (${
                (d.added_bindings || []).length
              })</div>
              ${
                (d.added_bindings || []).length
                  ? `<ul style="margin:0;padding-left:18px;font-size:0.76rem;">${d.added_bindings
                      .map((b) => `<li class="mono">${escapeHtml(b)}</li>`)
                      .join("")}</ul>`
                  : `<div style="font-size:0.78rem;color:#64748b;">No new IAM bindings introduced.</div>`
              }
            </div>
            <div class="chain-card">
              <div style="font-weight:700;margin-bottom:6px;color:#15803d;">Removed / Remediated Bindings (${
                (d.removed_bindings || []).length
              })</div>
              ${
                (d.removed_bindings || []).length
                  ? `<ul style="margin:0;padding-left:18px;font-size:0.76rem;">${d.removed_bindings
                      .map((b) => `<li class="mono">${escapeHtml(b)}</li>`)
                      .join("")}</ul>`
                  : `<div style="font-size:0.78rem;color:#64748b;">No bindings removed between these two runs.</div>`
              }
            </div>
          </div>`;
      } catch (err) {
        diffContent.innerHTML = `<div class="callout callout-info">Error computing diff: ${escapeHtml(
          String(err)
        )}</div>`;
      }
    });
    document.getElementById("btn-close-diff-modal")?.addEventListener("click", () => {
      diffModal?.classList.add("hidden");
    });
    diffModal?.addEventListener("click", (ev) => {
      if (ev.target === diffModal) diffModal.classList.add("hidden");
    });
    document.getElementById("btn-dl-compliance-md")?.addEventListener("click", () => {
      const cp = state.envelope?.modules?.compliance_mapper?.payload || {};
      triggerDownload(
        `compliance_evidence_${state.currentProject}.md`,
        cp.auditor_report_markdown
      );
    });

    // Master Recommendations (.md) Modal & Export
    const recsModal = document.getElementById("recs-modal");
    const recsViewer = document.getElementById("recs-md-viewer");
    const getMasterRecsMd = () =>
      state.envelope?.master_recommendations_markdown ||
      state.envelope?.modules?.recommender_audit?.payload?.artifacts?.report_markdown ||
      "# No recommendations report available in this snapshot yet.\n# Re-run scopeguard-orchestrator to populate master_recommendations_markdown.";

    document.getElementById("btn-open-recs-md")?.addEventListener("click", () => {
      if (recsViewer) recsViewer.textContent = getMasterRecsMd();
      recsModal?.classList.remove("hidden");
    });
    document.getElementById("btn-close-recs-modal")?.addEventListener("click", () => {
      recsModal?.classList.add("hidden");
    });
    recsModal?.addEventListener("click", (ev) => {
      if (ev.target === recsModal) recsModal.classList.add("hidden");
    });
    document.addEventListener("keydown", (ev) => {
      if (ev.key === "Escape") {
        recsModal?.classList.add("hidden");
        diffModal?.classList.add("hidden");
      }
    });
    document.getElementById("btn-copy-recs-md")?.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(getMasterRecsMd());
        showToast("Copied full Markdown recommendations to clipboard.");
      } catch (_err) {
        showToast("Clipboard copy unavailable in this browser context.");
      }
    });
    document.getElementById("btn-dl-recs-md")?.addEventListener("click", () => {
      const runTag = state.envelope?.run_id || "latest";
      triggerDownload(
        `scopeguard_recommendations_${state.currentProject}_${runTag}.md`,
        getMasterRecsMd(),
        "text/markdown"
      );
    });

    // Instant floating popover tooltip for all [data-tooltip] elements
    // (KPI ⓘ icons, Audit-Log Confidence badges, etc.). Attached to body so
    // it is never clipped by overflow:hidden cards or scroll containers.
    initFloatingTooltips();
  }

  function initFloatingTooltips() {
    let pop = document.getElementById("sg-tooltip");
    if (!pop) {
      pop = document.createElement("div");
      pop.id = "sg-tooltip";
      pop.className = "sg-tooltip hidden";
      pop.setAttribute("role", "tooltip");
      document.body.appendChild(pop);
    }
    let activeTarget = null;
    let pinnedTarget = null;

    const positionPopover = (el) => {
      const rect = el.getBoundingClientRect();
      pop.classList.remove("hidden");
      const pw = pop.offsetWidth;
      const ph = pop.offsetHeight;
      const gap = 8;
      let top = rect.top - ph - gap;
      let below = false;
      if (top < 8) {
        top = rect.bottom + gap;
        below = true;
      }
      let left = rect.left + rect.width / 2 - pw / 2;
      left = Math.max(10, Math.min(left, window.innerWidth - pw - 10));
      pop.style.top = `${Math.round(top)}px`;
      pop.style.left = `${Math.round(left)}px`;
      pop.classList.toggle("sg-tooltip-below", below);
    };

    const showTip = (el) => {
      const text = el?.getAttribute("data-tooltip") || "";
      if (!text) return;
      activeTarget = el;
      pop.textContent = text;
      positionPopover(el);
    };

    const hideTip = () => {
      activeTarget = null;
      pinnedTarget = null;
      pop.classList.add("hidden");
    };

    document.addEventListener("mouseover", (ev) => {
      const target = ev.target?.closest?.("[data-tooltip]");
      if (target) {
        showTip(target);
      } else if (!pinnedTarget && activeTarget) {
        hideTip();
      }
    });

    document.addEventListener("focusin", (ev) => {
      const target = ev.target?.closest?.("[data-tooltip]");
      if (target) showTip(target);
    });

    document.addEventListener("focusout", (ev) => {
      if (ev.target?.closest?.("[data-tooltip]") && !pinnedTarget) {
        hideTip();
      }
    });

    document.addEventListener("click", (ev) => {
      const target = ev.target?.closest?.("[data-tooltip]");
      if (target) {
        ev.stopPropagation();
        if (pinnedTarget === target) {
          hideTip();
        } else {
          pinnedTarget = target;
          showTip(target);
        }
      } else if (pinnedTarget) {
        hideTip();
      }
    });

    document.addEventListener("keydown", (ev) => {
      if (ev.key === "Escape" && (activeTarget || pinnedTarget)) hideTip();
    });

    window.addEventListener("scroll", () => {
      if (activeTarget) hideTip();
    }, true);
    window.addEventListener("resize", () => {
      if (activeTarget) hideTip();
    });
  }

  document.addEventListener("DOMContentLoaded", initApp);
})();
