/**
 * ScopeGuard Portal — Insights module (UI-1..UI-14).
 *
 * Adds the admin-oriented layer on top of the per-skill views in app.js:
 *   - Overview landing page (risk now, change since last run, next 5 actions)
 *   - Unified Findings queue with filters, search, sort, pagination
 *   - Stateless finding status (New / Open / Regressed / Resolved) from /api/findings
 *   - Run provenance / freshness bar and global HOLD / degraded alerts
 *   - Identity drawer and read-only change-plan modal
 *   - CSV / JSON / Markdown exports and a JSON evidence pack
 *   - URL state (deep links), global search, keyboard + focus management
 *
 * Security notes:
 *   - Every interpolated value goes through ctx.escapeHtml (XSS-safe innerHTML).
 *   - CSV cells are guarded against spreadsheet formula injection.
 *   - Generated gcloud commands are display-only text with POSIX single-quote
 *     escaping; the portal never calls IAM APIs (strictly read-only).
 *
 * Exposes window.ScopeGuardInsights = { init, onAssessmentLoaded, onTabSwitched }.
 * Zero external dependencies.
 */

(function () {
  "use strict";

  /** Shared helpers injected by app.js (escapeHtml, state, switchToTab, ...). */
  let ctx = null;

  const SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
  const SEV_RANK = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
  const PRI_RANK = { P0: 0, P1: 1, P2: 2, P3: 3 };
  const STATUS_ORDER = ["New", "Regressed", "Open", "Resolved"];
  const PAGE_SIZE = 50;
  const HISTORY_RUNS = 10;
  const TOTAL_SKILLS = 11;

  /** Module-local view state. */
  const S = {
    data: null, // Last /api/findings response
    loadSeq: 0, // Guards against out-of-order fetch responses
    filters: { q: "", sev: "", priority: "", status: "", cat: "", ptype: "", sort: "severity" },
    page: 1,
    filtered: [],
    copyStore: new Map(), // copy-button id -> text (avoids huge data attributes)
    copySeq: 0,
    lastFocus: null, // Element to restore focus to when a dialog closes
    drawerPrincipal: "",
    qjItems: [],
    qjActiveIdx: 0,
  };

  const TRIAGE_PRESETS = [
    { id: "all", label: "All Open", apply: () => ({}), count: (d) => (d.findings || []).length },
    { id: "new", label: "New Since Last Run", apply: () => ({ status: "New" }), count: (d) => (d.counts?.by_status || {}).New || 0 },
    { id: "scc_wiz", label: "SCC / Wiz Alerts", apply: () => ({ cat: "external_finding" }), count: (d) => (d.counts?.by_category || {}).external_finding || 0 },
    { id: "ai_agent", label: "AI / Agent SAs (F8)", apply: () => ({ cat: "ai_agent_blast_radius" }), count: (d) => (d.counts?.by_category || {}).ai_agent_blast_radius || 0 },
    { id: "wif_misconfig", label: "WIF Misconfigs", apply: () => ({ cat: "wif_provider_misconfig" }), count: (d) => (d.counts?.by_category || {}).wif_provider_misconfig || 0 },
    { id: "p0", label: "P0 Quick Wins", apply: () => ({ priority: "P0" }), count: (d) => (d.counts?.by_priority || {}).P0 || 0 },
  ];

  /* ---------------------------------------------------------------------- */
  /* Small utilities                                                         */
  /* ---------------------------------------------------------------------- */

  const $ = (id) => document.getElementById(id);
  const esc = (v) => ctx.escapeHtml(v);

  /** POSIX shell single-quote escaping for display-only commands. */
  function shQuote(value) {
    return `'${String(value ?? "").replace(/'/g, `'\\''`)}'`;
  }

  /** Strips the IAM member prefix (user:, serviceAccount:, ...). */
  function memberEmail(member) {
    return String(member || "").replace(/^[a-zA-Z]+:/, "");
  }

  function ageText(iso) {
    const t = Date.parse(iso || "");
    if (!Number.isFinite(t)) return "age unknown";
    const mins = Math.max(0, Math.round((Date.now() - t) / 60000));
    if (mins < 60) return `${mins} min ago`;
    const hrs = Math.round(mins / 60);
    if (hrs < 48) return `${hrs} h ago`;
    return `${Math.round(hrs / 24)} days ago`;
  }

  function sevChip(sev) {
    const s = String(sev || "LOW").toUpperCase();
    return `<span class="sev sev-${esc(s.toLowerCase())}">${esc(s.charAt(0) + s.slice(1).toLowerCase())}</span>`;
  }

  function statusChip(status) {
    const cls = { New: "st-new", Open: "st-open", Regressed: "st-regressed", Resolved: "st-resolved" }[status] || "st-open";
    return `<span class="chip ${cls}">${esc(status || "Open")}</span>`;
  }

  function confChip(level) {
    if (!level || level === "n/a") return `<span class="muted">—</span>`;
    const cls = level === "High" ? "conf-high" : level === "Medium" ? "conf-med" : "conf-low";
    return `<span class="chip ${cls}" title="Replay confidence">${esc(level)}</span>`;
  }

  /** Registers text for a copy button and returns the button HTML. */
  function copyButton(text, label = "Copy") {
    const id = `cp-${++S.copySeq}`;
    S.copyStore.set(id, String(text || ""));
    return `<button type="button" class="btn btn-secondary btn-sm copy-btn" data-copy-id="${id}">${esc(label)}</button>`;
  }

  /** Clipboard write with a textarea fallback for non-secure contexts. */
  async function copyText(text) {
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
        return true;
      }
    } catch (err) {
      console.warn("Clipboard API failed, using fallback", err);
    }
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    let ok = false;
    try {
      ok = document.execCommand("copy");
    } catch (err) {
      ok = false;
    }
    document.body.removeChild(ta);
    return ok;
  }

  function env() {
    return ctx.state.envelope || {};
  }
  function mods() {
    return env().modules || {};
  }
  function analysis() {
    return mods().recommender_audit?.payload?.analysis || {};
  }
  function simModule() {
    return mods().breakglass_simulator || {};
  }

  function sortFindings(list, key) {
    const bySev = (a, b) =>
      (SEV_RANK[b.severity] || 0) - (SEV_RANK[a.severity] || 0) ||
      (PRI_RANK[a.priority] ?? 9) - (PRI_RANK[b.priority] ?? 9);
    const cmp = {
      severity: bySev,
      priority: (a, b) => (PRI_RANK[a.priority] ?? 9) - (PRI_RANK[b.priority] ?? 9) || bySev(a, b),
      age: (a, b) => (b.age_days || 0) - (a.age_days || 0) || bySev(a, b),
      principal: (a, b) => String(a.principal).localeCompare(String(b.principal)) || bySev(a, b),
      category: (a, b) => String(a.category_label).localeCompare(String(b.category_label)) || bySev(a, b),
    }[key] || bySev;
    return list.slice().sort((a, b) => cmp(a, b) || String(a.id).localeCompare(String(b.id)));
  }

  /* ---------------------------------------------------------------------- */
  /* URL state (UI-11)                                                       */
  /* ---------------------------------------------------------------------- */

  function readUrlFilters() {
    const p = new URLSearchParams(window.location.search);
    S.filters.q = p.get("q") || "";
    S.filters.sev = p.get("sev") || "";
    S.filters.priority = p.get("priority") || "";
    S.filters.status = p.get("status") || "";
    S.filters.cat = p.get("cat") || "";
    S.filters.ptype = p.get("ptype") || "";
    S.filters.sort = p.get("sort") || "severity";
    S.drawerPrincipal = p.get("principal") || "";
  }

  /** Mirrors the current view into the query string without adding history entries. */
  function syncUrl() {
    const p = new URLSearchParams();
    const st = ctx.state;
    if (st.currentProject) p.set("project", st.currentProject);
    if (st.currentRun && st.currentRun !== "latest") p.set("run", st.currentRun);
    if (st.activeTab) p.set("tab", st.activeTab);
    const f = S.filters;
    ["q", "sev", "priority", "status", "cat", "ptype"].forEach((k) => f[k] && p.set(k, f[k]));
    if (f.sort && f.sort !== "severity") p.set("sort", f.sort);
    if (S.drawerPrincipal) p.set("principal", S.drawerPrincipal);
    const qs = p.toString();
    try {
      window.history.replaceState(null, "", qs ? `?${qs}` : window.location.pathname);
    } catch (err) {
      console.warn("URL state sync failed", err);
    }
  }

  /* ---------------------------------------------------------------------- */
  /* Data loading                                                            */
  /* ---------------------------------------------------------------------- */

  async function fetchFindings() {
    const st = ctx.state;
    const seq = ++S.loadSeq;
    const url = `/api/findings?project=${encodeURIComponent(st.currentProject)}&run=${encodeURIComponent(
      st.currentRun || "latest"
    )}&history=${HISTORY_RUNS}`;
    const res = await fetch(url, { cache: "no-store" });
    let data;
    try {
      data = await res.json();
    } catch (err) {
      throw new Error(`Invalid findings response (HTTP ${res.status})`);
    }
    if (!res.ok) throw new Error(data.details || data.error || `HTTP ${res.status}`);
    if (seq !== S.loadSeq) return null; // A newer load superseded this one.
    return data;
  }

  /* ---------------------------------------------------------------------- */
  /* Run provenance bar (UI-4 / UI-14)                                       */
  /* ---------------------------------------------------------------------- */

  function renderRunContextBar() {
    const host = $("run-context-bar");
    if (!host) return;
    const e = env();
    if (!e.run_id) {
      host.innerHTML = "";
      return;
    }
    const mo = e.modules || {};
    const executed = Object.values(mo).filter((m) => m && m.status && m.status !== "NOT_RUN").length;
    const triggered = Array.isArray(e.triggered_skills) ? e.triggered_skills.length : executed;
    const stale = e.freshness_overview?.potentially_stale_modules || [];
    const simSum = simModule().summary || {};
    const telemetry =
      simSum.telemetry_source || analysis().metadata?.telemetry_mode || "not recorded";
    const executedBy =
      e.executed_by || e.provenance?.executed_by || e.api_preflight?.caller_identity || "not recorded";
    const objectPath = e.gcs_metadata?.object_path || "";
    const items = [
      ["Run", `${esc((e.timestamp_utc || "").replace("T", " ").slice(0, 19))} UTC <span class="muted">(${esc(ageText(e.timestamp_utc))})</span>`],
      ["Mode", esc(e.trigger_mode || "—")],
      ["Skills run", `${triggered}/${TOTAL_SKILLS}`],
      [
        "Carried forward",
        stale.length
          ? `<span class="chip st-regressed" title="${esc(stale.join(", "))}">${stale.length} module(s) probably stale</span>`
          : `<span class="chip conf-high">none</span>`,
      ],
      ["Telemetry", `<code>${esc(telemetry)}</code>`],
      ["Policy etag", `<code>${esc(e.live_policy_etag || "—")}</code>`],
      ["Schema", esc(e.schema_version || "—")],
      ["Executed by", `<span class="${executedBy === "not recorded" ? "muted" : ""}">${esc(executedBy)}</span>`],
      ["History", S.data ? `${S.data.window_runs || 1} run(s) compared` : "—"],
    ];
    host.innerHTML =
      items
        .map(([k, v]) => `<span class="ctx-item"><span class="ctx-key">${esc(k)}</span> ${v}</span>`)
        .join("") +
      (objectPath ? `<span class="ctx-item ctx-path" title="${esc(objectPath)}"><span class="ctx-key">Source</span> <code>gs://${esc(e.gcs_metadata?.bucket || "")}/${esc(objectPath)}</code></span>` : "");
  }

  /* ---------------------------------------------------------------------- */
  /* Global alerts (UI-5): HOLD reconciliation, degraded preflight           */
  /* ---------------------------------------------------------------------- */

  function renderGlobalAlerts() {
    const host = $("global-alerts");
    if (!host) return;
    // Keep any load-error banner owned by app.js; replace only our alerts.
    host.querySelectorAll(".alert-insights").forEach((n) => n.remove());
    const parts = [];

    const sim = simModule();
    const sum = sim.summary || {};
    const replays = sim.payload?.principal_replays || [];
    const blocked = replays.filter((r) => Number(r.simulated_403_denials || 0) > 0);
    const verdict = String(sum.cutover_verdict || "");
    if (blocked.length || verdict.includes("HOLD")) {
      const rows = blocked
        .slice(0, 6)
        .map((r) => {
          const missing = r.uncovered_permissions || [];
          return `<li><button type="button" class="link-btn mono" data-principal="${esc(r.principal)}">${esc(
            r.principal
          )}</button> &mdash; <strong>${ctx.formatNumber(r.simulated_403_denials)}</strong> simulated 403s; missing: <code>${esc(
            missing.slice(0, 4).join(", ") || "n/a"
          )}</code>${missing.length > 4 ? ` +${missing.length - 4} more` : ""}</li>`;
        })
        .join("");
      parts.push(`<div class="alert alert-hold alert-insights" role="alert">
        <div><strong>&#9888; Cutover on HOLD:</strong> ${esc(verdict || "HOLD")} &mdash; the replay simulator predicts
          <strong>${ctx.formatNumber(sum.simulated_403_denials ?? blocked.length)}</strong> HTTP 403s if the proposed roles were applied as-is.
          Do not apply P2 role cutovers for these principals until the missing permissions are added to the proposed roles.
          <ul class="alert-list">${rows}</ul>${blocked.length > 6 ? `<div class="muted">+${blocked.length - 6} more principals in Changes &amp; Rollback.</div>` : ""}
        </div>
        <button type="button" class="btn btn-secondary btn-sm" data-goto-tab="view-compression">Open simulator</button>
      </div>`);
    }

    const pre = env().api_preflight || {};
    const preStatus = String(pre.status || "");
    const missingApis = pre.missing_apis || pre.disabled_apis || [];
    if (preStatus.includes("DEGRADED") || (Array.isArray(missingApis) && missingApis.length)) {
      parts.push(`<div class="alert alert-warn alert-insights" role="status">
        <div><strong>Degraded data collection:</strong> some GCP APIs were unavailable during this run
          ${missingApis.length ? `(<code>${esc(missingApis.join(", "))}</code>)` : ""}. Findings that depend on them may be missing; absence of a finding is not proof of compliance.</div>
      </div>`);
    }
    host.insertAdjacentHTML("beforeend", parts.join(""));
  }

  /* ---------------------------------------------------------------------- */
  /* Overview (UI-1, UI-3, UI-7)                                             */
  /* ---------------------------------------------------------------------- */

  function renderOverview() {
    const d = S.data || { findings: [], resolved: [], trend: [], counts: {} };
    const counts = d.counts || {};
    const bySev = counts.by_severity || {};
    const byStatus = counts.by_status || {};

    // Risk now
    const risk = $("overview-risk");
    if (risk) {
      const sum = simModule().summary || {};
      const replays = simModule().payload?.principal_replays || [];
      const lowConf = replays.filter(
        (r) => ctx.replayConfidence(r, sum).level === "Low" && Number(r.simulated_403_denials || 0) === 0
      ).length;
      const tiles = SEV_ORDER.map(
        (s) => `<button type="button" class="risk-tile risk-${s.toLowerCase()}" data-filter-sev="${s}" title="Show ${s.toLowerCase()} findings">
          <span class="risk-count">${ctx.formatNumber(bySev[s] || 0)}</span>
          <span class="risk-label">${s.charAt(0) + s.slice(1).toLowerCase()}</span></button>`
      ).join("");
      const verdict = sum.cutover_verdict || "Simulator not run";
      const verdictCls = String(verdict).includes("HOLD") ? "st-regressed" : sum.cutover_verdict ? "conf-high" : "st-open";
      const simConfHtml = ctx.renderSimConfidenceBadge ? ctx.renderSimConfidenceBadge(ctx.simAuditConfidence?.(simModule())) : "";
      risk.innerHTML = `<div class="risk-tiles">${tiles}</div>
        <div class="readiness">
          <div><span class="ctx-key">Cutover readiness</span> <span class="chip ${verdictCls}">${esc(verdict)}</span>
            ${sum.cutover_verdict ? `<span class="tag tag-simulated">Simulated</span>` : ""}</div>
          <div class="muted">${ctx.formatNumber(sum.simulated_403_denials ?? 0)} simulated 403s across ${replays.length} replayed principal(s)${
            simConfHtml ? ` ${simConfHtml}` : ""
          }${
            lowConf ? `; <strong>${lowConf}</strong> PASS verdict(s) have <em>Low</em> confidence (few or zero observed calls)` : ""
          }.</div>
        </div>`;
    }

    // Change since last run + trend sparkline
    const trendHost = $("overview-trend");
    if (trendHost) {
      const trend = d.trend || [];
      const statusLine = ["New", "Regressed", "Open"]
        .map((s) => `<button type="button" class="link-btn" data-filter-status="${s}">${statusChip(s)} ${ctx.formatNumber(byStatus[s] || 0)}</button>`)
        .join(" ");
      const resolvedN = (d.resolved || []).length;
      if (trend.length < 2) {
        trendHost.innerHTML = `<div class="trend-status">${statusLine} ${statusChip("Resolved")} ${resolvedN}</div>
          <p class="muted">Only one run is available for this project, so every finding is reported as Open. Trends appear after the next run is published to GCS.</p>`;
      } else {
        trendHost.innerHTML = `<div class="trend-status">${statusLine} <button type="button" class="link-btn" data-filter-status="Resolved">${statusChip(
          "Resolved"
        )} ${resolvedN}</button></div>
          ${sparkline(trend)}
          <div class="trend-runs">${trend
            .slice(-5)
            .reverse()
            .map(
              (t) => `<div class="trend-run"><code>${esc((t.timestamp_utc || "").slice(0, 16).replace("T", " "))}</code>
                <span>${ctx.formatNumber(t.total)} open</span>
                ${t.new !== null && t.new !== undefined ? `<span class="delta-up">+${t.new}</span> <span class="delta-down">&minus;${t.resolved}</span>` : `<span class="muted">baseline</span>`}
                <span class="muted">${esc(t.trigger_mode || "")}</span></div>`
            )
            .join("")}</div>`;
      }
    }

    renderOverviewKpis(counts);

    // Next 5 actions
    const next = $("overview-next-actions");
    if (next) {
      const top = sortFindings(d.findings || [], "severity").slice(0, 5);
      next.innerHTML = top.length
        ? `<ol class="next-actions">${top
            .map(
              (f) => `<li class="next-action">
            <div class="na-head">${sevChip(f.severity)} <span class="badge badge-neutral">${esc(f.priority)}</span>
              <span class="mono muted">${esc(f.id)}</span> ${statusChip(f.status)}</div>
            <div class="na-title">${esc(f.title)}</div>
            <div class="na-meta">${f.principal ? `<button type="button" class="link-btn mono" data-principal="${esc(f.principal)}">${esc(f.principal)}</button> &middot; ` : ""}${esc(
              f.recommended_action || ""
            )}</div>
            <div class="na-actions"><button type="button" class="btn btn-primary btn-sm" data-plan="${esc(f.id)}">Change plan</button>
              <span class="muted">Deliverable: ${esc(f.deliverable || "—")}</span></div>
          </li>`
            )
            .join("")}</ol>`
        : `<div class="empty-note">No open findings in this run. &#10003;</div>`;
    }

    // Resolved since previous
    const resHost = $("overview-resolved");
    if (resHost) {
      const res = d.resolved || [];
      resHost.innerHTML = res.length
        ? `<ul class="resolved-list">${res
            .slice(0, 10)
            .map(
              (f) => `<li>${statusChip("Resolved")} ${sevChip(f.severity)} <span class="mono muted">${esc(f.id)}</span> ${esc(f.title)}</li>`
            )
            .join("")}</ul>${res.length > 10 ? `<button type="button" class="link-btn" data-filter-status="Resolved">View all ${res.length} &rarr;</button>` : ""}`
        : `<div class="empty-note">${(d.trend || []).length < 2 ? "Needs at least two runs." : "Nothing resolved since the previous run."}</div>`;
    }
  }

  /** Inline SVG sparkline of open findings per run (stacked critical+high highlighted). */
  function sparkline(trend) {
    const w = 320;
    const h = 64;
    const pad = 6;
    const max = Math.max(1, ...trend.map((t) => t.total || 0));
    const step = trend.length > 1 ? (w - pad * 2) / (trend.length - 1) : 0;
    const pt = (v, i) => `${(pad + i * step).toFixed(1)},${(h - pad - ((v || 0) / max) * (h - pad * 2)).toFixed(1)}`;
    const total = trend.map((t, i) => pt(t.total, i)).join(" ");
    const crit = trend
      .map((t, i) => pt((t.by_severity?.CRITICAL || 0) + (t.by_severity?.HIGH || 0), i))
      .join(" ");
    const label = `Open findings over the last ${trend.length} runs: ${trend.map((t) => t.total).join(", ")}`;
    return `<svg class="sparkline" viewBox="0 0 ${w} ${h}" width="100%" height="${h}" role="img" aria-label="${esc(label)}">
      <polyline points="${total}" fill="none" stroke="#1a73e8" stroke-width="2"/>
      <polyline points="${crit}" fill="none" stroke="#dc2626" stroke-width="1.5" stroke-dasharray="4,3"/>
    </svg><div class="spark-legend"><span class="lg lg-total"></span> all open <span class="lg lg-crit"></span> critical + high</div>`;
  }

  /** KPI cards with definitions and principal-type split (UI-3). */
  function renderOverviewKpis(counts) {
    const host = $("overview-kpis");
    if (!host) return;
    const an = analysis();
    const k = an.executive_kpis || {};
    const dig = env().recommendation_digest?.executive_kpis || {};
    const m = mods();
    const pam = m.jit_pam_architect?.payload || {};
    const fed = m.federation_architect?.payload || {};
    const comp = m.compliance_mapper?.summary || m.compliance_mapper?.payload?.summary || {};
    const keyedSas = (fed.service_accounts || []).filter((s) => Number(s.user_managed_key_count || 0) > 0).length;
    const ptypes = counts.by_principal_type || {};
    const ptSplit = Object.entries(ptypes)
      .filter(([t]) => t !== "None")
      .sort((a, b) => b[1] - a[1])
      .map(([t, n]) => `<button type="button" class="pt-chip" data-filter-ptype="${esc(t)}">${esc(t)}: <strong>${n}</strong></button>`)
      .join(" ");
    const cards = [
      {
        label: "Open findings",
        tip: "Distinct findings in this run across all executed modules, de-duplicated by stable finding ID.",
        value: ctx.formatNumber(counts.total || 0),
        foot: ptSplit || "No principal-scoped findings",
        tag: "Observed",
        rawFoot: true,
      },
      {
        label: "Permission grants (principal × permission)",
        tip: "Sum over every principal of the distinct permissions its bound roles grant, versus after the proposed least-privilege roles. One permission held by 10 principals counts 10 times.",
        value: `${ctx.formatNumber(k.total_permissions_before ?? dig.permissions_before)} → ${ctx.formatNumber(
          k.total_permissions_after ?? dig.permissions_after
        )}`,
        foot: `-${k.permissions_reduction_pct ?? dig.permissions_reduction_pct ?? 0}% if all proposals are applied`,
        tag: "Proposal",
      },
      {
        label: "Escalation paths",
        tip: "Transitive actAs / getAccessToken / setIamPolicy chains that let one identity gain another's privileges. Observed now; closable by P1 proposals.",
        value: ctx.formatNumber(k.escalation_chains_count ?? dig.escalation_chains_count ?? 0),
        foot: `${ctx.formatNumber(k.escalation_chains_closed_count || 0)} closable by proposals`,
        tag: "Observed",
      },
      {
        label: "Standing human admins",
        tip: "Humans or groups holding persistent admin roles that are candidates for just-in-time PAM entitlements.",
        value: ctx.formatNumber(
          dig.standing_privileged_humans_count ?? (pam.entitlements || pam.pam_entitlements || []).length ?? 0
        ),
        foot: "JIT PAM entitlements proposed",
        tag: "Observed",
      },
      {
        label: "SAs with user-managed keys",
        tip: "Service accounts holding at least one user-managed (downloadable) JSON key. Each key is a long-lived credential that should be replaced by Workload Identity Federation.",
        value: ctx.formatNumber(keyedSas),
        foot: `${ctx.formatNumber((fed.service_accounts || []).length)} SAs audited`,
        tag: "Observed",
      },
      {
        label: "Compliance score",
        tip: "Share of mapped CIS / SOC 2 / ISO 27001 / PCI-DSS IAM controls passing now, versus projected after all proposals are applied.",
        value: `${comp.compliance_score_before_pct ?? dig.compliance_score_before_pct ?? 0}% → ${
          comp.compliance_score_after_pct ?? dig.compliance_score_after_pct ?? 0
        }%`,
        foot: "Projected value is a proposal",
        tag: "Proposal",
      },
    ];
    host.innerHTML = cards
      .map(
        (c) => `<div class="kpi-card">
          <div class="kpi-label">${esc(c.label)}${ctx.infoTip(c.tip)}</div>
          <div class="kpi-value-row"><span class="kpi-value">${esc(c.value)}</span>
            <span class="tag ${c.tag === "Proposal" ? "tag-proposed" : "tag-observed"}">${esc(c.tag)}</span></div>
          <div class="kpi-foot">${c.rawFoot ? c.foot : esc(c.foot)}</div>
        </div>`
      )
      .join("");
  }

  /* ---------------------------------------------------------------------- */
  /* Findings queue (UI-2)                                                   */
  /* ---------------------------------------------------------------------- */

  function fillSelect(id, values, labelFn, current, allLabel) {
    const el = $(id);
    if (!el) return;
    const opts = [`<option value="">${esc(allLabel)}</option>`].concat(
      values.map((v) => `<option value="${esc(v)}" ${v === current ? "selected" : ""}>${esc(labelFn(v))}</option>`)
    );
    el.innerHTML = opts.join("");
    el.value = current || "";
  }

  function activePresetId() {
    const f = S.filters;
    const hasQ = Boolean(f.q && f.q.trim());
    if (hasQ || f.sev || f.ptype) return "";
    if (!f.priority && !f.status && !f.cat) return "all";
    if (f.status === "New" && !f.priority && !f.cat) return "new";
    if (f.cat === "external_finding" && !f.priority && !f.status) return "scc_wiz";
    if (f.cat === "ai_agent_blast_radius" && !f.priority && !f.status) return "ai_agent";
    if (f.cat === "wif_provider_misconfig" && !f.priority && !f.status) return "wif_misconfig";
    if (f.priority === "P0" && !f.status && !f.cat) return "p0";
    return "";
  }

  function renderTriagePresets() {
    const host = $("findings-preset-pills");
    if (!host) return;
    const d = S.data || { findings: [], counts: {} };
    const active = activePresetId();
    host.innerHTML = TRIAGE_PRESETS.map((p) => {
      const n = p.count(d);
      const isActive = p.id === active;
      return `<button type="button" class="preset-pill${isActive ? " active" : ""}" data-triage-preset="${esc(
        p.id
      )}" aria-pressed="${isActive ? "true" : "false"}">${esc(p.label)} <span class="preset-pill-count">${ctx.formatNumber(
        n
      )}</span></button>`;
    }).join("");
  }

  function applyTriagePreset(presetId) {
    const preset = TRIAGE_PRESETS.find((p) => p.id === presetId);
    if (!preset) return;
    const patch = preset.apply();
    S.filters = {
      q: "",
      sev: "",
      priority: patch.priority || "",
      status: patch.status || "",
      cat: patch.cat || "",
      ptype: "",
      sort: S.filters.sort || "severity",
    };
    S.page = 1;
    populateFilterOptions();
    renderFindingsQueue();
    syncUrl();
  }

  function populateFilterOptions() {
    const d = S.data || {};
    const c = d.counts || {};
    const all = (d.findings || []).concat(d.resolved || []);
    const catLabels = {};
    all.forEach((f) => (catLabels[f.category] = f.category_label));
    const f = S.filters;
    fillSelect("f-severity", SEV_ORDER, (v) => `${v.charAt(0) + v.slice(1).toLowerCase()} (${(c.by_severity || {})[v] || 0})`, f.sev, "All severities");
    fillSelect("f-priority", ["P0", "P1", "P2", "P3"], (v) => `${v} (${(c.by_priority || {})[v] || 0})`, f.priority, "All priorities");
    fillSelect(
      "f-status",
      STATUS_ORDER,
      (v) => `${v} (${v === "Resolved" ? (d.resolved || []).length : (c.by_status || {})[v] || 0})`,
      f.status,
      "All open statuses"
    );
    fillSelect(
      "f-category",
      Object.keys(catLabels).sort((a, b) => String(catLabels[a]).localeCompare(String(catLabels[b]))),
      (v) => `${catLabels[v]} (${(c.by_category || {})[v] || 0})`,
      f.cat,
      "All categories"
    );
    fillSelect(
      "f-ptype",
      Object.keys(c.by_principal_type || {}).sort(),
      (v) => `${v === "None" ? "No principal" : v} (${(c.by_principal_type || {})[v]})`,
      f.ptype,
      "All principal types"
    );
    const sortEl = $("f-sort");
    if (sortEl) sortEl.value = f.sort || "severity";
    const search = $("f-search");
    if (search && search.value !== f.q) search.value = f.q;
    const g = $("global-search");
    if (g && document.activeElement !== g) g.value = f.q;
    renderTriagePresets();
  }

  /** Applies filters + sort; Resolved items only appear when explicitly requested. */
  function applyFilters() {
    const d = S.data || {};
    const f = S.filters;
    const pool = f.status === "Resolved" ? d.resolved || [] : d.findings || [];
    const q = f.q.trim().toLowerCase();
    const out = pool.filter((x) => {
      if (f.sev && x.severity !== f.sev) return false;
      if (f.priority && x.priority !== f.priority) return false;
      if (f.status && f.status !== "Resolved" && x.status !== f.status) return false;
      if (f.cat && x.category !== f.cat) return false;
      if (f.ptype && x.principal_type !== f.ptype) return false;
      if (q) {
        const hay = [x.id, x.principal, x.title, x.detail, x.resource, x.category_label, x.recommended_action, x.source_skill]
          .join(" ")
          .toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
    S.filtered = sortFindings(out, f.sort);
  }

  function renderFindingsQueue() {
    applyFilters();
    const tbody = $("findings-tbody");
    const pager = $("findings-pager");
    const summary = $("findings-summary");
    const total = S.filtered.length;
    const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));
    S.page = Math.min(Math.max(1, S.page), pages);
    const slice = S.filtered.slice((S.page - 1) * PAGE_SIZE, S.page * PAGE_SIZE);

    const countEl = $("tab-findings-count");
    if (countEl) {
      const n = (S.data?.findings || []).length;
      const crit = (S.data?.counts?.by_severity || {}).CRITICAL || 0;
      countEl.textContent = n ? String(n) : "";
      countEl.className = `tab-count${crit ? " tab-count-crit" : ""}`;
      countEl.title = `${n} open findings (${crit} critical)`;
    }

    if (summary) {
      const allN = (S.data?.findings || []).length;
      const active = Object.entries(S.filters).filter(([k, v]) => v && k !== "sort").length;
      summary.textContent = `Showing ${total ? (S.page - 1) * PAGE_SIZE + 1 : 0}–${Math.min(S.page * PAGE_SIZE, total)} of ${total} finding(s)${
        active ? ` (filtered from ${allN} open)` : ""
      }. Status is inferred by comparing this run with up to ${HISTORY_RUNS - 1} earlier runs in GCS.`;
    }

    if (tbody) {
      if (!S.data) {
        tbody.innerHTML = `<tr><td colspan="9">Loading findings&hellip;</td></tr>`;
      } else if (!slice.length) {
        tbody.innerHTML = `<tr><td colspan="9" class="empty-note">No findings match these filters. <button type="button" class="link-btn" data-clear-filters>Clear filters</button></td></tr>`;
      } else {
        tbody.innerHTML = slice
          .map(
            (f) => `<tr class="${f.severity === "CRITICAL" ? "row-critical" : ""}">
            <td class="mono nowrap">${esc(f.id)}</td>
            <td>${sevChip(f.severity)}</td>
            <td><span class="badge badge-neutral">${esc(f.priority)}</span></td>
            <td style="font-size:0.78rem;">${esc(f.category_label)}<div class="muted mono" style="font-size:0.68rem;">${esc(f.source_skill)}</div></td>
            <td>${
              f.principal
                ? `<button type="button" class="link-btn mono" data-principal="${esc(f.principal)}" title="Open identity details">${esc(
                    f.principal
                  )}</button><div class="muted" style="font-size:0.7rem;">${esc(f.principal_type)}</div>`
                : `<span class="muted">${esc(f.resource || "—")}</span>`
            }</td>
            <td><div style="font-weight:600;">${esc(f.title)}</div>
              ${f.detail ? `<div class="muted" style="font-size:0.75rem;">${esc(f.detail)}</div>` : ""}
              ${f.deliverable ? `<div style="font-size:0.72rem;margin-top:2px;">Fix: <code>${esc(f.deliverable)}</code></div>` : ""}</td>
            <td class="nowrap">${statusChip(f.status)}<div class="muted" style="font-size:0.7rem;" title="First seen ${esc(f.first_seen || "")}">${
              f.status === "Resolved"
                ? `last seen ${esc((f.last_seen || "").slice(0, 10))}`
                : `${f.first_seen_is_window_start ? "≥" : ""}${f.age_days || 0}d open`
            }</div></td>
            <td>${confChip(f.confidence)}</td>
            <td class="nowrap">${
              f.status === "Resolved" ? "" : `<button type="button" class="btn btn-secondary btn-sm" data-plan="${esc(f.id)}">Plan</button>`
            }</td>
          </tr>`
          )
          .join("");
      }
    }

    if (pager) {
      pager.innerHTML =
        pages > 1
          ? `<button type="button" class="btn btn-secondary btn-sm" data-page="${S.page - 1}" ${S.page === 1 ? "disabled" : ""} aria-label="Previous page">&larr; Prev</button>
             <span aria-current="page">Page ${S.page} of ${pages}</span>
             <button type="button" class="btn btn-secondary btn-sm" data-page="${S.page + 1}" ${S.page === pages ? "disabled" : ""} aria-label="Next page">Next &rarr;</button>`
          : "";
    }
  }

  function setFilter(key, value, opts = {}) {
    S.filters[key] = value;
    S.page = 1;
    populateFilterOptions();
    renderFindingsQueue();
    syncUrl();
    if (opts.goto) ctx.switchToTab("view-findings");
  }

  function clearFilters() {
    S.filters = { q: "", sev: "", priority: "", status: "", cat: "", ptype: "", sort: S.filters.sort || "severity" };
    S.page = 1;
    populateFilterOptions();
    renderFindingsQueue();
    syncUrl();
  }

  /* ---------------------------------------------------------------------- */
  /* Dialog management (UI-13): focus trap, Esc, focus restore              */
  /* ---------------------------------------------------------------------- */

  const FOCUSABLE =
    'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

  function openDialog(el, focusTarget) {
    S.lastFocus = document.activeElement;
    el.classList.remove("hidden");
    (focusTarget || el.querySelector(FOCUSABLE))?.focus();
  }

  function closeDialog(el) {
    if (!el || el.classList.contains("hidden")) return;
    el.classList.add("hidden");
    const back = S.lastFocus;
    S.lastFocus = null;
    if (back && typeof back.focus === "function" && document.contains(back)) back.focus();
  }

  /** Returns the topmost open dialog element, if any. */
  function topDialog() {
    const plan = $("plan-modal");
    if (plan && !plan.classList.contains("hidden")) return plan;
    const drawer = $("identity-drawer");
    if (drawer && !drawer.classList.contains("hidden")) return drawer;
    return Array.from(document.querySelectorAll(".modal-backdrop")).find((m) => !m.classList.contains("hidden")) || null;
  }

  function closeTop() {
    const top = topDialog();
    if (!top) return false;
    if (top.id === "identity-drawer") {
      closeDrawer();
    } else if (top.id === "plan-modal") {
      closeDialog(top);
    } else {
      // Existing app.js modals (diff, recommendations) expose their own close buttons.
      const btn = top.querySelector('button[id^="btn-close"]');
      if (btn) btn.click();
      else top.classList.add("hidden");
    }
    return true;
  }

  function trapFocus(e) {
    const top = topDialog();
    if (!top || e.key !== "Tab") return;
    const nodes = Array.from(top.querySelectorAll(FOCUSABLE)).filter((n) => n.offsetParent !== null);
    if (!nodes.length) return;
    const first = nodes[0];
    const last = nodes[nodes.length - 1];
    if (!top.contains(document.activeElement)) {
      e.preventDefault();
      first.focus();
    } else if (e.shiftKey && document.activeElement === first) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault();
      first.focus();
    }
  }

  /* ---------------------------------------------------------------------- */
  /* Identity drawer (UI-6)                                                  */
  /* ---------------------------------------------------------------------- */

  /** Best-effort ownership hint; ScopeGuard does not record owners (Part B). */
  function ownerHint(principal, fedSa) {
    const email = memberEmail(principal);
    const m = email.match(/@([a-z0-9-]+)\.iam\.gserviceaccount\.com$/i);
    if (m) {
      return `Service account owned by project <code>${esc(m[1])}</code>${
        fedSa?.display_name ? ` &middot; display name “${esc(fedSa.display_name)}”` : ""
      }. Check its <code>owner</code> label or the project's IAM admins.`;
    }
    if (/gserviceaccount\.com$/i.test(email)) return "Google-managed identity; owned by the Google service that created it.";
    if (/^user:/i.test(principal)) return `Human user <code>${esc(email)}</code>; confirm with their manager before removing access.`;
    if (/^group:/i.test(principal)) return `Group <code>${esc(email)}</code>; the group owners in Cloud Identity control membership.`;
    return "Owner not recorded.";
  }

  function closeDrawer() {
    const drawer = $("identity-drawer");
    $("drawer-backdrop")?.classList.add("hidden");
    S.drawerPrincipal = "";
    closeDialog(drawer);
    syncUrl();
  }

  function openDrawer(principal) {
    const drawer = $("identity-drawer");
    const body = $("drawer-body");
    if (!drawer || !body || !principal) return;
    S.drawerPrincipal = principal;
    S.copyStore.clear();
    const an = analysis();
    const m = mods();
    const email = memberEmail(principal).toLowerCase();
    const matches = (p) => p && (p === principal || memberEmail(p).toLowerCase() === email);

    const mapping = (an.principal_mappings || []).find((pm) => matches(pm.principal));
    const findings = (S.data?.findings || []).filter((f) => matches(f.principal));
    const simSum = simModule().summary || {};
    const replay = (simModule().payload?.principal_replays || []).find((r) => matches(r.principal));
    const fedSa = (m.federation_architect?.payload?.service_accounts || []).find(
      (s) => String(s.email || "").toLowerCase() === email
    );
    const pamList = (m.jit_pam_architect?.payload?.entitlements || m.jit_pam_architect?.payload?.pam_entitlements || []).filter(
      (e) => matches(e.eligible_requester)
    );
    const triage = (an.triage_matrix || []).filter((t) => matches(t.principal));
    const paths = (an.transitive_paths || []).filter((p) => matches(p.source_principal) || matches(p.intermediate_principal));
    const ptype = findings[0]?.principal_type || mapping?.category || "Principal";

    $("drawer-title").textContent = memberEmail(principal) || principal;
    $("drawer-subtitle").innerHTML = `${esc(ptype)} &middot; <span class="mono">${esc(principal)}</span>`;

    const rollbacks = []
      .concat(mapping?.rollback_commands || [])
      .concat(triage.map((t) => t.rollback_command).filter(Boolean));
    const uniqRollbacks = Array.from(new Set(rollbacks));
    const sections = [];

    sections.push(`<section class="drawer-sec"><h3>Ownership <span class="muted">(best-effort)</span></h3><p>${ownerHint(principal, fedSa)}</p></section>`);

    sections.push(`<section class="drawer-sec"><h3>Access <span class="tag tag-observed">Observed</span> → <span class="tag tag-proposed">Proposal</span></h3>
      ${
        mapping
          ? `<div class="kv"><span>Current roles</span><div class="role-pill-list">${(mapping.current_roles || [])
              .map((r) => `<span class="role-pill">${esc(r)}</span>`)
              .join("") || "—"}</div></div>
             <div class="kv"><span>Proposed</span><div><strong>${esc(mapping.target_mapping || "Retain current")}</strong>
               <div class="muted">${esc(mapping.recommended_action || "")}</div></div></div>
             <div class="kv"><span>Phase</span><div><span class="badge badge-neutral">${esc(mapping.remediation_phase || "—")}</span></div></div>`
          : `<p class="muted">Not present in the principal inventory of this run.</p>`
      }</section>`);

    sections.push(`<section class="drawer-sec"><h3>Findings (${findings.length})</h3>${
      findings.length
        ? `<ul class="drawer-findings">${sortFindings(findings, "severity")
            .map(
              (f) => `<li>${sevChip(f.severity)} ${statusChip(f.status)} <span class="mono muted">${esc(f.id)}</span>
              <div>${esc(f.title)}</div>
              <button type="button" class="btn btn-secondary btn-sm" data-plan="${esc(f.id)}">Change plan</button></li>`
            )
            .join("")}</ul>`
        : `<p class="muted">No open findings for this identity.</p>`
    }</section>`);

    if (replay) {
      const conf = ctx.replayConfidence(replay, simSum);
      const missing = replay.uncovered_permissions || [];
      sections.push(`<section class="drawer-sec"><h3>Replay simulation <span class="tag tag-simulated">Simulated</span></h3>
        <div class="kv"><span>Verdict</span><div><span class="chip ${
          Number(replay.simulated_403_denials || 0) ? "st-regressed" : "conf-high"
        }">${esc(replay.verdict)}</span> ${ctx.confidenceChip(conf)} <span class="muted">${esc(conf.reason)}</span></div></div>
        <div class="kv"><span>Replayed calls</span><div>${ctx.formatNumber(replay.replayed_api_calls)} &middot; ${ctx.formatNumber(
          replay.simulated_403_denials
        )} simulated 403s &middot; ${esc(replay.replay_coverage_pct)}% coverage</div></div>
        ${missing.length ? `<div class="kv"><span>Missing permissions</span><div><code>${esc(missing.join(", "))}</code></div></div>` : ""}
        ${replay.troubleshoot_cli ? `<pre class="code-block small">${esc(replay.troubleshoot_cli)}</pre>${copyButton(replay.troubleshoot_cli, "Copy troubleshoot command")}` : ""}
      </section>`);
    }

    if (paths.length) {
      sections.push(`<section class="drawer-sec"><h3>Escalation paths (${paths.length})</h3><ul>${paths
        .map(
          (p) => `<li><span class="mono">${esc(ctx.shortPrincipal(p.source_principal))}</span> &rarr; <code>${esc(
            p.edge_role || p.edge_permission
          )}</code> &rarr; <span class="mono">${esc(ctx.shortPrincipal(p.intermediate_principal))}</span> &rArr; <code>${esc(p.terminal_capability)}</code></li>`
        )
        .join("")}</ul></section>`);
    }

    if (fedSa || pamList.length) {
      sections.push(`<section class="drawer-sec"><h3>Credentials &amp; elevation</h3>
        ${fedSa ? `<div class="kv"><span>User-managed keys</span><div><strong>${esc(fedSa.user_managed_key_count)}</strong> &middot; ${esc(
          fedSa.posture_status
        )}<div class="muted">${esc(fedSa.recommended_federation || "")}</div></div></div>` : ""}
        ${pamList
          .map(
            (e) => `<div class="kv"><span>PAM entitlement</span><div><code>${esc(e.entitlement_id)}</code> &middot; JIT roles <code>${esc(
              (e.jit_granted_roles || []).join(", ")
            )}</code> &middot; max ${esc(e.max_request_duration || "—")} &middot; approver ${esc(e.approver_principal || "—")}</div></div>`
          )
          .join("")}
      </section>`);
    }

    sections.push(`<section class="drawer-sec"><h3>Rollback</h3>${
      uniqRollbacks.length
        ? uniqRollbacks.map((c) => `<pre class="code-block small">${esc(c)}</pre>`).join("") +
          copyButton(uniqRollbacks.join("\n"), "Copy rollback commands")
        : `<p class="muted">No principal-specific rollback recorded. Use the run's <code>rollback_runbook.sh</code> (etag restore).</p>`
    }</section>`);

    const pid = ctx.state.currentProject || "<project-id>";
    const fastPathCmd = `python3 plugins/scopeguard/skills/scopeguard-orchestrator/scripts/scopeguard_pipeline.py --project=${pid} --principal=${shQuote(principal)} --canary`;
    const verifyCmd = `python3 plugins/scopeguard/skills/gcp-iam-finding-remediator/scripts/finding_remediator_cli.py --project=${pid} --verify --plan-file=finding-remediation/finding_remediations.json`;
    sections.push(`<section class="drawer-sec"><h3>Terminal Quick Commands</h3>
      <div class="drawer-cmd-label">Fast-path single-principal re-run (canary mode)</div>
      <div class="cmd-row"><pre class="code-block small">${esc(fastPathCmd)}</pre>${copyButton(fastPathCmd, "Copy")}</div>
      <div class="drawer-cmd-label">Post-cutover verification (--verify)</div>
      <div class="cmd-row"><pre class="code-block small">${esc(verifyCmd)}</pre>${copyButton(verifyCmd, "Copy")}</div>
    </section>`);

    body.innerHTML = sections.join("");
    $("drawer-backdrop")?.classList.remove("hidden");
    openDialog(drawer, $("btn-close-drawer"));
    syncUrl();
  }

  /* ---------------------------------------------------------------------- */
  /* Change-plan modal (UI-9) — display-only, never executed                 */
  /* ---------------------------------------------------------------------- */

  function findById(id) {
    const d = S.data || {};
    return (d.findings || []).find((f) => f.id === id) || (d.resolved || []).find((f) => f.id === id) || null;
  }

  /**
   * Resolves the exact deliverable file contents (role YAML, PAM/WIF/Deny/GitOps
   * Terraform HCL, or shell script) from the loaded envelope for a given finding
   * so the Change Plan modal is self-contained without leaving the window.
   */
  function resolvePlanArtifacts(f, mapping) {
    const out = [];
    const seen = new Set();
    const pushArt = (filename, label, content, mime = "text/plain;charset=utf-8") => {
      if (!content || !String(content).trim() || seen.has(filename)) return;
      seen.add(filename);
      out.push({ filename, label, content: String(content), mime });
    };

    const m = mods();
    const auditArt = m.recommender_audit?.payload?.artifacts || {};
    const modelAYamls = auditArt.model_a_role_yamls || {};
    const capYamls = auditArt.disjoint_role_yamls || {};

    const findYaml = (map, roleId) => {
      if (!roleId) return null;
      const direct = map[`${roleId}.yaml`] || map[roleId];
      if (direct) return { name: `${roleId}.yaml`, content: direct };
      const needle = String(roleId).toLowerCase();
      const key = Object.keys(map).find(
        (k) => k.toLowerCase() === `${needle}.yaml` || k.toLowerCase().endsWith(`/${needle}.yaml`)
      );
      return key ? { name: key, content: map[key] } : null;
    };

    // 1. Persona custom role YAML (Model A) + Model B capability bundle if applicable.
    const target = mapping?.target_mapping || "";
    const roleMatch = target.match(/^projects\/[^/]+\/roles\/([A-Za-z0-9_.]+)$/);
    const personaId = mapping?.persona_role_id || (roleMatch ? roleMatch[1] : "");
    if (personaId) {
      const y = findYaml(modelAYamls, personaId);
      if (y) pushArt(`custom-roles/personas/${y.name}`, "Persona Role YAML (Model A · default)", y.content, "text/yaml");
    }
    const bundleIds = Array.isArray(mapping?.disjoint_model_b_bundle) ? mapping.disjoint_model_b_bundle : [];
    if (bundleIds.length && auditArt.bundles_yaml) {
      pushArt("custom-roles/bundles.yaml", `Model B Capability Bundle (${bundleIds.length} capability role(s))`, auditArt.bundles_yaml, "text/yaml");
    }
    if (bundleIds.length && !personaId) {
      bundleIds.slice(0, 3).forEach((cid) => {
        const cy = findYaml(capYamls, cid);
        if (cy) pushArt(`custom-roles/capabilities/${cy.name}`, `Capability Role YAML (${cid})`, cy.content, "text/yaml");
      });
    }

    // 2. Category-specific IaC / runbook deliverables from sibling modules.
    const cat = f.category || "";
    const isHumanPam =
      cat === "standing_admin" ||
      cat === "pam_not_ready" ||
      /PAM|Google Group/i.test(target) ||
      /PAM/i.test(mapping?.target_bucket || "");
    if (isHumanPam) {
      const pamHcl = m.jit_pam_architect?.payload?.pam_terraform_hcl;
      pushArt("jit-pam/pam_entitlements.tf", "JIT PAM Entitlement Terraform", pamHcl);
    }
    if (cat === "sa_key" || cat === "wif_candidate" || cat === "wif_provider_misconfig") {
      const fed = m.federation_architect?.payload || {};
      if (cat === "wif_provider_misconfig") {
        const auditFindings = fed.existing_wif_audit?.findings || [];
        const match = auditFindings.find(
          (w) => (w.provider || w.pool) && String(f.resource || "").includes(w.provider || w.pool)
        ) || auditFindings[0];
        if (match?.hardening_terraform) {
          pushArt("federation-wif/wif_hardening.tf", "WIF Provider Hardening HCL", match.hardening_terraform);
        }
      }
      pushArt("federation-wif/wif_federation.tf", "Keyless WIF Terraform", fed.wif_terraform_hcl);
      if (cat === "sa_key") {
        pushArt("federation-wif/retire_sa_keys.sh", "SA Key Retirement Script (dry-run default)", fed.key_retirement_runbook_sh);
      }
    }
    if (cat === "ai_agent_blast_radius") {
      const denyHcl = m.deny_policy_architect?.payload?.deny_terraform_hcl;
      pushArt("deny-policies/deny_policies.tf", "IAM v2 Deny Policy (incl. D5 AI Agent Containment)", denyHcl);
    }
    if (cat === "iac_violation") {
      const gitops = m.gitops_pr_guardrail?.payload || {};
      pushArt("gitops-guardrail/remediated_patch.tf", "GitOps Remediated Terraform Patch", gitops.remediated_terraform_hcl);
    }
    if (cat === "external_finding") {
      const rem = m.finding_remediator?.payload || {};
      pushArt("finding-remediation/remediation_patch.tf", "Finding Remediator Terraform Patch", rem.remediation_terraform_hcl);
    }
    return out;
  }

  /**
   * Builds a category-specific change plan. Commands are text for a human to
   * review and run via their own change process; values are shell-quoted.
   */
  function buildPlan(f) {
    const pid = f.project_id || ctx.state.currentProject;
    const P = shQuote(pid);
    const M = shQuote(f.principal);
    const email = shQuote(memberEmail(f.principal));
    const an = analysis();
    const mapping = (an.principal_mappings || []).find((pm) => pm.principal === f.principal);
    const simSum = simModule().summary || {};
    const replay = (simModule().payload?.principal_replays || []).find((r) => r.principal === f.principal);
    const etag = env().live_policy_etag || "";
    const backup = `gcloud projects get-iam-policy ${P} --format=json > iam_backup_${pid}_$(date -u +%Y%m%dT%H%M%SZ).json`;

    const pre = [];
    pre.push({ text: "Open or link a change ticket; schedule outside peak traffic." });
    if (etag) {
      pre.push({
        text: `Confirm the live policy is unchanged since this assessment (expected etag ${etag}). If it differs, re-run ScopeGuard first.`,
        cmd: `gcloud projects get-iam-policy ${P} --format='value(etag)'`,
      });
    }
    pre.push({ text: "Back up the current project IAM policy.", cmd: backup });
    if (f.principal) {
      if (replay) {
        const conf = ctx.replayConfidence(replay, simSum);
        pre.push({
          text: `Replay simulator for this principal: ${replay.verdict}, ${replay.simulated_403_denials} simulated 403s, confidence ${conf.level} (${conf.reason})${
            Number(replay.simulated_403_denials || 0) > 0 ? " — DO NOT proceed with a role cutover until the missing permissions are added." : ""
          }`,
        });
      } else {
        pre.push({ text: "No replay simulation recorded for this principal; treat the change as unverified and monitor closely." });
      }
      pre.push({ text: `Notify the identity owner (${memberEmail(f.principal)}) of the change window.` });
    }

    const steps = [];
    const rollback = [];
    const verify = [];
    const ev = f.evidence || {};
    const role = f.resource || "";

    switch (f.category) {
      case "basic_role":
      case "overprivileged":
      case "role_sprawl":
      case "escalation_risk":
      case "ai_agent_blast_radius": {
        const target = mapping?.target_mapping || "";
        const isServiceAgent =
          /service_agent|serviceagent/i.test(target) ||
          /@gcp-sa-[a-z0-9-]+\.iam\.gserviceaccount\.com$/i.test(memberEmail(f.principal)) ||
          /@cloudservices\.gserviceaccount\.com$/i.test(memberEmail(f.principal));
        const isHumanPam =
          /PAM|Google Group/i.test(target) ||
          /PAM/i.test(mapping?.target_bucket || "") ||
          String(f.principal || "").startsWith("user:");
        const roleMatch = target.match(/^projects\/[^/]+\/roles\/([A-Za-z0-9_.]+)$/);
        const personaId = mapping?.persona_role_id || (roleMatch ? roleMatch[1] : "");
        const targetRole = personaId
          ? `projects/${pid}/roles/${personaId}`
          : /^(projects\/|organizations\/|roles\/)/.test(target)
          ? target
          : "";

        if (isServiceAgent) {
          steps.push({
            text: "Retain the native Google-managed Service Agent role (roles/*.serviceAgent) — no custom role is needed for a Google-managed service agent.",
          });
        } else if (isHumanPam) {
          steps.push({
            text: "Provision the JIT PAM entitlement (see inline pam_entitlements.tf below) and verify a test elevation before removing standing access.",
            cmd: "terraform apply -target=module.pam   # from jit-pam/pam_entitlements.tf",
          });
        } else if (personaId) {
          steps.push({
            text: `Create the custom role ${personaId} from the inline YAML shown below (skip if already created).`,
            cmd: `gcloud iam roles create ${shQuote(personaId)} --project=${P} --file=${shQuote(`custom-roles/personas/${personaId}.yaml`)}`,
          });
          steps.push({
            text: "Grant the least-privilege role alongside the existing role first (canary / zero access gap).",
            cmd: `gcloud projects add-iam-policy-binding ${P} --member=${M} --role=${shQuote(targetRole)} --condition=None`,
          });
        } else if (targetRole) {
          steps.push({
            text: "Grant the proposed least-privilege role first (no access gap).",
            cmd: `gcloud projects add-iam-policy-binding ${P} --member=${M} --role=${shQuote(targetRole)} --condition=None`,
          });
        } else if (target) {
          steps.push({ text: `Apply the proposed target mapping: ${target}.` });
        }
        if (f.category === "ai_agent_blast_radius") {
          steps.push({
            text: "Attach IAM v2 Deny Policy D5 (see inline deny_policies.tf below) as an unbypassable control-plane ceiling complementing Agent Gateway / Model Armor.",
            cmd: "terraform plan -out=tfplan   # from deny-policies/deny_policies.tf",
          });
        }
        if (role) {
          steps.push({ text: `Remove the over-broad role ${role}.`, cmd: `gcloud projects remove-iam-policy-binding ${P} --member=${M} --role=${shQuote(role)}` });
          rollback.push({ text: "Re-grant the removed role.", cmd: `gcloud projects add-iam-policy-binding ${P} --member=${M} --role=${shQuote(role)} --condition=None` });
        }
        break;
      }
      case "dormant_sa":
        steps.push({ text: "Stage 1: disable (reversible). Delete only after an observation window.", cmd: `gcloud iam service-accounts disable ${email} --project=${P}` });
        rollback.push({ text: "Re-enable the service account.", cmd: `gcloud iam service-accounts enable ${email} --project=${P}` });
        verify.push({ text: "Confirm disabled state.", cmd: `gcloud iam service-accounts describe ${email} --project=${P} --format='value(disabled)'` });
        if (ev.unique_id) rollback.push({ text: `If deleted, undelete within 30 days using uniqueId ${ev.unique_id}.`, cmd: `gcloud beta iam service-accounts undelete ${shQuote(ev.unique_id)}` });
        break;
      case "expired_condition": {
        const cond = `expression=${ev.condition_expression || ""},title=${ev.condition_title || ""}`;
        steps.push({ text: "Remove the past-window conditional binding.", cmd: `gcloud projects remove-iam-policy-binding ${P} --member=${M} --role=${shQuote(role)} --condition=${shQuote(cond)}` });
        rollback.push({ text: "Restore the conditional binding.", cmd: `gcloud projects add-iam-policy-binding ${P} --member=${M} --role=${shQuote(role)} --condition=${shQuote(cond)}` });
        break;
      }
      case "service_agent_excess":
        steps.push({ text: `Remove the extra non-agent role ${role} from the service agent.`, cmd: `gcloud projects remove-iam-policy-binding ${P} --member=${M} --role=${shQuote(role)}` });
        rollback.push({ text: "Re-grant the role.", cmd: `gcloud projects add-iam-policy-binding ${P} --member=${M} --role=${shQuote(role)} --condition=None` });
        break;
      case "escalation_path": {
        const path = (an.transitive_paths || []).find((p) => p.id === ev.chain_id) || {};
        const inter = memberEmail(path.intermediate_principal || "");
        const src = path.source_principal || f.principal;
        const edgeRole = path.edge_role || "roles/iam.serviceAccountUser";
        if (inter) {
          steps.push({ text: `Sever the impersonation edge on ${inter}.`, cmd: `gcloud iam service-accounts remove-iam-policy-binding ${shQuote(inter)} --project=${P} --member=${shQuote(src)} --role=${shQuote(edgeRole)}` });
          rollback.push({ text: "Restore the edge.", cmd: `gcloud iam service-accounts add-iam-policy-binding ${shQuote(inter)} --project=${P} --member=${shQuote(src)} --role=${shQuote(edgeRole)}` });
          verify.push({ text: "Confirm the source can no longer act as the intermediate SA.", cmd: `gcloud policy-intelligence troubleshoot-policy iam //iam.googleapis.com/projects/${pid}/serviceAccounts/${inter} --principal-email=${shQuote(memberEmail(src))} --permission=iam.serviceAccounts.actAs` });
        }
        break;
      }
      case "cutover_blocker": {
        const missing = ev.uncovered_permissions || [];
        const target = replay?.proposed_model_a_role || "";
        steps.push({
          text: `Add the ${missing.length} uncovered permission(s) to the proposed role before cutover.`,
          cmd: target ? `gcloud iam roles update ${shQuote(String(target).split("/").pop())} --project=${P} --add-permissions=${shQuote(missing.join(","))}` : "",
        });
        if (ev.troubleshoot_cli) verify.push({ text: "Re-check with Policy Troubleshooter.", cmd: ev.troubleshoot_cli });
        break;
      }
      case "iac_violation":
        steps.push({ text: `Apply the fixed Terraform patch via a pull request (${ev.file || "file"}:${ev.line || "?"}).` });
        steps.push({ text: "Plan and review.", cmd: "terraform plan -out=tfplan" });
        rollback.push({ text: "Revert the pull request and re-apply." });
        break;
      case "standing_admin":
        steps.push({ text: "Create the JIT PAM entitlement.", cmd: "terraform apply -target=module.pam   # from pam_entitlements.tf" });
        if (role) steps.push({ text: `After a successful test elevation, remove the standing ${role} grant.`, cmd: `gcloud projects remove-iam-policy-binding ${P} --member=${M} --role=${shQuote(role)}` });
        if (role) rollback.push({ text: "Re-grant the standing role.", cmd: `gcloud projects add-iam-policy-binding ${P} --member=${M} --role=${shQuote(role)} --condition=None` });
        break;
      case "sa_key":
        steps.push({ text: "List user-managed keys and identify consumers before disabling.", cmd: `gcloud iam service-accounts keys list --iam-account=${email} --managed-by=user --project=${P}` });
        steps.push({ text: "Disable (not delete) each key, then observe for errors.", cmd: `gcloud iam service-accounts keys disable KEY_ID --iam-account=${email} --project=${P}` });
        rollback.push({ text: "Re-enable a key.", cmd: `gcloud iam service-accounts keys enable KEY_ID --iam-account=${email} --project=${P}` });
        break;
      case "wif_candidate":
        steps.push({ text: "Provision the Workload Identity pool/provider from wif_federation.tf and switch the pipeline to OIDC.", cmd: "terraform plan -out=tfplan   # wif_federation.tf" });
        break;
      default:
        break;
    }
    if (!steps.length) {
      steps.push({ text: f.recommended_action || "Follow the recommended action in the deliverable." });
      if (f.deliverable) steps.push({ text: `Deliverable: ${f.deliverable}` });
    }
    rollback.push({ text: "Full restore from the backup taken in pre-checks (etag-safe).", cmd: `gcloud projects set-iam-policy ${P} iam_backup_${pid}_<timestamp>.json` });
    (mapping?.rollback_commands || []).slice(0, 3).forEach((c) => rollback.push({ text: "ScopeGuard rollback (from this run):", cmd: c }));
    verify.push({
      text: "Run post-cutover verification against live GCP IAM bindings (--verify).",
      cmd: `python3 plugins/scopeguard/skills/gcp-iam-finding-remediator/scripts/finding_remediator_cli.py --project=${pid} --verify --plan-file=finding-remediation/finding_remediations.json`,
    });
    verify.push({ text: `Re-run ScopeGuard and confirm ${f.id} shows as Resolved on the Overview.` });
    const artifacts = resolvePlanArtifacts(f, mapping);
    return { pre, steps, rollback, verify, artifacts };
  }

  function planToText(f, plan) {
    const sec = (title, items) =>
      `## ${title}\n` + items.map((it, i) => `${i + 1}. ${it.text}${it.cmd ? `\n   ${it.cmd}` : ""}`).join("\n");
    return [
      `# Change plan — ${f.id} (PROPOSAL — NOT APPLIED)`,
      `Project: ${f.project_id || ctx.state.currentProject} | Run: ${env().run_id || ""}`,
      `Finding: [${f.severity}/${f.priority}] ${f.title}`,
      f.principal ? `Principal: ${f.principal}` : "",
      "",
      sec("Pre-checks", plan.pre),
      sec("Steps", plan.steps),
      sec("Rollback", plan.rollback),
      sec("Verify", plan.verify),
    ]
      .filter((l) => l !== null)
      .join("\n");
  }

  function openPlan(id) {
    const f = findById(id);
    const modal = $("plan-modal");
    const body = $("plan-body");
    if (!f || !modal || !body) {
      ctx.showToast(`Finding ${id} not found in this run.`, true);
      return;
    }
    S.copyStore.clear();
    const plan = buildPlan(f);
    const block = (title, items, cls) =>
      `<section class="plan-sec ${cls}"><h3>${esc(title)}</h3><ol>${items
        .map(
          (it) => `<li><div>${esc(it.text)}</div>${
            it.cmd ? `<div class="cmd-row"><pre class="code-block small">${esc(it.cmd)}</pre>${copyButton(it.cmd)}</div>` : ""
          }</li>`
        )
        .join("")}</ol></section>`;
    const simConf = ctx.simAuditConfidence ? ctx.simAuditConfidence(simModule()) : { level: "", cutover: "", missing: [], warning: "" };
    const simConfBadgeHtml = ctx.renderSimConfidenceBadge ? ctx.renderSimConfidenceBadge(simConf) : "";
    let canaryBanner = "";
    if (simConf.level === "MEDIUM" || simConf.level === "LOW" || simConf.cutover === "CANARY_DUAL_BIND") {
      const missingNote = simConf.missing.length
        ? ` Missing Data Access audit logs for: <code>${esc(simConf.missing.join(", "))}</code>.`
        : "";
      canaryBanner = `<div class="alert alert-warn canary-banner" role="status">
        <strong>Canary Dual-Bind Recommended (Audit Confidence: ${esc(simConf.level || "LOW")}):</strong>
        Grant the proposed least-privilege role <em>alongside</em> the existing role first, observe production traffic for 24&ndash;72h, and remove the legacy role only after confirming zero permission errors.${missingNote}
      </div>`;
    }
    const artifacts = plan.artifacts || [];
    const artifactsHtml = artifacts.length
      ? `<section class="plan-sec plan-artifacts">
          <h3>Relevant Deliverable Content (Inline)</h3>
          ${artifacts
            .map((art, idx) => {
              const dlKey = `dl_${idx}_${S.copyStore.size}`;
              S.copyStore.set(dlKey, JSON.stringify({ filename: art.filename.split("/").pop(), content: art.content, mime: art.mime }));
              return `<div class="plan-artifact-card">
                <div class="plan-artifact-head">
                  <div>
                    <strong>${esc(art.label)}</strong>
                    <code class="mono muted">${esc(art.filename)}</code>
                  </div>
                  <div class="btn-group">
                    ${copyButton(art.content, "Copy")}
                    <button type="button" class="btn btn-secondary btn-sm" data-dl-artifact="${esc(dlKey)}">Download</button>
                  </div>
                </div>
                <pre class="code-block plan-artifact-code">${esc(art.content)}</pre>
              </div>`;
            })
            .join("")}
        </section>`
      : "";
    $("plan-modal-title").textContent = `Change Plan — ${f.id}`;
    body.innerHTML = `<div class="plan-head">${sevChip(f.severity)} <span class="badge badge-neutral">${esc(f.priority)}</span> ${statusChip(f.status)} ${simConfBadgeHtml}
        <strong>${esc(f.title)}</strong>
        ${f.principal ? `<div class="mono muted">${esc(f.principal)}</div>` : ""}
        ${f.detail ? `<div class="muted">${esc(f.detail)}</div>` : ""}</div>
      ${canaryBanner}
      ${block("1. Pre-checks", plan.pre, "pre")}
      ${block("2. Steps", plan.steps, "steps")}
      ${artifactsHtml}
      ${block("3. Rollback", plan.rollback, "rollback")}
      ${block("4. Verify", plan.verify, "verify")}`;
    S.copyStore.set("__plan__", planToText(f, plan));
    // If the drawer is open, keep its focus-restore target by stacking.
    openDialog(modal, $("btn-close-plan-modal"));
  }

  /* ---------------------------------------------------------------------- */
  /* Exports (UI-10)                                                         */
  /* ---------------------------------------------------------------------- */

  const EXPORT_COLS = [
    "id", "project_id", "severity", "priority", "status", "category_label", "principal", "principal_type",
    "title", "resource", "first_seen", "age_days", "confidence", "recommended_action", "deliverable", "source_skill",
  ];

  /** Neutralizes spreadsheet formula injection (OWASP CSV injection guidance). */
  function csvCell(value) {
    let s = value === null || value === undefined ? "" : String(value);
    if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
    return `"${s.replace(/"/g, '""')}"`;
  }

  function exportBase() {
    const st = ctx.state;
    const ts = (env().timestamp_utc || "").replace(/[:-]/g, "").slice(0, 15) || "run";
    return `scopeguard_findings_${st.currentProject}_${ts}`;
  }

  function exportCsv() {
    const rows = [EXPORT_COLS.join(",")].concat(S.filtered.map((f) => EXPORT_COLS.map((c) => csvCell(f[c])).join(",")));
    ctx.triggerDownload(`${exportBase()}.csv`, "\uFEFF" + rows.join("\r\n"), "text/csv;charset=utf-8");
    ctx.showToast(`Exported ${S.filtered.length} finding(s) to CSV.`);
  }

  function exportJson() {
    const payload = {
      project_id: ctx.state.currentProject,
      run_id: env().run_id,
      timestamp_utc: env().timestamp_utc,
      exported_at: new Date().toISOString(),
      filters: S.filters,
      findings: S.filtered,
    };
    ctx.triggerDownload(`${exportBase()}.json`, JSON.stringify(payload, null, 2), "application/json");
    ctx.showToast(`Exported ${S.filtered.length} finding(s) to JSON.`);
  }

  function exportMd() {
    const cell = (v) => String(v ?? "").replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
    const lines = [
      `# ScopeGuard findings — ${ctx.state.currentProject}`,
      "",
      `Run \`${env().run_id || ""}\` (${env().timestamp_utc || ""}). ${S.filtered.length} finding(s).`,
      "",
      "| ID | Severity | Priority | Status | Category | Principal | Finding | Action | Deliverable |",
      "|---|---|---|---|---|---|---|---|---|",
    ].concat(
      S.filtered.map(
        (f) => `| ${cell(f.id)} | ${cell(f.severity)} | ${cell(f.priority)} | ${cell(f.status)} | ${cell(f.category_label)} | ${cell(
          f.principal
        )} | ${cell(f.title)} | ${cell(f.recommended_action)} | ${cell(f.deliverable)} |`
      )
    );
    ctx.triggerDownload(`${exportBase()}.md`, lines.join("\n"), "text/markdown;charset=utf-8");
    ctx.showToast(`Exported ${S.filtered.length} finding(s) to Markdown.`);
  }

  async function sha256Hex(text) {
    try {
      if (!window.crypto?.subtle) return "unavailable (non-secure context)";
      const buf = await window.crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
      return Array.from(new Uint8Array(buf))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
    } catch (err) {
      console.warn("SHA-256 failed", err);
      return "unavailable";
    }
  }

  /** Collects text deliverables (Terraform, scripts, Markdown) from every module. */
  function collectDeliverables() {
    const out = {};
    const re = /(_hcl|_markdown|_md|_sh|_yaml|_yml|_tf|terraform)$/i;
    Object.entries(mods()).forEach(([key, mod]) => {
      const scan = (obj, prefix) => {
        if (!obj || typeof obj !== "object") return;
        Object.entries(obj).forEach(([k, v]) => {
          if (typeof v === "string" && re.test(k) && v.length) out[`${key}.${prefix}${k}`] = v;
        });
      };
      scan(mod?.payload, "");
      scan(mod?.payload?.artifacts, "artifacts.");
    });
    const art = mods().recommender_audit?.payload?.artifacts || {};
    if (art.scc_findings) out["recommender_audit.artifacts.scc_findings"] = art.scc_findings;
    if (art.sarif) out["recommender_audit.artifacts.sarif"] = art.sarif;
    return out;
  }

  async function exportEvidencePack() {
    const e = env();
    const d = S.data || {};
    const findingsJson = JSON.stringify(d.findings || []);
    const pack = {
      schema: "scopeguard-evidence-pack/1",
      generated_at: new Date().toISOString(),
      generated_by: "ScopeGuard read-only portal (no IAM changes were made)",
      run: {
        project_id: e.project_id || ctx.state.currentProject,
        run_id: e.run_id,
        timestamp_utc: e.timestamp_utc,
        trigger_mode: e.trigger_mode,
        schema_version: e.schema_version,
        live_policy_etag: e.live_policy_etag,
        triggered_skills: e.triggered_skills,
        gcs_metadata: e.gcs_metadata,
        freshness_overview: e.freshness_overview,
        executed_by: e.executed_by || e.provenance?.executed_by || "not recorded",
        api_preflight: e.api_preflight || "not recorded",
      },
      integrity: { findings_sha256: await sha256Hex(findingsJson) },
      counts: d.counts,
      trend: d.trend,
      findings: d.findings || [],
      resolved_since_previous: d.resolved || [],
      simulator_summary: simModule().summary || {},
      recommendations_markdown: e.master_recommendations_markdown || "",
      deliverables: collectDeliverables(),
    };
    ctx.triggerDownload(
      `scopeguard_evidence_${ctx.state.currentProject}_${(e.run_id || "run").slice(-12)}.json`,
      JSON.stringify(pack, null, 2),
      "application/json"
    );
    ctx.showToast("Evidence pack downloaded.");
  }

  /* ---------------------------------------------------------------------- */
  /* Global Quick-Jump Search Dropdown (Cmd+K / /)                          */
  /* ---------------------------------------------------------------------- */

  function closeQuickJump() {
    const dd = $("quick-jump-results");
    const inp = $("global-search");
    if (dd) dd.classList.add("hidden");
    if (inp) inp.setAttribute("aria-expanded", "false");
    S.qjItems = [];
    S.qjActiveIdx = 0;
  }

  function buildQuickJumpGroups(rawQuery) {
    const q = String(rawQuery || "").trim().toLowerCase();
    const an = analysis();
    const findings = S.data?.findings || [];
    const remPlans = mods().finding_remediator?.payload?.remediation_plans || [];

    // 1. Principals
    const seenPrincipals = new Set();
    const principals = [];
    const addPrincipal = (member, sub) => {
      if (!member || seenPrincipals.has(member)) return;
      seenPrincipals.add(member);
      const hay = `${member} ${sub || ""}`.toLowerCase();
      if (!q || hay.includes(q)) {
        principals.push({ type: "principal", value: member, title: member, sub: sub || "Identity" });
      }
    };
    (an.principal_mappings || []).forEach((pm) => {
      addPrincipal(pm.principal, `${pm.category || pm.taxonomy || "Principal"} · ${(pm.current_roles || []).slice(0, 2).join(", ")}`);
    });
    findings.forEach((f) => {
      if (f.principal) addPrincipal(f.principal, f.principal_type || "Principal");
    });

    // 2. Findings / SCC-Wiz IDs
    const findingItems = [];
    const seenFindingIds = new Set();
    findings.forEach((f) => {
      const extId = f.evidence?.finding_id || "";
      const hay = [f.id, extId, f.title, f.principal, f.resource, f.category_label].join(" ").toLowerCase();
      if (!q || hay.includes(q)) {
        seenFindingIds.add(f.id);
        if (extId) seenFindingIds.add(extId);
        findingItems.push({
          type: "finding",
          value: f.id,
          title: `${f.id} — ${f.title}`,
          sub: `${f.severity} · ${f.priority}${f.principal ? ` · ${f.principal}` : ""}`,
        });
      }
    });
    remPlans.forEach((rp) => {
      const fid = rp.finding_id || "";
      if (!fid || seenFindingIds.has(fid)) return;
      const hay = [fid, rp.title, rp.principal, rp.source_platform, rp.replacement_role].join(" ").toLowerCase();
      if (!q || hay.includes(q)) {
        findingItems.push({
          type: "external_plan",
          value: fid,
          title: `${fid} — ${rp.title || "SCC/Wiz Alert"}`,
          sub: `${rp.source_platform || "External"} · ${rp.severity || "HIGH"} · ${rp.principal || ""}`,
        });
      }
    });

    // 3. Custom Role IDs (sg_persona_* / sg_cap_*)
    const roleItems = [];
    const seenRoles = new Set();
    const addRole = (roleId, label, permCount) => {
      if (!roleId || seenRoles.has(roleId)) return;
      seenRoles.add(roleId);
      const hay = `${roleId} ${label}`.toLowerCase();
      if (!q || hay.includes(q)) {
        roleItems.push({
          type: "role",
          value: roleId,
          title: roleId,
          sub: `${label}${permCount !== null && permCount !== undefined ? ` · ${permCount} perms` : ""}`,
        });
      }
    };
    Object.entries(an.custom_roles_model_a || {}).forEach(([slug, spec]) => {
      addRole(spec?.role_id || spec?.roleId || slug, "Model A Persona Role", (spec?.includedPermissions || []).length);
    });
    Object.entries(an.custom_roles_model_b_disjoint || {}).forEach(([slug, spec]) => {
      addRole(spec?.role_id || spec?.roleId || slug, "Model B Capability Role", (spec?.includedPermissions || []).length);
    });
    const art = mods().recommender_audit?.payload?.artifacts || {};
    Object.keys(art.model_a_role_yamls || {}).forEach((fname) => {
      addRole(fname.replace(/\.(ya?ml)$/i, ""), "Model A YAML", null);
    });
    Object.keys(art.disjoint_role_yamls || {}).forEach((fname) => {
      addRole(fname.replace(/\.(ya?ml)$/i, ""), "Model B YAML", null);
    });

    return [
      { label: "Principals", items: principals.slice(0, 5) },
      { label: "Findings & SCC / Wiz IDs", items: findingItems.slice(0, 5) },
      { label: "Custom Role IDs", items: roleItems.slice(0, 5) },
    ].filter((g) => g.items.length > 0);
  }

  function executeQuickJumpItem(item) {
    closeQuickJump();
    const inp = $("global-search");
    if (inp) inp.blur();
    if (!item) return;
    if (item.type === "principal") {
      openDrawer(item.value);
    } else if (item.type === "finding") {
      openPlan(item.value);
    } else if (item.type === "external_plan") {
      ctx.switchToTab("view-architect");
      $("remediator-cards")?.scrollIntoView({ behavior: "smooth", block: "center" });
    } else if (item.type === "role") {
      if (ctx.openYamlRole) ctx.openYamlRole(item.value);
      else ctx.switchToTab("view-compression");
    }
  }

  function renderQuickJump(rawQuery) {
    const dd = $("quick-jump-results");
    const inp = $("global-search");
    if (!dd || !inp) return;
    const groups = buildQuickJumpGroups(rawQuery);
    const flat = [];
    groups.forEach((g) => g.items.forEach((it) => flat.push(it)));
    S.qjItems = flat;
    S.qjActiveIdx = 0;

    if (!flat.length) {
      dd.innerHTML = `<div class="qj-empty">No matching principals, findings, or custom roles. Press Enter to filter the Findings queue.</div>`;
    } else {
      let idx = 0;
      dd.innerHTML = groups
        .map((g) => {
          const rows = g.items
            .map((it) => {
              const myIdx = idx++;
              return `<button type="button" class="qj-item${myIdx === 0 ? " active" : ""}" role="option" aria-selected="${
                myIdx === 0 ? "true" : "false"
              }" data-qj-idx="${myIdx}">
                <span class="qj-item-main mono">${esc(it.title)}</span>
                <span class="qj-item-sub">${esc(it.sub)}</span>
              </button>`;
            })
            .join("");
          return `<div class="qj-group"><div class="qj-group-title">${esc(g.label)}</div>${rows}</div>`;
        })
        .join("");
    }
    dd.classList.remove("hidden");
    inp.setAttribute("aria-expanded", "true");
  }

  function highlightQuickJump(newIdx) {
    const dd = $("quick-jump-results");
    if (!dd || !S.qjItems.length) return;
    S.qjActiveIdx = (newIdx + S.qjItems.length) % S.qjItems.length;
    dd.querySelectorAll(".qj-item").forEach((el, idx) => {
      const on = idx === S.qjActiveIdx;
      el.classList.toggle("active", on);
      el.setAttribute("aria-selected", on ? "true" : "false");
      if (on) el.scrollIntoView({ block: "nearest" });
    });
  }

  /* ---------------------------------------------------------------------- */
  /* Event binding                                                           */
  /* ---------------------------------------------------------------------- */

  function bindEvents() {
    const on = (id, ev, fn) => $(id)?.addEventListener(ev, fn);
    let searchTimer = null;
    on("f-search", "input", (e) => {
      window.clearTimeout(searchTimer);
      const v = e.target.value;
      searchTimer = window.setTimeout(() => setFilter("q", v), 150);
    });
    on("f-severity", "change", (e) => setFilter("sev", e.target.value));
    on("f-priority", "change", (e) => setFilter("priority", e.target.value));
    on("f-status", "change", (e) => setFilter("status", e.target.value));
    on("f-category", "change", (e) => setFilter("cat", e.target.value));
    on("f-ptype", "change", (e) => setFilter("ptype", e.target.value));
    on("f-sort", "change", (e) => setFilter("sort", e.target.value));
    on("btn-f-clear", "click", clearFilters);
    on("btn-export-csv", "click", exportCsv);
    on("btn-export-json", "click", exportJson);
    on("btn-export-md", "click", exportMd);
    on("btn-export-evidence", "click", () => exportEvidencePack().catch((err) => ctx.showToast(`Evidence pack failed: ${err.message}`, true)));
    on("btn-overview-all-findings", "click", () => ctx.switchToTab("view-findings"));
    on("btn-close-drawer", "click", closeDrawer);
    on("drawer-backdrop", "click", closeDrawer);
    on("btn-close-plan-modal", "click", () => closeDialog($("plan-modal")));
    on("btn-copy-plan", "click", async () => {
      const ok = await copyText(S.copyStore.get("__plan__") || "");
      ctx.showToast(ok ? "Change plan copied." : "Copy failed; select the text manually.", !ok);
    });

    // Global Quick-Jump Search (Cmd+K / /)
    on("global-search", "input", (e) => {
      renderQuickJump(e.target.value);
    });
    on("global-search", "focus", (e) => {
      renderQuickJump(e.target.value);
    });
    on("global-search", "keydown", (e) => {
      if (e.key === "ArrowDown" && S.qjItems.length) {
        e.preventDefault();
        highlightQuickJump(S.qjActiveIdx + 1);
      } else if (e.key === "ArrowUp" && S.qjItems.length) {
        e.preventDefault();
        highlightQuickJump(S.qjActiveIdx - 1);
      } else if (e.key === "Enter") {
        e.preventDefault();
        const dd = $("quick-jump-results");
        if (dd && !dd.classList.contains("hidden") && S.qjItems.length) {
          executeQuickJumpItem(S.qjItems[S.qjActiveIdx] || S.qjItems[0]);
        } else {
          closeQuickJump();
          setFilter("q", e.target.value.trim(), { goto: true });
        }
      } else if (e.key === "Escape") {
        e.preventDefault();
        closeQuickJump();
        e.target.blur();
      }
    });

    // Delegated clicks: quick-jump, triage presets, identity drawer, plans, copy, filters, pagination.
    document.addEventListener("click", async (e) => {
      if (!e.target.closest(".quick-jump-wrap")) {
        closeQuickJump();
      }
      const qjBtn = e.target.closest("[data-qj-idx]");
      if (qjBtn) {
        const idx = Number(qjBtn.dataset.qjIdx);
        executeQuickJumpItem(S.qjItems[idx]);
        return;
      }
      const presetBtn = e.target.closest("[data-triage-preset]");
      if (presetBtn) {
        applyTriagePreset(presetBtn.dataset.triagePreset);
        return;
      }
      const t = e.target.closest(
        "[data-principal],[data-plan],[data-copy-id],[data-dl-artifact],[data-page],[data-filter-sev],[data-filter-status],[data-filter-ptype],[data-goto-tab],[data-clear-filters]"
      );
      if (!t) return;
      if (t.dataset.copyId) {
        const ok = await copyText(S.copyStore.get(t.dataset.copyId) || "");
        ctx.showToast(ok ? "Copied to clipboard." : "Copy failed; select the text manually.", !ok);
      } else if (t.dataset.dlArtifact) {
        try {
          const rec = JSON.parse(S.copyStore.get(t.dataset.dlArtifact) || "{}");
          if (rec.filename && rec.content) {
            ctx.triggerDownload(rec.filename, rec.content, rec.mime || "text/plain;charset=utf-8");
          }
        } catch (_err) {
          ctx.showToast("Could not download deliverable.", true);
        }
      } else if (t.dataset.plan) {
        openPlan(t.dataset.plan);
      } else if (t.dataset.principal) {
        openDrawer(t.dataset.principal);
      } else if (t.dataset.page) {
        S.page = Number(t.dataset.page) || 1;
        renderFindingsQueue();
        $("findings-summary")?.scrollIntoView({ block: "nearest" });
      } else if (t.dataset.filterSev) {
        clearFilters();
        setFilter("sev", t.dataset.filterSev, { goto: true });
      } else if (t.dataset.filterStatus) {
        clearFilters();
        setFilter("status", t.dataset.filterStatus, { goto: true });
      } else if (t.dataset.filterPtype) {
        clearFilters();
        setFilter("ptype", t.dataset.filterPtype, { goto: true });
      } else if (t.dataset.gotoTab) {
        ctx.switchToTab(t.dataset.gotoTab);
      } else if (t.hasAttribute("data-clear-filters")) {
        clearFilters();
      }
    });

    // Keyboard: Cmd+K / Ctrl+K or "/" focuses search, Esc closes the top dialog, Tab is trapped.
    document.addEventListener("keydown", (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        const gs = $("global-search");
        if (gs) {
          gs.focus();
          gs.select();
          renderQuickJump(gs.value);
        }
        return;
      }
      const tag = (e.target.tagName || "").toLowerCase();
      const typing = tag === "input" || tag === "textarea" || tag === "select" || e.target.isContentEditable;
      if (e.key === "/" && !typing && !topDialog()) {
        e.preventDefault();
        const gs = $("global-search");
        if (gs) {
          gs.focus();
          renderQuickJump(gs.value);
        }
        return;
      }
      if (e.key === "Escape" && closeTop()) {
        e.preventDefault();
        return;
      }
      trapFocus(e);
    });
  }

  /* ---------------------------------------------------------------------- */
  /* Public API                                                              */
  /* ---------------------------------------------------------------------- */

  function init(context) {
    ctx = context;
    readUrlFilters();
    bindEvents();
  }

  /** Called by app.js after each successful loadAssessment(). */
  async function onAssessmentLoaded() {
    S.data = null;
    S.page = 1;
    renderRunContextBar();
    renderGlobalAlerts();
    renderTriagePresets(); // render pills immediately even before /api/findings resolves
    renderFindingsQueue(); // shows loading state
    let data = null;
    try {
      data = await fetchFindings();
    } catch (err) {
      const tbody = $("findings-tbody");
      if (tbody) {
        tbody.innerHTML = `<tr><td colspan="9">Could not load findings: ${esc(err.message)}
          <button type="button" class="btn btn-secondary btn-sm" id="btn-findings-retry">Retry</button></td></tr>`;
        $("btn-findings-retry")?.addEventListener("click", () => onAssessmentLoaded());
      }
      const next = $("overview-next-actions");
      if (next) next.innerHTML = `<div class="empty-note">Findings unavailable: ${esc(err.message)}</div>`;
      throw err;
    }
    if (!data) return; // superseded by a newer load
    S.data = data;
    populateFilterOptions();
    renderOverview();
    renderFindingsQueue();
    renderRunContextBar();
    if (S.drawerPrincipal) {
      const p = S.drawerPrincipal;
      // Only re-open from a deep link if the principal exists in this run.
      const exists = (data.findings || []).some((f) => f.principal === p) ||
        (analysis().principal_mappings || []).some((pm) => pm.principal === p);
      if (exists) openDrawer(p);
      else S.drawerPrincipal = "";
    }
    syncUrl();
  }

  function onTabSwitched() {
    syncUrl();
  }

  window.ScopeGuardInsights = { init, onAssessmentLoaded, onTabSwitched };
})();
