#!/usr/bin/env python3
# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0

"""Unified Master Recommendation Synthesizer for the ScopeGuard 10-Skill Suite.

Transforms an assembled ScopeGuard v2.x Assessment Envelope (full-suite or
partial carry-forward runs) into:

  1. `recommendation_digest`: Structured executive KPIs and P0->P3 action items
     printed to CLI stdout so agents can present recommendations immediately.
  2. `master_recommendations_markdown`: The consolidated reference report
     (`scopeguard_recommendations_<pid>.md`, still referenced by plugin rules).
  3. Audience-specific documents (ART-5), rendered by
     `render_audience_documents()`:
       - `EXECUTIVE_SUMMARY.md` (security leadership, 1 page),
       - `REMEDIATION_PLAN.md` (DevOps, grouped by change batch / phase),
       - `EVIDENCE.md` (GRC / auditors: provenance, sources, gates).

All renderers are tolerant of missing keys so that legacy 2.0 envelopes and
partial runs still render. Principals are displayed with short names
(`naming.short_principal`) and the full identities are listed once in an
appendix, so Markdown tables stay readable in the side pane, GitHub and
Confluence.
"""

import logging
import re
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence

from .findings_engine import SEVERITY_RANK, normalize_findings
from .naming import short_principal

LOGGER = logging.getLogger(__name__)

FRESHNESS_LABELS = {
    "CURRENT": "Current (This Run)",
    "CARRIED_FORWARD_PROBABLY_STALE": "Carried Forward (Probably Stale)",
    "STALE_POLICY_DRIFT": "Stale — Live IAM Policy Etag Changed",
    "NOT_RUN": "Not Executed Yet",
}

# Remediation SLAs per phase, shown in the executive summary and plan.
PHASE_SLA = {
    "P0": "1 business day",
    "P1": "7 days",
    "P2": "30 days",
    "P3": "90 days",
}

PHASE_TITLES = {
    "P0": "Phase P0 — Zero-Impact Hygiene & Dead-Binding Cleanup (Day 1)",
    "P1": "Phase P1 — Privilege Escalation, Standing Admin (PAM), WIF & IaC Blockers (Week 1)",
    "P2": "Phase P2 — Replay-Verified Persona Custom Role Cutover (Weeks 2–3)",
    "P3": "Phase P3 — Preventive IAM v2 Deny Policies, Org Guardrails & Compliance Sign-Off (Week 4)",
}

# Companion documents written next to the consolidated report (ART-5).
AUDIENCE_DOCS = ("EXECUTIVE_SUMMARY.md", "REMEDIATION_PLAN.md", "EVIDENCE.md")

# Member prefixes that identify an IAM principal string.
_MEMBER_RE = re.compile(
    r"^(user|group|serviceAccount|domain|principal|principalSet|deleted:[a-zA-Z]+):",
)

# Per-skill change-batch metadata used to explain each remediation item.
# `risk` and `rollback` are deliberately conservative, plain-English texts.
_SKILL_META: Dict[str, Dict[str, Any]] = {
    "gcp-iam-recommender-audit": {
        "batch": "Least-privilege persona role cutover",
        "risk": (
            "Medium — the workload may receive HTTP 403 if a used permission was "
            "missed. Validate with the breakglass simulator replay before removing "
            "old bindings."
        ),
        "rollback": (
            "Run `./rollback_runbook.sh` for this principal (condition-aware "
            "restore), or the full etag-pinned restore from the policy backup."
        ),
        "pre_checks": [
            "Confirm the live policy etag still matches the assessment etag.",
            "Create the persona custom role(s) before adding any binding.",
            "Review the simulator verdict for the affected principals.",
        ],
        "verification": [
            "Re-run `scopeguard_pipeline.py --stages=recommender_audit,breakglass_simulator`.",
            "Watch Cloud Logging for `PERMISSION_DENIED` for 24–48h after cutover.",
        ],
    },
    "gcp-iam-jit-pam-architect": {
        "batch": "Standing admin to just-in-time (PAM)",
        "risk": (
            "Low — admins keep access through approved PAM grants. Ensure the "
            "approver is a different person or group than the requester."
        ),
        "rollback": "Re-add the standing role bindings listed in `rollback_runbook.sh`.",
        "pre_checks": [
            "Nominate a distinct approver group (no self-approval).",
            "Test one PAM grant end-to-end before removing standing roles.",
        ],
        "verification": ["Request a test grant and confirm it expires on time."],
    },
    "gcp-iam-federation-architect": {
        "batch": "Service account keys to Workload Identity Federation",
        "risk": (
            "Medium — CI/CD jobs using a disabled key fail until switched to WIF. "
            "Disable keys first (reversible) before deleting them."
        ),
        "rollback": "Re-enable the disabled key with `gcloud iam service-accounts keys enable`.",
        "pre_checks": [
            "Inventory every pipeline that uses the key.",
            "Apply the WIF pool/provider and update the CI workflow first.",
        ],
        "verification": ["Confirm CI runs succeed with WIF and no key usage in logs."],
    },
    "gcp-iam-gitops-pr-guardrail": {
        "batch": "Terraform IAM drift fixes & PR gate",
        "risk": "Low — changes go through code review and `terraform plan`.",
        "rollback": "Revert the merge commit and re-apply the previous Terraform state.",
        "pre_checks": ["Run `terraform plan` and review IAM diffs."],
        "verification": ["The PR gate passes and SARIF shows no CRITICAL/HIGH results."],
    },
    "gcp-iam-finding-remediator": {
        "batch": "Inbound SCC / Wiz finding fixes",
        "risk": (
            "Medium — replaces broad roles; the replacement role was replay-checked "
            "against observed usage."
        ),
        "rollback": "Run the rollback section of `finding-remediation/` runbook.",
        "pre_checks": ["Confirm the external finding is still ACTIVE."],
        "verification": ["Re-run with `--verify` and attach the note to the ticket."],
    },
    "gcp-iam-breakglass-simulator": {
        "batch": "Pre-cutover replay verification",
        "risk": "None — read-only simulation.",
        "rollback": "Not applicable (no change applied).",
        "pre_checks": [],
        "verification": ["Simulated HTTP 403 count is 0 for every principal."],
    },
    "gcp-iam-role-architect": {
        "batch": "Greenfield scoped role blueprints",
        "risk": "Low — applies to new workloads only.",
        "rollback": "Destroy the new Terraform resources.",
        "pre_checks": ["Review the blueprint permissions with the workload owner."],
        "verification": ["`terraform plan` shows only the intended scoped bindings."],
    },
    "gcp-iam-deny-policy-architect": {
        "batch": "Preventive IAM deny policies",
        "risk": (
            "Medium — deny rules can lock out administrators. Observe first and "
            "confirm break-glass exception principals."
        ),
        "rollback": "Delete the deny policy (`gcloud iam policies delete`).",
        "pre_checks": ["Confirm break-glass exception principals."],
        "verification": ["Attempt a denied action with a test identity."],
    },
    "gcp-iam-org-hierarchy-auditor": {
        "batch": "Organization policy guardrails",
        "risk": "Medium — org policies apply to every project below the node.",
        "rollback": "Restore the previous org policy (`gcloud org-policies set-policy`).",
        "pre_checks": ["Dry-run the constraint where supported."],
        "verification": ["`gcloud org-policies describe` shows the constraint enforced."],
    },
    "gcp-iam-compliance-mapper": {
        "batch": "Compliance evidence sign-off",
        "risk": "None — evidence archival only.",
        "rollback": "Not applicable.",
        "pre_checks": [],
        "verification": ["Auditor accepts the evidence pack."],
    },
}


# -----------------------------------------------------------------------------
# Small helpers
# -----------------------------------------------------------------------------
def _freshness_tag(mod: Dict[str, Any]) -> str:
  """Returns the human label for a module's freshness state."""
  raw = mod.get("freshness", "NOT_RUN")
  return FRESHNESS_LABELS.get(raw, raw)


def _completed(mod: Optional[Dict[str, Any]]) -> bool:
  """True when a module entry exists and completed successfully."""
  return bool(mod) and mod.get("status") == "COMPLETED"


def _as_list(value: Any) -> List[Any]:
  """Normalises scalars / None / tuples into a list."""
  if value is None or value == "":
    return []
  if isinstance(value, (list, tuple, set)):
    return list(value)
  return [value]


def _int(value: Any, default: int = 0) -> int:
  """Best-effort integer conversion that never raises."""
  try:
    return int(value)
  except (TypeError, ValueError):
    return default


def _remediator_403_display(plan: Dict[str, Any]) -> str:
  """Simulated-403 text for a remediator plan without inventing a zero.

  v2.1 remediator plans carry `simulated_403_display` (e.g. "0", "n/a (not
  run)"); v2.0 plans only had a numeric `simulated_403_denials`.
  """
  disp = plan.get("simulated_403_display")
  if disp not in (None, ""):
    return str(disp)
  if plan.get("simulated_403_denials") is not None:
    return str(plan.get("simulated_403_denials"))
  return "n/a (not run)"


def _format_attack_path(plan: Dict[str, Any]) -> str:
  """Formats optional `attack_path_summary` / choke-point metadata from a plan."""
  raw = plan.get("attack_path_summary")
  choke = plan.get("choke_point") or plan.get("choke_points")
  parts: List[str] = []
  if isinstance(raw, dict):
    summary_text = raw.get("summary") or raw.get("description") or raw.get("path")
    if summary_text:
      parts.append(str(summary_text))
    cp = raw.get("choke_point") or raw.get("choke_points")
    if cp and not choke:
      choke = cp
  elif raw:
    parts.append(str(raw))
  if choke:
    if isinstance(choke, (list, tuple)):
      choke_str = ", ".join(str(c) for c in choke if c)
    else:
      choke_str = str(choke)
    if choke_str and choke_str not in " ".join(parts):
      parts.append(f"choke point: {choke_str}")
  return " — ".join(p for p in parts if p)


def _sim_confidence_and_cutover(
    envelope: Dict[str, Any], digest: Optional[Dict[str, Any]] = None
) -> tuple:
  """Extracts `(audit_log_confidence, recommended_cutover)` from digest or simulator."""
  kpis = (digest or {}).get("executive_kpis") or {}
  sim_mod = (envelope.get("modules") or {}).get("breakglass_simulator") or {}
  sim_sum = sim_mod.get("summary") or {}
  sim_payload = sim_mod.get("payload") or {}
  confidence = (
      kpis.get("audit_log_confidence")
      or sim_sum.get("audit_log_confidence")
      or sim_payload.get("audit_log_confidence")
  )
  cutover = (
      kpis.get("recommended_cutover")
      or sim_sum.get("recommended_cutover")
      or sim_payload.get("recommended_cutover")
  )
  return (str(confidence).upper() if confidence else None,
          str(cutover).upper() if cutover else None)


def is_member(text: Any) -> bool:
  """True when `text` looks like a single IAM member or e-mail address."""
  s = str(text or "").strip()
  if not s or " " in s:
    return False
  return bool(_MEMBER_RE.match(s)) or "@" in s


def display_principal(text: Any) -> str:
  """Short display form for IAM members; free text is returned unchanged."""
  s = str(text or "")
  return short_principal(s) if is_member(s) else s


def _md_cell(text: Any) -> str:
  """Escapes pipes/newlines so a value is safe inside a Markdown table cell."""
  return str(text if text is not None else "").replace("|", "\\|").replace("\n", " ")


def _audit_analysis(envelope: Dict[str, Any]) -> Dict[str, Any]:
  """Returns the recommender-audit analysis dict (empty when absent)."""
  mod = (envelope.get("modules") or {}).get("recommender_audit") or {}
  return (mod.get("payload") or {}).get("analysis") or {}


def _persona_roles(an: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
  """Model A persona roles keyed by persona role id (new or legacy shape)."""
  return an.get("custom_roles_model_a") or {}


def _capability_roles(an: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
  """Model B capability (disjoint) roles keyed by capability role id."""
  return an.get("custom_roles_model_b_disjoint") or {}


def _bundles(an: Dict[str, Any]) -> Dict[str, List[str]]:
  """Persona -> capability bundle map; falls back to legacy `model_a_to_b_map`."""
  bundles = an.get("model_b_bundles")
  if isinstance(bundles, dict) and bundles:
    return {k: _as_list(v) for k, v in bundles.items()}
  legacy = an.get("model_a_to_b_map") or {}
  return {k: _as_list(v) for k, v in legacy.items()} if isinstance(legacy, dict) else {}


def _is_v21_layout(spec: Dict[str, Any], key: str) -> bool:
  """True when a role follows the 2.1 naming contract (personas/ + capabilities/).

  2.1 role IDs are `<prefix>persona_<workload>` / `<prefix>cap_<domain>_<access>`;
  older 2.0 envelopes used flat `custom-roles/` and `custom-roles/disjoint/`.
  """
  role_id = str(spec.get("role_id") or key)
  return "persona_" in role_id or "_cap_" in f"_{role_id}" or bool(spec.get("model"))


def _persona_yaml_path(key: str, spec: Dict[str, Any]) -> str:
  """Relative YAML path for a persona role (contract path or legacy path)."""
  if spec.get("yaml_path"):
    return str(spec["yaml_path"])
  if _is_v21_layout(spec, key):
    return f"custom-roles/personas/{spec.get('role_id') or key}.yaml"
  return f"custom-roles/{key}.yaml"


def _capability_yaml_path(key: str, spec: Dict[str, Any]) -> str:
  """Relative YAML path for a capability role (contract path or legacy path)."""
  if spec.get("yaml_path"):
    return str(spec["yaml_path"])
  if _is_v21_layout(spec, key):
    return f"custom-roles/capabilities/{spec.get('role_id') or key}.yaml"
  return f"custom-roles/disjoint/{key}.yaml"


def _mappings_by_principal(an: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
  """Indexes `principal_mappings` entries by full member string."""
  return {
      pm.get("principal", ""): pm
      for pm in (an.get("principal_mappings") or [])
      if isinstance(pm, dict)
  }


def _persona_members(
    key: str, spec: Dict[str, Any], an: Dict[str, Any]
) -> List[str]:
  """Members of a persona role from the role spec, else from principal mappings."""
  members = _as_list(spec.get("members"))
  if members:
    return [str(m) for m in members]
  role_id = str(spec.get("role_id") or key)
  found = []
  for pm in an.get("principal_mappings") or []:
    if pm.get("persona_role_id") == key or role_id in str(pm.get("target_mapping", "")):
      found.append(str(pm.get("principal", "")))
  return found


def _findings_safe(envelope: Dict[str, Any]) -> List[Dict[str, Any]]:
  """Runs the unified findings engine, never raising on malformed envelopes."""
  try:
    return normalize_findings(envelope)
  except Exception as exc:  # pylint: disable=broad-except
    LOGGER.warning("Findings normalisation failed; continuing without findings: %s", exc)
    return []


# -----------------------------------------------------------------------------
# 1. Digest (stdout + envelope)
# -----------------------------------------------------------------------------
def build_recommendation_digest(envelope: Dict[str, Any]) -> Dict[str, Any]:
  """Extracts unified executive KPIs and prioritized P0-P3 actions from envelope.

  Each phased item has `skill`, `freshness`, `target` (display text),
  `principal` (full member or ""), `action` and `deliverable`.

  Args:
    envelope: A v2.0 or v2.1 assessment envelope.

  Returns:
    Dict with `executive_kpis`, `phased_action_plan`, `freshness_overview`.
  """
  modules = envelope.get("modules", {}) or {}

  audit_mod = modules.get("recommender_audit", {}) or {}
  arch_mod = modules.get("role_architect", {}) or {}
  sim_mod = modules.get("breakglass_simulator", {}) or {}
  comp_mod = modules.get("compliance_mapper", {}) or {}
  pam_mod = modules.get("jit_pam_architect", {}) or {}
  fed_mod = modules.get("federation_architect", {}) or {}
  gitops_mod = modules.get("gitops_pr_guardrail", {}) or {}
  deny_mod = modules.get("deny_policy_architect", {}) or {}
  org_mod = modules.get("org_hierarchy_auditor", {}) or {}
  rem_mod = modules.get("finding_remediator", {}) or {}

  audit_sum = audit_mod.get("summary", {}) or {}
  sim_sum = sim_mod.get("summary", {}) or {}
  comp_sum = comp_mod.get("summary", {}) or {}
  pam_sum = pam_mod.get("summary", {}) or {}
  fed_sum = fed_mod.get("summary", {}) or {}
  gitops_sum = gitops_mod.get("summary", {}) or {}
  deny_sum = deny_mod.get("summary", {}) or {}
  org_sum = org_mod.get("summary", {}) or {}
  rem_sum = rem_mod.get("summary", {}) or {}

  an = _audit_analysis(envelope)
  an_sum = an.get("summary", {}) or {}
  persona_count = audit_sum.get("persona_roles_count", an_sum.get("persona_roles_count"))
  if persona_count is None:
    persona_count = len(_persona_roles(an))
  capability_count = audit_sum.get(
      "capability_roles_count",
      an_sum.get("capability_roles_count", audit_sum.get("disjoint_roles_count")),
  )
  if capability_count is None:
    capability_count = len(_capability_roles(an))
  verification = an.get("model_b_verification") or {}
  # Personas synthesized without usage evidence (role engine fell back to
  # granted permissions) need a human review before cutover.
  no_usage = audit_sum.get("no_usage_data_personas", an_sum.get("no_usage_data_personas"))
  no_usage_count = (
      len(no_usage) if isinstance(no_usage, (list, tuple, dict)) else _int(no_usage)
  )
  no_usage_count = _int(
      ((audit_sum.get("executive_kpis") or {}).get("no_usage_data_persona_count")),
      no_usage_count,
  ) or no_usage_count

  sim_payload = sim_mod.get("payload", {}) or {}
  audit_log_confidence = (
      sim_sum.get("audit_log_confidence") or sim_payload.get("audit_log_confidence")
  )
  recommended_cutover = (
      sim_sum.get("recommended_cutover") or sim_payload.get("recommended_cutover")
  )
  f8_ai_findings = (an.get("findings") or {}).get("F8_ai_agent_blast_radius") or []
  wif_audit = (fed_mod.get("payload") or {}).get("existing_wif_audit") or {}
  wif_misconfigs = wif_audit.get("findings") or []

  kpis = {
      "project_id": envelope.get("project_id", ""),
      "run_id": envelope.get("run_id", ""),
      "trigger_mode": envelope.get("trigger_mode", ""),
      "total_principals": audit_sum.get("total_principals", 0),
      "permissions_before": audit_sum.get("permissions_before", 0),
      "permissions_after": audit_sum.get("permissions_after", 0),
      "permissions_reduction_pct": audit_sum.get("permissions_reduction_pct", 0.0),
      "persona_roles_count": persona_count,
      "capability_roles_count": capability_count,
      "disjoint_roles_count": audit_sum.get("disjoint_roles_count", capability_count or 0),
      "no_usage_data_persona_count": no_usage_count,
      "model_b_exact_cover": verification.get("exact_cover"),
      "model_b_pairwise_overlap": verification.get("pairwise_overlap"),
      "escalation_chains_count": audit_sum.get("escalation_chains_count", 0),
      "ai_agent_blast_radius_count": len(f8_ai_findings),
      "simulated_403_denials": sim_sum.get("simulated_403_denials"),
      "cutover_verdict": sim_sum.get("cutover_verdict", "NOT_EVALUATED"),
      "audit_log_confidence": audit_log_confidence,
      "recommended_cutover": recommended_cutover,
      "standing_privileged_humans_count": pam_sum.get(
          "standing_privileged_humans_count", 0
      ),
      "wif_migration_candidates": fed_sum.get("wif_migration_candidates", 0),
      "user_managed_keys_found": fed_sum.get("user_managed_keys_found", 0),
      "wif_misconfigurations_count": len(wif_misconfigs),
      "deny_rules_count": deny_sum.get("deny_rules_count", 0),
      "org_constraints_enforced": (
          f"{org_sum.get('constraints_enforced', 0)}/"
          f"{org_sum.get('constraints_evaluated', 0)}"
          if org_mod.get("status") == "COMPLETED"
          else "N/A"
      ),
      "gitops_pr_verdict": gitops_sum.get("pr_gate_verdict", "N/A"),
      "gitops_violations_count": gitops_sum.get("total_violations", 0),
      "compliance_score_before_pct": comp_sum.get("overall_score_before_pct"),
      "compliance_score_after_pct": comp_sum.get("overall_score_after_pct"),
      "inbound_findings_remediated": rem_sum.get("findings_ingested", 0),
  }

  phased: Dict[str, List[Dict[str, str]]] = {"P0": [], "P1": [], "P2": [], "P3": []}

  # Recommender audit: expired bindings (P0) and per-principal persona cutover.
  if _completed(audit_mod):
    f_tag = audit_mod.get("freshness", "CURRENT")
    findings = an.get("findings", {}) or {}
    personas = _persona_roles(an)

    for exp in findings.get("F5_expired_conditional_bindings", []) or []:
      phased["P0"].append({
          "skill": "gcp-iam-recommender-audit",
          "freshness": f_tag,
          "target": exp.get("principal", ""),
          "principal": exp.get("principal", ""),
          "action": (
              f"Remove expired conditional binding `{exp.get('role')}` "
              f"(title: `{exp.get('condition_title')}` — zero runtime impact)."
          ),
          "deliverable": "REMEDIATION_PLAN.md / rollback_runbook.sh",
      })

    for f8 in findings.get("F8_ai_agent_blast_radius", []) or []:
      f8_principal = f8.get("principal", "")
      f8_roles = ", ".join(f8.get("dangerous_roles") or f8.get("roles") or []) or str(f8.get("role") or "")
      phased["P1"].append({
          "skill": "gcp-iam-recommender-audit",
          "freshness": f_tag,
          "target": f8_principal,
          "principal": f8_principal,
          "action": (
              f"Contain AI agent blast radius (`F8`: {f8_roles or 'broad permissions'}): "
              "replace with a scoped persona custom role and attach D5 IAM v2 Deny Policy."
          ),
          "deliverable": "custom-roles/personas/ + deny-policies/deny_policies.tf (D5)",
      })

    for pm in an.get("principal_mappings", []) or []:
      phase_raw = str(pm.get("remediation_phase", ""))
      act = pm.get("recommended_action", "")
      if str(act).startswith("Retain Google-managed serviceAgent") or (
          "Managed Service Agent" in str(pm.get("target_mapping", ""))
      ):
        continue
      bucket_phase = "P2"
      if phase_raw.startswith("P0"):
        bucket_phase = "P0"
      elif "P1" in phase_raw:
        bucket_phase = "P1"
      elif "P3" in phase_raw:
        bucket_phase = "P3"

      persona_id = pm.get("persona_role_id", "")
      deliverable = "custom-roles/personas/ (Model A) · custom-roles/capabilities/ (Model B)"
      if persona_id and persona_id in personas:
        deliverable = _persona_yaml_path(persona_id, personas[persona_id])
      elif not persona_id and not an.get("model_b_bundles"):
        deliverable = "custom-roles/ & custom-roles/disjoint/"  # Legacy 2.0 layout.
      else:
        deliverable = (
            "custom-roles/personas/ & custom-roles/capabilities/ + custom-roles/bundles.yaml"
        )
      phased[bucket_phase].append({
          "skill": "gcp-iam-recommender-audit",
          "freshness": f_tag,
          "target": pm.get("principal", ""),
          "principal": pm.get("principal", ""),
          "action": act,
          "deliverable": deliverable,
      })

  # JIT PAM standing human privilege elimination -> P1
  if _completed(pam_mod):
    f_tag = pam_mod.get("freshness", "CURRENT")
    for ent in (pam_mod.get("payload", {}) or {}).get("entitlements", []) or []:
      phased["P1"].append({
          "skill": "gcp-iam-jit-pam-architect",
          "freshness": f_tag,
          "target": ent.get("eligible_requester", ""),
          "principal": ent.get("eligible_requester", ""),
          "action": (
              f"Convert standing `{', '.join(ent.get('standing_roles_removed', []) or [])}` "
              f"into JIT PAM entitlement `{ent.get('entitlement_id')}` "
              f"(max `{ent.get('max_request_duration')}`, approver "
              f"`{display_principal(ent.get('approver_principal'))}`)."
          ),
          "deliverable": "jit-pam/pam_entitlements.tf",
      })

  # WIF & SA keys -> P1
  if _completed(fed_mod):
    f_tag = fed_mod.get("freshness", "CURRENT")
    key_cnt = _int(fed_sum.get("user_managed_keys_found", 0))
    wif_cands = (fed_mod.get("payload", {}) or {}).get("wif_candidates", []) or []
    if key_cnt > 0:
      phased["P1"].append({
          "skill": "gcp-iam-federation-architect",
          "freshness": f_tag,
          "target": f"{key_cnt} customer-managed SA key(s)",
          "principal": "",
          "action": (
              "Disable user-managed JSON keys (reversible quarantine window) "
              "and migrate CI/CD callers to Workload Identity Federation."
          ),
          "deliverable": "federation-wif/retire_sa_keys.sh & wif_federation.tf",
      })
    elif wif_cands:
      names = ", ".join(short_principal(c.get("email", "")) for c in wif_cands[:4])
      phased["P1"].append({
          "skill": "gcp-iam-federation-architect",
          "freshness": f_tag,
          "target": f"{len(wif_cands)} automation SAs ({names})",
          "principal": "",
          "action": (
              "Bind keyless OIDC Workload Identity Pool & Provider with anti-spoofing "
              "CEL `attribute_condition` guards (0 static keys currently present)."
          ),
          "deliverable": "federation-wif/wif_federation.tf",
      })

    if wif_misconfigs:
      phased["P1"].append({
          "skill": "gcp-iam-federation-architect",
          "freshness": f_tag,
          "target": f"{len(wif_misconfigs)} existing WIF provider issue(s)",
          "principal": "",
          "action": (
              f"Remediate `{len(wif_misconfigs)}` existing Workload Identity Federation "
              "provider misconfiguration(s) (tighten CEL `attribute_condition` / issuer guards)."
          ),
          "deliverable": "federation-wif/WIF_MIGRATION.md",
      })

  # GitOps Terraform PR guardrail -> P1
  if _completed(gitops_mod):
    f_tag = gitops_mod.get("freshness", "CURRENT")
    v_cnt = _int(gitops_sum.get("total_violations", 0))
    if v_cnt > 0:
      phased["P1"].append({
          "skill": "gcp-iam-gitops-pr-guardrail",
          "freshness": f_tag,
          "target": ", ".join(
              (gitops_mod.get("payload", {}) or {}).get("scanned_files", ["Terraform HCL"])
              or ["Terraform HCL"]
          ),
          "principal": "",
          "action": (
              f"Remediate `{v_cnt}` Terraform IAM drift violation(s) "
              f"(`{gitops_sum.get('critical_count', 0)}` CRITICAL, "
              f"`{gitops_sum.get('high_count', 0)}` HIGH — verdict `{gitops_sum.get('pr_gate_verdict')}`) "
              "and enable the GitHub Actions PR gate."
          ),
          "deliverable": "gitops-guardrail/scopeguard-iam-guardrail.yml & scopeguard.sarif.json",
      })
  # A scan error (bad plan JSON, missing path) is NOT a clean result: surface it
  # explicitly so an unreadable plan can never be mistaken for APPROVE_CLEAN.
  gitops_payload = gitops_mod.get("payload", {}) or {}
  if gitops_mod and (
      str(gitops_mod.get("status", "")).upper() == "FAILED"
      or gitops_sum.get("pr_gate_verdict") == "SCAN_ERROR"
  ):
    phased["P1"].append({
        "skill": "gcp-iam-gitops-pr-guardrail",
        "freshness": gitops_mod.get("freshness", "CURRENT"),
        "target": "Terraform scan",
        "principal": "",
        "action": (
            "GitOps scan failed (verdict `SCAN_ERROR`): "
            f"{gitops_payload.get('error') or 'see gitops_guardrail_report.md'}. "
            "Fix the input (pass `terraform show -json` output to `--plan-json`) and re-run; "
            "treat the PR as NOT clean until then."
        ),
        "deliverable": "gitops-guardrail/gitops_guardrail_report.md",
    })

  # Inbound SCC / Wiz finding remediation -> P1
  if _completed(rem_mod):
    f_tag = rem_mod.get("freshness", "CURRENT")
    for rp in (rem_mod.get("payload", {}) or {}).get("remediation_plans", []) or []:
      status = str(rp.get("status") or "READY")
      # NO_CHANGE_NEEDED plans need no work; BLOCKED_* plans need input, not a patch.
      if status == "NO_CHANGE_NEEDED":
        continue
      sim_disp = _remediator_403_display(rp)
      if status.startswith("BLOCKED"):
        action = (
            f"Remediation blocked (`{status}`): {rp.get('status_reason') or 'missing evidence'}. "
            "Supply role evidence / a valid finding, then re-run the remediator."
        )
      else:
        action = (
            f"Apply Terraform fix replacing "
            f"{', '.join(rp.get('offending_roles', []) or []) or 'the offending role(s)'} with "
            f"`{rp.get('replacement_role') or 'n/a'}` (simulated 403s: {sim_disp})"
            + (" — HOLD until the simulated 403s are resolved" if status == "HOLD_SIMULATED_403" else "")
            + ", then verify and close the ticket."
        )
      ap_text = _format_attack_path(rp)
      item_dict: Dict[str, str] = {
          "skill": "gcp-iam-finding-remediator",
          "freshness": f_tag,
          "target": (
              f"[{rp.get('source_platform')}] {rp.get('finding_id')} "
              f"({display_principal(rp.get('principal'))})"
          ),
          "principal": rp.get("principal", ""),
          "action": action,
          "deliverable": "finding-remediation/remediation_patch.tf & ticket_proposed_remediation.md",
      }
      if ap_text:
        item_dict["attack_path_summary"] = ap_text
      phased["P1"].append(item_dict)

  # Breakglass simulator + role architect -> P2
  if _completed(sim_mod):
    f_tag = sim_mod.get("freshness", "CURRENT")
    phased["P2"].append({
        "skill": "gcp-iam-breakglass-simulator",
        "freshness": f_tag,
        "target": (
            f"{sim_sum.get('principals_simulated', 0)} principals "
            f"({sim_sum.get('total_replayed_operations', 0)} ops)"
        ),
        "principal": "",
        "action": (
            f"Gate the custom-role cutover on the replay verdict (`{sim_sum.get('cutover_verdict')}`: "
            f"`{sim_sum.get('simulated_403_denials', 0)}` simulated HTTP 403s across "
            f"{sim_sum.get('lookback_days', 90)}d Cloud Audit Log replay)."
        ),
        "deliverable": "simulator/verify_policy_troubleshooter.sh",
    })

  if _completed(arch_mod):
    f_tag = arch_mod.get("freshness", "CURRENT")
    prim = (arch_mod.get("payload", {}) or {}).get("primary_design", {}) or {}
    if prim:
      arch_sum = arch_mod.get("summary", {}) or {}
      phased["P2"].append({
          "skill": "gcp-iam-role-architect",
          "freshness": f_tag,
          "target": prim.get("title", "New Workload Blueprint"),
          "principal": "",
          "action": (
              f"Enforce resource-scoped role splitting (`{arch_sum.get('primary_scoped_roles_count', 0)}` "
              f"scoped roles, `{arch_sum.get('primary_total_permissions', 0)}` total headless permissions) "
              "on greenfield workloads to prevent role sprawl."
          ),
          "deliverable": "role-designs/*/main.tf",
      })

  # Deny policies, org hierarchy & compliance -> P3
  if _completed(deny_mod):
    f_tag = deny_mod.get("freshness", "CURRENT")
    phased["P3"].append({
        "skill": "gcp-iam-deny-policy-architect",
        "freshness": f_tag,
        "target": deny_sum.get("attachment_scope", f"projects/{envelope.get('project_id')}"),
        "principal": "",
        "action": (
            f"Attach IAM v2 Preventive Deny Policy (`{deny_sum.get('deny_rules_count', 0)}` rules "
            f"hard-blocking `{deny_sum.get('high_risk_permissions_guarded', 0)}` escalation/key-minting "
            "permissions) after an observe-first review of break-glass exceptions."
        ),
        "deliverable": "deny-policies/deny_policies.tf & deny_policy_v2.json",
    })

  if _completed(org_mod):
    f_tag = org_mod.get("freshness", "CURRENT")
    attn = _int(org_sum.get("constraints_needing_attention", 0))
    if attn > 0:
      action = (
          f"Enforce `{attn}` unconfigured IAM Organization Policy constraint(s) "
          "across project/folder hierarchy."
      )
    else:
      action = (
          f"Maintain all `{org_sum.get('constraints_enforced', 0)}/{org_sum.get('constraints_evaluated', 0)}` "
          "enforced IAM Organization Policy constraints under Terraform state lock."
      )
    phased["P3"].append({
        "skill": "gcp-iam-org-hierarchy-auditor",
        "freshness": f_tag,
        "target": org_sum.get("ancestry_path", ""),
        "principal": "",
        "action": action,
        "deliverable": "org-hierarchy/org_policies.tf",
    })

  if _completed(comp_mod):
    f_tag = comp_mod.get("freshness", "CURRENT")
    phased["P3"].append({
        "skill": "gcp-iam-compliance-mapper",
        "freshness": f_tag,
        "target": ", ".join(comp_sum.get("frameworks_covered", []) or []),
        "principal": "",
        "action": (
            f"Archive post-cutover auditor evidence raising control pass rate from "
            f"`{comp_sum.get('overall_score_before_pct', 0)}%` to "
            f"`{comp_sum.get('overall_score_after_pct', 100)}%` across "
            f"`{comp_sum.get('total_controls_evaluated', 0)}` controls."
        ),
        "deliverable": "compliance/compliance_evidence_report.md",
    })

  return {
      "executive_kpis": kpis,
      "phased_action_plan": phased,
      "freshness_overview": envelope.get("freshness_overview", {}),
  }


# -----------------------------------------------------------------------------
# 2. Consolidated reference report (scopeguard_recommendations_<pid>.md)
# -----------------------------------------------------------------------------
def _render_role_section(
    lines: List[str], an: Dict[str, Any], project_id: str
) -> None:
  """Appends section 4: Model A personas (default), Model B capabilities, verification."""
  personas = _persona_roles(an)
  capabilities = _capability_roles(an)
  bundles = _bundles(an)
  verification = an.get("model_b_verification") or {}

  lines.extend([
      "---",
      "",
      "## 4. Synthesized Least-Privilege Custom Roles",
      "",
      "> [!NOTE]",
      "> **Persona roles (Model A)** are the recommended default: one custom role per "
      "workload persona. **Capability roles (Model B)** are the alternative for teams "
      "that want reusable, non-overlapping building blocks combined into per-persona bundles.",
      "",
      f"### 4.1 Persona roles (Model A — recommended) · `{len(personas)}` role(s)",
      "",
  ])
  if personas:
    lines.extend([
        "| Persona role ID | Perms | Members | Evidence | Capability bundle (Model B) | YAML |",
        "| :--- | :---: | :--- | :--- | :--- | :--- |",
    ])
    for key, spec in personas.items():
      spec = spec or {}
      role_id = spec.get("role_id", key)
      members = _persona_members(key, spec, an)
      member_str = ", ".join(f"`{short_principal(m)}`" for m in members[:4]) or "—"
      if len(members) > 4:
        member_str += f" +{len(members) - 4}"
      bundle = bundles.get(key) or bundles.get(role_id) or []
      bundle_str = ", ".join(f"`{b}`" for b in bundle[:4]) or "—"
      if len(bundle) > 4:
        bundle_str += f" +{len(bundle) - 4}"
      evidence = spec.get("evidence_source", "—")
      lines.append(
          f"| **`{role_id}`** | `{len(spec.get('includedPermissions', []) or [])}` | "
          f"{member_str} | `{evidence}` | {bundle_str} | `{_persona_yaml_path(key, spec)}` |"
      )
    stripped_total = sum(
        len((s or {}).get("strippedUnsupportedPermissions", []) or [])
        for s in personas.values()
    )
    if stripped_total:
      lines.append("")
      lines.append(
          f"_`{stripped_total}` permission(s) not supported in custom roles were stripped "
          "automatically (see each YAML header)._"
      )
    first_key, first_spec = next(iter(personas.items()))
    lines.extend([
        "",
        "Provision a persona role (repeat per YAML):",
        "",
        "```bash",
        f"gcloud iam roles create {(first_spec or {}).get('role_id', first_key)} "
        f"--project={project_id} --file={_persona_yaml_path(first_key, first_spec or {})}",
        "```",
        "",
    ])
  else:
    lines.append("_No persona roles were synthesized in this run._\n")

  lines.extend([
      f"### 4.2 Capability roles (Model B) · `{len(capabilities)}` role(s)",
      "",
  ])
  if capabilities:
    lines.extend([
        "| Capability role ID | Perms | Used by personas | Sensitive | YAML |",
        "| :--- | :---: | :--- | :---: | :--- |",
    ])
    for key, spec in capabilities.items():
      spec = spec or {}
      used_by = _as_list(spec.get("used_by"))
      if not used_by:
        used_by = [p for p, caps in bundles.items() if key in caps]
      used_str = ", ".join(f"`{u}`" for u in used_by[:4]) or "—"
      if len(used_by) > 4:
        used_str += f" +{len(used_by) - 4}"
      sensitive = spec.get("sensitive")
      sens_str = "⚠️ yes" if sensitive else ("no" if sensitive is not None else "—")
      lines.append(
          f"| `{spec.get('role_id', key)}` | `{len(spec.get('includedPermissions', []) or [])}` | "
          f"{used_str} | {sens_str} | `{_capability_yaml_path(key, spec)}` |"
      )
    if an.get("model_b_bundles"):
      lines.append("")
      lines.append("Bundle definitions: `custom-roles/bundles.yaml`.")
    lines.append("")
  else:
    lines.append("_No capability roles were synthesized in this run._\n")

  lines.extend(["### 4.3 Model B verification", ""])
  if verification:
    exact = verification.get("exact_cover")
    overlap = _int(verification.get("pairwise_overlap"))
    over = _as_list(verification.get("over_grant"))
    under = _as_list(verification.get("under_grant"))
    lines.extend([
        "| Check | Result |",
        "| :--- | :--- |",
        f"| Exact cover (bundle = persona permissions) | {'✅ pass' if exact else '❌ fail'} |",
        f"| Pairwise overlap between capability roles | {'✅' if overlap == 0 else '❌'} `{overlap}` |",
        f"| Over-grant (bundle grants more than persona) | `{len(over) if isinstance(verification.get('over_grant'), (list, dict)) else verification.get('over_grant', 0)}` |",
        f"| Under-grant (bundle misses persona permissions) | `{len(under) if isinstance(verification.get('under_grant'), (list, dict)) else verification.get('under_grant', 0)}` |",
        f"| Capability count / max bundle size | `{verification.get('capability_count', len(capabilities))}` / `{verification.get('max_bundle_size', '—')}` |",
        "",
    ])
    for warn in _as_list(verification.get("warnings"))[:10]:
      lines.append(f"- ⚠️ {warn}")
    if verification.get("warnings"):
      lines.append("")
  else:
    gate = (an.get("verification_gates") or {}).get("gate_2_mathematical_disjointness") or {}
    if gate:
      lines.append(
          f"- Pairwise overlap (legacy gate 2): `{gate.get('pairwise_overlap_count', 'n/a')}` "
          f"across `{gate.get('disjoint_role_count', len(capabilities))}` roles "
          f"({'✅ passed' if gate.get('passed') else '❌ failed'})."
      )
      lines.append("")
    else:
      lines.append("_No Model B verification data in this envelope._\n")


def synthesize_master_markdown(
    envelope: Dict[str, Any], digest: Dict[str, Any]
) -> str:
  """Renders the consolidated multi-skill Markdown recommendations report.

  Args:
    envelope: Assessment envelope (v2.0 or v2.1).
    digest: Output of `build_recommendation_digest`.

  Returns:
    Markdown text for `scopeguard_recommendations_<pid>.md`.
  """
  project_id = envelope.get("project_id", "unknown-project")
  run_id = envelope.get("run_id", "latest")
  ts_utc = envelope.get("timestamp_utc", "")
  trigger_mode = envelope.get("trigger_mode", "full-suite")
  etag = envelope.get("live_policy_etag", "")
  gcs_meta = envelope.get("gcs_metadata", {}) or {}
  freshness_ov = envelope.get("freshness_overview", {}) or {}
  modules = envelope.get("modules", {}) or {}
  kpis = digest["executive_kpis"]
  phased = digest["phased_action_plan"]
  principals_seen: Dict[str, None] = {}

  lines: List[str] = [
      f"# ScopeGuard IAM Recommendations: `{project_id}`",
      "",
      f"- **Run ID / Timestamp**: `{run_id}` (`{ts_utc}`)",
      f"- **Schema version**: `{envelope.get('schema_version', '2.0')}`",
      f"- **Execution Mode**: `{trigger_mode}` (`{len(freshness_ov.get('current_modules', []) or [])}` module(s) executed in this run)",
      f"- **Live Project IAM `etag`**: `{etag or 'N/A'}`",
      f"- **GCS Versioned Run Artifact**: `gs://{gcs_meta.get('bucket', 'local')}/{gcs_meta.get('object_path', '')}`",
      "- **Companion documents**: `EXECUTIVE_SUMMARY.md` (leadership) · "
      "`REMEDIATION_PLAN.md` (DevOps, change batches) · `EVIDENCE.md` (auditors) · "
      "`README.md` / `manifest.json` (file index with SHA-256)",
      "",
      "> [!IMPORTANT]",
      "> **Human-in-the-Loop Safety Gate**: ScopeGuard is read-only. Generated scripts "
      "default to dry-run. Review the replay verdict and keep `rollback_runbook.sh` "
      "staged before applying any `P0`–`P3` change.",
      "",
  ]

  if freshness_ov.get("has_stale_carried_forward_data"):
    stale_list = ", ".join(
        f"`{m}`" for m in freshness_ov.get("potentially_stale_modules", []) or []
    )
    curr_list = ", ".join(
        f"`{m}`" for m in freshness_ov.get("current_modules", []) or []
    ) or "_none_"
    lines.extend([
        "> [!WARNING]",
        f"> **Partial Run Notice**: Only {curr_list} executed in this run. Sibling "
        f"modules ({stale_list}) were carried forward from the prior snapshot and are "
        "marked **Carried Forward (Probably Stale)**. Run `scopeguard-orchestrator` "
        "(`--stages=all`) to refresh all modules.",
        "",
    ])

  # 1. Executive scorecard -----------------------------------------------------
  lines.extend([
      "---",
      "",
      "## 1. Executive Posture & Multi-Skill Governance Scorecard",
      "",
      "| Governance Dimension | Skill Module | Freshness | Key Finding / Baseline | Target Outcome |",
      "| :--- | :--- | :--- | :--- | :--- |",
  ])

  def _skill(m: Dict[str, Any]) -> str:
    return m.get("skill_name", m.get("module_key", ""))

  if _completed(modules.get("recommender_audit")):
    m = modules["recommender_audit"]
    lines.append(
        f"| **Brownfield Posture & Custom Roles** | `{_skill(m)}` | `{_freshness_tag(m)}` | "
        f"`{kpis['total_principals']}` principals holding `{_int(kpis['permissions_before']):,}` "
        f"permissions (`{kpis['escalation_chains_count']}` escalation paths) | "
        f"Compress to `{_int(kpis['permissions_after']):,}` permissions "
        f"(**`-{kpis['permissions_reduction_pct']}%`**) via `{kpis.get('persona_roles_count', 0)}` "
        f"persona roles (or `{kpis.get('capability_roles_count', 0)}` capability roles) |"
    )
  if _completed(modules.get("breakglass_simulator")):
    m = modules["breakglass_simulator"]
    s = m.get("summary", {}) or {}
    conf, cutover = _sim_confidence_and_cutover(envelope, digest)
    conf_note = (
        f" · confidence `{conf}` / `{cutover or 'n/a'}`"
        if conf or cutover
        else ""
    )
    lines.append(
        f"| **90-Day Audit Log Shadow Replay** | `{_skill(m)}` | `{_freshness_tag(m)}` | "
        f"`{s.get('total_replayed_operations', 0)}` historical API operations replayed across "
        f"`{s.get('principals_simulated', 0)}` principals | "
        f"**`{s.get('simulated_403_denials', 0)}` simulated HTTP 403s** (`{s.get('cutover_verdict')}`){conf_note} |"
    )
  if _completed(modules.get("jit_pam_architect")):
    m = modules["jit_pam_architect"]
    s = m.get("summary", {}) or {}
    lines.append(
        f"| **Zero-Standing Human Privilege (PAM)** | `{_skill(m)}` | `{_freshness_tag(m)}` | "
        f"`{s.get('standing_privileged_humans_count', 0)}` human admin(s) holding "
        f"`{s.get('standing_bindings_to_convert', 0)}` standing bindings | "
        f"Convert to `{s.get('pam_entitlements_designed', 0)}` time-bound PAM entitlements |"
    )
  if _completed(modules.get("federation_architect")):
    m = modules["federation_architect"]
    s = m.get("summary", {}) or {}
    lines.append(
        f"| **SA Key Hygiene & Keyless WIF** | `{_skill(m)}` | `{_freshness_tag(m)}` | "
        f"`{s.get('service_accounts_scanned', 0)}` SAs scanned, `{s.get('user_managed_keys_found', 0)}` "
        f"static `USER_MANAGED` keys | Onboard `{s.get('wif_migration_candidates', 0)}` automation SAs to WIF |"
    )
  if _completed(modules.get("role_architect")):
    m = modules["role_architect"]
    s = m.get("summary", {}) or {}
    lines.append(
        f"| **Shift-Left Scoped Role Architect** | `{_skill(m)}` | `{_freshness_tag(m)}` | "
        f"`{s.get('designs_count', 0)}` reference blueprints (`{s.get('escalation_warnings_count', 0)}` "
        f"escalation warnings) | Resource-scoped role splitting (`{s.get('primary_total_permissions', 0)}` perms) |"
    )
  if _completed(modules.get("gitops_pr_guardrail")):
    m = modules["gitops_pr_guardrail"]
    s = m.get("summary", {}) or {}
    lines.append(
        f"| **GitOps Terraform PR Gate** | `{_skill(m)}` | `{_freshness_tag(m)}` | "
        f"`{s.get('total_violations', 0)}` IaC violations (`{s.get('critical_count', 0)}` CRITICAL, "
        f"`{s.get('high_count', 0)}` HIGH) | Enforce CI gate (`{s.get('pr_gate_verdict')}`) via GitHub Action + SARIF |"
    )
  if _completed(modules.get("deny_policy_architect")):
    m = modules["deny_policy_architect"]
    s = m.get("summary", {}) or {}
    lines.append(
        f"| **IAM v2 Preventive Deny Guardrails** | `{_skill(m)}` | `{_freshness_tag(m)}` | "
        f"`{s.get('high_risk_permissions_guarded', 0)}` high-risk permissions exposed | "
        f"Attach `{s.get('deny_rules_count', 0)}` deny rules at `{s.get('attachment_scope')}` |"
    )
  if _completed(modules.get("org_hierarchy_auditor")):
    m = modules["org_hierarchy_auditor"]
    s = m.get("summary", {}) or {}
    lines.append(
        f"| **Org Ancestry & Policy Baseline** | `{_skill(m)}` | `{_freshness_tag(m)}` | "
        f"Ancestry `{s.get('ancestry_path')}` | "
        f"`{s.get('constraints_enforced', 0)}/{s.get('constraints_evaluated', 0)}` IAM org policies enforced |"
    )
  if _completed(modules.get("compliance_mapper")):
    m = modules["compliance_mapper"]
    s = m.get("summary", {}) or {}
    lines.append(
        f"| **Regulatory Compliance Matrix** | `{_skill(m)}` | `{_freshness_tag(m)}` | "
        f"Baseline **`{s.get('overall_score_before_pct', 0)}%`** "
        f"(`{s.get('controls_passing_before', 0)}/{s.get('total_controls_evaluated', 0)}` controls) | "
        f"Post-remediation **`{s.get('overall_score_after_pct', 100)}%`** |"
    )
  if _completed(modules.get("finding_remediator")):
    m = modules["finding_remediator"]
    s = m.get("summary", {}) or {}
    srcs = ", ".join(s.get("sources_integrated", []) or []) or "SCC / Wiz"
    lines.append(
        f"| **Inbound SCC & Wiz Finding Fixes** | `{_skill(m)}` | `{_freshness_tag(m)}` | "
        f"`{s.get('findings_ingested', 0)}` inbound alert(s) from {srcs} | "
        "Replay-verified Terraform fixes + verification notes |"
    )

  # 2. Phased plan (summary; details in REMEDIATION_PLAN.md) ------------------
  lines.extend([
      "",
      "---",
      "",
      "## 2. Unified Prioritized Remediation Plan (`P0` → `P3`)",
      "",
      "_Step-by-step change batches with pre-checks, verification and rollback are in "
      "`REMEDIATION_PLAN.md`._",
      "",
  ])
  for p_key in ("P0", "P1", "P2", "P3"):
    items = phased.get(p_key, []) or []
    lines.append(f"### {PHASE_TITLES[p_key]}")
    if not items:
      lines.append("_No open actions in this phase._\n")
      continue
    lines.append("")
    lines.append("| Target | Source Skill | Recommended Action | Deliverable |")
    lines.append("| :--- | :--- | :--- | :--- |")
    for it in items:
      stale_suffix = " *(carried forward)*" if it.get("freshness") != "CURRENT" else ""
      if it.get("principal"):
        principals_seen[it["principal"]] = None
      lines.append(
          f"| `{_md_cell(display_principal(it.get('target')))}` | `{it.get('skill')}`{stale_suffix} | "
          f"{_md_cell(it.get('action'))} | `{_md_cell(it.get('deliverable'))}` |"
      )
    lines.append("")

  # 3/4. Principal matrix and roles -------------------------------------------
  audit_mod = modules.get("recommender_audit", {}) or {}
  if _completed(audit_mod):
    an = _audit_analysis(envelope)
    pms = an.get("principal_mappings", []) or []
    lines.extend([
        "---",
        "",
        f"## 3. Principal-by-Principal Remediation Matrix (`{len(pms)}` Principals)",
        "",
        "| Principal | Category | Current Roles | Phase | Target Role | Action |",
        "| :--- | :--- | :--- | :---: | :--- | :--- |",
    ])
    for pm in pms:
      member = pm.get("principal", "")
      principals_seen[member] = None
      curr = _as_list(pm.get("current_roles"))
      curr_roles = ", ".join(f"`{r}`" for r in curr[:3])
      if len(curr) > 3:
        curr_roles += f" +{len(curr) - 3}"
      target = pm.get("persona_role_id") or pm.get("target_mapping", "")
      lines.append(
          f"| `{short_principal(member)}` | {_md_cell(pm.get('category'))} | {curr_roles} | "
          f"**`{pm.get('remediation_phase')}`** | `{_md_cell(target)}` | "
          f"{_md_cell(pm.get('recommended_action'))} |"
      )
    lines.append("")
    _render_role_section(lines, an, project_id)

  # 5. Breakglass replay -------------------------------------------------------
  if _completed(modules.get("breakglass_simulator")):
    sim_p = modules["breakglass_simulator"].get("payload", {}) or {}
    replays = sim_p.get("principal_replays", []) or []
    active_replays = [r for r in replays if _int(r.get("replayed_api_calls", 0)) > 0]
    lines.extend([
        "---",
        "",
        f"## 5. Pre-Cutover 90-Day Cloud Audit Log Replay (`{sim_p.get('cutover_verdict')}`)",
        "",
        "| Principal | Replayed Ops | Distinct Perms | Proposed Role Perms | Simulated 403s | Coverage | Verdict |",
        "| :--- | :---: | :---: | :---: | :---: | :---: | :--- |",
    ])
    for r in (active_replays or replays[:8]):
      obs = r.get("observed_distinct_permissions", 0)
      obs_cnt = len(obs) if isinstance(obs, list) else _int(obs)
      principals_seen[r.get("principal", "")] = None
      lines.append(
          f"| `{short_principal(r.get('principal', ''))}` | `{r.get('replayed_api_calls', 0)}` | "
          f"`{obs_cnt}` | `{r.get('proposed_role_permissions', 0)}` | "
          f"**`{r.get('simulated_403_denials', 0)}`** | `{r.get('replay_coverage_pct', 100.0)}%` | `{r.get('verdict')}` |"
      )
    lines.append("")

  # 6. PAM & WIF ---------------------------------------------------------------
  if _completed(modules.get("jit_pam_architect")) or _completed(modules.get("federation_architect")):
    lines.extend([
        "---",
        "",
        "## 6. Zero-Standing Human Privilege (PAM) & Keyless Workload Federation (WIF)",
        "",
    ])
    if _completed(modules.get("jit_pam_architect")):
      ents = (modules["jit_pam_architect"].get("payload", {}) or {}).get("entitlements", []) or []
      lines.extend([
          "### 6.1 PAM Entitlements (`jit-pam/pam_entitlements.tf`)",
          "",
          "| Entitlement ID | Requester | Standing Roles Removed | JIT Role(s) | Max Duration | Approver |",
          "| :--- | :--- | :--- | :--- | :---: | :--- |",
      ])
      for e in ents:
        req, appr = e.get("eligible_requester", ""), e.get("approver_principal", "")
        principals_seen[req] = None
        self_approval = " ⚠️ self-approval" if req and req == appr else ""
        rem = ", ".join(f"`{r}`" for r in e.get("standing_roles_removed", []) or [])
        grt = ", ".join(f"`{r}`" for r in e.get("jit_granted_roles", []) or [])
        lines.append(
            f"| `{e.get('entitlement_id')}` | `{short_principal(req)}` | {rem} | {grt} | "
            f"`{e.get('max_request_duration')}` | `{display_principal(appr)}`{self_approval} |"
        )
      lines.append("")

    if _completed(modules.get("federation_architect")):
      cands = (modules["federation_architect"].get("payload", {}) or {}).get("wif_candidates", []) or []
      lines.extend([
          "### 6.2 Workload Identity Federation & Key Retirement (`federation-wif/wif_federation.tf`)",
          "",
          "| Service Account | Display Name | `USER_MANAGED` Keys | Posture | Recommended Provider |",
          "| :--- | :--- | :---: | :--- | :--- |",
      ])
      for c in cands:
        email = c.get("email", "")
        principals_seen[f"serviceAccount:{email}" if email else ""] = None
        lines.append(
            f"| `{short_principal(email)}` | {_md_cell(c.get('display_name'))} | "
            f"`{c.get('user_managed_key_count', 0)}` | `{c.get('posture_status')}` | "
            f"{_md_cell(c.get('recommended_federation'))} |"
        )
      lines.append("")
      wif_findings = (
          ((modules["federation_architect"].get("payload") or {}).get("existing_wif_audit") or {})
          .get("findings") or []
      )
      if wif_findings:
        lines.extend([
            "#### Existing WIF Provider Audit Findings (`federation-wif/WIF_MIGRATION.md`)",
            "",
            "| Provider / Pool | Severity | Issue | Remediation |",
            "| :--- | :---: | :--- | :--- |",
        ])
        for wf in wif_findings:
          if not isinstance(wf, dict):
            continue
          prov = wf.get("provider") or wf.get("provider_name") or wf.get("pool") or "—"
          issue = wf.get("title") or wf.get("rule_id") or wf.get("message") or "—"
          rem = wf.get("remediation") or wf.get("recommended_action") or "Tighten CEL attribute_condition."
          lines.append(
              f"| `{_md_cell(prov)}` | **`{_md_cell(wf.get('severity', 'HIGH'))}`** | "
              f"{_md_cell(issue)} | {_md_cell(rem)} |"
          )
        lines.append("")

  # 7. Preventive guardrails ---------------------------------------------------
  lines.extend(["---", "", "## 7. Preventive Guardrails & Shift-Left Enforcement", ""])
  if _completed(modules.get("deny_policy_architect")):
    rules = (modules["deny_policy_architect"].get("payload", {}) or {}).get("rules", []) or []
    lines.extend([
        "### 7.1 IAM v2 Deny Policy Rules (`deny-policies/deny_policies.tf`)",
        "",
        "| Rule ID | Objective | Denied Permissions | Break-glass Exceptions | Condition |",
        "| :--- | :--- | :--- | :--- | :--- |",
    ])
    for r in rules:
      dp = _as_list(r.get("denied_permissions"))
      dp_str = ", ".join(f"`{p}`" for p in dp[:3]) + (f" +{len(dp) - 3}" if len(dp) > 3 else "")
      ex = ", ".join(f"`{display_principal(p)}`" for p in _as_list(r.get("exception_principals")))
      cond = (r.get("denial_condition") or {}).get("expression", "Unconditional")
      lines.append(
          f"| **`{r.get('rule_id')}`** | {_md_cell(r.get('description'))} | {dp_str} | "
          f"{ex or '⚠️ none'} | `{_md_cell(cond)}` |"
      )
    lines.append("")

  if _completed(modules.get("org_hierarchy_auditor")):
    constraints = (
        (modules["org_hierarchy_auditor"].get("payload", {}) or {}).get("org_policy_constraints", [])
        or []
    )
    lines.extend([
        "### 7.2 Organization Policy Baseline (`org-hierarchy/org_policies.tf`)",
        "",
        "| Constraint | Title | Live Status | Rationale |",
        "| :--- | :--- | :---: | :--- |",
    ])
    for c in constraints:
      lines.append(
          f"| `{c.get('constraint')}` | {_md_cell(c.get('title'))} | **`{c.get('status')}`** | "
          f"{_md_cell(c.get('rationale'))} |"
      )
    lines.append("")

  if _completed(modules.get("gitops_pr_guardrail")):
    viols = (modules["gitops_pr_guardrail"].get("payload", {}) or {}).get("violations", []) or []
    lines.extend([
        "### 7.3 GitOps Terraform PR Violations (`gitops-guardrail/`, `scopeguard.sarif.json`)",
        "",
        "| Rule | Severity | File : Line | Role / Principal | Remediation |",
        "| :--- | :---: | :--- | :--- | :--- |",
    ])
    for v in viols:
      lines.append(
          f"| `{v.get('rule_id')}` | **`{v.get('severity')}`** | `{v.get('file')}:{v.get('line')}` | "
          f"`{v.get('role')}` on `{_md_cell(display_principal(v.get('principal')))}` | "
          f"{_md_cell(v.get('remediation'))} |"
      )
    lines.append("")
    # Coverage warnings (unparsed resources, unresolved references) explain what
    # the scan could NOT see, so reviewers do not over-trust a short list.
    cov = (modules["gitops_pr_guardrail"].get("payload", {}) or {}).get("coverage") or {}
    cov_warnings = _as_list(cov.get("warnings"))
    if cov_warnings:
      lines.append("> [!WARNING]")
      lines.append("> Scan coverage gaps:")
      for w in cov_warnings[:20]:
        lines.append(f"> - {_md_cell(w)}")
      lines.append("")

  if _completed(modules.get("finding_remediator")):
    plans = (modules["finding_remediator"].get("payload", {}) or {}).get("remediation_plans", []) or []
    if plans:
      lines.extend([
          "### 7.4 Inbound SCC & Wiz Finding Fixes (`finding-remediation/remediation_patch.tf`)",
          "",
          "| Source | Finding ID | Severity | Principal | Replacement Role | Simulated 403s | Status |",
          "| :--- | :--- | :---: | :--- | :--- | :---: | :--- |",
      ])
      for rp in plans:
        principals_seen[rp.get("principal", "")] = None
        lines.append(
            f"| **{rp.get('source_platform')}** | `{rp.get('finding_id')}` | **`{rp.get('severity')}`** | "
            f"`{short_principal(rp.get('principal', ''))}` | `{rp.get('replacement_role') or 'n/a'}` "
            f"(`{rp.get('replacement_permissions_count', 0)}` perms) | {_md_cell(_remediator_403_display(rp))} | "
            f"`{rp.get('status', 'READY')}` |"
        )
      readiness = ((modules["finding_remediator"].get("summary") or {}).get("remediation_readiness"))
      if readiness:
        lines.append("")
        lines.append(f"Remediator readiness: **`{readiness}`**.")
      ap_lines = []
      for rp in plans:
        ap = _format_attack_path(rp)
        if ap:
          ap_lines.append(f"- `{rp.get('finding_id', 'finding')}` (`{short_principal(rp.get('principal', ''))}`): {ap}")
      if ap_lines:
        lines.extend(["", "**Attack-path choke points:**"] + ap_lines)
      lines.append("")

  # 8. Compliance --------------------------------------------------------------
  if _completed(modules.get("compliance_mapper")):
    fws = (modules["compliance_mapper"].get("payload", {}) or {}).get("framework_scorecards", []) or []
    lines.extend([
        "---",
        "",
        "## 8. Regulatory Compliance Scorecard (`compliance/compliance_evidence_report.md`)",
        "",
        "| Framework | Controls | Baseline Passing | Post-Remediation Passing | Delta |",
        "| :--- | :---: | :---: | :---: | :---: |",
    ])
    for fw in fws:
      try:
        delta = round(float(fw.get("score_after_pct", 100)) - float(fw.get("score_before_pct", 0)), 1)
      except (TypeError, ValueError):
        delta = 0.0
      lines.append(
          f"| **{fw.get('framework')}** | `{fw.get('controls_total')}` | "
          f"`{fw.get('controls_passing_before')}/{fw.get('controls_total')}` (`{fw.get('score_before_pct')}%`) | "
          f"**`{fw.get('controls_passing_after')}/{fw.get('controls_total')}` (`{fw.get('score_after_pct')}%`)** | "
          f"**`+{delta}%`** |"
      )
    lines.append("")

  # 9. Rollback ----------------------------------------------------------------
  lines.extend([
      "---",
      "",
      "## 9. Deterministic Rollback Safety Net",
      "",
      "- **Per-principal restore (condition-aware)**: `./rollback_runbook.sh` "
      "(dry-run by default; restores every original binding including IAM conditions).",
      "- **Full project restore (etag-pinned)**:",
      "  ```bash",
      f"  gcloud projects set-iam-policy {project_id} iam_policy_backup_{project_id}.json",
      "  ```",
      "",
  ])
  lines.extend(_principal_appendix(principals_seen.keys(), "Appendix A — Principal reference"))
  return "\n".join(lines)


def _principal_appendix(members: Iterable[str], heading: str) -> List[str]:
  """Renders a short-name -> full-identity table so body tables stay compact."""
  uniq = sorted({m for m in members if m and is_member(m)}, key=short_principal)
  if not uniq:
    return []
  out = ["---", "", f"## {heading}", "", "| Short name | Full identity |", "| :--- | :--- |"]
  for m in uniq:
    out.append(f"| `{short_principal(m)}` | `{m}` |")
  out.append("")
  return out


# -----------------------------------------------------------------------------
# 3. Change batches (REMEDIATION_PLAN.md + bundles)
# -----------------------------------------------------------------------------
def build_change_batches(
    envelope: Dict[str, Any],
    digest: Optional[Dict[str, Any]] = None,
    findings: Optional[Sequence[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
  """Groups digest actions into ordered change batches (phase x mechanism).

  Each item explains what to change, why (linked findings), risk, files to
  apply and rollback, so a DevOps engineer can execute one batch at a time.

  Args:
    envelope: Assessment envelope.
    digest: Optional pre-computed digest (computed when omitted).
    findings: Optional pre-computed unified findings.

  Returns:
    Ordered list of batch dicts:
    `{batch_id, phase, skill, title, sla, pre_checks, verification, items}`.
  """
  digest = digest or build_recommendation_digest(envelope)
  findings = list(findings) if findings is not None else _findings_safe(envelope)
  project_id = envelope.get("project_id", "")
  an = _audit_analysis(envelope)
  mappings = _mappings_by_principal(an)
  personas = _persona_roles(an)
  bundles = _bundles(an)

  by_principal: Dict[str, List[Dict[str, Any]]] = {}
  for f in findings:
    if f.get("principal"):
      by_principal.setdefault(f["principal"], []).append(f)

  batches: List[Dict[str, Any]] = []
  phased = digest.get("phased_action_plan", {}) or {}
  for phase in ("P0", "P1", "P2", "P3"):
    groups: Dict[str, List[Dict[str, Any]]] = {}
    for it in phased.get(phase, []) or []:
      groups.setdefault(it.get("skill", "other"), []).append(it)
    for b_idx, (skill, items) in enumerate(groups.items(), start=1):
      meta = _SKILL_META.get(skill, {})
      batch_id = f"{phase}-{b_idx}"
      batch_items: List[Dict[str, Any]] = []
      for i_idx, it in enumerate(items, start=1):
        principal = it.get("principal") or ""
        pm = mappings.get(principal, {}) if principal else {}
        p_findings = by_principal.get(principal, []) if principal else []
        why = "; ".join(
            f"{f.get('severity')}: {f.get('title')}"
            for f in sorted(p_findings, key=lambda x: -SEVERITY_RANK.get(x.get("severity"), 0))[:3]
        ) or "Reduces standing privilege / closes a governance gap identified in this run."

        files = [str(it.get("deliverable", ""))] if it.get("deliverable") else []
        risk = meta.get("risk", "Review before applying.")
        rollback = meta.get("rollback", "Restore from the etag-pinned policy backup.")
        if skill == "gcp-iam-recommender-audit":
          persona_id = pm.get("persona_role_id", "")
          files = []
          if persona_id and persona_id in personas:
            files.append(_persona_yaml_path(persona_id, personas[persona_id]))
            caps = bundles.get(persona_id) or []
            if caps:
              files.append(f"alt. Model B bundle: {', '.join(caps[:4])}")
          elif it.get("deliverable"):
            files.append(str(it["deliverable"]))
          files.append("rollback_runbook.sh")
          if "expired" in str(it.get("action", "")).lower():
            risk = "None — the binding's condition has already expired."
          before = _as_list(pm.get("bindings_before"))
          if before:
            roles = ", ".join(str(b.get("role", "")) for b in before if isinstance(b, dict))
            rollback = (
                f"`./rollback_runbook.sh` restores {len(before)} original binding(s) "
                f"({roles}) for `{short_principal(principal)}`, including conditions."
            )
        batch_items.append({
            "id": f"{batch_id}.{i_idx}",
            "phase": phase,
            "skill": skill,
            "principal": principal,
            "target_display": display_principal(it.get("target", "")),
            "what": str(it.get("action", "")),
            "why": why,
            "risk": risk,
            "files": files,
            "rollback": rollback,
            "rollback_commands": _as_list(pm.get("rollback_commands"))[:6],
            "freshness": it.get("freshness", "CURRENT"),
            "finding_ids": [f.get("id") for f in p_findings],
            "attack_path_summary": it.get("attack_path_summary", ""),
        })
      batches.append({
          "batch_id": batch_id,
          "phase": phase,
          "skill": skill,
          "title": f"{meta.get('batch', skill)}",
          "sla": PHASE_SLA[phase],
          "pre_checks": list(meta.get("pre_checks", [])) + (
              [f"Policy backup present: `iam_policy_backup_{project_id}.json`."]
              if skill == "gcp-iam-recommender-audit" else []
          ),
          "verification": list(meta.get("verification", [])),
          "items": batch_items,
      })
  return batches


def synthesize_remediation_plan(
    envelope: Dict[str, Any],
    digest: Optional[Dict[str, Any]] = None,
    findings: Optional[Sequence[Dict[str, Any]]] = None,
    include: Optional[Callable[[Dict[str, Any]], bool]] = None,
    subtitle: str = "",
) -> str:
  """Renders `REMEDIATION_PLAN.md` grouped by change batch / phase P0-P3.

  Args:
    envelope: Assessment envelope.
    digest: Optional pre-computed digest.
    findings: Optional pre-computed unified findings.
    include: Optional predicate over plan items (used for per-owner bundles).
    subtitle: Optional extra heading text (e.g. bundle key).

  Returns:
    Markdown text.
  """
  project_id = envelope.get("project_id", "unknown-project")
  digest = digest or build_recommendation_digest(envelope)
  batches = build_change_batches(envelope, digest, findings)
  principals: Dict[str, None] = {}
  sim_conf, sim_cutover = _sim_confidence_and_cutover(envelope, digest)
  title = f"# Remediation Plan: `{project_id}`" + (f" — {subtitle}" if subtitle else "")
  lines = [
      title,
      "",
      f"- **Run ID**: `{envelope.get('run_id', '')}` (`{envelope.get('timestamp_utc', '')}`)",
      f"- **Assessment etag**: `{envelope.get('live_policy_etag', '') or 'N/A'}`",
      "- **Audience**: DevOps / platform engineers applying changes.",
  ]
  if sim_conf or sim_cutover:
    lines.append(
        f"- **Audit log confidence / Recommended cutover**: "
        f"`{sim_conf or 'n/a'}` · `{sim_cutover or 'n/a'}`"
    )
  lines.extend([
      "",
      "> [!IMPORTANT]",
      "> Apply one batch at a time, in order. Scripts are dry-run by default; "
      "keep `rollback_runbook.sh` and the policy backup ready. Files marked ⚠️ in "
      "`README.md` change IAM when executed.",
      "",
  ])
  if sim_conf in ("LOW", "MEDIUM"):
    lines.extend([
        "> [!WARNING]",
        f"> **Audit Log Confidence is `{sim_conf}`** (recommended cutover: "
        f"`{sim_cutover or 'CANARY_DUAL_BIND'}`). Re-run remediation with `--canary` "
        "to emit dual-bind canary cutover scripts (bind the new least-privilege role "
        "alongside the legacy role and observe before removing legacy access).",
        "",
    ])
  total = 0
  for batch in batches:
    items = [it for it in batch["items"] if include is None or include(it)]
    if not items:
      continue
    total += len(items)
    lines.extend([
        "---",
        "",
        f"## Batch {batch['batch_id']} · {batch['title']} (SLA: {batch['sla']})",
        "",
    ])
    if batch["pre_checks"]:
      lines.append("**Pre-checks**")
      lines.extend(f"- [ ] {c}" for c in batch["pre_checks"])
      lines.append("")
    for it in items:
      if it["principal"]:
        principals[it["principal"]] = None
      stale = " _(carried forward — re-run to refresh)_" if it["freshness"] != "CURRENT" else ""
      lines.extend([
          f"### {it['id']} · `{_md_cell(it['target_display'])}`{stale}",
          "",
          f"- **What:** {it['what']}",
          f"- **Why:** {it['why']}",
          f"- **Risk:** {it['risk']}",
          f"- **Files to apply:** {', '.join(f'`{f}`' for f in it['files']) or '—'}",
          f"- **Rollback:** {it['rollback']}",
      ])
      if it["finding_ids"]:
        lines.append(f"- **Findings:** {', '.join(f'`{x}`' for x in it['finding_ids'][:6])}")
      if it.get("attack_path_summary"):
        lines.append(f"- **Attack path / choke point:** {it['attack_path_summary']}")
      if it["rollback_commands"]:
        lines.extend(["", "  <details><summary>Manual rollback commands</summary>", "", "  ```bash"])
        lines.extend(f"  {cmd}" for cmd in it["rollback_commands"])
        lines.extend(["  ```", "", "  </details>"])
      lines.append("")
    if batch["verification"]:
      lines.append("**Verification**")
      lines.extend(f"- [ ] {v}" for v in batch["verification"])
      lines.append("")
  if total == 0:
    lines.append("_No remediation actions apply to this scope._")
    lines.append("")
  lines.extend(_principal_appendix(principals.keys(), "Appendix — Principal reference"))
  return "\n".join(lines)


# -----------------------------------------------------------------------------
# 4. Executive summary (EXECUTIVE_SUMMARY.md)
# -----------------------------------------------------------------------------
_SEVERITY_WEIGHT = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1}


def risk_score(findings: Sequence[Dict[str, Any]]) -> int:
  """Weighted open-findings score clipped to 0..100 (higher = riskier)."""
  return min(100, sum(_SEVERITY_WEIGHT.get(f.get("severity"), 0) for f in findings))


def _decision_asks(
    envelope: Dict[str, Any], digest: Dict[str, Any], findings: Sequence[Dict[str, Any]]
) -> List[str]:
  """Builds the 'what we need from you' list for leadership."""
  modules = envelope.get("modules", {}) or {}
  kpis = digest.get("executive_kpis", {}) or {}
  an = _audit_analysis(envelope)
  asks: List[str] = []

  if kpis.get("persona_roles_count"):
    asks.append(
        f"Approve creation of `{kpis['persona_roles_count']}` persona custom roles "
        "(Model A, recommended) — or choose capability bundles (Model B)."
    )
  pam_mod = modules.get("jit_pam_architect") or {}
  pam_sum = pam_mod.get("summary") or {}
  ents = (pam_mod.get("payload") or {}).get("entitlements") or []
  if ents:
    # Prefer the PAM module's own readiness counters (v2.1); fall back to a
    # local requester==approver comparison for v2.0 envelopes.
    self_appr_n = _int(pam_sum.get("self_approval_conflicts"), -1)
    if self_appr_n < 0:
      self_appr_n = len([e for e in ents if e.get("approver_principal") and
                         e.get("approver_principal") == e.get("eligible_requester")])
    not_ready = _int(pam_sum.get("pam_entitlements_not_ready"))
    ask = f"Nominate a distinct approver group (`--approver-group`) for `{len(ents)}` PAM entitlement(s)"
    details = []
    if not_ready:
      details.append(f"`{not_ready}` NOT READY")
    if self_appr_n:
      details.append(f"`{self_appr_n}` self-approve")
    if details:
      ask += " — " + ", ".join(details)
    asks.append(ask + ".")
  if _int(kpis.get("user_managed_keys_found")) > 0:
    asks.append(f"Approve disabling `{kpis['user_managed_keys_found']}` user-managed SA key(s).")
  sim_sum = (modules.get("breakglass_simulator") or {}).get("summary") or {}
  meta = an.get("metadata") or {}
  telemetry = str(sim_sum.get("telemetry_source") or meta.get("telemetry_mode") or "")
  if sim_sum.get("log_limit_hit") or (telemetry and "bigquery" not in telemetry.lower()):
    asks.append(
        "Enable Data Access audit logs / provide a Log Analytics table "
        "(`--audit-bq-table`) for full 90-day replay coverage."
    )
  if _int(sim_sum.get("simulated_403_denials")) > 0:
    asks.append(
        f"Hold the custom-role cutover until `{sim_sum.get('simulated_403_denials')}` "
        "simulated HTTP 403s are resolved (permission delta review)."
    )
  sim_conf, sim_cutover = _sim_confidence_and_cutover(envelope, digest)
  if sim_conf in ("LOW", "MEDIUM"):
    asks.append(
        f"Use `--canary` dual-bind cutover (`{sim_cutover or 'CANARY_DUAL_BIND'}`) "
        f"because audit log replay confidence is `{sim_conf}`."
    )
  deny_mod = modules.get("deny_policy_architect") or {}
  rules = (deny_mod.get("payload") or {}).get("rules") or []
  if rules:
    src = (deny_mod.get("summary") or {}).get("breakglass_source")
    if (deny_mod.get("summary") or {}).get("breakglass_supplied"):
      asks.append("Re-confirm the supplied break-glass principals before attaching deny policies.")
    else:
      asks.append(
          "Confirm break-glass exception principals (`--breakglass-principal`) before attaching "
          f"deny policies{f' — currently `{src}`' if src else ''}."
      )
  gitops_sum = (modules.get("gitops_pr_guardrail") or {}).get("summary") or {}
  if gitops_sum.get("pr_gate_verdict") == "SCAN_ERROR":
    asks.append("Provide a valid `terraform show -json` plan (`--plan-json`): the GitOps scan errored.")
  if (envelope.get("freshness_overview") or {}).get("has_stale_carried_forward_data"):
    asks.append("Approve a full-suite refresh: some modules are carried forward and may be stale.")
  p01 = [f for f in findings if f.get("priority") in ("P0", "P1")]
  if p01:
    asks.append(f"Schedule a change window for `{len(p01)}` P0/P1 item(s).")
  return asks or ["No decisions required — maintain current posture."]


def synthesize_executive_summary(
    envelope: Dict[str, Any],
    digest: Optional[Dict[str, Any]] = None,
    findings: Optional[Sequence[Dict[str, Any]]] = None,
) -> str:
  """Renders the one-page `EXECUTIVE_SUMMARY.md` for security leadership.

  Args:
    envelope: Assessment envelope.
    digest: Optional pre-computed digest.
    findings: Optional pre-computed unified findings.

  Returns:
    Markdown text.
  """
  digest = digest or build_recommendation_digest(envelope)
  findings = list(findings) if findings is not None else _findings_safe(envelope)
  kpis = digest.get("executive_kpis", {}) or {}
  project_id = envelope.get("project_id", "unknown-project")
  counts = {p: 0 for p in ("P0", "P1", "P2", "P3")}
  for f in findings:
    if f.get("priority") in counts:
      counts[f["priority"]] += 1
  sev_counts = {s: 0 for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
  for f in findings:
    if f.get("severity") in sev_counts:
      sev_counts[f["severity"]] += 1

  def _kv(label: str, value: Any) -> str:
    return f"| {label} | {value} |"

  comp_b, comp_a = kpis.get("compliance_score_before_pct"), kpis.get("compliance_score_after_pct")
  lines = [
      f"# Executive Summary: `{project_id}`",
      "",
      f"Run `{envelope.get('run_id', '')}` · `{envelope.get('timestamp_utc', '')}` · "
      f"mode `{envelope.get('trigger_mode', '')}`",
      "",
      "## Posture at a glance",
      "",
      "| Metric | Value |",
      "| :--- | :--- |",
      _kv("Risk score (weighted open findings, 0–100)", f"**{risk_score(findings)}**"),
      _kv("Open findings by severity",
          " · ".join(f"{k} {v}" for k, v in sev_counts.items())),
      _kv("Principals audited", kpis.get("total_principals", 0)),
      _kv("Permissions before → after",
          f"{_int(kpis.get('permissions_before')):,} → {_int(kpis.get('permissions_after')):,} "
          f"(-{kpis.get('permissions_reduction_pct', 0)}%)"),
      _kv("Privilege escalation paths", kpis.get("escalation_chains_count", 0)),
      _kv("Standing privileged humans", kpis.get("standing_privileged_humans_count", 0)),
      _kv("Simulated HTTP 403s at cutover",
          f"{kpis.get('simulated_403_denials', 'n/a')} ({kpis.get('cutover_verdict', 'NOT_EVALUATED')})"),
  ]
  sim_conf, sim_cutover = _sim_confidence_and_cutover(envelope, digest)
  if sim_conf or sim_cutover:
    lines.append(
        _kv(
            "Audit log confidence / Recommended cutover",
            f"**{sim_conf or 'n/a'}** · `{sim_cutover or 'n/a'}`",
        )
    )
  f8_count = _int(kpis.get("ai_agent_blast_radius_count"))
  if f8_count > 0:
    lines.append(_kv("AI agent blast-radius findings (F8)", f8_count))
  wif_misconfig_count = _int(kpis.get("wif_misconfigurations_count"))
  if wif_misconfig_count > 0:
    lines.append(_kv("Existing WIF provider misconfigurations", wif_misconfig_count))
  if comp_b is not None or comp_a is not None:
    lines.append(_kv("Compliance pass rate (before → after)", f"{comp_b}% → {comp_a}%"))
  if sim_conf in ("LOW", "MEDIUM"):
    lines.extend([
        "",
        f"> [!WARNING]\n> Audit log replay confidence is **`{sim_conf}`** "
        f"(recommended cutover: `{sim_cutover or 'CANARY_DUAL_BIND'}`). "
        "Use `--canary` dual-bind cutover (bind the least-privilege role alongside "
        "the legacy role before removal) to prevent unexpected HTTP 403s.",
    ])
  no_usage_count = _int(kpis.get("no_usage_data_persona_count"))
  if no_usage_count > 0:
    lines.extend([
        "",
        f"> [!WARNING]\n> `{no_usage_count}` persona role(s) were built without usage data "
        "(no audit-log / Recommender evidence). Review them before cutover; see "
        "`EVIDENCE.md` → permission traceability.",
    ])
  lines.extend([
      "",
      "Trend across runs is shown in the portal history view.",
      "",
      "## Top risks",
      "",
  ])
  # Top risks are ranked by severity first (leadership view), then phase.
  top = sorted(
      findings,
      key=lambda f: (-SEVERITY_RANK.get(f.get("severity"), 0), str(f.get("priority", "P9"))),
  )[:5]
  if top:
    for idx, f in enumerate(top, start=1):
      who = short_principal(f.get("principal", "")) if f.get("principal") else f.get("resource", "")
      lines.append(f"{idx}. **{f.get('severity')}** ({f.get('priority')}) — `{who}`: {f.get('title')}")
  else:
    lines.append("_No open findings._")
  rem_payload = ((envelope.get("modules") or {}).get("finding_remediator") or {}).get("payload") or {}
  rem_plans = rem_payload.get("remediation_plans") or rem_payload.get("plans") or []
  ap_notes = []
  for rp in rem_plans:
    if not isinstance(rp, dict):
      continue
    ap = _format_attack_path(rp)
    if ap:
      who = short_principal(rp.get("principal", "")) if rp.get("principal") else rp.get("finding_id", "finding")
      ap_notes.append(f"- `{who}`: {ap}")
  if ap_notes:
    lines.extend(["", "## Attack-path choke points", ""] + ap_notes)
  lines.extend([
      "",
      "## Remediation SLAs",
      "",
      "| Phase | Open items | SLA |",
      "| :--- | :---: | :--- |",
  ])
  for p in ("P0", "P1", "P2", "P3"):
    lines.append(f"| {p} | {counts[p]} | {PHASE_SLA[p]} |")
  lines.extend(["", "## What we need from you", ""])
  lines.extend(f"- [ ] {a}" for a in _decision_asks(envelope, digest, findings))
  lines.extend([
      "",
      "Details: `REMEDIATION_PLAN.md` (how to apply) · `EVIDENCE.md` (audit trail) · "
      "`README.md` (file index).",
      "",
  ])
  return "\n".join(lines)


# -----------------------------------------------------------------------------
# 5. Evidence (EVIDENCE.md)
# -----------------------------------------------------------------------------
def synthesize_evidence(
    envelope: Dict[str, Any],
    digest: Optional[Dict[str, Any]] = None,
    findings: Optional[Sequence[Dict[str, Any]]] = None,
    artifact_hashes: Optional[Mapping[str, str]] = None,
) -> str:
  """Renders `EVIDENCE.md` for GRC / auditors.

  Args:
    envelope: Assessment envelope.
    digest: Optional pre-computed digest.
    findings: Optional pre-computed unified findings.
    artifact_hashes: Optional {relative_path: sha256}; when omitted the
      document points to `manifest.json`.

  Returns:
    Markdown text.
  """
  digest = digest or build_recommendation_digest(envelope)
  findings = list(findings) if findings is not None else _findings_safe(envelope)
  project_id = envelope.get("project_id", "unknown-project")
  modules = envelope.get("modules", {}) or {}
  an = _audit_analysis(envelope)
  meta = an.get("metadata") or {}
  sim_sum = (modules.get("breakglass_simulator") or {}).get("summary") or {}

  lines = [
      f"# Evidence Pack: `{project_id}`",
      "",
      "Audience: GRC, internal audit and incident reviewers.",
      "",
      "## 1. Run provenance",
      "",
      "| Field | Value |",
      "| :--- | :--- |",
      f"| Run ID | `{envelope.get('run_id', '')}` |",
      f"| Generated (UTC) | `{envelope.get('timestamp_utc', '')}` |",
      f"| Schema version | `{envelope.get('schema_version', '2.0')}` |",
      f"| Trigger mode | `{envelope.get('trigger_mode', '')}` |",
      f"| Skills executed | {', '.join(f'`{s}`' for s in envelope.get('triggered_skills', []) or []) or '—'} |",
      f"| Assessment policy etag | `{envelope.get('live_policy_etag', '') or 'N/A'}` |",
      f"| Telemetry mode | `{meta.get('telemetry_mode', 'n/a')}` |",
      f"| Lookback window (days) | `{meta.get('freshness_days', sim_sum.get('lookback_days', 'n/a'))}` |",
      f"| Audit log entries per principal (limit) | `{meta.get('log_limit', 'n/a')}` |",
      f"| GCS run object | `gs://{(envelope.get('gcs_metadata') or {}).get('bucket', 'local')}/"
      f"{(envelope.get('gcs_metadata') or {}).get('object_path', '')}` |",
      "",
  ]
  warnings = _as_list(meta.get("warnings"))
  if warnings:
    lines.append("**Collection warnings (degraded coverage):**")
    lines.extend(f"- {w}" for w in warnings[:20])
    lines.append("")

  # Module freshness.
  lines.extend(["## 2. Module freshness", "", "| Module | Status | Freshness | Generated |",
                "| :--- | :--- | :--- | :--- |"])
  for key, mod in modules.items():
    mod = mod or {}
    lines.append(
        f"| `{key}` | `{mod.get('status', 'NOT_RUN')}` | {_freshness_tag(mod)} | "
        f"`{mod.get('generated_at') or '—'}` |"
    )
  lines.append("")

  # Data sources & insight ids.
  insight_ids = sorted({
      str(i.get("insight_id")) for i in (an.get("policy_insights") or []) if isinstance(i, dict)
      and i.get("insight_id")
  } | {
      str((f.get("evidence") or {}).get("insight_id")) for f in findings
      if (f.get("evidence") or {}).get("insight_id")
  })
  audit_summary = an.get("audit_log_exercised_summary") or {}
  lines.extend([
      "## 3. Data sources",
      "",
      f"- **IAM policy**: live `getIamPolicy` snapshot, etag `{envelope.get('live_policy_etag', '') or 'N/A'}` "
      f"(backup: `iam_policy_backup_{project_id}.json`).",
      f"- **Recommender / Active Assist insights**: `{len(insight_ids)}` insight(s).",
      f"- **Cloud Audit Logs**: exercised permissions captured for `{len(audit_summary)}` principal(s); "
      f"simulator telemetry `{sim_sum.get('telemetry_source', 'n/a')}`, "
      f"`{sim_sum.get('audit_log_entries_sampled', 'n/a')}` entries sampled.",
  ])
  rem_sum = (modules.get("finding_remediator") or {}).get("summary") or {}
  if rem_sum:
    lines.append(
        f"- **External findings**: `{rem_sum.get('findings_ingested', 0)}` from "
        f"{', '.join(rem_sum.get('sources_integrated', []) or []) or 'SCC / Wiz'}."
    )
  if insight_ids:
    lines.extend(["", "<details><summary>Insight IDs</summary>", ""])
    lines.extend(f"- `{i}`" for i in insight_ids[:200])
    lines.extend(["", "</details>"])
  lines.append("")

  # Verification gates.
  gates = an.get("verification_gates") or {}
  lines.extend(["## 4. Verification gates", ""])
  if gates:
    lines.extend(["| Gate | Result | Details |", "| :--- | :---: | :--- |"])
    for name, gate in gates.items():
      gate = gate or {}
      details = ", ".join(
          f"{k}={v}" for k, v in gate.items() if k != "passed" and not isinstance(v, (dict, list))
      )
      lines.append(
          f"| `{name}` | {'✅' if gate.get('passed') else '❌'} | {_md_cell(details)} |"
      )
  else:
    lines.append("_No verification gates recorded._")
  verification = an.get("model_b_verification") or {}
  if verification:
    lines.extend([
        "",
        f"Model B verification: exact cover **{'yes' if verification.get('exact_cover') else 'no'}**, "
        f"pairwise overlap **{verification.get('pairwise_overlap', 'n/a')}**, "
        f"capabilities **{verification.get('capability_count', 'n/a')}**.",
    ])
  lines.append("")

  # Traceability.
  trace = an.get("role_traceability") or {}
  lines.extend(["## 5. Permission traceability", ""])
  if trace:
    lines.extend(["| Persona role | Kept | Dropped | Evidence types |", "| :--- | :---: | :---: | :--- |"])
    for role_id, rows in trace.items():
      rows = [r for r in _as_list(rows) if isinstance(r, dict)]
      kept = sum(1 for r in rows if r.get("decision") == "kept")
      dropped = sum(1 for r in rows if r.get("decision") == "dropped")
      ev = ", ".join(sorted({str(r.get("evidence")) for r in rows if r.get("evidence")}))[:120]
      lines.append(f"| `{role_id}` | {kept} | {dropped} | {_md_cell(ev) or '—'} |")
    lines.extend([
        "",
        f"Full per-permission table: `detailed_recommendations.md` (traceability section) "
        f"and `analysis_results_{project_id}.json` → `role_traceability`.",
    ])
  else:
    lines.append(
        f"_Per-permission traceability not present in this envelope; see "
        f"`analysis_results_{project_id}.json` and `custom-roles/` YAML headers._"
    )
  lines.append("")

  # Control mapping.
  controls = ((modules.get("compliance_mapper") or {}).get("payload") or {}).get("controls") or []
  if controls:
    lines.extend([
        "## 6. Control mapping",
        "",
        "| Framework | Control | Current | Projected | Evidence artifact |",
        "| :--- | :--- | :---: | :---: | :--- |",
    ])
    for c in controls:
      lines.append(
          f"| {_md_cell(c.get('framework'))} | `{_md_cell(c.get('control_id'))}` | "
          f"`{c.get('current_status')}` | `{c.get('projected_status')}` | "
          f"`{_md_cell(c.get('evidence_artifact'))}` |"
      )
    lines.append("")

  # Artifact integrity.
  lines.extend(["## 7. Artifact integrity", ""])
  if artifact_hashes:
    lines.extend(["| File | SHA-256 |", "| :--- | :--- |"])
    for path, digest_hex in sorted(artifact_hashes.items()):
      lines.append(f"| `{path}` | `{digest_hex}` |")
  else:
    lines.append(
        "SHA-256 hashes, sizes and producing module of every file are listed in "
        "`manifest.json` (human-readable index: `README.md`)."
    )
  lines.extend([
      "",
      "## 8. Change control statement",
      "",
      "ScopeGuard performed no IAM mutations. All changes are proposals that require "
      "human approval; generated scripts are dry-run by default.",
      "",
  ])
  return "\n".join(lines)


# -----------------------------------------------------------------------------
# Public entry points
# -----------------------------------------------------------------------------
def render_audience_documents(
    envelope: Dict[str, Any],
    findings: Optional[Sequence[Dict[str, Any]]] = None,
) -> Dict[str, str]:
  """Renders all human documents for a run (ART-5).

  Args:
    envelope: Assessment envelope (enriched or not).
    findings: Optional pre-computed unified findings.

  Returns:
    {file_name: markdown} for `EXECUTIVE_SUMMARY.md`, `REMEDIATION_PLAN.md`,
    `EVIDENCE.md` and `scopeguard_recommendations_<pid>.md`.
  """
  digest = envelope.get("recommendation_digest") or build_recommendation_digest(envelope)
  findings = list(findings) if findings is not None else _findings_safe(envelope)
  pid = envelope.get("project_id", "unknown-project")
  master = envelope.get("master_recommendations_markdown") or synthesize_master_markdown(
      envelope, digest
  )
  return {
      "EXECUTIVE_SUMMARY.md": synthesize_executive_summary(envelope, digest, findings),
      "REMEDIATION_PLAN.md": synthesize_remediation_plan(envelope, digest, findings),
      "EVIDENCE.md": synthesize_evidence(envelope, digest, findings),
      f"scopeguard_recommendations_{pid}.md": master,
  }


def enrich_envelope_with_recommendations(envelope: Dict[str, Any]) -> Dict[str, Any]:
  """Attaches `recommendation_digest` and `master_recommendations_markdown` to envelope."""
  digest = build_recommendation_digest(envelope)
  markdown = synthesize_master_markdown(envelope, digest)
  envelope["recommendation_digest"] = digest
  envelope["master_recommendations_markdown"] = markdown
  return envelope
