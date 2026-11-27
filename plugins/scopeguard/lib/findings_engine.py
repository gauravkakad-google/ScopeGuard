#!/usr/bin/env python3
# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0

"""Normalizes ScopeGuard run envelopes into a unified, stable findings queue.

The portal shows findings from 11 skills that each emit a different payload
shape. This module flattens them into one schema so that a security or DevOps
admin can triage, filter, export, and track them across runs:

  {
    "id": "SG-1A2B3C4D5E",          # Stable hash of project|category|key parts
    "category": "basic_role",       # Machine category
    "category_label": "Basic role", # Human label
    "severity": "CRITICAL",         # CRITICAL | HIGH | MEDIUM | LOW
    "priority": "P1",               # P0..P3 remediation phase
    "principal": "user:a@b.com",
    "principal_type": "Human",
    "title": "...", "detail": "...",
    "resource": "roles/editor",
    "module_key": "recommender_audit",
    "source_skill": "gcp-iam-recommender-audit",
    "recommended_action": "...", "deliverable": "...",
    "confidence": "High | Medium | Low | n/a",
  }

Status tracking is fully stateless: it is inferred by comparing the finding IDs
of the selected run with the previous N immutable run snapshots in GCS
(New / Open / Regressed / Resolved). No mutable state store is required, which
keeps the portal strictly read-only.

Pure standard library; no GCP calls are made here, so it is unit-testable.
"""

import datetime as _dt
import hashlib
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
PRIORITY_RANK = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}

CATEGORY_LABELS = {
    "basic_role": "Basic role (Owner/Editor)",
    "overprivileged": "Over-privileged role",
    "escalation_risk": "Privilege escalation risk",
    "escalation_path": "Transitive escalation path",
    "dormant_sa": "Dormant service account",
    "expired_condition": "Expired conditional binding",
    "service_agent_excess": "Service agent with extra roles",
    "role_sprawl": "Role sprawl",
    "ai_agent_blast_radius": "AI agent blast radius",
    "iac_violation": "Terraform / IaC violation",
    "standing_admin": "Standing admin (JIT candidate)",
    "pam_not_ready": "PAM entitlement not ready",
    "sa_key": "User-managed SA key",
    "wif_candidate": "Keyless WIF candidate",
    "wif_provider_misconfig": "WIF provider misconfiguration",
    "external_finding": "SCC / Wiz finding",
    "compliance_gap": "Compliance control gap",
    "cutover_blocker": "Cutover blocker (simulated 403)",
    "org_policy_gap": "Org policy not enforced",
}

_PHASE_RE = re.compile(r"P([0-3])")


def stable_finding_id(project_id: str, category: str, *parts: Any) -> str:
  """Returns a deterministic short ID for a finding.

  Uses SHA-256 (not for security, but to avoid weak-hash linter noise) over a
  normalized key so that the same finding keeps its ID across runs.

  Args:
    project_id: GCP project the finding belongs to.
    category: Normalized finding category.
    *parts: Additional identifying parts (principal, role, rule, ...).

  Returns:
    An ID such as `SG-1A2B3C4D5E`.
  """
  raw = "|".join([project_id or "", category] + [str(p or "") for p in parts])
  digest = hashlib.sha256(raw.lower().encode("utf-8")).hexdigest()[:10]
  return f"SG-{digest.upper()}"


def classify_principal(member: str) -> str:
  """Maps an IAM member string to a coarse, admin-friendly principal type."""
  m = (member or "").strip()
  if not m:
    return "None"
  low = m.lower()
  if low.startswith("user:"):
    return "Human"
  if low.startswith("group:"):
    return "Group"
  if low.startswith("domain:"):
    return "Domain"
  if low.startswith(("principal:", "principalset:")):
    return "Federated"
  if low.startswith("serviceaccount:") or low.endswith(".gserviceaccount.com"):
    if "@gcp-sa-" in low or "@cloudservices.gserviceaccount.com" in low or (
        low.split(":", 1)[-1].startswith("service-") and "gserviceaccount.com" in low
    ):
      return "Service agent"
    if "-compute@developer.gserviceaccount.com" in low or "@appspot.gserviceaccount.com" in low:
      return "Default SA"
    return "Service account"
  return "Other"


def _phase(value: Any, default: str) -> str:
  """Extracts the first `P0..P3` token from free-form phase text."""
  match = _PHASE_RE.search(str(value or ""))
  return f"P{match.group(1)}" if match else default


def _sev(value: Any, default: str) -> str:
  """Normalizes a severity string to the CRITICAL/HIGH/MEDIUM/LOW scale."""
  s = str(value or "").upper()
  if s in SEVERITY_RANK:
    return s
  if s in ("SEVERE", "BLOCKER"):
    return "CRITICAL"
  if s in ("WARN", "WARNING", "MODERATE"):
    return "MEDIUM"
  if s in ("INFO", "INFORMATIONAL", "NOTICE"):
    return "LOW"
  return default


def replay_confidence(replay: Dict[str, Any], sim_summary: Dict[str, Any]) -> str:
  """Grades how trustworthy a simulator replay verdict is.

  A PASS verdict based on zero observed API calls is vacuous; this helper makes
  that explicit so admins do not over-trust a green badge.

  Args:
    replay: One `principal_replays` entry from the breakglass simulator.
    sim_summary: The simulator module summary (telemetry source, etc.).

  Returns:
    "High", "Medium", or "Low".
  """
  calls = int(replay.get("replayed_api_calls") or 0)
  source = str(sim_summary.get("telemetry_source") or "").lower()
  if calls == 0:
    return "Low"
  if sim_summary.get("log_limit_hit") or replay.get("log_limit_hit"):
    return "Low"
  if "bigquery" in source:
    return "High"
  return "Medium" if calls >= 20 else "Low"


class _Builder:
  """Accumulates normalized findings while de-duplicating by stable ID."""

  def __init__(self, project_id: str) -> None:
    self.project_id = project_id
    self.items: Dict[str, Dict[str, Any]] = {}

  def add(
      self,
      category: str,
      key_parts: Sequence[Any],
      *,
      severity: str,
      priority: str,
      principal: str = "",
      title: str,
      detail: str = "",
      resource: str = "",
      module_key: str,
      source_skill: str,
      recommended_action: str = "",
      deliverable: str = "",
      confidence: str = "n/a",
      evidence: Optional[Dict[str, Any]] = None,
  ) -> None:
    fid = stable_finding_id(self.project_id, category, *key_parts)
    if fid in self.items:
      return
    self.items[fid] = {
        "id": fid,
        "project_id": self.project_id,
        "category": category,
        "category_label": CATEGORY_LABELS.get(category, category),
        "severity": severity,
        "priority": priority,
        "principal": principal or "",
        "principal_type": classify_principal(principal),
        "title": title,
        "detail": detail,
        "resource": resource,
        "module_key": module_key,
        "source_skill": source_skill,
        "recommended_action": recommended_action,
        "deliverable": deliverable,
        "confidence": confidence,
        "evidence": evidence or {},
    }


def _module(env: Dict[str, Any], key: str) -> Dict[str, Any]:
  return (env.get("modules") or {}).get(key) or {}


def _payload(env: Dict[str, Any], key: str) -> Dict[str, Any]:
  return _module(env, key).get("payload") or {}


def normalize_findings(env: Dict[str, Any]) -> List[Dict[str, Any]]:
  """Flattens every module of a run envelope into the unified findings schema.

  Missing modules or fields are tolerated so that partial runs (or older
  schema versions) still render.

  Args:
    env: A ScopeGuard v2 run envelope.

  Returns:
    Findings sorted by priority, then severity (most urgent first).
  """
  pid = str(env.get("project_id") or "")
  b = _Builder(pid)
  audit_skill = "gcp-iam-recommender-audit"

  analysis = _payload(env, "recommender_audit").get("analysis") or {}
  findings = analysis.get("findings") or {}
  mappings = {
      pm.get("principal"): pm for pm in (analysis.get("principal_mappings") or [])
  }

  def _action_for(principal: str, fallback: str) -> str:
    return (mappings.get(principal) or {}).get("recommended_action") or fallback

  for it in findings.get("F1_basic_roles") or []:
    p, role = it.get("principal", ""), it.get("role", "")
    used, total = it.get("exercised_count", 0), it.get("total_permissions", 0)
    b.add(
        "basic_role", [p, role], severity="CRITICAL", priority=_phase(it.get("phase"), "P1"),
        principal=p, resource=role,
        title=f"Basic role {role} granted",
        detail=f"Exercised {used} of {total} permissions in the observation window.",
        module_key="recommender_audit", source_skill=audit_skill,
        recommended_action=_action_for(p, f"Replace {role} with a least-privilege custom role."),
        deliverable="custom-roles/ & rollback_runbook.sh",
        evidence={"exercised": used, "granted": total, "insight_id": it.get("insight_id")},
    )

  for it in findings.get("F2_overprivileged_principals") or []:
    p, role = it.get("principal", ""), it.get("role", "")
    util = float(it.get("utilization_pct") or 0.0)
    unused = it.get("unused_permissions_count", 0)
    b.add(
        "overprivileged", [p, role], severity="HIGH" if util < 20 else "MEDIUM",
        priority=_phase(it.get("phase"), "P2"), principal=p, resource=role,
        title=f"Over-privileged {role}: {unused} unused permissions",
        detail=f"{util:.1f}% of granted permissions used in the observation window.",
        module_key="recommender_audit", source_skill=audit_skill,
        recommended_action=_action_for(p, f"Right-size {role} to exercised permissions."),
        deliverable="custom-roles/",
        evidence={"utilization_pct": util, "unused": unused, "insight_id": it.get("insight_id")},
    )

  for it in findings.get("F3_privilege_escalation_risks") or []:
    p = it.get("principal", "")
    roles = ", ".join(it.get("escalation_roles") or [])
    b.add(
        "escalation_risk", [p, roles], severity="CRITICAL", priority=_phase(it.get("phase"), "P1"),
        principal=p, resource=roles,
        title=f"Holds escalation-capable role(s): {roles}",
        detail="Can impersonate or modify IAM of other identities.",
        module_key="recommender_audit", source_skill=audit_skill,
        recommended_action=_action_for(p, "Remove project-level escalation roles; scope to specific SAs."),
        deliverable="rollback_runbook.sh",
    )

  for it in findings.get("F4_inactive_service_accounts") or []:
    email = it.get("email", "")
    p = f"serviceAccount:{email}" if email and ":" not in email else email
    days = it.get("observation_days", "")
    b.add(
        "dormant_sa", [email], severity=_sev(it.get("severity"), "HIGH"), priority="P0",
        principal=p, resource=", ".join(it.get("active_roles") or []),
        title=f"Dormant service account (no auth for {days} days)",
        detail=f"Last authenticated: {it.get('last_authenticated_time') or 'never'}; "
               f"active bindings: {'yes' if it.get('has_active_bindings') else 'no'}.",
        module_key="recommender_audit", source_skill=audit_skill,
        recommended_action="Disable first (reversible), observe, then remove bindings and delete.",
        deliverable="rollback_runbook.sh",
        evidence={"unique_id": it.get("service_account_id")},
    )

  for it in findings.get("F5_expired_conditional_bindings") or []:
    p, role = it.get("principal", ""), it.get("role", "")
    title = it.get("condition_title", "")
    b.add(
        "expired_condition", [p, role, title], severity="MEDIUM", priority=_phase(it.get("phase"), "P0"),
        principal=p, resource=role,
        title=f"Expired conditional binding {role} ({title})",
        detail=f"Condition expired at {it.get('expired_at', '')}: {it.get('condition_expression', '')}",
        module_key="recommender_audit", source_skill=audit_skill,
        recommended_action="Remove the expired binding (zero runtime impact).",
        deliverable="rollback_runbook.sh",
        evidence={"condition_expression": it.get("condition_expression"), "condition_title": title},
    )

  for it in findings.get("F6_overprivileged_service_agents") or []:
    p = it.get("principal", "")
    excess = ", ".join(it.get("excess_non_service_agent_roles") or [])
    b.add(
        "service_agent_excess", [p, excess], severity="MEDIUM", priority=_phase(it.get("phase"), "P3"),
        principal=p, resource=excess,
        title=f"Service agent holds extra role(s): {excess}",
        detail="Google-managed agents should only hold their service agent role.",
        module_key="recommender_audit", source_skill=audit_skill,
        recommended_action="Validate dependency, then remove the non-agent roles.",
    )

  for it in findings.get("F7_role_sprawl_redundancy") or []:
    p = it.get("principal", "")
    b.add(
        "role_sprawl", [p], severity="LOW", priority=_phase(it.get("phase"), "P2"),
        principal=p, resource=", ".join(it.get("roles") or []),
        title=f"{it.get('roles_count', 0)} overlapping roles bound",
        detail="Consolidate into one persona custom role (Model A, default) or a capability-role bundle (Model B).",
        module_key="recommender_audit", source_skill=audit_skill,
        recommended_action=_action_for(p, "Consolidate overlapping roles."),
        deliverable="custom-roles/personas/ (or custom-roles/capabilities/ + bundles.yaml)",
    )

  for it in findings.get("F8_ai_agent_blast_radius") or []:
    p = it.get("principal", "")
    roles = ", ".join(it.get("dangerous_roles") or it.get("roles") or []) or str(it.get("role") or "")
    sev = _sev(it.get("severity") or it.get("risk_level"), "HIGH")
    if sev not in ("CRITICAL", "HIGH"):
      sev = "HIGH"
    signals = it.get("signals") or it.get("matched_signals") or []
    detail = (
        it.get("detail")
        or it.get("reason")
        or (
            f"AI agent identity holds broad blast-radius access ({roles or 'high-risk permissions'})"
            + (f"; signals: {', '.join(str(s) for s in signals)}" if signals else "")
            + "."
        )
    )
    b.add(
        "ai_agent_blast_radius", [p, roles or it.get("id") or ""],
        severity=sev, priority=_phase(it.get("phase"), "P1"),
        principal=p, resource=roles,
        title=it.get("title") or f"AI agent blast-radius exposure ({roles or 'privileged roles'})",
        detail=detail,
        module_key="recommender_audit", source_skill=audit_skill,
        recommended_action=_action_for(
            p,
            "Replace broad roles with a scoped persona custom role and attach D5 IAM v2 Deny Policy.",
        ),
        deliverable="custom-roles/personas/ + deny-policies/deny_policies.tf (D5)",
        evidence={
            "signals": signals,
            "dangerous_permissions": it.get("dangerous_permissions") or [],
        },
    )

  for it in analysis.get("transitive_paths") or []:
    src = it.get("source_principal", "")
    mid = it.get("intermediate_principal", "")
    b.add(
        "escalation_path", [src, it.get("edge_role"), mid], severity="CRITICAL", priority="P1",
        principal=src, resource=it.get("edge_role", ""),
        title=f"Can reach {it.get('terminal_capability', 'privileged capability')} via {mid}",
        detail=f"{src} → ({it.get('edge_permission', '')}) → {mid} → "
               f"{', '.join(it.get('inherited_roles') or [])}",
        module_key="recommender_audit", source_skill=audit_skill,
        recommended_action="Remove the SA-level impersonation edge or scope it with IAM Conditions.",
        evidence={"chain_id": it.get("id")},
    )

  # Breakglass simulator: principals whose proposed role would break traffic.
  sim_mod = _module(env, "breakglass_simulator")
  sim_summary = sim_mod.get("summary") or {}
  for r in (sim_mod.get("payload") or {}).get("principal_replays") or []:
    denials = int(r.get("simulated_403_denials") or 0)
    if denials <= 0:
      continue
    p = r.get("principal", "")
    missing = r.get("uncovered_permissions") or []
    b.add(
        "cutover_blocker", [p], severity="HIGH", priority=_phase(r.get("remediation_phase"), "P2"),
        principal=p, resource=str(r.get("proposed_model_a_role") or ""),
        title=f"Proposed role would cause {denials} simulated 403(s)",
        detail=f"Missing permissions: {', '.join(missing[:8]) or 'n/a'}"
               + (" …" if len(missing) > 8 else ""),
        module_key="breakglass_simulator", source_skill="gcp-iam-breakglass-simulator",
        recommended_action="Add the missing permissions to the proposed role, re-run the simulator, then cut over.",
        confidence=replay_confidence(r, sim_summary),
        evidence={"uncovered_permissions": missing, "troubleshoot_cli": r.get("troubleshoot_cli")},
    )

  # IaC priority follows severity: CRITICAL/HIGH block the PR (P1), MEDIUM is
  # P2, LOW (e.g. G5_LONG_LIVED_CONDITION_WINDOW) is hygiene (P3).
  iac_priority = {"CRITICAL": "P1", "HIGH": "P1", "MEDIUM": "P2", "LOW": "P3"}
  for v in _payload(env, "gitops_pr_guardrail").get("violations") or []:
    v_sev = _sev(v.get("severity"), "HIGH")
    b.add(
        "iac_violation", [v.get("rule_id"), v.get("file"), v.get("resource")],
        severity=v_sev, priority=iac_priority.get(v_sev, "P2"),
        principal=v.get("principal", ""), resource=v.get("role", ""),
        title=f"{v.get('rule_id', 'IaC rule')}: {v.get('resource', '')}",
        detail=f"{v.get('file', '')}:{v.get('line', '')} — {v.get('message', '')}",
        module_key="gitops_pr_guardrail", source_skill="gcp-iam-gitops-pr-guardrail",
        recommended_action=v.get("remediation", ""), deliverable="Fixed .tf patch / SARIF",
        evidence={"file": v.get("file"), "line": v.get("line")},
    )

  for e in _payload(env, "jit_pam_architect").get("entitlements") or []:
    p = e.get("eligible_requester", "")
    removed = e.get("standing_roles_removed") or []
    if not removed:
      continue
    b.add(
        "standing_admin", [p], severity="HIGH", priority="P3", principal=p,
        resource=", ".join(removed),
        title=f"Standing admin access ({len(removed)} role(s))",
        detail=f"Convert to JIT entitlement {e.get('entitlement_id', '')} "
               f"(max {e.get('max_request_duration', 'n/a')}).",
        module_key="jit_pam_architect", source_skill="gcp-iam-jit-pam-architect",
        recommended_action="Apply the PAM entitlement, verify a test grant, then remove standing roles.",
        deliverable="pam_entitlements.tf",
    )
    # ART-11: an entitlement without an independent approver must not ship;
    # surface it as its own finding so it is not lost inside the rollout doc.
    if str(e.get("readiness") or "").upper().startswith("NOT READY"):
      self_appr = bool(e.get("self_approval_detected"))
      b.add(
          "pam_not_ready", [p, e.get("entitlement_id")],
          severity="HIGH" if self_appr else "MEDIUM", priority="P3", principal=p,
          resource=str(e.get("entitlement_id", "")),
          title="PAM entitlement not ready: " + (
              "requester would approve own request" if self_appr else "approver group required"),
          detail="; ".join(str(w) for w in (e.get("warnings") or [])) or str(e.get("readiness")),
          module_key="jit_pam_architect", source_skill="gcp-iam-jit-pam-architect",
          recommended_action="Re-run with --approver-group <independent group> before applying.",
          deliverable="pam_rollout.md",
      )

  for sa in _payload(env, "federation_architect").get("service_accounts") or []:
    email = sa.get("email", "")
    p = f"serviceAccount:{email}" if email else ""
    keys = int(sa.get("user_managed_key_count") or 0)
    posture = str(sa.get("posture_status") or "")
    if keys > 0:
      b.add(
          "sa_key", [email], severity="HIGH", priority="P1", principal=p, resource=email,
          title=f"{keys} user-managed key(s) on service account",
          detail=f"Posture: {posture}. Recommended: {sa.get('recommended_federation', 'WIF')}.",
          module_key="federation_architect", source_skill="gcp-iam-federation-architect",
          recommended_action="Migrate the workload to Workload Identity Federation, then retire keys.",
          deliverable="wif_federation.tf / retire_sa_keys.sh",
      )
    elif "WIF" in posture.upper():
      b.add(
          "wif_candidate", [email], severity="LOW", priority="P3", principal=p, resource=email,
          title="Keyless Workload Identity Federation candidate",
          detail=f"Recommended: {sa.get('recommended_federation', 'WIF')}.",
          module_key="federation_architect", source_skill="gcp-iam-federation-architect",
          recommended_action="Adopt WIF for external automation using this SA.",
          deliverable="wif_federation.tf",
      )

  wif_audit = _payload(env, "federation_architect").get("existing_wif_audit") or {}
  for wf in wif_audit.get("findings") or []:
    if not isinstance(wf, dict):
      continue
    res = (
        wf.get("provider")
        or wf.get("provider_name")
        or wf.get("pool")
        or wf.get("resource")
        or ""
    )
    rule_id = wf.get("rule_id") or wf.get("check_id") or wf.get("issue") or ""
    b.add(
        "wif_provider_misconfig", [res, rule_id or wf.get("title") or ""],
        severity=_sev(wf.get("severity"), "HIGH"),
        priority="P1",
        principal=wf.get("principal", ""),
        resource=str(res),
        title=wf.get("title") or f"WIF provider misconfiguration ({rule_id or res})",
        detail=wf.get("detail") or wf.get("message") or wf.get("description") or "",
        module_key="federation_architect",
        source_skill="gcp-iam-federation-architect",
        recommended_action=(
            wf.get("remediation")
            or wf.get("recommended_action")
            or "Tighten WIF provider attribute_condition CEL guard to restrict issuer/repository claims."
        ),
        deliverable="federation-wif/WIF_MIGRATION.md",
        evidence={
            "pool": wf.get("pool"),
            "provider": wf.get("provider") or wf.get("provider_name"),
            "rule_id": rule_id,
        },
    )

  for rp in _payload(env, "finding_remediator").get("remediation_plans") or []:
    # Plan status (v2.1): READY | HOLD_SIMULATED_403 | BLOCKED_* | NO_CHANGE_NEEDED.
    # Legacy plans have no status; treat them as READY.
    plan_status = str(rp.get("status") or "READY").upper()
    if plan_status == "NO_CHANGE_NEEDED":
      continue
    status_note = {
        "HOLD_SIMULATED_403": " HOLD: the fix would cause simulated 403s; add the missing permissions first.",
        "BLOCKED_NO_ROLE_EVIDENCE": " BLOCKED: no custom-role evidence; run the recommender audit first.",
        "BLOCKED_INVALID_INPUT": " BLOCKED: finding contained an invalid principal/role and was not scripted.",
    }.get(plan_status, "")
    b.add(
        "external_finding", [rp.get("source_platform"), rp.get("finding_id")],
        severity=_sev(rp.get("severity"), "HIGH"), priority="P1",
        principal=rp.get("principal", ""), resource=rp.get("replacement_role", ""),
        title=f"[{rp.get('source_platform', 'External')}] {rp.get('title', '')}",
        detail=f"Finding {rp.get('finding_id', '')}; replacement role has "
               f"{rp.get('replacement_permissions_count', 0)} permissions; simulated 403s: "
               f"{rp.get('simulated_403_display') or rp.get('simulated_403_denials', 'n/a')}.{status_note}",
        module_key="finding_remediator", source_skill="gcp-iam-finding-remediator",
        recommended_action=rp.get("strategy") or "Apply the replacement role patch.",
        deliverable="terraform/ · remediation_commands.sh · ticket_proposed_remediation.md",
        evidence={
            "finding_id": rp.get("finding_id"),
            # None means "simulator not run" — never coerce it to 0.
            "remediator_simulated_403s": rp.get("simulated_403_denials"),
            "plan_status": plan_status,
        },
    )

  for c in _payload(env, "compliance_mapper").get("controls") or []:
    if str(c.get("current_status", "")).upper() not in ("FAIL", "FAILING", "NON_COMPLIANT"):
      continue
    b.add(
        "compliance_gap", [c.get("framework"), c.get("control_id")], severity="MEDIUM",
        priority=_phase(c.get("remediation_phase"), "P2"),
        resource=f"{c.get('framework', '')} {c.get('control_id', '')}",
        title=f"{c.get('control_id', '')}: {c.get('title', '')}",
        detail=f"{c.get('finding_detail', '')} (projected: {c.get('projected_status', 'n/a')})",
        module_key="compliance_mapper", source_skill="gcp-iam-compliance-mapper",
        recommended_action=f"Execute phase {c.get('remediation_phase', '')}.",
        deliverable=c.get("evidence_artifact", ""),
    )

  for oc in _payload(env, "org_hierarchy_auditor").get("org_policy_constraints") or []:
    if oc.get("enforced", True):
      continue
    b.add(
        "org_policy_gap", [oc.get("constraint")], severity="MEDIUM", priority="P3",
        resource=oc.get("constraint", ""),
        title=f"Org policy {oc.get('constraint', '')} not enforced",
        detail=str(oc.get("status", "")),
        module_key="org_hierarchy_auditor", source_skill="gcp-iam-org-hierarchy-auditor",
        recommended_action="Enforce the constraint at the org or folder level.",
        deliverable="org_policy.tf",
    )

  return sort_findings(b.items.values())


def sort_findings(items: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
  """Sorts by priority (P0 first), then severity (CRITICAL first), then ID."""
  return sorted(
      items,
      key=lambda f: (
          PRIORITY_RANK.get(f.get("priority"), 9),
          -SEVERITY_RANK.get(f.get("severity"), 0),
          f.get("id", ""),
      ),
  )


def _parse_ts(value: Any) -> Optional[_dt.datetime]:
  """Parses `YYYY-MM-DDTHH:MM:SSZ` timestamps; returns None on failure."""
  try:
    return _dt.datetime.strptime(str(value), "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=_dt.timezone.utc
    )
  except (TypeError, ValueError):
    return None


def summarize_run(env: Dict[str, Any]) -> Dict[str, Any]:
  """Builds a compact, cacheable summary of one run for history comparisons."""
  findings = normalize_findings(env)
  kpis = (env.get("recommendation_digest") or {}).get("executive_kpis") or {}
  modules = env.get("modules") or {}
  return {
      "run_id": env.get("run_id", ""),
      "timestamp_utc": env.get("timestamp_utc", ""),
      "trigger_mode": env.get("trigger_mode", ""),
      "executed_modules": sorted(
          k for k, m in modules.items() if (m or {}).get("status") not in (None, "NOT_RUN")
      ),
      "findings": findings,
      "kpis": {
          "permissions_before": kpis.get("permissions_before") or 0,
          "permissions_after": kpis.get("permissions_after") or 0,
          "escalation_chains_count": kpis.get("escalation_chains_count") or 0,
          "simulated_403_denials": kpis.get("simulated_403_denials") or 0,
          "standing_privileged_humans_count": kpis.get("standing_privileged_humans_count") or 0,
          "compliance_score_before_pct": kpis.get("compliance_score_before_pct") or 0,
      },
  }


def _count_by(items: Iterable[Dict[str, Any]], field: str) -> Dict[str, int]:
  out: Dict[str, int] = {}
  for it in items:
    k = str(it.get(field) or "n/a")
    out[k] = out.get(k, 0) + 1
  return out


def compute_history(summaries: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
  """Derives finding status and trend from run summaries (newest first).

  Status rules (stateless):
    * New       - present now, absent from every earlier run in the window.
    * Open      - present now and in the immediately previous run.
    * Regressed - present now, absent previously, but seen in an older run.
    * Resolved  - present in the previous run, absent now, and the producing
                  module actually re-ran (avoids false "resolved" on partial runs).
  With only one run available every current finding is reported as Open.

  Args:
    summaries: Outputs of `summarize_run`, index 0 being the selected run.

  Returns:
    Dict with `findings`, `resolved`, `trend` (oldest first) and `counts`.
  """
  if not summaries:
    return {"findings": [], "resolved": [], "trend": [], "counts": {}, "window_runs": 0}

  current = summaries[0]
  key_sets: List[set] = [{f["id"] for f in s["findings"]} for s in summaries]
  cur_ts = _parse_ts(current.get("timestamp_utc"))
  has_prev = len(summaries) > 1

  enriched: List[Dict[str, Any]] = []
  for f in current["findings"]:
    fid = f["id"]
    seen_idx = [i for i, ks in enumerate(key_sets) if fid in ks]
    oldest_idx = max(seen_idx)
    if not has_prev:
      status = "Open"
    elif fid in key_sets[1]:
      status = "Open"
    elif any(fid in ks for ks in key_sets[2:]):
      status = "Regressed"
    else:
      status = "New"
    first_seen = summaries[oldest_idx].get("timestamp_utc", "")
    first_dt = _parse_ts(first_seen)
    age_days = (cur_ts - first_dt).days if (cur_ts and first_dt) else 0
    enriched.append(
        dict(
            f,
            status=status,
            first_seen=first_seen,
            first_seen_is_window_start=oldest_idx == len(summaries) - 1 and has_prev,
            last_seen=current.get("timestamp_utc", ""),
            age_days=max(age_days, 0),
            runs_seen=len(seen_idx),
        )
    )

  resolved: List[Dict[str, Any]] = []
  if has_prev:
    executed_now = set(current.get("executed_modules") or [])
    for f in summaries[1]["findings"]:
      if f["id"] in key_sets[0]:
        continue
      if executed_now and f.get("module_key") not in executed_now:
        continue  # Module not re-run; cannot claim resolution.
      resolved.append(dict(f, status="Resolved", last_seen=summaries[1].get("timestamp_utc", "")))

  trend: List[Dict[str, Any]] = []
  for idx in range(len(summaries) - 1, -1, -1):
    s = summaries[idx]
    prev_keys = key_sets[idx + 1] if idx + 1 < len(summaries) else None
    cur_keys = key_sets[idx]
    trend.append(
        {
            "run_id": s.get("run_id", ""),
            "timestamp_utc": s.get("timestamp_utc", ""),
            "trigger_mode": s.get("trigger_mode", ""),
            "total": len(cur_keys),
            "by_severity": _count_by(s["findings"], "severity"),
            "new": len(cur_keys - prev_keys) if prev_keys is not None else None,
            "resolved": len(prev_keys - cur_keys) if prev_keys is not None else None,
            "kpis": s.get("kpis", {}),
        }
    )

  counts = {
      "total": len(enriched),
      "by_severity": _count_by(enriched, "severity"),
      "by_priority": _count_by(enriched, "priority"),
      "by_status": _count_by(enriched, "status"),
      "by_category": _count_by(enriched, "category"),
      "by_principal_type": _count_by(enriched, "principal_type"),
      "resolved_since_previous": len(resolved),
  }
  return {
      "findings": enriched,
      "resolved": resolved,
      "trend": trend,
      "counts": counts,
      "window_runs": len(summaries),
  }


def top_principals(
    rows: Sequence[Tuple[str, List[Dict[str, Any]]]], limit: int = 10
) -> List[Dict[str, Any]]:
  """Ranks principals across projects by weighted finding severity.

  Args:
    rows: `(project_id, findings)` tuples.
    limit: Maximum principals to return.

  Returns:
    Ranked principals with score, finding counts, and projects touched.
  """
  agg: Dict[str, Dict[str, Any]] = {}
  for project_id, findings in rows:
    for f in findings:
      p = f.get("principal")
      if not p:
        continue
      entry = agg.setdefault(
          p,
          {
              "principal": p,
              "principal_type": f.get("principal_type", ""),
              "score": 0,
              "findings": 0,
              "critical": 0,
              "projects": set(),
              "categories": set(),
          },
      )
      entry["score"] += SEVERITY_RANK.get(f.get("severity"), 1) ** 2
      entry["findings"] += 1
      entry["critical"] += 1 if f.get("severity") == "CRITICAL" else 0
      entry["projects"].add(project_id)
      entry["categories"].add(f.get("category_label", ""))
  ranked = sorted(agg.values(), key=lambda e: (-e["score"], e["principal"]))[:limit]
  for e in ranked:
    e["projects"] = sorted(e["projects"])
    e["categories"] = sorted(c for c in e["categories"] if c)
  return ranked
