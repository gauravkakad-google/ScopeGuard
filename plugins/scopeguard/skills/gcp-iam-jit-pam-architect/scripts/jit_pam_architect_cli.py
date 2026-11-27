#!/usr/bin/env python3
# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0

"""Just-in-Time (JIT) Privileged Access Manager (PAM) & CEL Condition Architect.

Scans project IAM policies for standing human/group administrative grants and
expired conditional bindings, converting them into PAM Entitlement YAML/Terraform
definitions with mandatory justification and approval workflows.

Separation-of-duties guardrail (ART-11): an entitlement must never be approved
by the same principal that requests it. When no distinct approver group is
supplied (``--approver-group``) or the approver equals the requester, the
entitlement is emitted with a clearly-marked placeholder approver and flagged
``NOT READY: approver required`` in every output (JSON, Markdown, Terraform).
"""

import argparse
import json
import logging
from pathlib import Path
import re
import sys
from typing import Any, Dict, Iterable, List, Optional

PLUGIN_ROOT = Path(__file__).resolve().parents[3]
if str(PLUGIN_ROOT) not in sys.path:
  sys.path.insert(0, str(PLUGIN_ROOT))

from lib.envelope_schema import SCHEMA_VERSION, utc_now_iso  # pylint: disable=wrong-import-position
from lib.gcp_client import ScopeGuardGCPClient  # pylint: disable=wrong-import-position
from lib.gcs_publisher import (  # pylint: disable=wrong-import-position
    GCSAssessmentStore,
    add_gcs_publish_arguments,
    run_skill_gcs_preflight,
)

logger = logging.getLogger("scopeguard.jit_pam_architect")

SENSITIVE_ROLE_PATTERNS = (
    "roles/owner",
    "roles/editor",
    "admin",
    "security",
    "iam.serviceaccountuser",
    "iam.serviceaccounttokencreator",
    "secretmanager.secretaccessor",
    "bigquery.dataeditor",
)

# Placeholders are deliberately invalid-looking so `terraform apply` fails
# loudly (unknown group) rather than silently wiring a wrong approver.
PLACEHOLDER_APPROVER = "group:REPLACE-pam-approvers@example.com"
PLACEHOLDER_NOTIFICATION = "REPLACE-security-alerts@example.com"

READY = "READY"
NOT_READY_APPROVER = "NOT READY: approver required"

DEFAULT_CEL_GUARD = (
    'request.time.getHours("Asia/Singapore") >= 8 && '
    'request.time.getHours("Asia/Singapore") <= 20'
)


def _is_standing_privileged_role(role: str) -> bool:
  """Returns True when the role matches a privileged/sensitive pattern."""
  low = role.lower()
  return any(pat in low for pat in SENSITIVE_ROLE_PATTERNS)


def _slugify(value: str) -> str:
  """Converts arbitrary text into a PAM-safe entitlement ID fragment."""
  return re.sub(r"[^a-z0-9-]+", "-", value.lower()).strip("-")[:48]


def _normalize_principal(value: str) -> str:
  """Normalizes an approver string to an IAM v1 member (`group:` by default).

  Args:
    value: Raw principal such as `pam-approvers@corp.com` or `user:a@b.com`.

  Returns:
    The normalized member string, or "" when the input is blank.
  """
  value = (value or "").strip()
  if not value:
    return ""
  if ":" not in value and "@" in value:
    # Bare emails are treated as Google Groups: PAM approvals should be
    # delegated to a group, never to a single individual.
    return f"group:{value}"
  return value


def _parse_approvers(approver_principal: Any) -> List[str]:
  """Parses approvers from a str (comma separated) or an iterable of str."""
  if isinstance(approver_principal, str):
    raw: Iterable[str] = approver_principal.split(",")
  else:
    raw = approver_principal or []
  out: List[str] = []
  for item in raw:
    norm = _normalize_principal(item)
    if norm and norm not in out:
      out.append(norm)
  return out


def _same_identity(a: str, b: str) -> bool:
  """Compares two IAM members by email, ignoring the `user:`/`group:` prefix."""
  return a.split(":", 1)[-1].strip().lower() == b.split(":", 1)[-1].strip().lower()


def _hcl_list(values: List[str]) -> str:
  """Renders a list of strings as an HCL list literal."""
  return "[" + ", ".join(f'"{v}"' for v in values) + "]"


def _render_entitlement_hcl(project_id: str, ent: Dict[str, Any]) -> str:
  """Renders one `google_privileged_access_manager_entitlement` block."""
  ent_id = ent["entitlement_id"]
  role_bindings_hcl = "\n".join(
      f'      role_bindings {{\n        role = "{r}"\n      }}'
      for r in ent["jit_granted_roles"]
  )
  notif = ent["notification_recipients"]
  header: List[str] = []
  if ent["readiness"] != READY:
    # A loud banner so reviewers cannot miss the blocking issue in a PR diff.
    header.append(f"# !!! {ent['readiness']} !!!")
    for w in ent["warnings"]:
      header.append(f"# !!! {w}")
  header_txt = ("\n".join(header) + "\n") if header else ""
  return (
      header_txt
      + f'resource "google_privileged_access_manager_entitlement" "{ent_id.replace("-", "_")}" {{\n'
      f'  entitlement_id       = "{ent_id}"\n'
      f'  location             = "global"\n'
      f'  parent               = "projects/{project_id}"\n'
      f'  max_request_duration = "{ent["max_request_duration"]}"\n\n'
      f"  eligible_users {{\n"
      f'    principals = ["{ent["eligible_requester"]}"]\n'
      f"  }}\n\n"
      f"  privileged_access {{\n"
      f"    gcp_iam_access {{\n"
      f'      resource      = "//cloudresourcemanager.googleapis.com/projects/{project_id}"\n'
      f'      resource_type = "cloudresourcemanager.googleapis.com/Project"\n'
      f"{role_bindings_hcl}\n"
      f"    }}\n"
      f"  }}\n\n"
      f"  # Requesters must always state a business justification.\n"
      f"  requester_justification_config {{\n"
      f"    unstructured {{}}\n"
      f"  }}\n\n"
      f"  # Separation of duties: approvers MUST be distinct from the requester.\n"
      f"  approval_workflow {{\n"
      f"    manual_approvals {{\n"
      f"      require_approver_justification = true\n"
      f"      steps {{\n"
      f"        approvals_needed          = 1\n"
      f"        approver_email_recipients = {_hcl_list(notif['approver_email_recipients'])}\n"
      f"        approvers {{\n"
      f"          principals = {_hcl_list(ent['approver_principals'])}\n"
      f"        }}\n"
      f"      }}\n"
      f"    }}\n"
      f"  }}\n\n"
      f"  additional_notification_targets {{\n"
      f"    admin_email_recipients     = {_hcl_list(notif['admin_email_recipients'])}\n"
      f"    requester_email_recipients = {_hcl_list(notif['requester_email_recipients'])}\n"
      f"  }}\n"
      f"}}\n"
  )


def _render_markdown(
    project_id: str,
    generated_at: str,
    entitlements: List[Dict[str, Any]],
    global_warnings: List[str],
) -> str:
  """Renders the human-readable PAM rollout guide (`pam_rollout.md`)."""
  lines = [
      f"# ScopeGuard PAM Entitlement Rollout — `{project_id}`",
      "",
      f"_Generated {generated_at} · schema {SCHEMA_VERSION}_",
      "",
  ]
  not_ready = [e for e in entitlements if e["readiness"] != READY]
  if not_ready or global_warnings:
    lines.extend([
        "> [!WARNING]",
        f"> **{len(not_ready)} of {len(entitlements)} entitlement(s) are NOT READY.** "
        "Resolve the items below before `terraform apply`.",
    ])
    for w in global_warnings:
      lines.append(f"> - {w}")
    lines.append("")
  lines.extend([
      "| Entitlement | Requester | Approver(s) | Granted role(s) | Max duration | "
      "Justification | Notifications | Status |",
      "| :--- | :--- | :--- | :--- | :---: | :---: | :--- | :--- |",
  ])
  for e in entitlements:
    notif = e["notification_recipients"]
    lines.append(
        f"| `{e['entitlement_id']}` | `{e['eligible_requester']}` | "
        f"{', '.join(f'`{a}`' for a in e['approver_principals'])} | "
        f"{', '.join(f'`{r}`' for r in e['jit_granted_roles'])} | "
        f"`{e['max_request_duration']}` | "
        f"{'required' if e['justification_required'] else 'optional'} | "
        f"{', '.join(notif['admin_email_recipients'])} | **{e['readiness']}** |"
    )
  lines.append("")
  for e in entitlements:
    if e["warnings"]:
      lines.append(f"### `{e['entitlement_id']}` warnings")
      lines.extend(f"- ⚠️ {w}" for w in e["warnings"])
      lines.append("")
  lines.extend([
      "## Rollout steps",
      "",
      "1. Replace every `REPLACE-…` placeholder (approver group, notification "
      "recipients) and re-run with `--approver-group` / `--notification-email`.",
      "2. `terraform plan` → review → `terraform apply` the entitlements (they add "
      "eligibility only; no standing access is granted).",
      "3. Ask each requester to raise a test grant; a *different* member of the "
      "approver group approves it. Confirm the grant expires at max duration.",
      "4. Only after a successful test grant, remove the standing roles listed in "
      "`standing_roles_removed` (use the recommender-audit rollback runbook).",
      "",
      "> [!NOTE]",
      "> PAM never lets a requester approve their own grant. If the approver group "
      "contains the requester, at least one *other* member must be available, "
      "otherwise the grant can never be approved.",
      "",
  ])
  return "\n".join(lines)


def run_jit_pam_architect(
    project_id: str,
    policy_data: Optional[Dict[str, Any]] = None,
    analysis_data: Optional[Dict[str, Any]] = None,
    approver_principal: Any = "",
    gcp_client: Optional[ScopeGuardGCPClient] = None,
    output_dir: Optional[Path] = None,
    notification_emails: Optional[List[str]] = None,
) -> Dict[str, Any]:
  """Identifies standing human privileges and synthesizes PAM + CEL configurations.

  Args:
    project_id: Target GCP project ID.
    policy_data: Pre-fetched project IAM policy (fetched read-only if None).
    analysis_data: Optional recommender-audit analysis for Model A roles.
    approver_principal: Approver group(s); comma-separated str or list. When
      empty a placeholder is used and entitlements are marked NOT READY.
    gcp_client: Optional injected client (tests / orchestrator).
    output_dir: When set, writes JSON/Terraform/Markdown deliverables.
    notification_emails: Admin/approver notification email recipients.

  Returns:
    Module entry dict with `summary`, `payload`, and `status`.
  """
  generated_at = utc_now_iso()
  if policy_data is None:
    client = gcp_client or ScopeGuardGCPClient(quota_project=project_id)
    policy = client.fetch_project_iam_policy(project_id)
  else:
    policy = policy_data

  global_warnings: List[str] = []
  approvers = _parse_approvers(approver_principal)
  approver_is_placeholder = not approvers
  if approver_is_placeholder:
    # Previously the approver was inferred as `user:admin@<domain>`, which
    # frequently equalled the requester (self-approval). Never infer.
    approvers = [PLACEHOLDER_APPROVER]
    global_warnings.append(
        "No --approver-group supplied: using placeholder "
        f"`{PLACEHOLDER_APPROVER}`. Provide a dedicated approver Google Group "
        "distinct from all requesters."
    )
    logger.warning("No approver group supplied; entitlements marked NOT READY.")

  notif_list = [e.strip() for e in (notification_emails or []) if e and e.strip()]
  notif_is_placeholder = not notif_list
  if notif_is_placeholder:
    notif_list = [PLACEHOLDER_NOTIFICATION]
    global_warnings.append(
        "No --notification-email supplied: admin/approver notification "
        f"recipients use placeholder `{PLACEHOLDER_NOTIFICATION}`."
    )

  standing_by_principal: Dict[str, List[str]] = {}
  conditional_findings: List[Dict[str, Any]] = []

  for binding in policy.get("bindings", []):
    role = binding.get("role", "")
    cond = binding.get("condition")
    for member in binding.get("members", []):
      is_human_or_group = member.startswith(("user:", "group:"))
      if cond:
        conditional_findings.append(
            {
                "principal": member,
                "role": role,
                "condition_title": cond.get("title", "untitled"),
                "expression": cond.get("expression", ""),
            }
        )
      if is_human_or_group and _is_standing_privileged_role(role):
        standing_by_principal.setdefault(member, [])
        if role not in standing_by_principal[member]:
          standing_by_principal[member].append(role)

  # Enrich with Model A persona roles from recommender_audit so PAM grants
  # least-privilege roles rather than re-granting roles/owner or roles/editor.
  pm_lookup: Dict[str, Dict[str, Any]] = {}
  for pm in (analysis_data or {}).get("principal_mappings", []) or []:
    pm_lookup[pm.get("principal", "")] = pm

  entitlements: List[Dict[str, Any]] = []
  tf_blocks: List[str] = [
      "# ScopeGuard Zero-Standing-Privilege (PAM) Terraform Blueprint",
      f"# Target Project: {project_id}",
      f"# Generated: {generated_at} (schema {SCHEMA_VERSION})",
      "# Review every '!!! NOT READY' banner before applying.",
      "",
  ]

  for idx, (member, current_roles) in enumerate(
      sorted(standing_by_principal.items()), start=1
  ):
    short_user = member.split(":", 1)[-1].split("@", 1)[0]
    ent_id = _slugify(f"jit-{short_user}-access-{idx}")
    pm_info = pm_lookup.get(member, {})
    # Contract key `persona_role_id`; `model_a_custom_role` kept for old envelopes.
    model_a_role = pm_info.get("persona_role_id") or pm_info.get(
        "model_a_custom_role"
    )

    # Never grant roles/owner via PAM; replace basic roles with right-sized role.
    pam_roles: List[str] = []
    if model_a_role:
      pam_roles.append(f"projects/{project_id}/roles/{model_a_role}")
    else:
      for r in current_roles:
        mapped = "roles/viewer" if r in ("roles/owner", "roles/editor") else r
        if mapped not in pam_roles:
          pam_roles.append(mapped)

    is_high_priv = any(r in ("roles/owner", "roles/editor") for r in current_roles)
    max_duration = "3600s" if is_high_priv else "14400s"
    tier_label = (
        "Tier-0 Breakglass Diagnostics (1h Max)"
        if is_high_priv
        else "Tier-1 Operational Elevation (4h Max)"
    )

    # Separation-of-duties check: strip the requester from its own approvers.
    warnings: List[str] = []
    self_approval = any(_same_identity(a, member) for a in approvers)
    effective_approvers = [a for a in approvers if not _same_identity(a, member)]
    if self_approval:
      warnings.append(
          f"SELF-APPROVAL: approver equals requester `{member}`. Self-approval "
          "defeats PAM; a distinct approver group is required."
      )
      logger.warning("Entitlement %s: approver equals requester %s", ent_id, member)
    if not effective_approvers:
      effective_approvers = [PLACEHOLDER_APPROVER]
    if PLACEHOLDER_APPROVER in effective_approvers:
      warnings.append(
          f"Approver is the placeholder `{PLACEHOLDER_APPROVER}`; supply "
          "--approver-group."
      )
    if notif_is_placeholder:
      warnings.append("Notification recipients are placeholders.")
    readiness = (
        NOT_READY_APPROVER
        if (self_approval or PLACEHOLDER_APPROVER in effective_approvers)
        else READY
    )

    requester_email = member.split(":", 1)[-1] if member.startswith("user:") else ""
    notification_recipients = {
        "admin_email_recipients": list(notif_list),
        "approver_email_recipients": list(notif_list),
        "requester_email_recipients": [requester_email] if requester_email else [],
    }

    ent = {
        "entitlement_id": ent_id,
        "eligible_requester": member,
        # Kept as a string for backwards compatibility with report consumers.
        "approver_principal": ", ".join(effective_approvers),
        "approver_principals": effective_approvers,
        "self_approval_detected": self_approval,
        "readiness": readiness,
        "warnings": warnings,
        "standing_roles_removed": current_roles,
        "jit_granted_roles": pam_roles,
        "max_request_duration": max_duration,
        "tier": tier_label,
        "justification_required": True,
        "approver_justification_required": True,
        "approvals_needed": 1,
        "notification_recipients": notification_recipients,
        "recommended_cel_guard": DEFAULT_CEL_GUARD,
    }
    entitlements.append(ent)
    tf_blocks.append(_render_entitlement_hcl(project_id, ent))

  pam_tf = "\n".join(tf_blocks)
  self_approval_count = sum(1 for e in entitlements if e["self_approval_detected"])
  not_ready_count = sum(1 for e in entitlements if e["readiness"] != READY)
  if self_approval_count:
    global_warnings.insert(
        0,
        f"{self_approval_count} entitlement(s) had approver == requester; the "
        "requester was removed from its own approver list.",
    )

  summary = {
      "standing_privileged_humans_count": len(standing_by_principal),
      "standing_bindings_to_convert": sum(
          len(v) for v in standing_by_principal.values()
      ),
      "pam_entitlements_designed": len(entitlements),
      "pam_entitlements_not_ready": not_ready_count,
      "self_approval_conflicts": self_approval_count,
      "approver_placeholder_used": approver_is_placeholder,
      "conditional_bindings_inspected": len(conditional_findings),
      "standing_privilege_reduction_pct": (
          100.0 if standing_by_principal else 0.0
      ),
  }
  payload = {
      "schema_version": SCHEMA_VERSION,
      "generated_at": generated_at,
      "warnings": global_warnings,
      "entitlements": entitlements,
      "conditional_bindings": conditional_findings,
      "pam_terraform_hcl": pam_tf,
  }

  if output_dir:
    try:
      output_dir.mkdir(parents=True, exist_ok=True)
      (output_dir / "jit_pam_spec.json").write_text(
          json.dumps(
              {
                  "schema_version": SCHEMA_VERSION,
                  "generated_at": generated_at,
                  "project_id": project_id,
                  "summary": summary,
                  "payload": payload,
              },
              indent=2,
          )
          + "\n",
          encoding="utf-8",
      )
      (output_dir / "pam_entitlements.tf").write_text(pam_tf, encoding="utf-8")
      (output_dir / "pam_rollout.md").write_text(
          _render_markdown(project_id, generated_at, entitlements, global_warnings),
          encoding="utf-8",
      )
    except OSError as exc:
      logger.error("Failed writing PAM deliverables to %s: %s", output_dir, exc)
      raise

  return {"summary": summary, "payload": payload, "status": "COMPLETED"}


def main() -> int:
  """CLI entry point."""
  logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
  parser = argparse.ArgumentParser(
      description="Convert standing human IAM grants into GCP PAM JIT entitlements."
  )
  parser.add_argument("--project", required=True, help="Target GCP Project ID.")
  parser.add_argument(
      "--approver-group",
      default="",
      help=(
          "Approver Google Group (e.g. pam-approvers@corp.com) for PAM manual "
          "approval; comma-separate multiple. MUST be distinct from requesters. "
          f"If omitted, `{PLACEHOLDER_APPROVER}` is used and entitlements are "
          "marked NOT READY."
      ),
  )
  parser.add_argument(
      "--notification-email",
      action="append",
      default=[],
      help="Admin/approver notification email recipient (repeatable).",
  )
  parser.add_argument(
      "--analysis-json",
      default="",
      help="Optional path to local analysis_results_<project>.json.",
  )
  parser.add_argument(
      "--output-dir",
      required=True,
      help="Directory to write PAM Terraform and specification files.",
  )
  add_gcs_publish_arguments(parser)
  args = parser.parse_args()

  store = GCSAssessmentStore()
  gcs_check = run_skill_gcs_preflight(args, args.project, store=store)

  policy_data = store.client.fetch_project_iam_policy(args.project)
  analysis_data: Optional[Dict[str, Any]] = None
  if args.analysis_json and Path(args.analysis_json).exists():
    try:
      analysis_data = json.loads(
          Path(args.analysis_json).read_text(encoding="utf-8")
      )
    except (OSError, json.JSONDecodeError) as exc:
      logger.error("Could not read --analysis-json %s: %s", args.analysis_json, exc)
      return 2
  elif gcs_check:
    prior = store.get_json_object(
        gcs_check["bucket"], f"{args.project}/latest.json"
    )
    analysis_data = (
        (prior or {})
        .get("modules", {})
        .get("recommender_audit", {})
        .get("payload", {})
        .get("analysis")
    )

  out_dir = Path(args.output_dir)
  mod_entry = run_jit_pam_architect(
      project_id=args.project,
      policy_data=policy_data,
      analysis_data=analysis_data,
      approver_principal=args.approver_group,
      gcp_client=store.client,
      output_dir=out_dir,
      notification_emails=args.notification_email,
  )

  publish_info = None
  if gcs_check:
    publish_info = store.publish_assessment_run(
        bucket=gcs_check["bucket"],
        region=gcs_check["region"],
        project_id=args.project,
        trigger_mode="jit-pam-architect",
        updated_modules={"jit_pam_architect": mod_entry},
        live_policy_etag=policy_data.get("etag", ""),
        local_output_dir=out_dir,
    )

  print(
      json.dumps(
          {
              "jit_pam_summary": mod_entry["summary"],
              "warnings": mod_entry["payload"]["warnings"],
              "gcs_publish": publish_info,
          },
          indent=2,
      )
  )
  return 0


if __name__ == "__main__":
  sys.exit(main())
