#!/usr/bin/env python3
# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0

"""Deterministic IAM Compliance Mapper (CIS GCP v3.0, SOC 2, ISO 27001, PCI-DSS).

Evaluates ScopeGuard IAM findings (F1-F7) and workload key telemetry against
enterprise audit controls, calculating current posture score vs. projected
post-remediation score and generating auditor-ready Markdown/JSON evidence.
"""

import argparse
import json
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional

PLUGIN_ROOT = Path(__file__).resolve().parents[3]
if str(PLUGIN_ROOT) not in sys.path:
  sys.path.insert(0, str(PLUGIN_ROOT))

from lib.gcs_publisher import (  # pylint: disable=wrong-import-position
    GCSAssessmentStore,
    add_gcs_publish_arguments,
    run_skill_gcs_preflight,
)

# Deterministic Control Matrix linking regulatory clauses to ScopeGuard detectors
CONTROL_CATALOG: List[Dict[str, Any]] = [
    {
        "framework": "CIS GCP v3.0",
        "control_id": "CIS 1.4",
        "title": "Ensure There Are Only GCP-Managed Service Account Keys",
        "detector": "USER_MANAGED_SA_KEYS",
        "remediation_phase": "P1 / WIF",
        "evidence_artifact": "federation_wif/main.tf",
    },
    {
        "framework": "CIS GCP v3.0",
        "control_id": "CIS 1.5",
        "title": "Ensure Service Account Has No Admin Privileges",
        "detector": "F1_F2_EXCESS_ADMIN",
        "remediation_phase": "P2",
        "evidence_artifact": "custom-roles/personas/*.yaml (+ capabilities/, bundles.yaml)",
    },
    {
        "framework": "CIS GCP v3.0",
        "control_id": "CIS 1.6",
        "title": "Ensure Basic Roles (Owner/Editor) Are Not Used at Project Level",
        "detector": "F1_BASIC_ROLES",
        "remediation_phase": "P1 / P2",
        "evidence_artifact": "principal_mapping.json",
    },
    {
        "framework": "CIS GCP v3.0",
        "control_id": "CIS 1.8",
        "title": "Ensure Separation of Duties for Service Account Admin & User",
        "detector": "F3_TRANSITIVE_SA",
        "remediation_phase": "P1",
        "evidence_artifact": "scopeguard.sarif.json",
    },
    {
        "framework": "CIS GCP v3.0",
        "control_id": "CIS 1.15",
        "title": "Ensure Unused Credentials & Dormant Service Accounts Are Disabled",
        "detector": "F4_INACTIVE_SA",
        "remediation_phase": "P1",
        "evidence_artifact": "rollback_runbook.sh",
    },
    {
        "framework": "SOC 2 Type II",
        "control_id": "CC6.1",
        "title": "Logical Access Security & Least-Privilege Enforcement",
        "detector": "F2_UNUSED_PERMS",
        "remediation_phase": "P2",
        "evidence_artifact": "custom-roles/personas/*.yaml (+ capabilities/, bundles.yaml)",
    },
    {
        "framework": "SOC 2 Type II",
        "control_id": "CC6.2",
        "title": "Prior Authorization & Just-in-Time Privileged Access",
        "detector": "F1_F3_STANDING_ADMIN",
        "remediation_phase": "P1 / PAM",
        "evidence_artifact": "pam_entitlements.tf",
    },
    {
        "framework": "SOC 2 Type II",
        "control_id": "CC6.3",
        "title": "Timely Modification & Revocation of Expired Access Grants",
        "detector": "F4_F5_EXPIRED_STALE",
        "remediation_phase": "P0 / P1",
        "evidence_artifact": "iam_audit_report.md",
    },
    {
        "framework": "ISO/IEC 27001:2022",
        "control_id": "A.5.15",
        "title": "Access Control Based on Business & Security Requirements",
        "detector": "F7_ROLE_SPRAWL",
        "remediation_phase": "P2",
        "evidence_artifact": "custom-roles/personas/*.yaml (+ capabilities/, bundles.yaml)",
    },
    {
        "framework": "ISO/IEC 27001:2022",
        "control_id": "A.5.18",
        "title": "Access Rights Review & De-Provisioning of Stale Identities",
        "detector": "F4_F5_EXPIRED_STALE",
        "remediation_phase": "P0 / P1",
        "evidence_artifact": "principal_mapping.json",
    },
    {
        "framework": "ISO/IEC 27001:2022",
        "control_id": "A.8.2",
        "title": "Restriction & Management of Privileged Access Rights",
        "detector": "F1_F3_STANDING_ADMIN",
        "remediation_phase": "P1 / PAM",
        "evidence_artifact": "deny_policies.tf",
    },
    {
        "framework": "ISO/IEC 27001:2022",
        "control_id": "A.8.3",
        "title": "Information Access Restriction (Resource-Boundary Scoping)",
        "detector": "F2_UNUSED_PERMS",
        "remediation_phase": "P2",
        "evidence_artifact": "role_design_spec.json",
    },
    {
        "framework": "PCI-DSS v4.0",
        "control_id": "Req 7.2.1",
        "title": "Explicit Role-Based Access Control Model Defined",
        "detector": "F7_ROLE_SPRAWL",
        "remediation_phase": "P2",
        "evidence_artifact": "custom-roles/personas/*.yaml (+ capabilities/, bundles.yaml)",
    },
    {
        "framework": "PCI-DSS v4.0",
        "control_id": "Req 7.2.2",
        "title": "Least Privileges Assigned Only as Needed for Job Function",
        "detector": "F1_F2_EXCESS_ADMIN",
        "remediation_phase": "P1 / P2",
        "evidence_artifact": "analysis_results.json",
    },
    {
        "framework": "PCI-DSS v4.0",
        "control_id": "Req 7.2.5",
        "title": "Application & System Accounts Strictly Scoped and Monitored",
        "detector": "F6_SERVICE_AGENTS",
        "remediation_phase": "P3",
        "evidence_artifact": "scc_findings_import.json",
    },
    {
        "framework": "PCI-DSS v4.0",
        "control_id": "Req 8.6.1",
        "title": "Interactive Login & Long-Lived Static Keys Prohibited for SAs",
        "detector": "USER_MANAGED_SA_KEYS",
        "remediation_phase": "P1 / WIF",
        "evidence_artifact": "federation_wif/main.tf",
    },
]


def _evaluate_detector(
    detector: str,
    findings: Dict[str, Any],
    user_managed_key_count: int,
) -> Dict[str, Any]:
  """Evaluates a detector bucket against current brownfield findings."""
  f1 = findings.get("F1_basic_roles", [])
  f2 = findings.get("F2_excess_permissions", [])
  f3 = findings.get("F3_privilege_escalation_risks", [])
  f4 = findings.get("F4_inactive_service_accounts", [])
  f5 = findings.get("F5_expired_conditional_bindings", [])
  f6 = findings.get("F6_excess_service_agent_roles", [])
  f7 = findings.get("F7_role_sprawl_candidates", [])

  mapping = {
      "USER_MANAGED_SA_KEYS": (
          user_managed_key_count,
          f"{user_managed_key_count} customer-managed SA JSON key(s) detected"
          if user_managed_key_count > 0
          else "0 static user-managed SA keys present (100% keyless/managed)",
      ),
      "F1_BASIC_ROLES": (
          len(f1),
          f"{len(f1)} principal(s) bound to legacy Basic Roles (Owner/Editor)"
          if f1
          else "No legacy Basic Roles bound at project scope",
      ),
      "F1_F2_EXCESS_ADMIN": (
          len(f1) + len(f2),
          f"{len(f1) + len(f2)} over-privileged binding finding(s) across F1/F2"
          if (f1 or f2)
          else "All principals right-sized to active usage",
      ),
      "F2_UNUSED_PERMS": (
          len(f2),
          f"{len(f2)} principal(s) hold unexercised predefined permissions"
          if f2
          else "Zero unused permissions detected",
      ),
      "F3_TRANSITIVE_SA": (
          len(f3),
          f"{len(f3)} transitive SA impersonation/attachment path(s) open"
          if f3
          else "No transitive SA attachment paths present",
      ),
      "F1_F3_STANDING_ADMIN": (
          len(f1) + len(f3),
          f"{len(f1) + len(f3)} standing administrative/transitive grant(s) without JIT PAM"
          if (f1 or f3)
          else "Zero standing administrative grants",
      ),
      "F4_INACTIVE_SA": (
          len(f4),
          f"{len(f4)} dormant Service Account(s) active past 90d threshold"
          if f4
          else "Zero dormant active Service Accounts",
      ),
      "F4_F5_EXPIRED_STALE": (
          len(f4) + len(f5),
          f"{len(f4)} dormant SA(s) and {len(f5)} expired IAM condition(s) present"
          if (f4 or f5)
          else "No expired conditional bindings or dormant SAs",
      ),
      "F6_SERVICE_AGENTS": (
          len(f6),
          f"{len(f6)} Google-managed service agent(s) hold broad project roles"
          if f6
          else "Service agents cleanly scoped",
      ),
      "F7_ROLE_SPRAWL": (
          len(f7),
          f"{len(f7)} overlapping predefined role cluster(s) eligible for Disjoint Model B"
          if f7
          else "Roles partitioned cleanly",
      ),
  }
  count, detail = mapping.get(detector, (0, "Verified"))
  return {
      "current_status": "FAIL" if count > 0 else "PASS",
      "projected_status": "PASS",
      "violation_count": count,
      "finding_detail": detail,
  }


def run_compliance_mapping(
    project_id: str,
    analysis_data: Dict[str, Any],
    user_managed_key_count: int = 0,
    output_dir: Optional[Path] = None,
) -> Dict[str, Any]:
  """Maps project IAM posture to CIS, SOC 2, ISO 27001, and PCI-DSS controls."""
  findings = analysis_data.get("findings", {})
  evaluated_controls: List[Dict[str, Any]] = []
  by_framework: Dict[str, Dict[str, int]] = {}

  for ctrl in CONTROL_CATALOG:
    fw = ctrl["framework"]
    by_framework.setdefault(fw, {"total": 0, "passing_now": 0, "passing_after": 0})
    ev = _evaluate_detector(ctrl["detector"], findings, user_managed_key_count)

    by_framework[fw]["total"] += 1
    if ev["current_status"] == "PASS":
      by_framework[fw]["passing_now"] += 1
    if ev["projected_status"] == "PASS":
      by_framework[fw]["passing_after"] += 1

    evaluated_controls.append(
        {
            "framework": fw,
            "control_id": ctrl["control_id"],
            "title": ctrl["title"],
            "current_status": ev["current_status"],
            "projected_status": ev["projected_status"],
            "violation_count": ev["violation_count"],
            "finding_detail": ev["finding_detail"],
            "remediation_phase": ctrl["remediation_phase"],
            "evidence_artifact": ctrl["evidence_artifact"],
        }
    )

  framework_scorecards: List[Dict[str, Any]] = []
  total_controls = len(evaluated_controls)
  total_pass_now = sum(1 for c in evaluated_controls if c["current_status"] == "PASS")

  for fw, counts in by_framework.items():
    tot = max(counts["total"], 1)
    now_pct = round((counts["passing_now"] / tot) * 100.0, 1)
    after_pct = round((counts["passing_after"] / tot) * 100.0, 1)
    framework_scorecards.append(
        {
            "framework": fw,
            "controls_total": counts["total"],
            "controls_passing_before": counts["passing_now"],
            "controls_passing_after": counts["passing_after"],
            "score_before_pct": now_pct,
            "score_after_pct": after_pct,
        }
    )

  overall_now_pct = round((total_pass_now / max(total_controls, 1)) * 100.0, 1)

  md_lines = [
      f"# ScopeGuard Regulatory Compliance Evidence Package — `{project_id}`",
      "",
      f"- **Current Baseline Compliance Posture**: `{overall_now_pct}%` ({total_pass_now}/{total_controls} controls passing)",
      f"- **Projected Post-Remediation Posture (`P0`–`P3` + PAM + WIF)**: `100.0%` ({total_controls}/{total_controls} controls passing)",
      "",
      "## Framework Scorecards",
      "",
      "| Framework | Passing Now | Projected After Cutover | Current Score | Projected Score |",
      "| :--- | :---: | :---: | :---: | :---: |",
  ]
  for sc in framework_scorecards:
    md_lines.append(
        f"| **{sc['framework']}** | {sc['controls_passing_before']}/{sc['controls_total']} "
        f"| {sc['controls_passing_after']}/{sc['controls_total']} "
        f"| `{sc['score_before_pct']}%` | `{sc['score_after_pct']}%` |"
    )
  md_lines.extend(
      [
          "",
          "## Control-by-Control Audit Matrix",
          "",
          "| Framework | Control | Status | Violation Detail | Remediation Wave | Evidence |",
          "| :--- | :--- | :---: | :--- | :---: | :--- |",
      ]
  )
  for c in evaluated_controls:
    md_lines.append(
        f"| {c['framework']} | `{c['control_id']}` — {c['title']} | **{c['current_status']}** "
        f"| {c['finding_detail']} | `{c['remediation_phase']}` | `{c['evidence_artifact']}` |"
    )
  report_md = "\n".join(md_lines) + "\n"

  summary = {
      "total_controls_evaluated": total_controls,
      "controls_passing_before": total_pass_now,
      "controls_failing_before": total_controls - total_pass_now,
      "overall_score_before_pct": overall_now_pct,
      "overall_score_after_pct": 100.0,
      "frameworks_covered": [f["framework"] for f in framework_scorecards],
  }
  payload = {
      "framework_scorecards": framework_scorecards,
      "controls": evaluated_controls,
      "auditor_report_markdown": report_md,
  }

  if output_dir:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "compliance_matrix.json").write_text(
        json.dumps({"summary": summary, "payload": payload}, indent=2) + "\n",
        encoding="utf-8",
    )
    (output_dir / "compliance_evidence_report.md").write_text(
        report_md, encoding="utf-8"
    )

  return {"summary": summary, "payload": payload, "status": "COMPLETED"}


def main() -> int:
  parser = argparse.ArgumentParser(
      description="Map ScopeGuard IAM posture to CIS, SOC 2, ISO 27001, and PCI-DSS."
  )
  parser.add_argument("--project", required=True, help="Target GCP Project ID.")
  parser.add_argument(
      "--analysis-json",
      default="",
      help="Optional path to local analysis_results_<project>.json.",
  )
  parser.add_argument(
      "--output-dir",
      required=True,
      help="Directory to write compliance deliverables.",
  )
  add_gcs_publish_arguments(parser)
  args = parser.parse_args()

  store = GCSAssessmentStore()
  gcs_check = run_skill_gcs_preflight(args, args.project, store=store)

  analysis_data: Dict[str, Any] = {}
  key_count = 0
  prior_env: Optional[Dict[str, Any]] = None

  if gcs_check:
    prior_env = store.get_json_object(
        gcs_check["bucket"], f"{args.project}/latest.json"
    )

  if args.analysis_json and Path(args.analysis_json).exists():
    analysis_data = json.loads(
        Path(args.analysis_json).read_text(encoding="utf-8")
    )
  elif prior_env:
    analysis_data = (
        prior_env.get("modules", {})
        .get("recommender_audit", {})
        .get("payload", {})
        .get("analysis", {})
    )
    key_count = int(
        prior_env.get("modules", {})
        .get("federation_architect", {})
        .get("summary", {})
        .get("user_managed_keys_found", 0)
    )

  if not analysis_data:
    print(
        "[Error] No Recommender Audit baseline found for "
        f"'{args.project}'. Run gcp-iam-recommender-audit or scopeguard-orchestrator first.",
        file=sys.stderr,
    )
    return 1

  out_dir = Path(args.output_dir)
  mod_entry = run_compliance_mapping(
      project_id=args.project,
      analysis_data=analysis_data,
      user_managed_key_count=key_count,
      output_dir=out_dir,
  )

  publish_info = None
  if gcs_check:
    live_etag = ""
    try:
      pol = store.client.fetch_project_iam_policy(args.project)
      live_etag = pol.get("etag", "")
    except Exception:  # pylint: disable=broad-except
      live_etag = analysis_data.get("metadata", {}).get("policy_etag", "")

    publish_info = store.publish_assessment_run(
        bucket=gcs_check["bucket"],
        region=gcs_check["region"],
        project_id=args.project,
        trigger_mode="compliance-mapper",
        updated_modules={"compliance_mapper": mod_entry},
        live_policy_etag=live_etag,
        local_output_dir=out_dir,
    )

  print(
      json.dumps(
          {"compliance_summary": mod_entry["summary"], "gcs_publish": publish_info},
          indent=2,
      )
  )
  return 0


if __name__ == "__main__":
  sys.exit(main())
