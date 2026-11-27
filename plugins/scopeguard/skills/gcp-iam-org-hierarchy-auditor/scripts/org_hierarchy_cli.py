#!/usr/bin/env python3
# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0

"""Organization & Folder Hierarchy + Org Policy Constraint Auditor.

Resolves the GCP project ancestry chain (`Organization -> Folders -> Project`),
probes effective IAM Organization Policy constraints where permitted (degrading
cleanly under project-only credentials), and generates Org Policy v2 Terraform.
"""

import argparse
import json
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional
from urllib import parse as urllib_parse

PLUGIN_ROOT = Path(__file__).resolve().parents[3]
if str(PLUGIN_ROOT) not in sys.path:
  sys.path.insert(0, str(PLUGIN_ROOT))

from lib.gcp_client import GCPHTTPError, ScopeGuardGCPClient  # pylint: disable=wrong-import-position
from lib.gcs_publisher import (  # pylint: disable=wrong-import-position
    GCSAssessmentStore,
    add_gcs_publish_arguments,
    run_skill_gcs_preflight,
)

CRITICAL_IAM_CONSTRAINTS = [
    {
        "constraint": "iam.disableServiceAccountKeyCreation",
        "title": "Disable Service Account Key Creation",
        "type": "boolean",
        "rationale": "Prevents developers or scripts from minting long-lived JSON keys (`CIS 1.4`).",
    },
    {
        "constraint": "iam.automaticIamGrantsForDefaultServiceAccounts",
        "title": "Disable Automatic `roles/editor` Grants on Default Compute/AppEngine SAs",
        "type": "boolean",
        "rationale": "Prevents new projects from granting `roles/editor` to default workload identities.",
    },
    {
        "constraint": "iam.disableCrossProjectServiceAccountUsage",
        "title": "Disable Cross-Project Service Account Attachment",
        "type": "boolean",
        "rationale": "Blocks cross-project lateral service account impersonation unless explicitly exempted.",
    },
    {
        "constraint": "iam.allowedPolicyMemberDomains",
        "title": "Domain Restricted Sharing (DRS)",
        "type": "list",
        "rationale": "Restricts IAM bindings strictly to verified Google Workspace / Cloud Identity customer IDs.",
    },
]


def _probe_effective_org_policy(
    client: ScopeGuardGCPClient, project_id: str, constraint_name: str
) -> Dict[str, Any]:
  """Checks effective v2 Org Policy on the project, handling 403/404 cleanly."""
  url = (
      "https://orgpolicy.googleapis.com/v2/projects/"
      f"{urllib_parse.quote(project_id, safe='')}/policies/"
      f"{urllib_parse.quote(constraint_name, safe='')}:getEffectivePolicy"
  )
  try:
    resp = client.request_json(
        url=url,
        method="GET",
        service_key="orgpolicy",
        include_quota_project=True,
    )
    rules = resp.get("spec", {}).get("rules", [])
    enforced = any(
        r.get("enforce") is True or bool(r.get("values")) for r in rules
    )
    return {
        "inspection_mode": "LIVE_ORGPOLICY_API",
        "enforced": enforced,
        "status": "ENFORCED" if enforced else "NOT_ENFORCED",
    }
  except (GCPHTTPError, RuntimeError):
    # Fallback to v1 getEffectiveOrgPolicy on Resource Manager
    v1_url = (
        "https://cloudresourcemanager.googleapis.com/v1/projects/"
        f"{urllib_parse.quote(project_id, safe='')}:getEffectiveOrgPolicy"
    )
    try:
      resp_v1 = client.request_json(
          url=v1_url,
          method="POST",
          body={"constraint": f"constraints/{constraint_name}"},
          service_key="cloudresourcemanager",
      )
      enforced = bool(
          resp_v1.get("booleanPolicy", {}).get("enforced")
          or resp_v1.get("listPolicy", {}).get("allowedValues")
      )
      return {
          "inspection_mode": "LIVE_CRM_V1_API",
          "enforced": enforced,
          "status": "ENFORCED" if enforced else "NOT_ENFORCED",
      }
    except (GCPHTTPError, RuntimeError):
      return {
          "inspection_mode": "PROJECT_SCOPED_RECOMMENDATION",
          "enforced": False,
          "status": "VERIFY_AT_ORG_LEVEL",
      }


def run_org_hierarchy_audit(
    project_id: str,
    gcp_client: Optional[ScopeGuardGCPClient] = None,
    output_dir: Optional[Path] = None,
) -> Dict[str, Any]:
  """Resolves resource ancestry and audits critical IAM Org Policy constraints."""
  client = gcp_client or ScopeGuardGCPClient(quota_project=project_id)
  raw_ancestors = client.fetch_project_ancestry(project_id)

  # Convert bottom-up ancestry response into top-down Organization -> Folder -> Project chain
  nodes: List[Dict[str, str]] = []
  for item in reversed(raw_ancestors):
    res = item.get("resourceId", {})
    r_type = res.get("type", "resource")
    r_id = res.get("id", "")
    nodes.append(
        {
            "type": r_type,
            "id": r_id,
            "resource_name": f"{r_type}s/{r_id}",
        }
    )

  org_id = next((n["id"] for n in nodes if n["type"] == "organization"), "")
  folder_count = sum(1 for n in nodes if n["type"] == "folder")

  evaluated_constraints: List[Dict[str, Any]] = []
  enforced_count = 0
  for c in CRITICAL_IAM_CONSTRAINTS:
    probe = _probe_effective_org_policy(client, project_id, c["constraint"])
    if probe["enforced"]:
      enforced_count += 1
    evaluated_constraints.append(
        {
            "constraint": f"constraints/{c['constraint']}",
            "title": c["title"],
            "policy_type": c["type"],
            "status": probe["status"],
            "enforced": probe["enforced"],
            "inspection_mode": probe["inspection_mode"],
            "rationale": c["rationale"],
        }
    )

  tf_lines = [
      "# ScopeGuard Organization Policy Preventive Baseline (Project-Scoped Override / Org Template)",
      f"# Target Project: {project_id}" + (f" (Organization: {org_id})" if org_id else ""),
      "",
  ]
  for c in CRITICAL_IAM_CONSTRAINTS:
    if c["type"] != "boolean":
      continue
    slug = c["constraint"].replace(".", "_")
    tf_lines.extend(
        [
            f'resource "google_org_policy_policy" "{slug}" {{',
            f'  name   = "projects/{project_id}/policies/{c["constraint"]}"',
            f'  parent = "projects/{project_id}"',
            "  spec {",
            "    rules {",
            '      enforce = "TRUE"',
            "    }",
            "  }",
            "}",
            "",
        ]
    )
  org_policy_tf = "\n".join(tf_lines)

  ancestry_path_str = " -> ".join(
      f"{n['type']}:{n['id']}" for n in nodes
  ) or f"project:{project_id}"

  summary = {
      "organization_id": org_id or "standalone_or_restricted",
      "folder_depth": folder_count,
      "ancestry_path": ancestry_path_str,
      "constraints_evaluated": len(evaluated_constraints),
      "constraints_enforced": enforced_count,
      "constraints_needing_attention": len(evaluated_constraints) - enforced_count,
  }
  payload = {
      "ancestry_nodes": nodes,
      "ancestry_path": ancestry_path_str,
      "org_policy_constraints": evaluated_constraints,
      "org_policy_terraform_hcl": org_policy_tf,
  }

  if output_dir:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "org_hierarchy_audit.json").write_text(
        json.dumps({"summary": summary, "payload": payload}, indent=2) + "\n",
        encoding="utf-8",
    )
    (output_dir / "org_policies.tf").write_text(org_policy_tf, encoding="utf-8")

  return {"summary": summary, "payload": payload, "status": "COMPLETED"}


def main() -> int:
  parser = argparse.ArgumentParser(
      description="Audit GCP Organization/Folder ancestry and IAM Org Policies."
  )
  parser.add_argument("--project", required=True, help="Target GCP Project ID.")
  parser.add_argument(
      "--output-dir",
      required=True,
      help="Directory to write hierarchy and Org Policy deliverables.",
  )
  add_gcs_publish_arguments(parser)
  args = parser.parse_args()

  store = GCSAssessmentStore()
  gcs_check = run_skill_gcs_preflight(args, args.project, store=store)

  out_dir = Path(args.output_dir)
  mod_entry = run_org_hierarchy_audit(
      project_id=args.project,
      gcp_client=store.client,
      output_dir=out_dir,
  )

  publish_info = None
  if gcs_check:
    live_etag = ""
    try:
      pol = store.client.fetch_project_iam_policy(args.project)
      live_etag = pol.get("etag", "")
    except Exception:  # pylint: disable=broad-except
      pass
    publish_info = store.publish_assessment_run(
        bucket=gcs_check["bucket"],
        region=gcs_check["region"],
        project_id=args.project,
        trigger_mode="org-hierarchy-auditor",
        updated_modules={"org_hierarchy_auditor": mod_entry},
        live_policy_etag=live_etag,
        local_output_dir=out_dir,
    )

  print(
      json.dumps(
          {"org_hierarchy_summary": mod_entry["summary"], "gcs_publish": publish_info},
          indent=2,
      )
  )
  return 0


if __name__ == "__main__":
  sys.exit(main())
