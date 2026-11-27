#!/usr/bin/env python3
# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0

"""ScopeGuard Required GCP APIs Pre-Req Preflight Checker.

Verifies that the Google Cloud APIs required by a ScopeGuard skill or pipeline
stage are enabled on the target project before executing IAM scans.

Follows the same human-in-the-loop safety contract as the GCS bucket pre-check:
- Never auto-enables APIs without explicit user confirmation (`--ensure-apis`).
- Exits with structured JSON (`exit code 23` — `APIS_ENABLEMENT_REQUIRED`) when
  required APIs are disabled so the agent can ask the user to either:
    1. Enable the missing APIs (`--ensure-apis`), OR
    2. Proceed in degraded mode (`--skip-api-check`).
"""

import argparse
import json
import sys
from typing import Any, Dict, List, Optional, Sequence

from lib.gcp_client import GCPHTTPError, ScopeGuardGCPClient

EXIT_APIS_ENABLEMENT_REQUIRED = 23

API_CATALOG: Dict[str, str] = {
    "cloudresourcemanager.googleapis.com": (
        "Reads live project IAM policies (`etag`), Organization/Folder ancestry, "
        "and discovers active projects during Org/Folder sweeps."
    ),
    "iam.googleapis.com": (
        "Audits Service Accounts, static `USER_MANAGED` keys, custom roles, "
        "and testable permissions for Model A/B role synthesis."
    ),
    "recommender.googleapis.com": (
        "Fetches Active Assist 90-day IAM usage insights, inactive Service Account "
        "insights, and lateral-movement risk signals."
    ),
    "logging.googleapis.com": (
        "Samples 90-day Cloud Audit Logs for breakglass shadow replay (`0` HTTP 403 proof)."
    ),
    "orgpolicy.googleapis.com": (
        "Audits effective Organization Policy IAM constraints (`CIS 1.4`, DRS, default SA grants)."
    ),
    "securitycenter.googleapis.com": (
        "Queries live active IAM findings from Google Cloud Security Command Center (`--fetch-live-scc`)."
    ),
    "storage.googleapis.com": (
        "Publishes versioned assessment JSON snapshots and Markdown reports to the GCS assessment bucket."
    ),
}

STAGE_REQUIRED_APIS: Dict[str, List[str]] = {
    "recommender_audit": [
        "cloudresourcemanager.googleapis.com",
        "iam.googleapis.com",
        "recommender.googleapis.com",
        "logging.googleapis.com",
    ],
    "role_architect": [],
    "breakglass_simulator": [
        "logging.googleapis.com",
        "iam.googleapis.com",
    ],
    "federation_architect": [
        "iam.googleapis.com",
    ],
    "jit_pam_architect": [
        "cloudresourcemanager.googleapis.com",
    ],
    "deny_policy_architect": [
        "cloudresourcemanager.googleapis.com",
    ],
    "org_hierarchy_auditor": [
        "cloudresourcemanager.googleapis.com",
        "orgpolicy.googleapis.com",
    ],
    "gitops_pr_guardrail": [],
    "compliance_mapper": [],
    "finding_remediator": [
        "cloudresourcemanager.googleapis.com",
        "iam.googleapis.com",
    ],
}


def resolve_required_apis_for_stages(
    stages: Optional[Sequence[str]] = None,
    include_live_scc: bool = False,
    include_gcs: bool = True,
) -> List[str]:
  """Computes the ordered, deduplicated list of required GCP APIs for a run."""
  target_stages = list(stages) if stages is not None else list(STAGE_REQUIRED_APIS.keys())
  seen: set[str] = set()
  ordered: List[str] = []
  for st in target_stages:
    for api in STAGE_REQUIRED_APIS.get(st, []):
      if api not in seen:
        seen.add(api)
        ordered.append(api)
  if include_live_scc and "securitycenter.googleapis.com" not in seen:
    seen.add("securitycenter.googleapis.com")
    ordered.append("securitycenter.googleapis.com")
  if include_gcs and "storage.googleapis.com" not in seen:
    seen.add("storage.googleapis.com")
    ordered.append("storage.googleapis.com")
  return ordered


def run_skill_api_preflight(
    args: argparse.Namespace,
    project_id: str,
    required_apis: Optional[Sequence[str]] = None,
    stages: Optional[Sequence[str]] = None,
    gcp_client: Optional[ScopeGuardGCPClient] = None,
    non_blocking: bool = False,
) -> Dict[str, Any]:
  """Checks whether required GCP APIs are enabled on `project_id`.

  Returns a structured status dict. Unless `non_blocking=True` or
  `--skip-api-check` is set, exits with `EXIT_APIS_ENABLEMENT_REQUIRED` (23)
  when required APIs are disabled and `--ensure-apis` was not passed.
  """
  apis_to_check = (
      list(required_apis)
      if required_apis is not None
      else resolve_required_apis_for_stages(
          stages=stages,
          include_live_scc=bool(getattr(args, "fetch_live_scc", False)),
          include_gcs=not bool(getattr(args, "local_only", False)),
      )
  )
  if not apis_to_check or getattr(args, "skip_api_check", False):
    return {
        "ok": True,
        "status": "SKIPPED" if getattr(args, "skip_api_check", False) else "NO_APIS_REQUIRED",
        "project_id": project_id,
        "checked_apis": apis_to_check,
        "missing_apis": [],
    }

  client = gcp_client or ScopeGuardGCPClient(quota_project=project_id)
  try:
    enabled_set = client.list_enabled_services(project_id)
  except (GCPHTTPError, RuntimeError, OSError) as exc:
    # Degrade gracefully if caller lacks `serviceusage.services.list` permission
    print(
        f"[Warning] Unable to verify enabled APIs on '{project_id}' "
        f"(serviceusage.services.list): {exc}. Proceeding.",
        file=sys.stderr,
    )
    return {
        "ok": True,
        "status": "CHECK_DEGRADED",
        "project_id": project_id,
        "checked_apis": apis_to_check,
        "missing_apis": [],
        "warning": str(exc),
    }

  missing = [api for api in apis_to_check if api not in enabled_set]
  if not missing:
    return {
        "ok": True,
        "status": "READY",
        "project_id": project_id,
        "checked_apis": apis_to_check,
        "missing_apis": [],
    }

  if getattr(args, "ensure_apis", False):
    print(
        f"[Preflight] Enabling {len(missing)} required GCP API(s) on '{project_id}': "
        f"{', '.join(missing)} ...",
        file=sys.stderr,
    )
    client.enable_services(project_id, missing)
    return {
        "ok": True,
        "status": "ENABLED_AND_READY",
        "project_id": project_id,
        "checked_apis": apis_to_check,
        "enabled_now": missing,
        "missing_apis": [],
    }

  enable_cmd = (
      f"gcloud services enable {' '.join(missing)} --project={project_id} --quiet"
  )
  payload = {
      "ok": False,
      "status": "APIS_ENABLEMENT_REQUIRED",
      "project_id": project_id,
      "checked_apis": apis_to_check,
      "missing_apis": [
          {
              "service": api,
              "purpose": API_CATALOG.get(api, "Required by ScopeGuard skill."),
          }
          for api in missing
      ],
      "enable_command": enable_cmd,
      "action_required": (
          f"One or more required GCP APIs are disabled on project '{project_id}': "
          f"{', '.join(missing)}. Ask the user to confirm whether to: "
          "(1) Enable these APIs now by re-running with `--ensure-apis` "
          f"(or running `{enable_cmd}`), OR "
          "(2) Continue in degraded mode without them by re-running with `--skip-api-check`."
      ),
  }
  if non_blocking:
    return payload

  print(json.dumps(payload, indent=2))
  sys.exit(EXIT_APIS_ENABLEMENT_REQUIRED)
