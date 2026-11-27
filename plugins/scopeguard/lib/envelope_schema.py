#!/usr/bin/env python3
# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0

"""Unified ScopeGuard v2.x Assessment Envelope schema and staleness merger.

Combines outputs across all 10 ScopeGuard skills into a single self-contained,
versioned JSON run artifact (`<project_id>/runs/<UTC_timestamp>_<mode>_<id>.json`).
Supports partial single-skill runs via carry-forward merging while explicitly
flagging non-executed modules as `CARRIED_FORWARD_PROBABLY_STALE` or
`STALE_POLICY_DRIFT` (when the project's live IAM policy `etag` has changed).
"""

import copy
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from .recommendation_synthesizer import enrich_envelope_with_recommendations

# Current envelope / artifact schema version written by this release.
# 2.1 adds Model A persona roles, Model B capability bundles + verification,
# run-level manifest/exports (ART-5..ART-14). Readers stay tolerant of 2.0.
SCHEMA_VERSION = "2.1"

# Every schema version that readers (synthesizer, portal, exports) accept.
SUPPORTED_SCHEMA_VERSIONS = ("2.0", "2.1")


def is_supported_schema(version: Any) -> bool:
  """Returns True when an envelope's `schema_version` can be rendered.

  Unknown or missing versions are treated as legacy 2.0 envelopes by callers;
  this helper only reports whether the version is explicitly recognised.

  Args:
    version: The raw `schema_version` value from a JSON document.

  Returns:
    True for "2.0", "2.1" and their "x.y.z" patch variants.
  """
  raw = str(version or "").strip()
  major_minor = ".".join(raw.split(".")[:2])
  return major_minor in SUPPORTED_SCHEMA_VERSIONS

# Canonical registry of the 9 analytical/architectural module slots managed by
# the orchestrator and individual skills.
MODULE_REGISTRY: Dict[str, str] = {
    "recommender_audit": "gcp-iam-recommender-audit",
    "role_architect": "gcp-iam-role-architect",
    "breakglass_simulator": "gcp-iam-breakglass-simulator",
    "compliance_mapper": "gcp-iam-compliance-mapper",
    "jit_pam_architect": "gcp-iam-jit-pam-architect",
    "federation_architect": "gcp-iam-federation-architect",
    "gitops_pr_guardrail": "gcp-iam-gitops-pr-guardrail",
    "deny_policy_architect": "gcp-iam-deny-policy-architect",
    "org_hierarchy_auditor": "gcp-iam-org-hierarchy-auditor",
    "finding_remediator": "gcp-iam-finding-remediator",
}


def utc_now_iso() -> str:
  """Returns current UTC timestamp in ISO-8601 format."""
  return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def generate_run_identifiers(trigger_mode: str) -> Dict[str, str]:
  """Generates chronologically sortable UTC run ID and GCS object filename."""
  now = datetime.now(timezone.utc)
  compact_ts = now.strftime("%Y%m%dT%H%M%SZ")
  iso_ts = now.strftime("%Y-%m-%dT%H:%M:%SZ")
  safe_mode = "".join(
      ch if (ch.isalnum() or ch == "-") else "-" for ch in trigger_mode.lower()
  ).strip("-") or "skill-run"
  short_uid = uuid.uuid4().hex[:6]
  run_id = f"{compact_ts}_{safe_mode}_{short_uid}"
  return {
      "run_id": run_id,
      "timestamp_utc": iso_ts,
      "compact_timestamp": compact_ts,
      "filename": f"{run_id}.json",
  }


def build_module_entry(
    module_key: str,
    summary: Dict[str, Any],
    payload: Dict[str, Any],
    run_id: str,
    timestamp_utc: str,
    live_policy_etag: str = "",
    status: str = "COMPLETED",
) -> Dict[str, Any]:
  """Constructs a fresh module envelope entry for a newly executed skill."""
  skill_name = MODULE_REGISTRY.get(module_key, module_key)
  return {
      "module_key": module_key,
      "skill_name": skill_name,
      "status": status,
      "freshness": "CURRENT",
      "is_potentially_stale": False,
      "stale_warning": None,
      "generated_at": timestamp_utc,
      "source_run_id": run_id,
      "policy_etag_at_generation": live_policy_etag,
      "summary": summary,
      "payload": payload,
  }


def mark_carried_forward_module(
    prior_entry: Dict[str, Any],
    live_policy_etag: str = "",
) -> Dict[str, Any]:
  """Clones a module from a prior run and marks it as potentially stale."""
  cloned = copy.deepcopy(prior_entry)
  orig_ts = cloned.get("generated_at", "prior run")
  orig_etag = cloned.get("policy_etag_at_generation", "")

  if live_policy_etag and orig_etag and live_policy_etag != orig_etag:
    cloned["freshness"] = "STALE_POLICY_DRIFT"
    cloned["is_potentially_stale"] = True
    cloned["stale_warning"] = (
        f"Probably stale: Project IAM policy etag changed ({orig_etag} -> "
        f"{live_policy_etag}) since this skill ran at {orig_ts}."
    )
  else:
    cloned["freshness"] = "CARRIED_FORWARD_PROBABLY_STALE"
    cloned["is_potentially_stale"] = True
    cloned["stale_warning"] = (
        f"Carried forward from prior run ({orig_ts}) — this skill was not "
        "re-executed in the latest run and its output is probably stale."
    )
  return cloned


def assemble_assessment_envelope(
    project_id: str,
    trigger_mode: str,
    updated_modules: Dict[str, Dict[str, Any]],
    prior_envelope: Optional[Dict[str, Any]] = None,
    live_policy_etag: str = "",
    bucket_name: str = "",
    bucket_region: str = "",
) -> Dict[str, Any]:
  """Builds a complete v2.x assessment envelope with carry-forward staleness tracking.

  Args:
    project_id: Target GCP project ID analyzed.
    trigger_mode: E.g., `full-suite` or individual skill name.
    updated_modules: Mapping of `module_key -> {"summary": ..., "payload": ..., "status": ...}`.
    prior_envelope: Previous `latest.json` envelope for this project (if any).
    live_policy_etag: Current project IAM policy etag observed during this run.
    bucket_name: Target GCS bucket storing the run.
    bucket_region: Target GCS bucket region.

  Returns:
    Self-contained JSON-serializable Assessment Envelope dict.
  """
  ids = generate_run_identifiers(trigger_mode)
  run_id = ids["run_id"]
  ts_utc = ids["timestamp_utc"]
  object_path = f"{project_id}/runs/{ids['filename']}"

  # Infer live_policy_etag from recommender_audit output if not passed explicitly
  if not live_policy_etag:
    audit_upd = updated_modules.get("recommender_audit", {})
    live_policy_etag = (
        audit_upd.get("payload", {})
        .get("analysis", {})
        .get("metadata", {})
        .get("policy_etag", "")
    )

  prior_modules = (prior_envelope or {}).get("modules", {})
  merged_modules: Dict[str, Any] = {}
  triggered_skills: List[str] = []

  for mod_key, skill_name in MODULE_REGISTRY.items():
    if mod_key in updated_modules:
      mod_data = updated_modules[mod_key]
      merged_modules[mod_key] = build_module_entry(
          module_key=mod_key,
          summary=mod_data.get("summary", {}),
          payload=mod_data.get("payload", {}),
          run_id=run_id,
          timestamp_utc=ts_utc,
          live_policy_etag=live_policy_etag,
          status=mod_data.get("status", "COMPLETED"),
      )
      triggered_skills.append(skill_name)
    elif mod_key in prior_modules and prior_modules[mod_key].get("status") != "NOT_RUN":
      merged_modules[mod_key] = mark_carried_forward_module(
          prior_modules[mod_key],
          live_policy_etag=live_policy_etag,
      )
    else:
      merged_modules[mod_key] = {
          "module_key": mod_key,
          "skill_name": skill_name,
          "status": "NOT_RUN",
          "freshness": "NOT_RUN",
          "is_potentially_stale": False,
          "stale_warning": "Skill has not been executed for this project yet.",
          "generated_at": None,
          "source_run_id": None,
          "policy_etag_at_generation": None,
          "summary": {},
          "payload": {},
      }

  stale_modules = [
      k for k, v in merged_modules.items() if v.get("is_potentially_stale")
  ]
  current_modules = [
      k for k, v in merged_modules.items() if v.get("freshness") == "CURRENT"
  ]

  envelope = {
      "schema_version": SCHEMA_VERSION,
      "run_id": run_id,
      "project_id": project_id,
      "timestamp_utc": ts_utc,
      "trigger_mode": trigger_mode,
      "triggered_skills": triggered_skills,
      "live_policy_etag": live_policy_etag,
      "freshness_overview": {
          "current_modules": current_modules,
          "potentially_stale_modules": stale_modules,
          "not_run_modules": [
              k for k, v in merged_modules.items() if v.get("status") == "NOT_RUN"
          ],
          "has_stale_carried_forward_data": bool(stale_modules),
      },
      "gcs_metadata": {
          "bucket": bucket_name,
          "region": bucket_region,
          "object_path": object_path,
          "latest_pointer_path": f"{project_id}/latest.json",
      },
      "modules": merged_modules,
  }
  return enrich_envelope_with_recommendations(envelope)
