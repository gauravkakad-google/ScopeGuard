#!/usr/bin/env python3
# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0

"""Dry-run Cloud Audit Log replay simulator for proposed IAM custom roles.

Replays observed Cloud Audit Log `methodName` events and Active Assist exercised
permissions against proposed Model A and Disjoint Model B custom roles to verify
zero production breakages (`simulated_403_count == 0`) prior to Phase P2 cutover.
"""

import argparse
from collections import defaultdict
import json
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional, Set

PLUGIN_ROOT = Path(__file__).resolve().parents[3]
if str(PLUGIN_ROOT) not in sys.path:
  sys.path.insert(0, str(PLUGIN_ROOT))

from lib.gcp_client import ScopeGuardGCPClient  # pylint: disable=wrong-import-position
from lib.gcs_publisher import (  # pylint: disable=wrong-import-position
    GCSAssessmentStore,
    add_gcs_publish_arguments,
    run_skill_gcs_preflight,
)

# Deterministic mapping from common Cloud Audit Log methodName patterns to IAM permissions
AUDIT_METHOD_TO_PERMISSION: Dict[str, str] = {
    "storage.objects.get": "storage.objects.get",
    "storage.objects.list": "storage.objects.list",
    "storage.objects.create": "storage.objects.create",
    "storage.buckets.get": "storage.buckets.get",
    "storage.buckets.list": "storage.buckets.list",
    "google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion": (
        "secretmanager.versions.access"
    ),
    "google.cloud.secretmanager.v1.SecretManagerService.GetSecret": (
        "secretmanager.secrets.get"
    ),
    "google.cloud.secretmanager.v1.SecretManagerService.ListSecrets": (
        "secretmanager.secrets.list"
    ),
    "google.cloud.bigquery.v2.JobService.InsertJob": "bigquery.jobs.create",
    "google.cloud.bigquery.v2.DatasetService.GetDataset": "bigquery.datasets.get",
    "google.cloud.bigquery.v2.TableService.GetTable": "bigquery.tables.get",
    "google.cloud.bigquery.v2.TableDataService.List": "bigquery.tables.getData",
    "jobservice.insert": "bigquery.jobs.create",
    "tableservice.get": "bigquery.tables.get",
    "tabledata.list": "bigquery.tables.getData",
    "google.cloud.aiplatform.v1.PredictionService.GenerateContent": (
        "aiplatform.endpoints.predict"
    ),
    "google.cloud.aiplatform.v1.PredictionService.StreamGenerateContent": (
        "aiplatform.endpoints.predict"
    ),
    "google.cloud.aiplatform.v1.PredictionService.Predict": (
        "aiplatform.endpoints.predict"
    ),
    "google.cloud.run.v2.Services.GetService": "run.services.get",
    "google.cloud.run.v2.Services.ListServices": "run.services.list",
    "google.cloud.run.v2.Services.UpdateService": "run.services.update",
    "google.devtools.cloudbuild.v1.CloudBuild.CreateBuild": (
        "cloudbuild.builds.create"
    ),
    "google.logging.v2.LoggingServiceV2.WriteLogEntries": (
        "logging.logEntries.create"
    ),
    "google.logging.v2.LoggingServiceV2.ListLogEntries": (
        "logging.logEntries.list"
    ),
    "google.iam.admin.v1.GetServiceAccount": "iam.serviceAccounts.get",
    "google.iam.admin.v1.ListServiceAccounts": "iam.serviceAccounts.list",
    "SetIamPolicy": "resourcemanager.projects.setIamPolicy",
    "GetIamPolicy": "resourcemanager.projects.getIamPolicy",
}


# GCP services where Data Access audit logs (DATA_READ / DATA_WRITE) are
# disabled by default; missing auditConfigs on these services means zero
# observed log entries cannot prove zero production breakage.
DATA_ACCESS_SENSITIVE_SERVICES: Dict[str, str] = {
    "storage": "storage.googleapis.com",
    "secretmanager": "secretmanager.googleapis.com",
    "cloudkms": "cloudkms.googleapis.com",
    "aiplatform": "aiplatform.googleapis.com",
    "bigquery": "bigquery.googleapis.com",
    "spanner": "spanner.googleapis.com",
    "bigtable": "bigtable.googleapis.com",
    "datastore": "datastore.googleapis.com",
    "firestore": "firestore.googleapis.com",
    "pubsub": "pubsub.googleapis.com",
    "cloudsql": "sqladmin.googleapis.com",
    "sql": "sqladmin.googleapis.com",
}


def evaluate_audit_log_confidence(
    policy_data: Optional[Dict[str, Any]],
    proposed_permissions: Set[str],
) -> Dict[str, Any]:
  """Evaluates Data Access audit-log visibility for proposed custom roles.

  Inspects ``policy_data.get("auditConfigs", [])`` (including ``allServices``
  wildcard) against the data, secret, KMS, and AI services touched by the
  proposed custom roles where GCP disables Data Access logs by default.

  Args:
    policy_data: Project IAM policy dict (may be None).
    proposed_permissions: Union of permissions across proposed custom roles.

  Returns:
    Dict with ``audit_log_confidence`` (HIGH/MEDIUM/LOW),
    ``missing_data_access_services`` (sorted list),
    ``touched_data_access_services`` (sorted list), and
    ``audit_log_confidence_warning`` (operator warning string or empty).
  """
  touched_services: Set[str] = set()
  for perm in proposed_permissions or set():
    prefix = str(perm).split(".", 1)[0].strip()
    if prefix in DATA_ACCESS_SENSITIVE_SERVICES:
      touched_services.add(DATA_ACCESS_SENSITIVE_SERVICES[prefix])

  audit_configs = (
      policy_data.get("auditConfigs", [])
      if isinstance(policy_data, dict)
      else []
  ) or []

  log_types_by_service: Dict[str, Set[str]] = defaultdict(set)
  for cfg in audit_configs:
    if not isinstance(cfg, dict):
      continue
    svc = str(cfg.get("service", "")).strip()
    if not svc:
      continue
    for entry in cfg.get("auditLogConfigs", []) or []:
      if isinstance(entry, dict):
        lt = str(entry.get("logType", "")).strip().upper()
        if lt:
          log_types_by_service[svc].add(lt)

  all_svc_types = log_types_by_service.get("allServices", set())
  all_services_full = {"DATA_READ", "DATA_WRITE"}.issubset(all_svc_types)

  missing_services: List[str] = []
  any_partial_or_admin = False
  for svc in sorted(touched_services):
    eff = log_types_by_service.get(svc, set()) | all_svc_types
    if {"DATA_READ", "DATA_WRITE"}.issubset(eff):
      any_partial_or_admin = True
    else:
      missing_services.append(svc)
      if eff & {"DATA_READ", "DATA_WRITE", "ADMIN_READ"}:
        any_partial_or_admin = True

  if not audit_configs:
    confidence = "LOW"
  elif all_services_full:
    confidence = "HIGH"
    missing_services = []
  elif touched_services:
    if not missing_services:
      confidence = "HIGH"
    elif any_partial_or_admin or (all_svc_types & {"DATA_READ", "DATA_WRITE", "ADMIN_READ"}):
      confidence = "MEDIUM"
    else:
      confidence = "LOW"
  else:
    # No data/secret/AI services touched, but auditConfigs exist.
    any_enabled = any(
        bool(lts & {"DATA_READ", "DATA_WRITE", "ADMIN_READ"})
        for lts in log_types_by_service.values()
    )
    confidence = "MEDIUM" if any_enabled else "LOW"

  warning = ""
  if confidence != "HIGH":
    missing_desc = (
        ", ".join(missing_services)
        if missing_services
        else "project auditConfigs absent or incomplete"
    )
    warning = (
        f"WARNING ({confidence} audit-log confidence): GCP disables Data Access "
        f"audit logs by default. Missing DATA_READ/DATA_WRITE coverage for: "
        f"{missing_desc}. Zero simulated 403s does NOT prove zero production "
        f"breakage — use CANARY_DUAL_BIND (bind new custom role alongside "
        f"existing role, monitor telemetry, then remove old role) or enable "
        f"Data Access audit logs before direct cutover."
    )

  return {
      "audit_log_confidence": confidence,
      "missing_data_access_services": sorted(missing_services),
      "touched_data_access_services": sorted(touched_services),
      "audit_log_confidence_warning": warning,
  }


def _render_simulation_markdown(
    project_id: str,
    summary: Dict[str, Any],
    principal_replays: List[Dict[str, Any]],
) -> str:
  """Renders the breakglass simulation Markdown report with confidence warnings."""
  missing = summary.get("missing_data_access_services") or []
  lines = [
      f"# Breakglass Policy Replay Simulation Report: `{project_id}`",
      "",
      "| Metric | Value |",
      "| :--- | :--- |",
      f"| Cutover Verdict | `{summary.get('cutover_verdict', '')}` |",
      f"| Recommended Cutover Strategy | **`{summary.get('recommended_cutover', '')}`** |",
      f"| Audit-Log Confidence | **`{summary.get('audit_log_confidence', 'LOW')}`** |",
      f"| Missing Data Access Services | {', '.join(f'`{s}`' for s in missing) if missing else '*None*'} |",
      f"| Lookback Window | `{summary.get('lookback_days', 90)}` days |",
      f"| Principals Simulated | `{summary.get('principals_simulated', 0)}` |",
      f"| Simulated HTTP 403 Denials | `{summary.get('simulated_403_denials', 0)}` |",
      f"| Replay Pass Rate | `{summary.get('replay_pass_rate_pct', 100.0)}%` |",
      "",
  ]
  warn = summary.get("audit_log_confidence_warning")
  if warn:
    lines += [
        f"> **Operator Warning**: {warn}",
        "",
    ]
  lines += [
      "## Per-Principal Replay Results",
      "",
      "| Principal | Phase | Proposed Role | Observed Perms | Simulated 403s | Coverage | Verdict |",
      "| :--- | :---: | :--- | :---: | :---: | :---: | :--- |",
  ]
  for r in principal_replays:
    lines.append(
        f"| `{r['principal']}` | `{r['remediation_phase']}` | "
        f"`{r['proposed_model_a_role']}` | `{r['observed_distinct_permissions']}` | "
        f"`{r['simulated_403_denials']}` | `{r['replay_coverage_pct']}%` | `{r['verdict']}` |"
    )
  return "\n".join(lines) + "\n"


def map_audit_entry_to_permissions(entry: Dict[str, Any]) -> Set[str]:
  """Extracts required IAM permissions from a Cloud Audit Log entry."""
  perms: Set[str] = set()
  proto = entry.get("protoPayload", {})
  if not isinstance(proto, dict):
    return perms

  # 1. Explicit authorizationInfo permissions recorded by GCP IAM
  for auth in proto.get("authorizationInfo", []) or []:
    if isinstance(auth, dict) and auth.get("granted") is not False:
      perm = auth.get("permission", "").strip()
      if perm:
        perms.add(perm)

  # 2. Fallback deterministic methodName mapping
  method_name = proto.get("methodName", "").strip()
  if method_name in AUDIT_METHOD_TO_PERMISSION:
    perms.add(AUDIT_METHOD_TO_PERMISSION[method_name])
  return perms


def run_breakglass_simulation(
    project_id: str,
    analysis_data: Dict[str, Any],
    bundle_data: Optional[Dict[str, Any]] = None,
    lookback_days: int = 90,
    gcp_client: Optional[ScopeGuardGCPClient] = None,
    output_dir: Optional[Path] = None,
    audit_bq_table: str = "",
    max_per_principal: int = 250,
    policy_data: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
  """Executes dry-run shadow replay against proposed Model A and Model B roles.

  Supports two production telemetry backends:
  1. BigQuery / Cloud Logging Log Analytics (`audit_bq_table`) -> 100% 90-day coverage.
  2. Per-principal paginated Cloud Logging queries -> avoids noisy-neighbor drowning.

  Also evaluates project IAM ``auditConfigs`` visibility (from ``policy_data``
  or ``bundle_data["iam_policy"]``) so operators never mistake disabled Data
  Access audit logs for proof of zero production breakage.
  """
  client = gcp_client or ScopeGuardGCPClient(quota_project=project_id)

  observed_by_principal: Dict[str, Set[str]] = defaultdict(set)
  call_counts_by_principal: Dict[str, int] = defaultdict(int)
  audit_entries: List[Dict[str, Any]] = []
  telemetry_source = "cloud_logging_per_principal_paginated"
  sampling_coverage_note = (
      f"Per-principal paginated Cloud Audit Logs (up to {max_per_principal} granted entries/principal "
      f"over {lookback_days}d) combined with Active Assist 90d exercised permissions. "
      "For high-volume production projects, pass --audit-bq-table=<project>.<dataset>._AllLogs "
      "for 100% 90-day SQL aggregation."
  )

  # Tier 1: 100% 90-day BigQuery / Cloud Logging Log Analytics aggregation
  bq_rows: List[Dict[str, Any]] = []
  if audit_bq_table:
    bq_rows = client.query_bigquery_audit_permissions(
        project_id=project_id,
        bq_table=audit_bq_table,
        freshness_days=lookback_days,
    )
    if bq_rows:
      telemetry_source = "bigquery_log_analytics_100pct"
      sampling_coverage_note = (
          f"100% {lookback_days}-day Cloud Audit Log aggregation via BigQuery table `{audit_bq_table}` "
          f"({len(bq_rows)} distinct principal-permission pairs)."
      )
      for row in bq_rows:
        email = row["principal_email"]
        member = (
            f"serviceAccount:{email}"
            if email.endswith(".gserviceaccount.com")
            else f"user:{email}"
        )
        observed_by_principal[member].add(row["permission"])
        call_counts_by_principal[member] += int(row.get("call_count") or 1)

  # Tier 2: Per-principal paginated Cloud Audit Logs (prevents noisy-neighbor drowning)
  if not bq_rows:
    target_principals = [
        pm.get("principal", "")
        for pm in analysis_data.get("principal_mappings", [])
        if (pm.get("taxonomy") or pm.get("category", "")) != "Google-Managed Service Agents"
        and pm.get("principal")
    ]
    if target_principals:
      audit_entries = client.fetch_audit_logs_per_principal(
          project_id=project_id,
          principal_emails=target_principals,
          max_per_principal=max_per_principal,
          freshness_days=lookback_days,
      )
    if bundle_data and bundle_data.get("audit_logs_sample"):
      audit_entries.extend(bundle_data.get("audit_logs_sample", []))
    elif bundle_data and bundle_data.get("audit_logs"):
      audit_entries.extend(bundle_data.get("audit_logs", []))
    if not audit_entries:
      audit_entries = client.fetch_cloud_audit_logs(
          project_id, max_entries=max(500, max_per_principal), freshness_days=lookback_days
      )

    # Seed from live Cloud Audit Log entries
    for entry in audit_entries:
      proto = entry.get("protoPayload", {})
      if not isinstance(proto, dict):
        continue
      email = (
          proto.get("authenticationInfo", {}).get("principalEmail", "").strip()
      )
      if not email:
        continue
      member = (
          f"serviceAccount:{email}"
          if email.endswith(".gserviceaccount.com")
          else f"user:{email}"
      )
      mapped_perms = map_audit_entry_to_permissions(entry)
      if mapped_perms:
        observed_by_principal[member].update(mapped_perms)
        call_counts_by_principal[member] += 1

  # Combine with Active Assist 90d exercised permissions from analysis_results
  for rec in analysis_data.get("policy_recommendations", []):
    member = rec.get("principal", "")
    exercised = rec.get("exercised_permissions", [])
    if member and exercised:
      observed_by_principal[member].update(exercised)
      call_counts_by_principal[member] = max(
          call_counts_by_principal[member], len(exercised) * 14
      )

  model_a_roles = analysis_data.get("custom_roles_model_a", {})
  model_b_roles = analysis_data.get("custom_roles_model_b_disjoint", {})
  model_a_to_b = analysis_data.get("model_a_to_b_map", {})

  # Build lookup from GCP role_id (e.g., customProjectAdminRecommenderLP) -> dict key
  role_id_to_model_a_key: Dict[str, str] = {}
  for k, spec in model_a_roles.items():
    rid = spec.get("role_id", "")
    if rid:
      role_id_to_model_a_key[rid] = k
    role_id_to_model_a_key[k] = k

  principal_replays: List[Dict[str, Any]] = []
  total_replayed_ops = 0
  total_simulated_403 = 0

  for pm in analysis_data.get("principal_mappings", []):
    principal = pm.get("principal", "")
    taxonomy = pm.get("taxonomy") or pm.get("category", "")
    if taxonomy == "Google-Managed Service Agents":
      continue

    target_mapping = str(pm.get("target_mapping", ""))
    model_a_id = pm.get("model_a_custom_role")
    if not model_a_id and ":" in target_mapping:
      cand_rid = target_mapping.split(":", 1)[1].strip().split(" ", 1)[0]
      model_a_id = role_id_to_model_a_key.get(cand_rid)
    elif model_a_id and model_a_id not in model_a_roles:
      model_a_id = role_id_to_model_a_key.get(model_a_id)

    model_b_ids = list(pm.get("model_b_disjoint_roles", []) or [])
    if not model_b_ids and model_a_id and model_a_id in model_a_to_b:
      mb_ref = model_a_to_b[model_a_id]
      model_b_ids = [mb_ref] if isinstance(mb_ref, str) else list(mb_ref or [])

    action = pm.get("recommended_action") or pm.get("remediation_action", target_mapping)

    # Determine proposed permission set after cutover
    proposed_perms: Set[str] = set()
    if model_a_id and model_a_id in model_a_roles:
      proposed_perms.update(
          model_a_roles[model_a_id].get("includedPermissions", [])
      )
    for mb_id in model_b_ids:
      if mb_id in model_b_roles:
        proposed_perms.update(
            model_b_roles[mb_id].get("includedPermissions", [])
        )

    observed_perms = sorted(observed_by_principal.get(principal, set()))
    # Strip any permissions that were already excluded because GCP marks them NOT_SUPPORTED
    stripped_unsupported: Set[str] = set()
    if model_a_id and model_a_id in model_a_roles:
      stripped_unsupported.update(
          model_a_roles[model_a_id].get("strippedUnsupportedPermissions", [])
      )

    testable_observed = [
        p for p in observed_perms if p not in stripped_unsupported
    ]
    ops_count = call_counts_by_principal.get(
        principal, len(testable_observed) * 10
    )

    if not model_a_id and not model_b_ids:
      # Principal is either untouched (already minimal) or inactive SA slated for disablement
      is_inactive = "Disable" in action or "inactive" in action.lower()
      uncovered = testable_observed if is_inactive else []
      verdict = (
          "SAFE_ZERO_ACTIVITY_DISABLE"
          if is_inactive and not uncovered
          else ("RETAINED_AS_IS" if not is_inactive else "REVIEW_RECENT_CALLS")
      )
    else:
      uncovered = [p for p in testable_observed if p not in proposed_perms]
      verdict = "PASS_ZERO_BREAKAGE" if not uncovered else "GAP_DETECTED"

    denied_ops = len(uncovered)
    total_replayed_ops += ops_count
    total_simulated_403 += denied_ops
    coverage_pct = (
        100.0
        if not testable_observed
        else round(
            ((len(testable_observed) - len(uncovered)) / len(testable_observed))
            * 100.0,
            2,
        )
    )

    sample_perm = (
        testable_observed[0]
        if testable_observed
        else (sorted(proposed_perms)[0] if proposed_perms else "resourcemanager.projects.get")
    )
    principal_email = principal.split(":", 1)[-1]
    troubleshoot_cmd = (
        f"gcloud policy-troubleshoot iam "
        f"//cloudresourcemanager.googleapis.com/projects/{project_id} "
        f"--principal-email={principal_email} "
        f"--permission={sample_perm} --quiet"
    )

    principal_replays.append(
        {
            "principal": principal,
            "taxonomy": taxonomy,
            "remediation_phase": pm.get("remediation_phase", "P2"),
            "proposed_model_a_role": model_a_id or "N/A (No Custom Role Needed)",
            "proposed_model_b_roles": model_b_ids,
            "replayed_api_calls": ops_count,
            "observed_distinct_permissions": len(testable_observed),
            "proposed_role_permissions": len(proposed_perms),
            "uncovered_permissions": uncovered,
            "simulated_403_denials": denied_ops,
            "replay_coverage_pct": coverage_pct,
            "verdict": verdict,
            "troubleshoot_cli": troubleshoot_cmd,
        }
    )

  overall_status = (
      "READY_FOR_ZERO_DOWNTIME_CUTOVER"
      if total_simulated_403 == 0
      else "HOLD_REQUIRES_PERMISSION_DELTA"
  )

  # Evaluate Data Access audit-log visibility against services touched by the
  # proposed custom roles (falls back to bundle["iam_policy"] when policy_data
  # is not explicitly passed).
  effective_policy = (
      policy_data
      if policy_data is not None
      else (bundle_data.get("iam_policy") if isinstance(bundle_data, dict) else None)
  )
  proposed_all_perms: Set[str] = set()
  for spec in model_a_roles.values():
    proposed_all_perms.update(spec.get("includedPermissions", []) or [])
  for spec in model_b_roles.values():
    proposed_all_perms.update(spec.get("includedPermissions", []) or [])
  if not proposed_all_perms:
    for obs_perms in observed_by_principal.values():
      proposed_all_perms.update(obs_perms)

  confidence_info = evaluate_audit_log_confidence(effective_policy, proposed_all_perms)
  audit_log_confidence = confidence_info["audit_log_confidence"]
  missing_data_access_services = confidence_info["missing_data_access_services"]
  audit_log_confidence_warning = confidence_info["audit_log_confidence_warning"]

  if total_simulated_403 > 0:
    recommended_cutover = "HOLD"
  elif audit_log_confidence == "HIGH":
    recommended_cutover = "DIRECT"
  else:
    recommended_cutover = "CANARY_DUAL_BIND"

  summary = {
      "lookback_days": lookback_days,
      "telemetry_source": telemetry_source,
      "sampling_coverage_note": sampling_coverage_note,
      "principals_simulated": len(principal_replays),
      "audit_log_entries_sampled": len(bq_rows) if bq_rows else len(audit_entries),
      "total_replayed_operations": total_replayed_ops,
      "simulated_403_denials": total_simulated_403,
      "replay_pass_rate_pct": (
          100.0
          if total_replayed_ops == 0
          else round(
              ((total_replayed_ops - total_simulated_403) / max(total_replayed_ops, 1))
              * 100.0,
              2,
          )
      ),
      "cutover_verdict": overall_status,
      "audit_log_confidence": audit_log_confidence,
      "missing_data_access_services": missing_data_access_services,
      "recommended_cutover": recommended_cutover,
      "audit_log_confidence_warning": audit_log_confidence_warning,
  }

  simulator_commands_sh = "\n".join(
      [
          "#!/usr/bin/env bash",
          "# ScopeGuard Pre-Cutover Policy Troubleshooter & Simulator Commands",
          "set -euo pipefail",
          f'PROJECT_ID="{project_id}"',
          "",
      ]
      + [r["troubleshoot_cli"] for r in principal_replays[:10]]
  ) + "\n"

  report_markdown = _render_simulation_markdown(project_id, summary, principal_replays)

  payload = {
      "cutover_verdict": overall_status,
      "audit_log_confidence": audit_log_confidence,
      "missing_data_access_services": missing_data_access_services,
      "recommended_cutover": recommended_cutover,
      "audit_log_confidence_warning": audit_log_confidence_warning,
      "lookback_days": lookback_days,
      "principal_replays": principal_replays,
      "verification_script_sh": simulator_commands_sh,
      "report_markdown": report_markdown,
  }

  if output_dir:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "breakglass_simulation.json").write_text(
        json.dumps({"summary": summary, "payload": payload}, indent=2) + "\n",
        encoding="utf-8",
    )
    (output_dir / "verify_policy_troubleshooter.sh").write_text(
        simulator_commands_sh, encoding="utf-8"
    )
    (output_dir / "breakglass_simulation_report.md").write_text(
        report_markdown, encoding="utf-8"
    )

  return {"summary": summary, "payload": payload, "status": "COMPLETED"}


def main() -> int:
  parser = argparse.ArgumentParser(
      description="Replay Cloud Audit Logs against proposed Model A/B custom roles."
  )
  parser.add_argument("--project", required=True, help="Target GCP Project ID.")
  parser.add_argument(
      "--lookback-days",
      type=int,
      default=90,
      help="Historical replay window in days (default: 90).",
  )
  parser.add_argument(
      "--analysis-json",
      default="",
      help="Optional path to local analysis_results_<project>.json.",
  )
  parser.add_argument(
      "--bundle-json",
      default="",
      help="Optional path to local audit_bundle_<project>.json.",
  )
  parser.add_argument(
      "--policy-json",
      default="",
      help="Optional path to local iam_policy_backup_<project>.json for auditConfigs visibility check.",
  )
  parser.add_argument(
      "--output-dir",
      required=True,
      help="Directory to write simulation results.",
  )
  parser.add_argument(
      "--audit-bq-table",
      default="",
      help=(
          "Optional BigQuery / Cloud Logging Log Analytics table for 100%% 90-day "
          "audit log coverage (e.g. my-project.global._Default._AllLogs)."
      ),
  )
  parser.add_argument(
      "--log-limit",
      type=int,
      default=250,
      help="Max paginated Cloud Audit Log entries per principal when --audit-bq-table is not set (default: 250).",
  )
  add_gcs_publish_arguments(parser)
  args = parser.parse_args()

  store = GCSAssessmentStore()
  gcs_check = run_skill_gcs_preflight(args, args.project, store=store)

  analysis_data: Dict[str, Any] = {}
  bundle_data: Optional[Dict[str, Any]] = None
  policy_data: Optional[Dict[str, Any]] = None

  if args.analysis_json and Path(args.analysis_json).exists():
    analysis_data = json.loads(
        Path(args.analysis_json).read_text(encoding="utf-8")
    )
  elif gcs_check:
    prior = store.get_json_object(
        gcs_check["bucket"], f"{args.project}/latest.json"
    )
    analysis_data = (
        (prior or {})
        .get("modules", {})
        .get("recommender_audit", {})
        .get("payload", {})
        .get("analysis", {})
    )

  if args.bundle_json and Path(args.bundle_json).exists():
    bundle_data = json.loads(Path(args.bundle_json).read_text(encoding="utf-8"))

  if args.policy_json and Path(args.policy_json).exists():
    policy_data = json.loads(Path(args.policy_json).read_text(encoding="utf-8"))

  if not analysis_data:
    print(
        "[Error] No prior Recommender Audit analysis found for "
        f"'{args.project}'. Run gcp-iam-recommender-audit or scopeguard-orchestrator first.",
        file=sys.stderr,
    )
    return 1

  out_dir = Path(args.output_dir)
  mod_entry = run_breakglass_simulation(
      project_id=args.project,
      analysis_data=analysis_data,
      bundle_data=bundle_data,
      lookback_days=args.lookback_days,
      output_dir=out_dir,
      audit_bq_table=args.audit_bq_table,
      max_per_principal=args.log_limit,
      policy_data=policy_data,
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
        trigger_mode="breakglass-simulator",
        updated_modules={"breakglass_simulator": mod_entry},
        live_policy_etag=live_etag,
        local_output_dir=out_dir,
    )

  print(
      json.dumps(
          {"simulation_summary": mod_entry["summary"], "gcs_publish": publish_info},
          indent=2,
      )
  )
  return 0


if __name__ == "__main__":
  sys.exit(main())
