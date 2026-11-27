#!/usr/bin/env python3
# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0

"""ScopeGuard Master End-to-End Sequential Pipeline Runner.

Coordinates all 9 ScopeGuard analytical and architectural skill modules in a
single shared-telemetry pass (or a user-selected subset of stages), runs the
mandatory GCS preflight check first, and publishes a new immutable timestamped
assessment envelope (`<project_id>/runs/<ts>_<mode>_<id>.json` + `latest.json`).
"""

import argparse
import importlib.util
import inspect
import json
from pathlib import Path
import sys
import time
from typing import Any, Dict, List, Optional

PLUGIN_ROOT = Path(__file__).resolve().parents[3]
if str(PLUGIN_ROOT) not in sys.path:
  sys.path.insert(0, str(PLUGIN_ROOT))

from lib.api_preflight import (  # pylint: disable=wrong-import-position
    EXIT_APIS_ENABLEMENT_REQUIRED,
    run_skill_api_preflight,
)
from lib import artifact_index  # pylint: disable=wrong-import-position
from lib import naming  # pylint: disable=wrong-import-position
from lib.envelope_schema import (  # pylint: disable=wrong-import-position
    SCHEMA_VERSION,
    assemble_assessment_envelope,
    generate_run_identifiers,
)
from lib.gcp_client import ScopeGuardGCPClient  # pylint: disable=wrong-import-position
from lib.gcs_publisher import (  # pylint: disable=wrong-import-position
    GCSAssessmentStore,
    add_gcs_publish_arguments,
    run_skill_gcs_preflight,
)


def _load_skill_module(skill_folder: str, script_name: str) -> Any:
  """Dynamically imports a sibling skill's CLI module from `plugins/scopeguard/skills/`."""
  script_path = PLUGIN_ROOT / "skills" / skill_folder / "scripts" / script_name
  mod_name = f"scopeguard_skill_{skill_folder.replace('-', '_')}"
  spec = importlib.util.spec_from_file_location(mod_name, script_path)
  if spec is None or spec.loader is None:
    raise RuntimeError(f"Unable to load skill script: {script_path}")
  module = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(module)
  return module


ALL_STAGES_ORDERED = [
    "recommender_audit",
    "role_architect",
    "breakglass_simulator",
    "federation_architect",
    "jit_pam_architect",
    "deny_policy_architect",
    "org_hierarchy_auditor",
    "gitops_pr_guardrail",
    "compliance_mapper",
    "finding_remediator",
]


def _build_reference_architect_scenarios(
    role_arch_mod: Any,
    project_id: str,
    disjoint_roles_dir: Path,
    base_out_dir: Path,
    role_prefix: str = "",
) -> Dict[str, Any]:
  """Synthesizes 3 production Shift-Left Role Architect blueprints for the project.

  Args:
    role_arch_mod: Loaded role architect CLI module.
    project_id: Target project ID.
    disjoint_roles_dir: Folder holding Model B capability roles from the audit
      (its parent is offered to the architect as `existing_roles_dir`).
    base_out_dir: Project output directory.
    role_prefix: Optional `--role-prefix`; when set, every scenario's role ID
      prefix is rebased onto it so all generated roles share one convention.

  Returns:
    The role architect envelope module.
  """
  scenarios = [
      {
          "slug": "cloudrun-gemini-rag",
          "requirement": (
              "Allow a headless Cloud Run GenAI RAG agent service account to "
              "invoke Vertex AI Gemini endpoints, read embeddings from a GCS "
              "bucket, access a Secret Manager API key, and query a BigQuery "
              "analytics dataset"
          ),
          "persona": "headless",
          "principal": f"serviceAccount:genai-rag-agent-sa@{project_id}.iam.gserviceaccount.com",
          "role_prefix": "custom_genai_rag_runtime",
          "bucket_name": f"{project_id}-rag-corpus",
          "secret_id": "gemini-rag-config",
          "dataset_id": "rag_analytics",
          "add_permissions": "",
      },
      {
          "slug": "bq-interactive-analyst",
          "requirement": (
              "Give a human data analyst interactive Console access to read "
              "tables in a BigQuery dataset and run query jobs without project-wide data access"
          ),
          "persona": "both",
          "principal": "user:analyst@example.com",
          "role_prefix": "custom_bq_scoped_analyst",
          "bucket_name": "YOUR_GCS_BUCKET",
          "secret_id": "YOUR_SECRET_ID",
          "dataset_id": "rag_analytics",
          "add_permissions": "",
      },
      {
          "slug": "cicd-cloudrun-deployer",
          "requirement": (
              "Allow a headless CI/CD deployer service account to push container "
              "images to Artifact Registry and deploy a specific Cloud Run service"
          ),
          "persona": "headless",
          "principal": f"serviceAccount:cicd-deployer-sa@{project_id}.iam.gserviceaccount.com",
          "role_prefix": "custom_cicd_run_deployer",
          "bucket_name": "YOUR_GCS_BUCKET",
          "secret_id": "YOUR_SECRET_ID",
          "dataset_id": "YOUR_BQ_DATASET",
          "add_permissions": "iam.serviceAccounts.actAs",
      },
  ]

  built_bundles: List[Dict[str, Any]] = []
  primary_spec: Dict[str, Any] = {}
  primary_dir = base_out_dir / "role-designs" / scenarios[0]["slug"]

  if role_prefix:
    # Rebase the per-scenario prefixes ("custom_<workload>") onto the
    # user-selected convention, e.g. "acme_" -> "acme_genai_rag_runtime".
    resolved = naming.role_prefix(role_prefix)
    for sc in scenarios:
      workload = sc["role_prefix"].removeprefix("custom_")
      sc["role_prefix"] = f"{resolved}{workload}"

  for idx, sc in enumerate(scenarios):
    sc_dir = base_out_dir / "role-designs" / sc["slug"]
    sc_dir.mkdir(parents=True, exist_ok=True)
    ns = argparse.Namespace(
        requirement=sc["requirement"],
        capabilities="",
        add_permissions=sc["add_permissions"],
        from_roles="",
        persona=sc["persona"],
        include_storage_read_api=False,
        project=project_id,
        offline=False,
        role_prefix=sc["role_prefix"],
        stage="GA",
        principal=sc["principal"],
        dataset_id=sc["dataset_id"],
        bucket_name=sc["bucket_name"],
        secret_id=sc["secret_id"],
        topic_id="YOUR_PUBSUB_TOPIC",
        subscription_id="YOUR_PUBSUB_SUBSCRIPTION",
        kms_location="asia-southeast1",
        key_ring="YOUR_KEY_RING",
        crypto_key="YOUR_CRYPTO_KEY",
        target_sa=f"genai-rag-agent-sa@{project_id}.iam.gserviceaccount.com",
        region="asia-southeast1",
        service_name="scopeguard-rag-api",
        repository_id="scopeguard-containers",
        existing_roles_dir=str(disjoint_roles_dir.parent)
        if disjoint_roles_dir.exists()
        else "./custom-roles",
    )
    spec = role_arch_mod.design_roles(ns)
    (sc_dir / "role_design_spec.json").write_text(
        json.dumps(spec, indent=2) + "\n", encoding="utf-8"
    )
    role_arch_mod.generate_artifacts_from_spec(spec, sc_dir)
    single_mod = role_arch_mod.build_architect_envelope_module(spec, sc_dir)
    design_entry = single_mod["payload"]["primary_design"]
    design_entry["scenario_slug"] = sc["slug"]
    built_bundles.append(design_entry)
    if idx == 0:
      primary_spec = spec

  return role_arch_mod.build_architect_envelope_module(
      primary_spec, primary_dir, extra_designs=built_bundles[1:]
  )


def _format_duration(seconds: float) -> str:
  """Formats elapsed/ETA seconds into a compact human-readable duration."""
  secs = max(0, int(round(seconds)))
  mins, rem = divmod(secs, 60)
  hrs, mins = divmod(mins, 60)
  if hrs:
    return f"{hrs}h {mins}m {rem}s"
  if mins:
    return f"{mins}m {rem}s"
  return f"{seconds:.1f}s" if seconds < 10 else f"{secs}s"


def _render_progress_bar(completed: int, total: int, width: int = 20) -> str:
  """Renders an ASCII progress bar safe for terminals and CI/task logs."""
  if total <= 0:
    return f"[{'#' * width}] 100% (0/0)"
  ratio = min(1.0, max(0.0, completed / total))
  filled = int(round(ratio * width))
  bar = "#" * filled + "-" * (width - filled)
  pct = int(round(ratio * 100))
  return f"[{bar}] {pct:3d}% ({completed}/{total})"


def _log_progress(msg: str) -> None:
  """Writes an immediately-flushed progress update to stderr."""
  print(msg, file=sys.stderr, flush=True)


def _load_all_skill_modules() -> Dict[str, Any]:
  """Loads sibling skill modules once so org/folder sweeps reuse them."""
  return {
      "audit": _load_skill_module("gcp-iam-recommender-audit", "iam_audit_cli.py"),
      "arch": _load_skill_module("gcp-iam-role-architect", "role_architect_cli.py"),
      "sim": _load_skill_module(
          "gcp-iam-breakglass-simulator", "breakglass_simulator_cli.py"
      ),
      "fed": _load_skill_module(
          "gcp-iam-federation-architect", "federation_architect_cli.py"
      ),
      "pam": _load_skill_module(
          "gcp-iam-jit-pam-architect", "jit_pam_architect_cli.py"
      ),
      "deny": _load_skill_module(
          "gcp-iam-deny-policy-architect", "deny_policy_cli.py"
      ),
      "org": _load_skill_module(
          "gcp-iam-org-hierarchy-auditor", "org_hierarchy_cli.py"
      ),
      "gitops": _load_skill_module(
          "gcp-iam-gitops-pr-guardrail", "gitops_guardrail_cli.py"
      ),
      "comp": _load_skill_module(
          "gcp-iam-compliance-mapper", "compliance_mapper_cli.py"
      ),
      "rem": _load_skill_module(
          "gcp-iam-finding-remediator", "finding_remediator_cli.py"
      ),
  }


# --- Optional pass-through flags ---------------------------------------------
# Each helper returns kwargs ONLY for flags the user actually set, so a sibling
# skill CLI that predates a flag keeps working with its own defaults.


def _split_csv(value: Any) -> List[str]:
  """Splits a comma-separated flag value (or list of values) into clean items."""
  items = value if isinstance(value, (list, tuple)) else [value]
  out: List[str] = []
  for item in items:
    out.extend(p.strip() for p in str(item or "").split(",") if p.strip())
  return out


def _federation_kwargs(args: argparse.Namespace) -> Dict[str, Any]:
  """Builds optional WIF kwargs (GitHub/GitLab federation targets)."""
  kwargs: Dict[str, Any] = {}
  for name in ("github_org", "github_repo", "github_ref", "gitlab_project",
               "gitlab_ref", "project_number"):
    value = (getattr(args, name, "") or "").strip()
    if value:
      kwargs[name] = value
  gitlab_url = (getattr(args, "gitlab_url", "") or "").strip()
  if gitlab_url and gitlab_url != "https://gitlab.com":
    kwargs["gitlab_url"] = gitlab_url
  platforms = _split_csv(getattr(args, "ci_platforms", "") or "")
  if platforms and sorted(platforms) != ["github", "gitlab"]:
    kwargs["ci_platforms"] = platforms
  return kwargs


def _pam_kwargs(args: argparse.Namespace) -> Dict[str, Any]:
  """Builds optional PAM kwargs (approver group(s), notification emails)."""
  kwargs: Dict[str, Any] = {}
  approvers = _split_csv(getattr(args, "approver_group", "") or "")
  if approvers:
    kwargs["approver_principal"] = ",".join(approvers)
  emails = _split_csv(getattr(args, "notification_email", None) or [])
  if emails:
    kwargs["notification_emails"] = emails
  return kwargs


def _filter_supported_kwargs(fn: Any, kwargs: Dict[str, Any]) -> Dict[str, Any]:
  """Returns only kwargs accepted by `fn` (or all kwargs if `fn` accepts `**kwargs`).

  Guards new orchestrator pass-through flags so older sibling skill CLIs or
  lightweight test stubs never fail with `TypeError: unexpected keyword argument`.
  """
  try:
    sig = inspect.signature(fn)
  except (TypeError, ValueError):
    return kwargs
  params = sig.parameters
  if any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values()):
    return kwargs
  return {k: v for k, v in kwargs.items() if k in params}


def _principal_matches(candidate: Any, target: str) -> bool:
  """Case-insensitive principal match supporting bare emails or `type:email`."""
  cand = str(candidate or "").strip().lower()
  tgt = str(target or "").strip().lower()
  if not cand or not tgt:
    return False
  if cand == tgt:
    return True
  cand_bare = cand.split(":", 1)[-1] if ":" in cand else cand
  tgt_bare = tgt.split(":", 1)[-1] if ":" in tgt else tgt
  return bool(cand_bare and cand_bare == tgt_bare)


def _filter_analysis_for_principal(
    analysis_data: Dict[str, Any], target_principal: str
) -> Dict[str, Any]:
  """Returns a copy of `analysis_data` scoped to a single IAM principal.

  Preserves `metadata` (including `policy_etag`) and verification structures so
  downstream stages (simulator, remediator, compliance, synthesizer) stay valid
  while focusing work on the single triaged identity.
  """
  filtered = dict(analysis_data)
  meta = dict(analysis_data.get("metadata") or {})
  meta["principal_filter"] = target_principal
  filtered["metadata"] = meta

  kept_mappings = [
      pm for pm in (analysis_data.get("principal_mappings") or [])
      if isinstance(pm, dict) and _principal_matches(pm.get("principal"), target_principal)
  ]
  filtered["principal_mappings"] = kept_mappings

  raw_findings = analysis_data.get("findings") or {}
  if isinstance(raw_findings, dict):
    kept_findings: Dict[str, Any] = {}
    for fkey, flist in raw_findings.items():
      if isinstance(flist, list):
        kept_findings[fkey] = [
            it for it in flist
            if isinstance(it, dict) and (
                _principal_matches(it.get("principal"), target_principal)
                or _principal_matches(it.get("email"), target_principal)
            )
        ]
      else:
        kept_findings[fkey] = flist
    filtered["findings"] = kept_findings

  if isinstance(analysis_data.get("transitive_paths"), list):
    filtered["transitive_paths"] = [
        tp for tp in analysis_data["transitive_paths"]
        if isinstance(tp, dict) and (
            _principal_matches(tp.get("source_principal"), target_principal)
            or _principal_matches(tp.get("intermediate_principal"), target_principal)
        )
    ]

  kept_persona_ids = {
      str(pm.get("persona_role_id"))
      for pm in kept_mappings
      if pm.get("persona_role_id")
  }
  raw_model_a = analysis_data.get("custom_roles_model_a") or {}
  if isinstance(raw_model_a, dict):
    kept_model_a = {}
    for role_key, spec in raw_model_a.items():
      members = (spec or {}).get("members") or []
      if role_key in kept_persona_ids or any(
          _principal_matches(m, target_principal) for m in members
      ):
        kept_model_a[role_key] = spec
        kept_persona_ids.add(role_key)
    filtered["custom_roles_model_a"] = kept_model_a

  raw_bundles = analysis_data.get("model_b_bundles")
  if isinstance(raw_bundles, dict):
    kept_bundles = {
        k: v for k, v in raw_bundles.items() if k in kept_persona_ids
    }
    filtered["model_b_bundles"] = kept_bundles
    kept_caps = {cap for caps in kept_bundles.values() for cap in (caps or [])}
    raw_model_b = analysis_data.get("custom_roles_model_b_disjoint") or {}
    if isinstance(raw_model_b, dict):
      filtered["custom_roles_model_b_disjoint"] = {
          k: v for k, v in raw_model_b.items() if k in kept_caps
      }

  raw_audit_sum = analysis_data.get("audit_log_exercised_summary")
  if isinstance(raw_audit_sum, dict):
    filtered["audit_log_exercised_summary"] = {
        k: v for k, v in raw_audit_sum.items()
        if _principal_matches(k, target_principal)
    }

  if isinstance(analysis_data.get("policy_insights"), list):
    filtered["policy_insights"] = [
        ins for ins in analysis_data["policy_insights"]
        if isinstance(ins, dict) and (
            _principal_matches(ins.get("principal") or ins.get("member"), target_principal)
            or not (ins.get("principal") or ins.get("member"))
        )
    ]

  if isinstance(analysis_data.get("summary"), dict):
    summary_copy = dict(analysis_data["summary"])
    summary_copy["total_principals"] = len(kept_mappings)
    summary_copy["principal_filter"] = target_principal
    filtered["summary"] = summary_copy

  return filtered


def _deny_kwargs(args: argparse.Namespace) -> Dict[str, Any]:
  """Builds optional Deny-policy kwargs (break-glass & AI agent principals)."""
  kwargs: Dict[str, Any] = {}
  principals = _split_csv(getattr(args, "breakglass_principal", None) or [])
  if principals:
    kwargs["breakglass_principals"] = principals
  ai_agents = _split_csv(getattr(args, "ai_agent_principal", None) or [])
  if ai_agents:
    kwargs["ai_agent_principals"] = ai_agents
  return kwargs


def _gitops_kwargs(args: argparse.Namespace) -> Dict[str, Any]:
  """Builds optional GitOps kwargs (`terraform show -json` plan, expiry window)."""
  kwargs: Dict[str, Any] = {}
  plan_json = (getattr(args, "plan_json", "") or "").strip()
  if plan_json:
    kwargs["plan_json"] = Path(plan_json).expanduser().resolve()
  max_expiry = getattr(args, "max_expiry_days", None)
  if max_expiry is not None and int(max_expiry) != 90:
    kwargs["max_expiry_days"] = int(max_expiry)
  if getattr(args, "include_unchanged", False):
    kwargs["include_unchanged"] = True
  return kwargs


def _remediator_kwargs(
    args: argparse.Namespace, updated_modules: Dict[str, Dict[str, Any]]
) -> Dict[str, Any]:
  """Builds remediator kwargs: replay evidence, correlation run id, authoritative/canary TF."""
  kwargs: Dict[str, Any] = {}
  sim_payload = (updated_modules.get("breakglass_simulator") or {}).get("payload")
  if sim_payload:
    kwargs["simulation_data"] = sim_payload
  correlation_id = getattr(args, "_pipeline_run_id", "")
  if correlation_id:
    kwargs["run_id"] = correlation_id
  if getattr(args, "authoritative", False):
    kwargs["authoritative"] = True
  if getattr(args, "canary", False):
    kwargs["canary"] = True
  return kwargs


def _finalize_project_outputs(
    project_id: str,
    out_dir: Path,
    publish_info: Optional[Dict[str, Any]],
    args: argparse.Namespace,
    project_meta: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
  """Writes audience docs, exports, bundles, shareable copies and README/manifest.

  The freshly written local envelope is re-read from disk (both the GCS and the
  local-only branch write `assessment_envelope_<pid>.json`), so the index always
  reflects exactly what was published. Failures are logged and returned rather
  than raised: the assessment itself has already succeeded at this point.

  Args:
    project_id: Target project ID.
    out_dir: Project output directory.
    publish_info: GCS publish result (may carry the envelope), or None.
    args: Parsed CLI args (`bundle_by`, `redact`).
    project_meta: Optional sweep discovery metadata (folder_path / parent).

  Returns:
    The `artifact_index.finalize_run_outputs` report, or an error dict.
  """
  envelope: Optional[Dict[str, Any]] = None
  env_path = out_dir / f"assessment_envelope_{project_id}.json"
  try:
    if env_path.exists():
      envelope = json.loads(env_path.read_text(encoding="utf-8"))
    elif isinstance((publish_info or {}).get("envelope"), dict):
      envelope = publish_info["envelope"]
  except (OSError, ValueError) as exc:
    _log_progress(f"  !! Unable to reload envelope {env_path}: {exc}")
  if not envelope:
    return {"errors": [f"envelope not found at {env_path}"]}
  if project_meta:
    # In-memory only: lets --bundle-by=folder use the sweep's folder lineage.
    envelope.setdefault("folder_path", project_meta.get("folder_path") or [])
    if project_meta.get("parent"):
      envelope.setdefault("parent", project_meta["parent"])
  try:
    report = artifact_index.finalize_run_outputs(
        envelope,
        out_dir,
        bundle_by=getattr(args, "bundle_by", "") or "",
        redact=bool(getattr(args, "redact", False)),
    )
  except Exception as exc:  # pylint: disable=broad-except
    _log_progress(f"  !! Output finalization failed for {project_id}: {exc}")
    return {"errors": [f"finalize_run_outputs failed: {exc}"]}
  for err in report.get("errors") or []:
    _log_progress(f"  !! {project_id} output finalization warning: {err}")
  return report


def _run_single_project_pipeline(
    project_id: str,
    args: argparse.Namespace,
    requested_stages: List[str],
    gcs_check: Optional[Dict[str, Any]],
    store: GCSAssessmentStore,
    out_dir: Path,
    mods: Dict[str, Any],
    project_meta: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
  """Executes the requested ScopeGuard stages for one GCP project.

  `project_meta` (sweep discovery metadata: parent / folder_path) is only used
  to key `--bundle-by=folder` bundles; it is never written into the envelope.
  """
  out_dir.mkdir(parents=True, exist_ok=True)
  gcp_client = ScopeGuardGCPClient(quota_project=project_id)

  start_ts = time.monotonic()
  stage_timings: Dict[str, float] = {}
  updated_modules: Dict[str, Dict[str, Any]] = {}

  raw_policy: Optional[Dict[str, Any]] = None
  bundle_data: Optional[Dict[str, Any]] = None
  analysis_data: Optional[Dict[str, Any]] = None
  user_key_count = 0
  total_stages = len(requested_stages)
  stage_idx = 0

  role_prefix_arg = (getattr(args, "role_prefix", "") or "").strip()
  target_principal = (getattr(args, "principal", "") or "").strip()
  failed_stages: Dict[str, str] = {}

  def _stage_start(stage_name: str) -> float:
    nonlocal stage_idx
    stage_idx += 1
    _log_progress(
        f"  -> [Stage {stage_idx}/{total_stages}] {project_id}: {stage_name} ..."
    )
    return time.monotonic()

  # 1. Recommender Audit (Brownfield F1-F7 + Model A/B + P0-P3 + Rollback)
  if "recommender_audit" in requested_stages:
    t0 = _stage_start("recommender_audit")
    audit_client = mods["audit"].HybridGCPAuditClient(project_id, args.location)
    bundle_data, raw_policy = audit_client.collect_all(
        freshness_days=args.freshness_days,
        log_limit=args.log_limit,
    )
    backup_path = out_dir / f"iam_policy_backup_{project_id}.json"
    bundle_path = out_dir / f"audit_bundle_{project_id}.json"
    analysis_path = out_dir / f"analysis_results_{project_id}.json"
    mods["audit"].write_json_file(raw_policy, backup_path, "IAM Policy Backup")
    mods["audit"].write_json_file(bundle_data, bundle_path, "Audit Bundle")
    # `--role-prefix` is passed only when set so older audit CLIs (without the
    # kwarg) keep working; lib.naming falls back to env / "sg_" otherwise.
    if role_prefix_arg:
      analysis_data = mods["audit"].analyze_bundle(
          bundle_data, role_prefix=role_prefix_arg
      )
    else:
      analysis_data = mods["audit"].analyze_bundle(bundle_data)
    mods["audit"].write_json_file(analysis_data, analysis_path, "Analysis Results")
    mods["audit"].generate_all_artifacts(analysis_data, backup_path, out_dir)
    updated_modules["recommender_audit"] = mods["audit"].build_audit_envelope_module(
        analysis_data, out_dir, project_id
    )
    stage_timings["recommender_audit"] = round(time.monotonic() - t0, 2)
  else:
    local_an = out_dir / f"analysis_results_{project_id}.json"
    if local_an.exists():
      analysis_data = json.loads(local_an.read_text(encoding="utf-8"))
    elif gcs_check:
      prior = store.get_json_object(
          gcs_check["bucket"], f"{project_id}/latest.json"
      )
      analysis_data = (
          (prior or {})
          .get("modules", {})
          .get("recommender_audit", {})
          .get("payload", {})
          .get("analysis")
      )

  if raw_policy is None:
    try:
      raw_policy = gcp_client.fetch_project_iam_policy(project_id)
    except Exception:  # pylint: disable=broad-except
      raw_policy = {}

  # Optional single-principal fast-path: scope analysis_data & audit module
  # payload to the target identity while preserving policy etag/metadata.
  if target_principal and isinstance(analysis_data, dict):
    analysis_data = _filter_analysis_for_principal(analysis_data, target_principal)
    _log_progress(
        f"  -> [Principal Fast-Path] {project_id}: filtered analysis to "
        f"{target_principal} ({len(analysis_data.get('principal_mappings') or [])} matched)"
    )
    if "recommender_audit" in updated_modules:
      audit_mod = updated_modules["recommender_audit"]
      if isinstance(audit_mod.get("payload"), dict):
        audit_mod["payload"]["analysis"] = analysis_data
      if isinstance(audit_mod.get("summary"), dict):
        audit_mod["summary"]["total_principals"] = len(
            analysis_data.get("principal_mappings") or []
        )
        audit_mod["summary"]["principal_filter"] = target_principal

  # 2. Shift-Left Role Architect (Reference Scoped Role Blueprints)
  if "role_architect" in requested_stages:
    t0 = _stage_start("role_architect")
    # Model B capability roles live in custom-roles/capabilities/ (contract);
    # fall back to the legacy custom-roles/disjoint/ folder for older audits.
    capability_dir = out_dir / "custom-roles" / "capabilities"
    if not capability_dir.exists():
      legacy_dir = out_dir / "custom-roles" / "disjoint"
      if legacy_dir.exists():
        capability_dir = legacy_dir
    updated_modules["role_architect"] = _build_reference_architect_scenarios(
        mods["arch"], project_id, capability_dir, out_dir,
        role_prefix=role_prefix_arg,
    )
    stage_timings["role_architect"] = round(time.monotonic() - t0, 2)

  # 3. Breakglass & Audit Log Replay Simulator
  if "breakglass_simulator" in requested_stages and analysis_data:
    t0 = _stage_start("breakglass_simulator")
    sim_fn = mods["sim"].run_breakglass_simulation
    sim_kwargs = _filter_supported_kwargs(
        sim_fn,
        {
            "project_id": project_id,
            "analysis_data": analysis_data,
            "bundle_data": bundle_data,
            "lookback_days": args.freshness_days,
            "gcp_client": gcp_client,
            "output_dir": out_dir / "simulator",
            "audit_bq_table": getattr(args, "audit_bq_table", ""),
            "max_per_principal": getattr(args, "log_limit", 500),
            "policy_data": raw_policy,
        },
    )
    updated_modules["breakglass_simulator"] = sim_fn(**sim_kwargs)
    stage_timings["breakglass_simulator"] = round(time.monotonic() - t0, 2)

  # 4. Workload Identity Federation & SA Key Audit
  if "federation_architect" in requested_stages:
    t0 = _stage_start("federation_architect")
    fed_fn = mods["fed"].run_federation_architect
    fed_extra = _filter_supported_kwargs(fed_fn, _federation_kwargs(args))
    fed_res = fed_fn(
        project_id=project_id,
        gcp_client=gcp_client,
        output_dir=out_dir / "federation-wif",
        **fed_extra,
    )
    updated_modules["federation_architect"] = fed_res
    user_key_count = int(fed_res["summary"].get("user_managed_keys_found", 0))
    stage_timings["federation_architect"] = round(time.monotonic() - t0, 2)

  # 5. Just-in-Time PAM Entitlement Architect
  if "jit_pam_architect" in requested_stages:
    t0 = _stage_start("jit_pam_architect")
    pam_fn = mods["pam"].run_jit_pam_architect
    pam_extra = _filter_supported_kwargs(pam_fn, _pam_kwargs(args))
    updated_modules["jit_pam_architect"] = pam_fn(
        project_id=project_id,
        policy_data=raw_policy,
        analysis_data=analysis_data,
        gcp_client=gcp_client,
        output_dir=out_dir / "jit-pam",
        **pam_extra,
    )
    stage_timings["jit_pam_architect"] = round(time.monotonic() - t0, 2)

  # 6. IAM v2 Preventive Deny Policy Architect
  if "deny_policy_architect" in requested_stages:
    t0 = _stage_start("deny_policy_architect")
    deny_fn = mods["deny"].run_deny_policy_architect
    deny_candidates = dict(_deny_kwargs(args))
    if analysis_data is not None:
      deny_candidates["analysis_data"] = analysis_data
    deny_extra = _filter_supported_kwargs(deny_fn, deny_candidates)
    updated_modules["deny_policy_architect"] = deny_fn(
        project_id=project_id,
        policy_data=raw_policy,
        gcp_client=gcp_client,
        output_dir=out_dir / "deny-policies",
        **deny_extra,
    )
    stage_timings["deny_policy_architect"] = round(time.monotonic() - t0, 2)

  # 7. Organization & Folder Hierarchy Auditor
  if "org_hierarchy_auditor" in requested_stages:
    t0 = _stage_start("org_hierarchy_auditor")
    updated_modules["org_hierarchy_auditor"] = mods["org"].run_org_hierarchy_audit(
        project_id=project_id,
        gcp_client=gcp_client,
        output_dir=out_dir / "org-hierarchy",
    )
    stage_timings["org_hierarchy_auditor"] = round(time.monotonic() - t0, 2)

  # 8. GitOps Terraform PR Guardrail
  if "gitops_pr_guardrail" in requested_stages:
    t0 = _stage_start("gitops_pr_guardrail")
    try:
      gitops_fn = mods["gitops"].run_gitops_guardrail
      gitops_extra = _filter_supported_kwargs(gitops_fn, _gitops_kwargs(args))
      gitops_res = gitops_fn(
          project_id=project_id,
          scan_path=Path(args.tf_scan_path).resolve(),
          output_dir=out_dir / "gitops-guardrail",
          **gitops_extra,
      )
    except Exception as exc:  # pylint: disable=broad-except
      # A scanner crash must not abort the other stages; it is reported as a
      # failed (not clean) stage instead.
      _log_progress(f"  !! gitops_pr_guardrail crashed for {project_id}: {exc}")
      gitops_res = None
      failed_stages["gitops_pr_guardrail"] = f"exception: {exc}"
    if gitops_res is not None:
      updated_modules["gitops_pr_guardrail"] = gitops_res
      verdict = str((gitops_res.get("summary") or {}).get("verdict", ""))
      if gitops_res.get("status") == "FAILED" or verdict == "SCAN_ERROR":
        reason = (gitops_res.get("payload") or {}).get("error") or verdict
        failed_stages["gitops_pr_guardrail"] = f"SCAN_ERROR: {reason}"
        _log_progress(
            f"  !! gitops_pr_guardrail SCAN_ERROR for {project_id} (not clean): {reason}"
        )
    stage_timings["gitops_pr_guardrail"] = round(time.monotonic() - t0, 2)

  # 9. Regulatory Compliance Mapper (CIS, SOC 2, ISO 27001, PCI-DSS)
  if "compliance_mapper" in requested_stages and analysis_data:
    t0 = _stage_start("compliance_mapper")
    updated_modules["compliance_mapper"] = mods["comp"].run_compliance_mapping(
        project_id=project_id,
        analysis_data=analysis_data,
        user_managed_key_count=user_key_count,
        output_dir=out_dir / "compliance",
    )
    stage_timings["compliance_mapper"] = round(time.monotonic() - t0, 2)

  # 10. Inbound SCC & Wiz Finding-to-Fix Remediator
  if "finding_remediator" in requested_stages:
    t0 = _stage_start("finding_remediator")
    inbound_findings = []
    scc_path = Path(args.scc_finding_file) if args.scc_finding_file else None
    wiz_path = Path(args.wiz_issue_file) if args.wiz_issue_file else None
    if scc_path and scc_path.exists():
      doc = json.loads(scc_path.read_text(encoding="utf-8"))
      docs = doc if isinstance(doc, list) else [doc]
      inbound_findings.extend(
          mods["rem"].normalize_inbound_finding(d, "scc") for d in docs
      )
    if wiz_path and wiz_path.exists():
      doc = json.loads(wiz_path.read_text(encoding="utf-8"))
      docs = doc if isinstance(doc, list) else [doc]
      inbound_findings.extend(
          mods["rem"].normalize_inbound_finding(d, "wiz") for d in docs
      )
    if getattr(args, "fetch_live_scc", True):
      scc_live = mods["rem"].fetch_live_scc_iam_findings(project_id, gcp_client)
      if scc_live:
        _log_progress(f"  -> Auto-pulled {len(scc_live)} active IAM finding(s) from Cloud SCC.")
        inbound_findings.extend(scc_live)
    if getattr(args, "fetch_live_wiz", True) and hasattr(mods["rem"], "fetch_live_wiz_iam_findings"):
      wiz_live = mods["rem"].fetch_live_wiz_iam_findings(project_id)
      if wiz_live:
        _log_progress(f"  -> Auto-pulled {len(wiz_live)} open GCP IAM issue(s) from Wiz.")
        inbound_findings.extend(wiz_live)
    if target_principal and inbound_findings:
      inbound_findings = [
          f for f in inbound_findings
          if _principal_matches(f.get("principal") or f.get("member") or "", target_principal)
      ]
    if inbound_findings:
      rem_fn = mods["rem"].run_finding_remediator
      rem_extra = _filter_supported_kwargs(
          rem_fn, _remediator_kwargs(args, updated_modules)
      )
      updated_modules["finding_remediator"] = rem_fn(
          project_id=project_id,
          inbound_findings=inbound_findings,
          analysis_data=analysis_data,
          policy_data=raw_policy,
          gcp_client=gcp_client,
          output_dir=out_dir / "finding-remediation",
          **rem_extra,
      )
      stage_timings["finding_remediator"] = round(time.monotonic() - t0, 2)

  trigger_label = (
      "full-suite"
      if len(requested_stages) == len(ALL_STAGES_ORDERED)
      else f"pipeline-{len(requested_stages)}-stages"
  )
  live_etag = (raw_policy or {}).get("etag", "") or (
      (analysis_data or {}).get("metadata", {}).get("policy_etag", "")
  )

  local_recs_md_path = out_dir / f"scopeguard_recommendations_{project_id}.md"
  publish_info = None
  recommendation_digest = None
  if gcs_check:
    publish_info = store.publish_assessment_run(
        bucket=gcs_check["bucket"],
        region=gcs_check["region"],
        project_id=project_id,
        trigger_mode=trigger_label,
        updated_modules=updated_modules,
        live_policy_etag=live_etag,
        local_output_dir=out_dir,
    )
    recommendation_digest = publish_info.get("recommendation_digest")
  else:
    local_env_path = out_dir / f"assessment_envelope_{project_id}.json"
    prior_local = (
        json.loads(local_env_path.read_text(encoding="utf-8"))
        if local_env_path.exists()
        else None
    )
    local_env = assemble_assessment_envelope(
        project_id=project_id,
        trigger_mode=trigger_label,
        updated_modules=updated_modules,
        prior_envelope=prior_local,
        live_policy_etag=live_etag,
        bucket_name="local-only",
        bucket_region="local",
    )
    local_env_path.write_text(
        json.dumps(local_env, indent=2) + "\n", encoding="utf-8"
    )
    local_recs_md_path.write_text(
        local_env.get("master_recommendations_markdown", "") + "\n",
        encoding="utf-8",
    )
    recommendation_digest = local_env.get("recommendation_digest")

  # Audience documents, exports, bundles, redacted copies and README/manifest.
  run_outputs = _finalize_project_outputs(
      project_id, out_dir, publish_info, args, project_meta
  )
  # Finalized docs/exports are created after the envelope publish, so push
  # them to GCS now (best-effort; the envelope is already durable).
  if gcs_check and publish_info and isinstance(run_outputs, dict):
    try:
      run_outputs["gcs_upload"] = store.publish_run_outputs(
          bucket=gcs_check["bucket"],
          project_id=project_id,
          run_id=str(publish_info.get("run_id") or ""),
          local_output_dir=out_dir,
      )
      for err in run_outputs["gcs_upload"].get("errors") or []:
        _log_progress(f"  !! {project_id} GCS output upload warning: {err}")
    except Exception as exc:  # pylint: disable=broad-except
      _log_progress(f"  !! {project_id} GCS output upload failed: {exc}")
      run_outputs["gcs_upload"] = {"uploaded": [], "errors": [str(exc)]}

  result: Dict[str, Any] = {
      "project_id": project_id,
      "stages_executed": list(updated_modules.keys()),
      "stage_timings_seconds": stage_timings,
      "total_elapsed_seconds": round(time.monotonic() - start_ts, 2),
      "local_output_dir": str(out_dir),
      "master_recommendations_markdown_path": str(local_recs_md_path),
      "gcs_publish": publish_info,
      "recommendation_digest": recommendation_digest,
      "failed_stages": failed_stages,
      "run_outputs": run_outputs,
  }
  if target_principal:
    result["principal_filter"] = target_principal
  return result


def _render_scope_rollup_markdown(rollup: Dict[str, Any]) -> str:
  """Renders an executive Org / Folder multi-project Markdown summary."""
  kpis = rollup.get("aggregate_kpis", {})
  lines = [
      f"# ScopeGuard {rollup['scope_type'].title()} Fleet IAM Assessment: `{rollup['scope_resource']}`",
      "",
      f"- **Sweep ID**: `{rollup['sweep_id']}` (`{rollup['timestamp_utc']}`)",
      f"- **Projects Discovered / Assessed / Failed**: `{rollup['discovered_count']}` / `{rollup['succeeded_count']}` / `{rollup['failed_count']}`",
      "",
      "## Fleet-Wide Aggregate KPIs",
      "",
      "| Metric | Fleet Total / Average |",
      "| :--- | :---: |",
      f"| **Total Principals Audited** | `{kpis.get('total_principals', 0):,}` |",
      f"| **Permissions Before → After** | `{kpis.get('permissions_before', 0):,}` → `{kpis.get('permissions_after', 0):,}` (**`-{kpis.get('permissions_reduction_pct', 0.0)}%`**) |",
      f"| **Privilege Escalation Paths** | `{kpis.get('escalation_chains_count', 0)}` |",
      f"| **Standing Privileged Humans (PAM Targets)** | `{kpis.get('standing_privileged_humans_count', 0)}` |",
      f"| **WIF Automation Candidates** | `{kpis.get('wif_migration_candidates', 0)}` |",
      f"| **Inbound SCC & Wiz Findings Remediated** | `{kpis.get('inbound_findings_remediated', 0)}` |",
      f"| **Avg Compliance Score (Before → After)** | `{kpis.get('avg_compliance_before_pct', 0.0)}%` → **`{kpis.get('avg_compliance_after_pct', 0.0)}%`** |",
      "",
      "## Project-Wise Posture Breakdown",
      "",
      "| Project ID | Folder / Parent | Principals | Perms Before → After | Escalations | Standing Admins | SCC/Wiz Fixes | Compliance (Before → After) | Status |",
      "| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :--- |",
  ]
  for proj in rollup.get("projects", []):
    pk = proj.get("kpis", {})
    if proj.get("status") != "OK":
      lines.append(
          f"| `{proj['project_id']}` | `{proj.get('parent', '')}` | - | - | - | - | - | - | `FAILED: {proj.get('error', '')[:60]}` |"
      )
      continue
    lines.append(
        f"| `{proj['project_id']}` | `{proj.get('parent', '')}` | `{pk.get('total_principals', 0)}` | "
        f"`{pk.get('permissions_before', 0):,}` → `{pk.get('permissions_after', 0):,}` (`-{pk.get('permissions_reduction_pct', 0.0)}%`) | "
        f"`{pk.get('escalation_chains_count', 0)}` | `{pk.get('standing_privileged_humans_count', 0)}` | "
        f"`{pk.get('inbound_findings_remediated', 0)}` | "
        f"`{pk.get('compliance_score_before_pct', 0.0)}%` → `{pk.get('compliance_score_after_pct', 0.0)}%` | `OK` |"
    )
  lines.append("")
  return "\n".join(lines)


def _add_extended_arguments(parser: argparse.ArgumentParser) -> None:
  """Registers role naming, reporting and per-skill pass-through flags.

  Pass-through flags are forwarded to a stage only when explicitly set (see the
  `_*_kwargs` helpers), so their defaults here mirror the skill defaults.
  """
  naming_grp = parser.add_argument_group("Role Naming")
  naming_grp.add_argument(
      "--role-prefix",
      default="",
      help=(
          "Custom role ID prefix for recommender audit + role architect "
          "(default: $SCOPEGUARD_ROLE_PREFIX or 'sg_')."
      ),
  )

  report_grp = parser.add_argument_group("Reports & Exports")
  report_grp.add_argument(
      "--bundle-by",
      default="",
      choices=["", "owner", "folder", "principal"],
      help=(
          "Also write bundles/<key>/ subsets (findings.csv/jsonl, "
          "REMEDIATION_PLAN.md, manifest) per owner label, folder, or principal."
      ),
  )
  report_grp.add_argument(
      "--redact",
      action="store_true",
      help=(
          "Also write shareable/ copies of md/json/jsonl/csv exports with user "
          "emails, project numbers and external ids replaced by stable hashes "
          "(originals are never modified; set SCOPEGUARD_REDACT_SALT for a "
          "per-organisation salt)."
      ),
  )

  gitops_grp = parser.add_argument_group("GitOps PR Guardrail")
  gitops_grp.add_argument(
      "--plan-json",
      default="",
      help=(
          "Optional `terraform show -json <plan>` file; the guardrail evaluates "
          "the planned IAM changes (falls back to --tf-scan-path regex scan)."
      ),
  )
  gitops_grp.add_argument(
      "--max-expiry-days",
      type=int,
      default=90,
      help="Max allowed IAM condition expiry window in days (default: 90).",
  )
  gitops_grp.add_argument(
      "--include-unchanged",
      action="store_true",
      help="With --plan-json: also evaluate unchanged IAM resources.",
  )

  pam_grp = parser.add_argument_group("JIT PAM / Deny Policies")
  pam_grp.add_argument(
      "--approver-group",
      default="",
      help="Comma-separated PAM approver principal(s), e.g. group:iam-approvers@example.com.",
  )
  pam_grp.add_argument(
      "--notification-email",
      action="append",
      default=[],
      help="PAM grant notification email (repeatable).",
  )
  pam_grp.add_argument(
      "--breakglass-principal",
      action="append",
      default=[],
      help="Deny-policy exception (break-glass) principal (repeatable).",
  )
  pam_grp.add_argument(
      "--ai-agent-principal",
      action="append",
      default=[],
      help=(
          "AI agent / autonomous workload principal for D5 IAM v2 Deny Policy "
          "blast-radius guardrails (repeatable)."
      ),
  )

  rem_grp = parser.add_argument_group("Finding Remediator")
  rem_grp.add_argument(
      "--authoritative",
      action="store_true",
      help=(
          "Emit authoritative Terraform (google_project_iam_binding) in the "
          "remediator; replaces ALL members of a role - review the warning file."
      ),
  )
  rem_grp.add_argument(
      "--canary",
      action="store_true",
      help=(
          "Emit dual-bind canary cutover scripts/Terraform in the finding "
          "remediator (bind least-privilege role alongside legacy role before removal)."
      ),
  )

  wif_grp = parser.add_argument_group("Workload Identity Federation")
  wif_grp.add_argument("--github-org", default="", help="GitHub org for WIF provider conditions.")
  wif_grp.add_argument("--github-repo", default="", help="GitHub repo for WIF provider conditions.")
  wif_grp.add_argument("--github-ref", default="", help="GitHub ref (e.g. refs/heads/main).")
  wif_grp.add_argument("--gitlab-project", default="", help="GitLab project path (group/project).")
  wif_grp.add_argument(
      "--gitlab-url", default="https://gitlab.com", help="GitLab instance URL (default: https://gitlab.com)."
  )
  wif_grp.add_argument("--gitlab-ref", default="", help="GitLab ref (e.g. main).")
  wif_grp.add_argument(
      "--project-number", default="", help="Target project number for WIF principal URIs."
  )
  wif_grp.add_argument(
      "--ci-platforms",
      default="github,gitlab",
      help="Comma-separated CI platforms to generate WIF config for (default: github,gitlab).",
  )


def main() -> int:
  parser = argparse.ArgumentParser(
      description=(
          "Run ScopeGuard 11-skill IAM governance pipeline on a single GCP "
          "project or sweep an entire Organization / Folder and publish to GCS."
      )
  )
  scope_grp = parser.add_argument_group("Target Scope (specify one)")
  scope_grp.add_argument(
      "--project",
      default="",
      help="Single target GCP Project ID.",
  )
  scope_grp.add_argument(
      "--principal",
      default="",
      help=(
          "Optional single IAM principal (e.g. serviceAccount:foo@proj.iam.gserviceaccount.com) "
          "for fast single-identity SCC/Wiz alert triage; filters analysis and remediation focus."
      ),
  )
  scope_grp.add_argument(
      "--org-id",
      default="",
      help="Target GCP Organization ID (e.g. 123456789012) to sweep all active projects.",
  )
  scope_grp.add_argument(
      "--folder-id",
      default="",
      help="Target GCP Folder ID (e.g. 123456789012) to sweep all active projects recursively.",
  )
  scope_grp.add_argument(
      "--max-projects",
      type=int,
      default=25,
      help="Safety cap on max projects scanned during an --org-id / --folder-id sweep (default: 25).",
  )
  scope_grp.add_argument(
      "--exclude-projects",
      default="",
      help="Comma-separated project IDs to skip during an org/folder sweep.",
  )
  scope_grp.add_argument(
      "--include-projects",
      default="",
      help="Optional comma-separated allowlist of project IDs within the org/folder.",
  )
  scope_grp.add_argument(
      "--discover-only",
      action="store_true",
      help=(
          "For --org-id / --folder-id: discover active projects and run GCS + "
          "upfront GCP API preflight without scanning, returning the project list "
          "so an agent harness (agy CLI / Claude Code) can orchestrate project-by-project "
          "with live chat progress updates."
      ),
  )
  scope_grp.add_argument(
      "--finalize-rollup",
      action="store_true",
      help=(
          "For --org-id / --folder-id: assemble and publish the Org/Folder fleet "
          "rollup (_scopes/<scope>/latest.json + Markdown) from existing per-project "
          "snapshots in GCS (or --output-dir when --local-only)."
      ),
  )

  parser.add_argument(
      "--location",
      default="global",
      help="Recommender API location (default: global).",
  )
  parser.add_argument(
      "--freshness-days",
      type=int,
      default=90,
      help="Lookback window in days for Active Assist and Cloud Audit Logs.",
  )
  parser.add_argument(
      "--log-limit",
      type=int,
      default=500,
      help="Max paginated Cloud Audit Log entries per principal when --audit-bq-table is not set (default: 500).",
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
      "--stages",
      default="all",
      help=(
          "Comma-separated stages to execute, or 'all'. Valid stages: "
          + ",".join(ALL_STAGES_ORDERED)
      ),
  )
  parser.add_argument(
      "--tf-scan-path",
      default=".",
      help="Terraform directory or .tf file for GitOps PR Guardrail scan.",
  )
  parser.add_argument(
      "--scc-finding-file",
      default="",
      help="Optional inbound Cloud SCC finding JSON file for finding-to-fix remediation.",
  )
  parser.add_argument(
      "--wiz-issue-file",
      default="",
      help="Optional inbound Wiz issue / attack-path JSON file for finding-to-fix remediation.",
  )
  class _ExplicitLiveSccAction(argparse.Action):
    """Enables live SCC pull and marks it explicit for API preflight."""
    def __call__(self, _parser, namespace, _values, _option_string=None):
      setattr(namespace, "fetch_live_scc", True)
      setattr(namespace, "explicit_fetch_live_scc", True)

  parser.add_argument(
      "--fetch-live-scc",
      nargs=0,
      action=_ExplicitLiveSccAction,
      help="Explicitly require live Cloud SCC API lookup (auto-probed by default with graceful fallback if disabled).",
  )
  parser.add_argument(
      "--no-fetch-live-scc",
      dest="fetch_live_scc",
      action="store_false",
      help="Disable automatic live Cloud SCC IAM finding lookup.",
  )
  parser.add_argument(
      "--fetch-live-wiz",
      dest="fetch_live_wiz",
      action="store_true",
      default=True,
      help="Auto-pull open GCP IAM issues from Wiz GraphQL API when WIZ_CLIENT_ID, WIZ_CLIENT_SECRET, and WIZ_API_URL are set (default: enabled).",
  )
  parser.add_argument(
      "--no-fetch-live-wiz",
      dest="fetch_live_wiz",
      action="store_false",
      help="Disable automatic live Wiz GraphQL API lookup even when Wiz env vars are set.",
  )
  parser.set_defaults(fetch_live_scc=True, explicit_fetch_live_scc=False)
  parser.add_argument(
      "--output-dir",
      required=True,
      help="Local output directory for generated deliverables.",
  )
  _add_extended_arguments(parser)
  add_gcs_publish_arguments(parser)
  args = parser.parse_args()
  if args.max_expiry_days < 1:
    print("[Error] --max-expiry-days must be >= 1.", file=sys.stderr)
    return 1
  # One correlation id per pipeline invocation, passed to stages that stamp
  # their artifacts (e.g. remediator tickets). The published envelope gets its
  # own immutable run_id from lib.envelope_schema at publish time.
  args._pipeline_run_id = generate_run_identifiers("pipeline")["run_id"]  # pylint: disable=protected-access

  if not (args.project or args.org_id or args.folder_id):
    print(
        "[Error] Provide one of --project=<ID>, --org-id=<ORG_ID>, or --folder-id=<FOLDER_ID>.",
        file=sys.stderr,
    )
    return 1

  requested_stages = (
      list(ALL_STAGES_ORDERED)
      if args.stages.strip().lower() == "all"
      else [s.strip() for s in args.stages.split(",") if s.strip()]
  )
  invalid = [s for s in requested_stages if s not in ALL_STAGES_ORDERED]
  if invalid:
    print(f"[Error] Unknown stage(s): {invalid}", file=sys.stderr)
    return 1

  out_dir = Path(args.output_dir).resolve()
  out_dir.mkdir(parents=True, exist_ok=True)
  mods = _load_all_skill_modules()

  # --- MODE A: Single-Project Execution (default) ---
  if args.project and not (args.org_id or args.folder_id):
    gcp_client = ScopeGuardGCPClient(quota_project=args.project)
    store = GCSAssessmentStore(gcp_client=gcp_client)
    gcs_check = run_skill_gcs_preflight(args, args.project, store=store, check_apis=False)
    run_skill_api_preflight(
        args=args,
        project_id=args.project,
        stages=requested_stages,
        gcp_client=gcp_client,
    )
    report = _run_single_project_pipeline(
        project_id=args.project,
        args=args,
        requested_stages=requested_stages,
        gcs_check=gcs_check,
        store=store,
        out_dir=out_dir,
        mods=mods,
    )
    print(json.dumps(report, indent=2))
    return 0

  # --- MODE B: Native Organization / Folder Multi-Project Sweep ---
  import datetime
  import uuid

  sweep_start = time.monotonic()
  discovery_client = ScopeGuardGCPClient(quota_project=args.host_project or None)
  exclude_list = [p.strip() for p in args.exclude_projects.split(",") if p.strip()]
  include_list = [p.strip() for p in args.include_projects.split(",") if p.strip()]

  discovery = discovery_client.discover_projects_in_scope(
      org_id=args.org_id,
      folder_id=args.folder_id,
      max_projects=max(1, args.max_projects),
      exclude_projects=exclude_list,
      include_projects=include_list,
  )
  discovered_projects = discovery.get("projects", [])
  if not discovered_projects:
    print(
        json.dumps(
            {
                "status": "NO_ACTIVE_PROJECTS_FOUND",
                "scope": discovery["scope_resource"],
                "warnings": discovery.get("warnings", []),
            },
            indent=2,
        )
    )
    return 1

  preflight_project = args.host_project or discovered_projects[0]["project_id"]
  store = GCSAssessmentStore(
      gcp_client=ScopeGuardGCPClient(quota_project=preflight_project)
  )
  gcs_check = run_skill_gcs_preflight(args, preflight_project, store=store, check_apis=False)

  project_results: List[Dict[str, Any]] = []
  tot_principals = 0
  tot_perms_before = 0
  tot_perms_after = 0
  tot_escalations = 0
  tot_standing_humans = 0
  tot_wif = 0
  tot_inbound_rem = 0
  comp_before_vals: List[float] = []
  comp_after_vals: List[float] = []

  total_projects = len(discovered_projects)
  scope_prefix = "org" if discovery["scope_type"] == "organization" else "folder"
  scope_key = f"{scope_prefix}_{discovery['scope_id']}"
  _log_progress(
      f"[ScopeGuard Sweep] Discovered {total_projects} active project(s) under "
      f"{discovery['scope_resource']}: {', '.join(p['project_id'] for p in discovered_projects)}"
  )

  # --- MODE B1: Finalize Org / Folder Fleet Rollup from completed snapshots ---
  if args.finalize_rollup:
    _log_progress(
        f"[ScopeGuard Rollup] Assembling fleet rollup for {discovery['scope_resource']} "
        f"across {total_projects} discovered project(s)..."
    )
    for pmeta in discovered_projects:
      pid = pmeta["project_id"]
      env_doc = None
      if gcs_check:
        env_doc = store.get_json_object(gcs_check["bucket"], f"{pid}/latest.json")
      if not env_doc:
        local_env_file = out_dir / pid / f"assessment_envelope_{pid}.json"
        if local_env_file.exists():
          env_doc = json.loads(local_env_file.read_text(encoding="utf-8"))
      if not env_doc:
        project_results.append(
            {
                "project_id": pid,
                "display_name": pmeta.get("display_name", pid),
                "parent": pmeta.get("parent", discovery["scope_resource"]),
                "folder_path": pmeta.get("folder_path", [discovery["scope_resource"]]),
                "status": "NOT_ASSESSED",
                "kpis": {},
            }
        )
        continue

      kpis = (env_doc.get("recommendation_digest") or {}).get("executive_kpis", {})
      tot_principals += int(kpis.get("total_principals") or 0)
      tot_perms_before += int(kpis.get("permissions_before") or 0)
      tot_perms_after += int(kpis.get("permissions_after") or 0)
      tot_escalations += int(kpis.get("escalation_chains_count") or 0)
      tot_standing_humans += int(kpis.get("standing_privileged_humans_count") or 0)
      tot_wif += int(kpis.get("wif_migration_candidates") or 0)
      tot_inbound_rem += int(kpis.get("inbound_findings_remediated") or 0)
      if kpis.get("compliance_score_before_pct") is not None:
        comp_before_vals.append(float(kpis["compliance_score_before_pct"]))
      if kpis.get("compliance_score_after_pct") is not None:
        comp_after_vals.append(float(kpis["compliance_score_after_pct"]))

      project_results.append(
          {
              "project_id": pid,
              "display_name": pmeta.get("display_name", pid),
              "parent": pmeta.get("parent", discovery["scope_resource"]),
              "folder_path": pmeta.get("folder_path", [discovery["scope_resource"]]),
              "status": "OK",
              "run_id": env_doc.get("run_id", ""),
              "kpis": kpis,
              "gcs_latest_uri": (
                  f"gs://{gcs_check['bucket']}/{pid}/latest.json" if gcs_check else ""
              ),
          }
      )
  else:
    # Upfront Fleet API Pre-Check BEFORE starting multi-project scans
    api_checks_by_project: Dict[str, Dict[str, Any]] = {}
    if not getattr(args, "skip_api_check", False):
      _log_progress(
          f"[ScopeGuard Sweep] Running upfront GCP API preflight across {total_projects} project(s)..."
      )
      projects_needing_apis: List[Dict[str, Any]] = []
      for pmeta in discovered_projects:
        pid = pmeta["project_id"]
        chk = run_skill_api_preflight(
            args=args,
            project_id=pid,
            stages=requested_stages,
            gcp_client=ScopeGuardGCPClient(quota_project=pid),
            non_blocking=True,
        )
        api_checks_by_project[pid] = chk
        if chk.get("status") == "APIS_ENABLEMENT_REQUIRED":
          projects_needing_apis.append(
              {
                  "project_id": pid,
                  "missing_apis": chk.get("missing_apis", []),
                  "enable_command": chk.get("enable_command", ""),
              }
          )
      if projects_needing_apis:
        print(
            json.dumps(
                {
                    "ok": False,
                    "status": "APIS_ENABLEMENT_REQUIRED",
                    "scope_resource": discovery["scope_resource"],
                    "projects_checked": total_projects,
                    "projects_with_missing_apis_count": len(projects_needing_apis),
                    "projects_with_missing_apis": projects_needing_apis,
                    "action_required": (
                        f"{len(projects_needing_apis)} of {total_projects} project(s) in "
                        f"'{discovery['scope_resource']}' are missing required GCP APIs "
                        "(e.g. recommender.googleapis.com, orgpolicy.googleapis.com). "
                        "Ask the user to confirm whether to: "
                        "(1) Enable the missing APIs across these projects now by re-running with `--ensure-apis`, OR "
                        "(2) Proceed in degraded mode without enabling them by re-running with `--skip-api-check`."
                    ),
                },
                indent=2,
            )
        )
        return EXIT_APIS_ENABLEMENT_REQUIRED

    # --- MODE B2: Discover-Only (for Agent-Driven Live Chat Progress) ---
    if args.discover_only:
      print(
          json.dumps(
              {
                  "status": "DISCOVERY_READY",
                  "scope_type": discovery["scope_type"],
                  "scope_id": discovery["scope_id"],
                  "scope_resource": discovery["scope_resource"],
                  "project_count": total_projects,
                  "projects": discovered_projects,
                  "folders_discovered": discovery.get("folders_discovered", []),
                  "gcs_bucket": gcs_check["bucket"] if gcs_check else "local-only",
                  "api_preflight_summary": {
                      pid: chk.get("status", "SKIPPED")
                      for pid, chk in api_checks_by_project.items()
                  },
                  "next_steps": (
                      "Run `scopeguard_pipeline.py --project=<PID> ...` for each project "
                      "(posting a live progress update in chat after each project), then "
                      f"run `scopeguard_pipeline.py --{'org-id' if discovery['scope_type'] == 'organization' else 'folder-id'}={discovery['scope_id']} --finalize-rollup --output-dir={out_dir}`."
                  ),
              },
              indent=2,
          )
      )
      return 0

    def _write_live_progress(completed_count: int, current_pid: str, status: str) -> None:
      elapsed = time.monotonic() - sweep_start
      eta_sec = (
          (elapsed / completed_count) * (total_projects - completed_count)
          if completed_count > 0 and completed_count < total_projects
          else 0.0
      )
      prog_doc = {
          "schema_version": SCHEMA_VERSION,
          "status": status,
          "scope_resource": discovery["scope_resource"],
          "completed_count": completed_count,
          "total_projects": total_projects,
          "percent_complete": round((completed_count / total_projects) * 100.0, 1)
          if total_projects
          else 100.0,
          "current_project": current_pid,
          "elapsed_seconds": round(elapsed, 1),
          "eta_seconds": round(eta_sec, 1),
          "updated_utc": datetime.datetime.now(datetime.timezone.utc).strftime(
              "%Y-%m-%dT%H:%M:%SZ"
          ),
      }
      try:
        (out_dir / "sweep_progress.json").write_text(
            json.dumps(prog_doc, indent=2) + "\n", encoding="utf-8"
        )
        if gcs_check:
          store.put_json_object(
              bucket=gcs_check["bucket"],
              object_path=f"_scopes/{scope_key}/progress.json",
              payload=prog_doc,
              cache_control="no-store, max-age=0",
          )
      except Exception:  # pylint: disable=broad-except
        pass

    for idx, pmeta in enumerate(discovered_projects, start=1):
      pid = pmeta["project_id"]
      completed_so_far = idx - 1
      elapsed = time.monotonic() - sweep_start
      eta_str = (
          f"~{_format_duration((elapsed / completed_so_far) * (total_projects - completed_so_far))}"
          if completed_so_far > 0
          else "estimating..."
      )
      _log_progress(
          f"[ScopeGuard Sweep] {_render_progress_bar(completed_so_far, total_projects)} | "
          f"Project {idx}/{total_projects}: {pid} | Elapsed: {_format_duration(elapsed)} | ETA: {eta_str}"
      )
      _write_live_progress(completed_so_far, pid, "IN_PROGRESS")
      api_check = api_checks_by_project.get(
          pid, {"ok": True, "status": "SKIPPED", "project_id": pid, "missing_apis": []}
      )
      try:
        proj_report = _run_single_project_pipeline(
            project_id=pid,
            args=args,
            requested_stages=requested_stages,
            gcs_check=gcs_check,
            store=store,
            out_dir=out_dir / pid,
            mods=mods,
            project_meta=pmeta,
        )
        kpis = (proj_report.get("recommendation_digest") or {}).get(
            "executive_kpis", {}
        )
        tot_principals += int(kpis.get("total_principals") or 0)
        tot_perms_before += int(kpis.get("permissions_before") or 0)
        tot_perms_after += int(kpis.get("permissions_after") or 0)
        tot_escalations += int(kpis.get("escalation_chains_count") or 0)
        tot_standing_humans += int(kpis.get("standing_privileged_humans_count") or 0)
        tot_wif += int(kpis.get("wif_migration_candidates") or 0)
        tot_inbound_rem += int(kpis.get("inbound_findings_remediated") or 0)
        if kpis.get("compliance_score_before_pct") is not None:
          comp_before_vals.append(float(kpis["compliance_score_before_pct"]))
        if kpis.get("compliance_score_after_pct") is not None:
          comp_after_vals.append(float(kpis["compliance_score_after_pct"]))

        project_results.append(
            {
                "project_id": pid,
                "display_name": pmeta.get("display_name", pid),
                "parent": pmeta.get("parent", discovery["scope_resource"]),
                "folder_path": pmeta.get("folder_path", [discovery["scope_resource"]]),
                "status": "OK",
                "api_preflight": api_check,
                "run_id": (proj_report.get("gcs_publish") or {}).get("run_id", ""),
                "failed_stages": proj_report.get("failed_stages", {}),
                "readme_path": ((proj_report.get("run_outputs") or {}).get("index") or {}).get("readme", ""),
                "elapsed_seconds": proj_report.get("total_elapsed_seconds", 0.0),
                "kpis": kpis,
                "gcs_latest_uri": (proj_report.get("gcs_publish") or {}).get(
                    "gcs_latest_uri", ""
                ),
            }
        )
        _log_progress(
            f"  [OK] {pid} ({_format_duration(proj_report.get('total_elapsed_seconds', 0.0))}) | "
            f"{kpis.get('total_principals', 0)} principals | "
            f"{kpis.get('permissions_before', 0):,} -> {kpis.get('permissions_after', 0):,} perms "
            f"(-{kpis.get('permissions_reduction_pct', 0.0)}%) | GCS updated"
        )
      except Exception as exc:  # pylint: disable=broad-except
        project_results.append(
            {
                "project_id": pid,
                "display_name": pmeta.get("display_name", pid),
                "parent": pmeta.get("parent", discovery["scope_resource"]),
                "folder_path": pmeta.get("folder_path", [discovery["scope_resource"]]),
                "status": "FAILED",
                "error": str(exc),
                "kpis": {},
            }
        )
        _log_progress(f"  [FAILED] {pid}: {exc}")
      _write_live_progress(idx, pid, "COMPLETED" if idx == total_projects else "IN_PROGRESS")

    _log_progress(
        f"[ScopeGuard Sweep] {_render_progress_bar(total_projects, total_projects)} | "
        f"Done in {_format_duration(time.monotonic() - sweep_start)} — publishing Org/Folder rollup to GCS..."
    )

  now_utc = datetime.datetime.now(datetime.timezone.utc)
  sweep_id = f"{now_utc.strftime('%Y%m%dT%H%M%SZ')}_sweep_{uuid.uuid4().hex[:6]}"
  red_pct = (
      round((1.0 - (tot_perms_after / tot_perms_before)) * 100.0, 1)
      if tot_perms_before > 0
      else 0.0
  )
  succeeded = [p for p in project_results if p["status"] == "OK"]
  failed = [p for p in project_results if p["status"] != "OK"]

  rollup_payload = {
      "schema_version": SCHEMA_VERSION,
      "sweep_id": sweep_id,
      "timestamp_utc": now_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
      "scope_type": discovery["scope_type"],
      "scope_id": discovery["scope_id"],
      "scope_resource": discovery["scope_resource"],
      "folders_discovered": discovery.get("folders_discovered", []),
      "discovered_count": len(discovered_projects),
      "succeeded_count": len(succeeded),
      "failed_count": len(failed),
      "total_elapsed_seconds": round(time.monotonic() - sweep_start, 2),
      "aggregate_kpis": {
          "total_principals": tot_principals,
          "permissions_before": tot_perms_before,
          "permissions_after": tot_perms_after,
          "permissions_reduction_pct": red_pct,
          "escalation_chains_count": tot_escalations,
          "standing_privileged_humans_count": tot_standing_humans,
          "wif_migration_candidates": tot_wif,
          "inbound_findings_remediated": tot_inbound_rem,
          "avg_compliance_before_pct": (
              round(sum(comp_before_vals) / len(comp_before_vals), 1)
              if comp_before_vals
              else 0.0
          ),
          "avg_compliance_after_pct": (
              round(sum(comp_after_vals) / len(comp_after_vals), 1)
              if comp_after_vals
              else 0.0
          ),
      },
      "projects": project_results,
      "discovery_warnings": discovery.get("warnings", []),
  }
  rollup_md = _render_scope_rollup_markdown(rollup_payload)
  rollup_publish = None
  if gcs_check:
    rollup_publish = store.publish_scope_rollup(
        bucket=gcs_check["bucket"],
        region=gcs_check["region"],
        scope_type=discovery["scope_type"],
        scope_id=discovery["scope_id"],
        rollup_payload=rollup_payload,
        rollup_markdown=rollup_md,
        local_output_dir=out_dir,
    )
  else:
    prefix = "org" if discovery["scope_type"] == "organization" else "folder"
    scope_key = f"{prefix}_{discovery['scope_id']}"
    (out_dir / f"scope_rollup_{scope_key}.json").write_text(
        json.dumps(rollup_payload, indent=2) + "\n", encoding="utf-8"
    )
    (out_dir / f"scopeguard_scope_recommendations_{scope_key}.md").write_text(
        rollup_md + "\n", encoding="utf-8"
    )

  # Sweep-root README/manifest (per-project folders carry their own index).
  try:
    sweep_index = artifact_index.write_artifact_index(
        out_dir,
        run_id=sweep_id,
        project_id="",
        exclude_dirs=["shareable", "bundles"] + [p["project_id"] for p in project_results],
    )
  except Exception as exc:  # pylint: disable=broad-except
    _log_progress(f"  !! Sweep artifact index failed: {exc}")
    sweep_index = {"error": str(exc)}

  print(
      json.dumps(
          {
              "sweep_index": sweep_index,
              "sweep_summary": {
                  "sweep_id": sweep_id,
                  "scope_resource": discovery["scope_resource"],
                  "discovered_count": len(discovered_projects),
                  "succeeded_count": len(succeeded),
                  "failed_count": len(failed),
                  "aggregate_kpis": rollup_payload["aggregate_kpis"],
              },
              "gcs_rollup_publish": rollup_publish,
              "projects": project_results,
          },
          indent=2,
      )
  )
  return 0


if __name__ == "__main__":
  sys.exit(main())
