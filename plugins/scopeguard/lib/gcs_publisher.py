#!/usr/bin/env python3
# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0

"""GCS preflight validation, bucket bootstrap, and versioned run publishing.

Storage Layout inside `gs://<configured_bucket>/`:
  <project_id>/
    ├── latest.json
    └── runs/
        ├── 20261118T061500Z_full-suite_9f8a1c.json
        └── 20261118T082210Z_role-architect_3d1b4e.json

Enforces a fast (<1s) pre-check before any skill executes IAM queries:
  1. Verifies bucket & region configuration (or triggers first-run prompt).
  2. Verifies GCS bucket existence (`GET /storage/v1/b/<bucket>`).
  3. Verifies write/read permissions (`storage.buckets.testIamPermissions`).
"""

import argparse
import json
import logging
import re
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional
from urllib import parse as urllib_parse

from .config_store import (
    DEFAULT_REGION,
    normalize_bucket_name,
    resolve_effective_bucket_config,
    save_bucket_config,
)
from .envelope_schema import assemble_assessment_envelope
from .gcp_client import GCPHTTPError, ScopeGuardGCPClient

LOGGER = logging.getLogger("scopeguard.gcs_publisher")

EXIT_BUCKET_CONFIG_REQUIRED = 20
EXIT_BUCKET_NOT_FOUND = 21
EXIT_BUCKET_PERMISSION_DENIED = 22


class GCSAssessmentStore:
  """Client for GCS preflight verification, project/run listing, and publishing."""

  def __init__(self, gcp_client: Optional[ScopeGuardGCPClient] = None) -> None:
    self.client = gcp_client or ScopeGuardGCPClient()

  def preflight_check_bucket(
      self,
      bucket: str,
      region: str = DEFAULT_REGION,
      host_project: str = "",
      require_write: bool = True,
      create_if_missing: bool = False,
      persist_config: bool = False,
  ) -> Dict[str, Any]:
    """Verifies bucket existence and IAM permissions prior to skill execution."""
    normalized = normalize_bucket_name(bucket)
    meta_url = (
        "https://storage.googleapis.com/storage/v1/b/"
        f"{urllib_parse.quote(normalized, safe='')}"
    )

    bucket_meta: Dict[str, Any] = {}
    created_now = False

    try:
      bucket_meta = self.client.request_json(
          url=meta_url, method="GET", service_key="storage"
      )
    except GCPHTTPError as err:
      if err.status_code == 404:
        if not create_if_missing:
          return {
              "ok": False,
              "code": "BUCKET_NOT_FOUND",
              "bucket": normalized,
              "region": region,
              "host_project": host_project,
              "message": (
                  f"GCS bucket 'gs://{normalized}' does not exist yet. "
                  f"Ask the user to confirm creating 'gs://{normalized}' in "
                  f"region '{region}' (project '{host_project}'), then re-run "
                  "with `--ensure-bucket --save-bucket-config`."
              ),
          }
        if not host_project:
          return {
              "ok": False,
              "code": "HOST_PROJECT_REQUIRED",
              "bucket": normalized,
              "message": "Cannot create GCS bucket without a host GCP project ID.",
          }
        bucket_meta = self._create_secure_bucket(
            bucket=normalized, region=region, host_project=host_project
        )
        created_now = True
      elif err.status_code == 403:
        return {
            "ok": False,
            "code": "BUCKET_FORBIDDEN_OR_TAKEN",
            "bucket": normalized,
            "message": (
                f"Access denied to 'gs://{normalized}' (HTTP 403). Either this "
                "bucket name is owned by another GCP organization in the global "
                "GCS namespace or the current identity lacks storage access. "
                "Please choose a different custom bucket name."
            ),
        }
      else:
        return {
            "ok": False,
            "code": "GCS_HTTP_ERROR",
            "bucket": normalized,
            "message": str(err),
        }

    # Test object-level permissions before running long IAM scans
    needed_perms = ["storage.objects.get", "storage.objects.list"]
    if require_write:
      needed_perms.append("storage.objects.create")
    q_perms = "&".join(
        f"permissions={urllib_parse.quote(p, safe='')}" for p in needed_perms
    )
    perm_url = f"{meta_url}/iam/testPermissions?{q_perms}"
    try:
      perm_resp = self.client.request_json(
          url=perm_url, method="GET", service_key="storage"
      )
      granted = set(perm_resp.get("permissions", []))
      missing = [p for p in needed_perms if p not in granted]
      if missing:
        return {
            "ok": False,
            "code": "BUCKET_PERMISSION_DENIED",
            "bucket": normalized,
            "missing_permissions": missing,
            "message": (
                f"Active identity is missing {missing} on 'gs://{normalized}'."
            ),
        }
    except GCPHTTPError as err:
      LOGGER.debug("testPermissions check returned %s; continuing", err)

    actual_location = str(bucket_meta.get("location", region)).lower()
    saved_record = None
    if persist_config:
      saved_record = save_bucket_config(
          bucket=normalized,
          region=actual_location,
          host_project=host_project,
      )

    return {
        "ok": True,
        "code": "CREATED_AND_READY" if created_now else "READY",
        "bucket": normalized,
        "region": actual_location,
        "saved_config": saved_record,
        "message": f"GCS bucket 'gs://{normalized}' ({actual_location}) verified.",
    }

  def _create_secure_bucket(
      self, bucket: str, region: str, host_project: str
  ) -> Dict[str, Any]:
    """Creates a GCS bucket with uniform bucket-level access & public prevention."""
    create_url = (
        "https://storage.googleapis.com/storage/v1/b?project="
        f"{urllib_parse.quote(host_project, safe='')}"
    )
    body = {
        "name": bucket,
        "location": region,
        "storageClass": "STANDARD",
        "iamConfiguration": {
            "uniformBucketLevelAccess": {"enabled": True},
            "publicAccessPrevention": "enforced",
        },
        "versioning": {"enabled": False},
    }
    return self.client.request_json(
        url=create_url, method="POST", body=body, service_key="storage"
    )

  def get_json_object(
      self, bucket: str, object_path: str
  ) -> Optional[Dict[str, Any]]:
    """Downloads and parses a JSON object from GCS, returning None if 404."""
    normalized = normalize_bucket_name(bucket)
    encoded_obj = urllib_parse.quote(object_path.lstrip("/"), safe="")
    url = (
        f"https://storage.googleapis.com/storage/v1/b/"
        f"{urllib_parse.quote(normalized, safe='')}/o/{encoded_obj}?alt=media"
    )
    try:
      _, raw_bytes, _ = self.client.request_raw(
          url=url, method="GET", service_key="storage"
      )
      return json.loads(raw_bytes.decode("utf-8"))
    except GCPHTTPError as err:
      if err.status_code == 404:
        return None
      raise

  def get_text_object(
      self, bucket: str, object_path: str
  ) -> Optional[str]:
    """Downloads a UTF-8 text object from GCS, returning None on HTTP 404.

    Args:
      bucket: GCS bucket name (with or without `gs://` prefix).
      object_path: Object key inside the bucket.

    Returns:
      Decoded UTF-8 text on HTTP 200, or None if the object does not exist.

    Raises:
      GCPHTTPError: For non-404 GCS API errors.
    """
    normalized = normalize_bucket_name(bucket)
    encoded_obj = urllib_parse.quote(object_path.lstrip("/"), safe="")
    url = (
        "https://storage.googleapis.com/storage/v1/b/"
        f"{urllib_parse.quote(normalized, safe='')}/o/{encoded_obj}?alt=media"
    )
    try:
      _, raw_bytes, _ = self.client.request_raw(
          url=url, method="GET", service_key="storage"
      )
      return raw_bytes.decode("utf-8")
    except GCPHTTPError as err:
      if err.status_code == 404:
        return None
      raise

  def put_json_object(
      self,
      bucket: str,
      object_path: str,
      payload: Dict[str, Any],
      cache_control: str = "no-store, max-age=0",
  ) -> Dict[str, Any]:
    """Uploads a JSON document to GCS using multipart/metadata-safe media upload."""
    normalized = normalize_bucket_name(bucket)
    clean_obj = object_path.lstrip("/")
    encoded_name = urllib_parse.quote(clean_obj, safe="")
    upload_url = (
        "https://storage.googleapis.com/upload/storage/v1/b/"
        f"{urllib_parse.quote(normalized, safe='')}/o"
        f"?uploadType=media&name={encoded_name}"
    )
    raw_bytes = (json.dumps(payload, indent=2, sort_keys=False) + "\n").encode(
        "utf-8"
    )
    _, resp_bytes, _ = self.client.request_raw(
        url=upload_url,
        method="POST",
        raw_body=raw_bytes,
        content_type="application/json; charset=utf-8",
        extra_headers={"Cache-Control": cache_control},
        service_key="storage",
    )
    return json.loads(resp_bytes.decode("utf-8")) if resp_bytes else {}

  def put_text_object(
      self,
      bucket: str,
      object_path: str,
      text: str,
      content_type: str = "text/markdown; charset=utf-8",
      cache_control: str = "no-store, max-age=0",
  ) -> Dict[str, Any]:
    """Uploads a UTF-8 text/Markdown document to GCS."""
    normalized = normalize_bucket_name(bucket)
    clean_obj = object_path.lstrip("/")
    encoded_name = urllib_parse.quote(clean_obj, safe="")
    upload_url = (
        "https://storage.googleapis.com/upload/storage/v1/b/"
        f"{urllib_parse.quote(normalized, safe='')}/o"
        f"?uploadType=media&name={encoded_name}"
    )
    _, resp_bytes, _ = self.client.request_raw(
        url=upload_url,
        method="POST",
        raw_body=text.encode("utf-8"),
        content_type=content_type,
        extra_headers={"Cache-Control": cache_control},
        service_key="storage",
    )
    return json.loads(resp_bytes.decode("utf-8")) if resp_bytes else {}

  # Audience documents and machine exports produced by
  # artifact_index.finalize_run_outputs(). Only read-only documents are
  # published; executable .sh/.tf deliverables already travel inside the
  # envelope and stay out of the shared bucket listing on purpose.
  RUN_OUTPUT_FILES: Dict[str, str] = {
      "EXECUTIVE_SUMMARY.md": "text/markdown; charset=utf-8",
      "REMEDIATION_PLAN.md": "text/markdown; charset=utf-8",
      "EVIDENCE.md": "text/markdown; charset=utf-8",
      "README.md": "text/markdown; charset=utf-8",
      "manifest.json": "application/json",
      "findings.csv": "text/csv; charset=utf-8",
      "findings.jsonl": "application/x-ndjson",
      "scopeguard.sarif.json": "application/sarif+json",
      "scc_findings_import.json": "application/json",
  }

  def publish_run_outputs(
      self,
      bucket: str,
      project_id: str,
      run_id: str,
      local_output_dir: Path,
  ) -> Dict[str, Any]:
    """Uploads finalized audience docs/exports next to the envelope run file.

    Objects land under `<pid>/runs/<run_id>/` (immutable) and
    `<pid>/latest/` (mutable pointer). Each file is uploaded independently so
    one failure never blocks the rest; failures are returned, not raised,
    because the envelope itself has already been published successfully.

    Args:
      bucket: Assessment bucket name.
      project_id: Target project ID.
      run_id: Envelope run ID returned by publish_assessment_run().
      local_output_dir: Project output directory holding the finalized files.

    Returns:
      {"uploaded": [gs:// URIs], "errors": [str]}.
    """
    normalized = normalize_bucket_name(bucket)
    uploaded: List[str] = []
    errors: List[str] = []
    if not run_id or not re.match(r"^[A-Za-z0-9_.\-]+$", run_id):
      return {"uploaded": uploaded, "errors": [f"invalid run_id: {run_id!r}"]}
    for name, ctype in self.RUN_OUTPUT_FILES.items():
      path = local_output_dir / name
      if not path.is_file():
        continue
      try:
        text = path.read_text(encoding="utf-8")
        for obj, cache in (
            (f"{project_id}/runs/{run_id}/{name}", "public, max-age=31536000, immutable"),
            (f"{project_id}/latest/{name}", "no-store, max-age=0"),
        ):
          self.put_text_object(
              bucket=normalized,
              object_path=obj,
              text=text,
              content_type=ctype,
              cache_control=cache,
          )
          uploaded.append(f"gs://{normalized}/{obj}")
      except Exception as exc:  # pylint: disable=broad-except
        LOGGER.warning("Upload of %s failed: %s", name, exc)
        errors.append(f"{name}: {exc}")
    return {"uploaded": uploaded, "errors": errors}

  def list_projects(self, bucket: str) -> List[Dict[str, Any]]:
    """Lists top-level GCP project folders (`<project_id>/`) inside the bucket."""
    normalized = normalize_bucket_name(bucket)
    url = (
        "https://storage.googleapis.com/storage/v1/b/"
        f"{urllib_parse.quote(normalized, safe='')}/o?delimiter=/&maxResults=500"
    )
    resp = self.client.request_json(url=url, method="GET", service_key="storage")
    prefixes = resp.get("prefixes", [])
    projects: List[Dict[str, Any]] = []
    for pfx in sorted(prefixes):
      proj_id = pfx.rstrip("/")
      if not proj_id or proj_id.startswith(".") or proj_id.startswith("_"):
        continue
      runs = self.list_project_runs(normalized, proj_id)
      latest_run = runs[0] if runs else {}
      projects.append(
          {
              "project_id": proj_id,
              "run_count": len(runs),
              "latest_run_id": latest_run.get("run_id", ""),
              "latest_updated": latest_run.get("updated", ""),
              "latest_trigger_mode": latest_run.get("trigger_mode", ""),
          }
      )
    return projects

  def list_project_runs(
      self, bucket: str, project_id: str
  ) -> List[Dict[str, Any]]:
    """Lists all immutable timestamped run files for a project (newest first).

    Uses `delimiter=/` and a direct-child check so per-run deliverable JSON
    files stored under `<project_id>/runs/<run_id>/` (e.g. `manifest.json`,
    `scopeguard.sarif.json`, `scc_findings_import.json`) are never mistaken
    for assessment run envelopes.
    """
    normalized = normalize_bucket_name(bucket)
    raw_prefix = f"{project_id.strip('/')}/runs/"
    prefix = urllib_parse.quote(raw_prefix, safe="")
    url = (
        "https://storage.googleapis.com/storage/v1/b/"
        f"{urllib_parse.quote(normalized, safe='')}/o"
        f"?prefix={prefix}&delimiter=/&maxResults=250"
    )
    resp = self.client.request_json(url=url, method="GET", service_key="storage")
    items = resp.get("items", [])
    runs: List[Dict[str, Any]] = []
    for item in items:
      name = item.get("name", "")
      if not name.startswith(raw_prefix) or not name.endswith(".json"):
        continue
      rel = name[len(raw_prefix):]
      # Ignore nested per-run artifacts under `<project_id>/runs/<run_id>/*`.
      if "/" in rel:
        continue
      fname = rel
      run_id = fname[:-5]
      parts = run_id.split("_")
      ts_compact = parts[0] if parts else ""
      trigger_mode = parts[1] if len(parts) >= 3 else "assessment"
      runs.append(
          {
              "run_id": run_id,
              "object_path": name,
              "filename": fname,
              "compact_timestamp": ts_compact,
              "trigger_mode": trigger_mode,
              "size_bytes": int(item.get("size", 0)),
              "updated": item.get("updated", ""),
          }
      )
    # Lexicographical descending order on YYYYMMDDTHHMMSSZ puts newest run first
    runs.sort(key=lambda r: r["filename"], reverse=True)
    return runs

  def publish_assessment_run(
      self,
      bucket: str,
      region: str,
      project_id: str,
      trigger_mode: str,
      updated_modules: Dict[str, Dict[str, Any]],
      live_policy_etag: str = "",
      local_output_dir: Optional[Path] = None,
  ) -> Dict[str, Any]:
    """Merges with prior latest.json (if partial), writes new run file + latest.json."""
    normalized = normalize_bucket_name(bucket)
    prior_latest = self.get_json_object(normalized, f"{project_id}/latest.json")

    envelope = assemble_assessment_envelope(
        project_id=project_id,
        trigger_mode=trigger_mode,
        updated_modules=updated_modules,
        prior_envelope=prior_latest,
        live_policy_etag=live_policy_etag,
        bucket_name=normalized,
        bucket_region=region,
    )

    run_obj_path = envelope["gcs_metadata"]["object_path"]
    latest_obj_path = envelope["gcs_metadata"]["latest_pointer_path"]
    master_md = envelope.get("master_recommendations_markdown", "")
    run_md_path = f"{project_id}/runs/{envelope['run_id']}.md"
    latest_md_path = f"{project_id}/latest_recommendations.md"

    # 1. Write new immutable timestamped run file (1 new file per analysis)
    self.put_json_object(
        bucket=normalized,
        object_path=run_obj_path,
        payload=envelope,
        cache_control="public, max-age=31536000, immutable",
    )

    # 2. Update project's latest.json snapshot for instant default UI load
    self.put_json_object(
        bucket=normalized,
        object_path=latest_obj_path,
        payload=envelope,
        cache_control="no-store, max-age=0",
    )

    # 3. Upload standalone Markdown recommendations alongside JSON run + latest
    if master_md:
      self.put_text_object(
          bucket=normalized,
          object_path=run_md_path,
          text=master_md + "\n",
          cache_control="public, max-age=31536000, immutable",
      )
      self.put_text_object(
          bucket=normalized,
          object_path=latest_md_path,
          text=master_md + "\n",
          cache_control="no-store, max-age=0",
      )

    local_md_file_str = ""
    if local_output_dir:
      local_output_dir.mkdir(parents=True, exist_ok=True)
      local_file = local_output_dir / f"assessment_envelope_{project_id}.json"
      local_file.write_text(
          json.dumps(envelope, indent=2) + "\n", encoding="utf-8"
      )
      if master_md:
        local_md_file = (
            local_output_dir / f"scopeguard_recommendations_{project_id}.md"
        )
        local_md_file.write_text(master_md + "\n", encoding="utf-8")
        local_md_file_str = str(local_md_file)

    return {
        "run_id": envelope["run_id"],
        "project_id": project_id,
        "timestamp_utc": envelope["timestamp_utc"],
        "bucket": normalized,
        "region": region,
        "gcs_run_uri": f"gs://{normalized}/{run_obj_path}",
        "gcs_latest_uri": f"gs://{normalized}/{latest_obj_path}",
        "gcs_recommendations_md_uri": f"gs://{normalized}/{latest_md_path}",
        "local_recommendations_markdown": local_md_file_str,
        "freshness_overview": envelope["freshness_overview"],
        "recommendation_digest": envelope.get("recommendation_digest", {}),
    }

  def list_scopes(self, bucket: str) -> List[Dict[str, Any]]:
    """Lists published Organization / Folder sweep rollups under `_scopes/`."""
    normalized = normalize_bucket_name(bucket)
    url = (
        "https://storage.googleapis.com/storage/v1/b/"
        f"{urllib_parse.quote(normalized, safe='')}/o"
        "?prefix=_scopes/&delimiter=/&maxResults=250"
    )
    try:
      resp = self.client.request_json(url=url, method="GET", service_key="storage")
    except GCPHTTPError:
      return []
    scopes: List[Dict[str, Any]] = []
    for pfx in sorted(resp.get("prefixes", [])):
      scope_key = pfx.replace("_scopes/", "").strip("/")
      if not scope_key:
        continue
      latest = self.get_json_object(normalized, f"_scopes/{scope_key}/latest.json")
      if latest:
        scopes.append(latest)
    return scopes

  def publish_scope_rollup(
      self,
      bucket: str,
      region: str,
      scope_type: str,
      scope_id: str,
      rollup_payload: Dict[str, Any],
      rollup_markdown: str = "",
      local_output_dir: Optional[Path] = None,
  ) -> Dict[str, Any]:
    """Publishes an Org or Folder multi-project sweep rollup under `_scopes/`."""
    normalized = normalize_bucket_name(bucket)
    prefix = "org" if scope_type == "organization" else "folder"
    scope_key = f"{prefix}_{scope_id}"
    sweep_id = rollup_payload.get("sweep_id", "sweep")

    run_obj_path = f"_scopes/{scope_key}/runs/{sweep_id}.json"
    latest_obj_path = f"_scopes/{scope_key}/latest.json"
    latest_md_path = f"_scopes/{scope_key}/latest_recommendations.md"

    self.put_json_object(
        bucket=normalized,
        object_path=run_obj_path,
        payload=rollup_payload,
        cache_control="public, max-age=31536000, immutable",
    )
    self.put_json_object(
        bucket=normalized,
        object_path=latest_obj_path,
        payload=rollup_payload,
        cache_control="no-store, max-age=0",
    )
    if rollup_markdown:
      self.put_text_object(
          bucket=normalized,
          object_path=latest_md_path,
          text=rollup_markdown + "\n",
          cache_control="no-store, max-age=0",
      )

    local_md_str = ""
    if local_output_dir:
      local_output_dir.mkdir(parents=True, exist_ok=True)
      (local_output_dir / f"scope_rollup_{scope_key}.json").write_text(
          json.dumps(rollup_payload, indent=2) + "\n", encoding="utf-8"
      )
      if rollup_markdown:
        md_file = local_output_dir / f"scopeguard_scope_recommendations_{scope_key}.md"
        md_file.write_text(rollup_markdown + "\n", encoding="utf-8")
        local_md_str = str(md_file)

    return {
        "sweep_id": sweep_id,
        "scope_key": scope_key,
        "scope_type": scope_type,
        "scope_id": scope_id,
        "gcs_run_uri": f"gs://{normalized}/{run_obj_path}",
        "gcs_latest_uri": f"gs://{normalized}/{latest_obj_path}",
        "gcs_recommendations_md_uri": f"gs://{normalized}/{latest_md_path}",
        "local_recommendations_markdown": local_md_str,
    }


def add_gcs_publish_arguments(parser: argparse.ArgumentParser) -> None:
  """Adds uniform GCS preflight and publishing flags to any ScopeGuard skill CLI."""
  grp = parser.add_argument_group("ScopeGuard GCS Assessment Store Options")
  grp.add_argument(
      "--bucket",
      default="",
      help=(
          "Central GCS bucket for ScopeGuard assessments. Defaults to the "
          "saved bucket in ~/.scopeguard/config.json after first-run setup."
      ),
  )
  grp.add_argument(
      "--region",
      default="",
      help=f"GCS bucket region on first-run setup (default: {DEFAULT_REGION}).",
  )
  grp.add_argument(
      "--host-project",
      default="",
      help="GCP project hosting the GCS assessment bucket (defaults to --project-id).",
  )
  grp.add_argument(
      "--save-bucket-config",
      action="store_true",
      help="Persist confirmed --bucket and --region into ~/.scopeguard/config.json.",
  )
  grp.add_argument(
      "--ensure-bucket",
      action="store_true",
      help="Create the GCS bucket if missing (use only after user confirmation).",
  )
  grp.add_argument(
      "--local-only",
      action="store_true",
      help="Skip GCS preflight and write artifacts locally only.",
  )
  api_grp = parser.add_argument_group("ScopeGuard GCP API Preflight Options")
  api_grp.add_argument(
      "--ensure-apis",
      action="store_true",
      help="Enable missing required GCP APIs on the target project (use only after user confirmation).",
  )
  api_grp.add_argument(
      "--skip-api-check",
      action="store_true",
      help="Skip the GCP required APIs preflight check and proceed in degraded mode if any API is disabled.",
  )


_SCRIPT_TO_STAGE: Dict[str, str] = {
    "iam_audit_cli.py": "recommender_audit",
    "role_architect_cli.py": "role_architect",
    "breakglass_simulator_cli.py": "breakglass_simulator",
    "federation_architect_cli.py": "federation_architect",
    "jit_pam_architect_cli.py": "jit_pam_architect",
    "deny_policy_cli.py": "deny_policy_architect",
    "org_hierarchy_cli.py": "org_hierarchy_auditor",
    "gitops_guardrail_cli.py": "gitops_pr_guardrail",
    "compliance_mapper_cli.py": "compliance_mapper",
    "finding_remediator_cli.py": "finding_remediator",
}


def run_skill_gcs_preflight(
    args: argparse.Namespace,
    target_project_id: str,
    store: Optional[GCSAssessmentStore] = None,
    check_apis: bool = True,
) -> Optional[Dict[str, Any]]:
  """Runs mandatory GCS bucket and GCP required-API preflight checks.

  Returns `None` when `--local-only` is set; exits with structured JSON if
  first-run bucket configuration, bucket creation, or GCP API enablement
  confirmation is needed; otherwise returns the verified `{bucket, region, ...}` dict.
  """
  if check_apis:
    script_name = Path(sys.argv[0]).name if sys.argv else ""
    inferred_stage = _SCRIPT_TO_STAGE.get(script_name)
    if inferred_stage:
      from lib.api_preflight import run_skill_api_preflight  # pylint: disable=import-outside-toplevel

      run_skill_api_preflight(
          args=args,
          project_id=target_project_id,
          stages=[inferred_stage],
          gcp_client=store.client if store else None,
      )

  if getattr(args, "local_only", False):
    return None

  eff = resolve_effective_bucket_config(
      cli_bucket=getattr(args, "bucket", ""),
      cli_region=getattr(args, "region", ""),
      target_project_id=target_project_id,
  )
  if not eff.get("configured"):
    prompt_payload = {
        "status": "BUCKET_CONFIG_REQUIRED",
        "target_project_id": target_project_id,
        "suggested_default_bucket": eff["suggested_default_bucket"],
        "suggested_default_region": eff["suggested_default_region"],
        "config_path": eff["config_path"],
        "action_required": (
            "First-run setup: Ask the user to confirm the GCS bucket name "
            f"(default: '{eff['suggested_default_bucket']}', or custom bucket) "
            f"and region (default: '{eff['suggested_default_region']}', or "
            "custom region). Once confirmed, re-run with "
            "`--bucket <BUCKET> --region <REGION> --save-bucket-config` "
            "(add `--ensure-bucket` if the user confirms creating a new bucket)."
        ),
    }
    print(json.dumps(prompt_payload, indent=2))
    sys.exit(EXIT_BUCKET_CONFIG_REQUIRED)

  gcs_store = store or GCSAssessmentStore()
  host_proj = (
      getattr(args, "host_project", "").strip()
      or eff.get("host_project", "")
      or target_project_id
  )
  check = gcs_store.preflight_check_bucket(
      bucket=eff["bucket"],
      region=eff["region"],
      host_project=host_proj,
      require_write=True,
      create_if_missing=bool(getattr(args, "ensure_bucket", False)),
      persist_config=bool(getattr(args, "save_bucket_config", False)),
  )
  if not check.get("ok"):
    print(json.dumps(check, indent=2))
    code = check.get("code", "")
    if code == "BUCKET_NOT_FOUND":
      sys.exit(EXIT_BUCKET_NOT_FOUND)
    sys.exit(EXIT_BUCKET_PERMISSION_DENIED)

  return check
