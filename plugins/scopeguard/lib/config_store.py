#!/usr/bin/env python3
# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0

"""Persistent ScopeGuard bucket and region configuration manager.

Stores the user-confirmed central GCS assessment bucket and region on first run
so subsequent skill invocations (both sequential pipeline runs and standalone
individual skill runs across any target GCP project) automatically reuse the
confirmed bucket without re-prompting.
"""

from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import re
from typing import Any, Dict, Optional

LOGGER = logging.getLogger("scopeguard.config")

DEFAULT_REGION = "asia-southeast1"
BUCKET_NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]$")


def get_config_file_path() -> Path:
  """Resolves the persistent ScopeGuard configuration file path."""
  override = os.environ.get("SCOPEGUARD_CONFIG_PATH", "").strip()
  if override:
    return Path(override).expanduser().resolve()
  return Path.home() / ".scopeguard" / "config.json"


def normalize_bucket_name(raw_bucket: str) -> str:
  """Strips gs:// prefixes and trailing slashes, then validates bucket syntax."""
  cleaned = raw_bucket.strip()
  if cleaned.startswith("gs://"):
    cleaned = cleaned[len("gs://") :]
  cleaned = cleaned.strip("/")
  if not cleaned:
    raise ValueError("GCS bucket name cannot be empty.")
  if not BUCKET_NAME_PATTERN.match(cleaned):
    raise ValueError(
        f"Invalid GCS bucket name '{cleaned}'. Must start and end with a "
        "lowercase letter or number and contain only lowercase letters, "
        "numbers, hyphens (-), underscores (_), or dots (.)."
    )
  return cleaned


def default_bucket_for_project(project_id: str) -> str:
  """Returns the default first-run bucket suggestion `<project_id>_scopeguard_assessments`."""
  sanitized_proj = re.sub(r"[^a-z0-9._-]", "-", project_id.strip().lower())
  return f"{sanitized_proj}_scopeguard_assessments"


def load_saved_config() -> Optional[Dict[str, Any]]:
  """Loads the persisted ScopeGuard GCS configuration if present and valid."""
  cfg_path = get_config_file_path()
  if not cfg_path.exists():
    return None
  try:
    payload = json.loads(cfg_path.read_text(encoding="utf-8"))
    bucket = payload.get("bucket", "").strip()
    if not bucket:
      return None
    return {
        "bucket": normalize_bucket_name(bucket),
        "region": payload.get("region", DEFAULT_REGION).strip() or DEFAULT_REGION,
        "host_project": payload.get("host_project", "").strip(),
        "configured_at": payload.get("configured_at", ""),
        "config_path": str(cfg_path),
    }
  except (OSError, ValueError, json.JSONDecodeError) as exc:
    LOGGER.warning("Ignoring unreadable config at %s: %s", cfg_path, exc)
    return None


def save_bucket_config(
    bucket: str,
    region: str = DEFAULT_REGION,
    host_project: str = "",
) -> Dict[str, Any]:
  """Persists the confirmed GCS bucket and region to `~/.scopeguard/config.json`."""
  normalized_bucket = normalize_bucket_name(bucket)
  normalized_region = region.strip() or DEFAULT_REGION
  cfg_path = get_config_file_path()
  cfg_path.parent.mkdir(parents=True, exist_ok=True)

  record = {
      "bucket": normalized_bucket,
      "region": normalized_region,
      "host_project": host_project.strip(),
      "configured_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
  }
  # Write atomically via temporary sibling file with restrictive permissions
  tmp_path = cfg_path.with_suffix(".json.tmp")
  tmp_path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
  try:
    os.chmod(tmp_path, 0o600)
  except OSError:
    pass
  tmp_path.replace(cfg_path)
  record["config_path"] = str(cfg_path)
  return record


def resolve_effective_bucket_config(
    cli_bucket: Optional[str] = None,
    cli_region: Optional[str] = None,
    target_project_id: str = "",
) -> Dict[str, Any]:
  """Determines effective bucket/region from CLI flags, env vars, or saved config.

  Precedence:
    1. Explicit `--bucket` CLI argument
    2. `SCOPEGUARD_GCS_BUCKET` environment variable
    3. Persisted `~/.scopeguard/config.json` from first run
    4. Unconfigured (`configured: False`), returning suggested defaults so the
       skill prompts the user to confirm bucket name and region on first run.
  """
  saved = load_saved_config() or {}
  env_bucket = os.environ.get("SCOPEGUARD_GCS_BUCKET", "").strip()
  env_region = os.environ.get("SCOPEGUARD_GCS_REGION", "").strip()

  raw_bucket = (cli_bucket or "").strip() or env_bucket or saved.get("bucket", "")
  region = (
      (cli_region or "").strip()
      or env_region
      or saved.get("region", "")
      or DEFAULT_REGION
  )

  if not raw_bucket:
    suggested_bucket = (
        default_bucket_for_project(target_project_id)
        if target_project_id
        else "project-id_scopeguard_assessments"
    )
    return {
        "configured": False,
        "bucket": "",
        "region": region,
        "source": "unconfigured_first_run",
        "suggested_default_bucket": suggested_bucket,
        "suggested_default_region": DEFAULT_REGION,
        "config_path": str(get_config_file_path()),
    }

  source = (
      "cli_flag"
      if (cli_bucket or "").strip()
      else ("environment_var" if env_bucket else "saved_config")
  )
  return {
      "configured": True,
      "bucket": normalize_bucket_name(raw_bucket),
      "region": region,
      "host_project": saved.get("host_project", target_project_id),
      "source": source,
      "config_path": str(get_config_file_path()),
  }
