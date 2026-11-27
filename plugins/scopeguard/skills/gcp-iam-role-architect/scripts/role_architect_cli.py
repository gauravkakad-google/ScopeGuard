#!/usr/bin/env python3
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Multi-command CLI for designing least-privilege GCP IAM custom roles.

Translates plain-English DevOps access requirements, capability IDs, or
predefined role candidates into resource-scoped, least-privilege custom roles.
Enforces resource hierarchy splitting (Project vs. Dataset/Bucket/Secret/Topic/
Service/SA), persona-aware sizing (Headless SA vs. Console UI), privilege-
escalation detection (E1-E5), anti-sprawl deduplication against existing custom
roles (both Model A and strictly disjoint Model B where R_i n R_j = empty), and
generates Custom Role YAMLs, gcloud/bq CLI provisioning scripts, Terraform HCL,
and emergency rollback runbooks.

Uses only Python 3 standard library modules. Run via:
  uv run .agents/skills/gcp-iam-role-architect/scripts/role_architect_cli.py <subcommand> [options]
"""

import argparse
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib import error as urllib_error
from urllib import request as urllib_request

PLUGIN_ROOT = Path(__file__).resolve().parents[3]
if str(PLUGIN_ROOT) not in sys.path:
  sys.path.insert(0, str(PLUGIN_ROOT))

from lib import naming  # pylint: disable=wrong-import-position
from lib.gcp_client import ScopeGuardGCPClient  # pylint: disable=wrong-import-position
from lib.gcs_publisher import (  # pylint: disable=wrong-import-position
    GCSAssessmentStore,
    add_gcs_publish_arguments,
    run_skill_gcs_preflight,
)

# Workspace layout written by gcp-iam-recommender-audit (schema 2.1+):
#   custom-roles/personas/*.yaml      -> Model A persona roles
#   custom-roles/capabilities/*.yaml  -> Model B strictly disjoint capability roles
# Older runs wrote Model A to custom-roles/*.yaml and Model B to
# custom-roles/disjoint/*.yaml; readers fall back to those when the new
# directories are absent so existing workspaces keep working.
PERSONAS_SUBDIR = "personas"
CAPABILITIES_SUBDIR = "capabilities"
LEGACY_DISJOINT_SUBDIR = "disjoint"



class RateLimitError(Exception):
  """Raised when the Google Cloud API rate limit is exceeded after retries."""


class CrossProcessRateLimiter:
  """File-lock-backed rate limiter safe across concurrent processes/subagents."""

  LOCK_FILE = Path("/tmp/gcp_iam_audit_ratelimit.lock")

  def __init__(self, requests_per_second: float = 5.0) -> None:
    self.requests_per_second = max(requests_per_second, 0.1)
    self.delay = 1.0 / self.requests_per_second
    self.last_request_time = 0.0

  def wait(self, custom_rps: Optional[float] = None) -> None:
    """Blocks until the minimum inter-request delay has elapsed."""
    delay = (1.0 / custom_rps) if custom_rps else self.delay
    self.LOCK_FILE.touch(exist_ok=True)
    with open(self.LOCK_FILE, "r+", encoding="utf-8") as lock_fh:
      fcntl.flock(lock_fh.fileno(), fcntl.LOCK_EX)
      try:
        elapsed = time.monotonic() - self.last_request_time
        if elapsed < delay:
          time.sleep(delay - elapsed)
        self.last_request_time = time.monotonic()
      finally:
        fcntl.flock(lock_fh.fileno(), fcntl.LOCK_UN)


class HybridGCPRoleArchitectClient:
  """Hybrid REST (urllib) and validated gcloud CLI client with offline fallback."""

  SERVICE_RPS = {
      "iam": 10.0,
      "cloudresourcemanager": 4.0,
  }

  def __init__(
      self,
      project_id: Optional[str] = None,
      offline: bool = False,
  ) -> None:
    self.project_id = project_id
    self.offline = offline or not bool(project_id)
    self.limiter = CrossProcessRateLimiter(requests_per_second=5.0)
    self._adc_token: Optional[str] = None
    self._token_expiry: float = 0.0
    self._adc_checked = False
    self._has_gcloud = bool(shutil.which("gcloud"))
    self._prefer_rest = bool(os.environ.get("K_SERVICE")) or not self._has_gcloud
    self.transport_log: List[str] = []

  def _get_adc_token(self) -> Optional[str]:
    """Retrieves an access token from Cloud Run Metadata Server or local ADC."""
    if self.offline:
      return None
    now = time.monotonic()
    if self._adc_token and now < self._token_expiry:
      return self._adc_token

    meta_url = (
        "http://metadata.google.internal/computeMetadata/v1/"
        "instance/service-accounts/default/token"
    )
    try:
      req = urllib_request.Request(meta_url, method="GET")
      req.add_header("Metadata-Flavor", "Google")
      with urllib_request.urlopen(req, timeout=1.5) as resp:
        payload = json.loads(resp.read().decode("utf-8"))
        tok = payload.get("access_token", "")
        ttl = float(payload.get("expires_in", 300))
        if tok:
          self._adc_token = tok
          self._token_expiry = now + max(30.0, ttl - 60.0)
          self._prefer_rest = True
          return self._adc_token
    except (OSError, ValueError, urllib_error.URLError):
      pass

    if self._adc_checked:
      return self._adc_token
    self._adc_checked = True
    if self._has_gcloud:
      try:
        proc = subprocess.run(
            [
                "gcloud",
                "auth",
                "application-default",
                "print-access-token",
                "--quiet",
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if proc.returncode == 0 and proc.stdout.strip():
          self._adc_token = proc.stdout.strip()
          self._token_expiry = now + 1800.0
      except (OSError, subprocess.SubprocessError):
        self._adc_token = None
    return self._adc_token

  def _rest_request(
      self,
      url: str,
      method: str = "GET",
      body: Optional[Dict[str, Any]] = None,
      service_key: str = "iam",
      retries: int = 3,
  ) -> Dict[str, Any]:
    """Executes an HTTP request using urllib with rate limiting and retries."""
    token = self._get_adc_token()
    if not token:
      raise RuntimeError("ADC token unavailable; falling back to gcloud CLI.")

    rps = self.SERVICE_RPS.get(service_key, 5.0)
    payload_bytes = (
        json.dumps(body).encode("utf-8") if body is not None else None
    )

    for attempt in range(retries):
      self.limiter.wait(custom_rps=rps)
      req = urllib_request.Request(url, data=payload_bytes, method=method)
      req.add_header("Authorization", f"Bearer {token}")
      if self.project_id:
        req.add_header("X-Goog-User-Project", self.project_id)
      req.add_header("Accept", "application/json")
      req.add_header(
          "User-Agent",
          "agent-skills/1.0 (skill:gcp-iam-role-architect)",
      )
      if payload_bytes is not None:
        req.add_header("Content-Type", "application/json")

      try:
        with urllib_request.urlopen(req, timeout=25) as response:
          raw = response.read().decode("utf-8")
          return json.loads(raw) if raw.strip() else {}
      except urllib_error.HTTPError as err:
        if err.code == 429:
          wait = 2**attempt
          print(
              f"[RateLimit] HTTP 429 from {url}, retrying in {wait}s "
              f"(attempt {attempt + 1}/{retries})...",
              file=sys.stderr,
          )
          if attempt == retries - 1:
            raise RateLimitError(
                f"HTTP 429 Too Many Requests from {url}. Rate limit "
                f"({rps} req/s) exceeded after {retries} retries."
            ) from err
          time.sleep(wait)
          continue
        if err.code >= 500:
          wait = 2**attempt
          print(
              f"[ServerError] HTTP {err.code} from {url}, retrying in {wait}s "
              f"(attempt {attempt + 1}/{retries})...",
              file=sys.stderr,
          )
          if attempt == retries - 1:
            raise RuntimeError(
                f"Server error {err.code} from {url} after {retries} retries."
            ) from err
          time.sleep(wait)
          continue
        try:
          err_body = err.read().decode("utf-8", errors="replace")[:800]
        except OSError:
          err_body = "<unreadable response body>"
        raise RuntimeError(
            f"HTTP {err.code} from {url}: {err_body}"
        ) from err
      except urllib_error.URLError as err:
        raise RuntimeError(f"Network error calling {url}: {err}") from err
    return {}

  def _dispatch_rest_for_args(self, args: List[str], service_key: str) -> Any:
    """Executes equivalent REST API calls when running on Cloud Run or without gcloud."""
    if args[:2] == ["iam", "list-testable-permissions"]:
      resource = args[2]
      all_perms: List[Dict[str, Any]] = []
      page_token = ""
      for _ in range(15):
        body: Dict[str, Any] = {"fullResourceName": resource, "pageSize": 1000}
        if page_token:
          body["pageToken"] = page_token
        resp = self._rest_request(
            "https://iam.googleapis.com/v1/permissions:queryTestablePermissions",
            method="POST",
            body=body,
            service_key=service_key,
        )
        all_perms.extend(resp.get("permissions", []))
        page_token = resp.get("nextPageToken", "")
        if not page_token:
          break
      return all_perms
    if args[:3] == ["iam", "roles", "describe"]:
      role_ref = args[3]
      proj_arg = self.project_id
      for a in args[4:]:
        if a.startswith("--project="):
          proj_arg = a.split("=", 1)[1]
      if any(a.startswith("--project=") for a in args[4:]) and not role_ref.startswith(("roles/", "projects/")):
        role_path = f"projects/{proj_arg}/roles/{role_ref}"
      else:
        role_path = role_ref
      return self._rest_request(
          f"https://iam.googleapis.com/v1/{role_path}",
          method="GET",
          service_key=service_key,
      )
    if args[:3] == ["iam", "roles", "list"]:
      resp = self._rest_request(
          f"https://iam.googleapis.com/v1/projects/{self.project_id}/roles?pageSize=200",
          method="GET",
          service_key=service_key,
      )
      return resp.get("roles", [])
    raise RuntimeError(f"Unsupported REST command mapping: {args}")

  def _run_gcloud_json(
      self,
      args: List[str],
      service_key: str = "iam",
      timeout: int = 45,
  ) -> Any:
    """Runs a query via Cloud Run REST (when preferred/headless) or validated gcloud CLI."""
    if self._prefer_rest or not self._has_gcloud:
      try:
        return self._dispatch_rest_for_args(args, service_key=service_key)
      except Exception:  # pylint: disable=broad-except
        if not self._has_gcloud:
          raise

    rps = self.SERVICE_RPS.get(service_key, 5.0)
    self.limiter.wait(custom_rps=rps)
    cmd = ["gcloud"] + args + ["--format=json", "--quiet"]
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if proc.returncode != 0:
      stderr_snip = (proc.stderr or "").strip()[:800]
      raise RuntimeError(
          f"gcloud command failed ({' '.join(cmd)}): {stderr_snip}"
      )
    stdout_str = (proc.stdout or "").strip()
    return json.loads(stdout_str) if stdout_str else []

  def fetch_testable_permissions(self) -> Dict[str, Dict[str, str]]:
    """Fetches testable permissions for the target project or falls back cleanly."""
    if self.offline or not self.project_id:
      self.transport_log.append(
          "offline_mode: skipped live queryTestablePermissions API call."
      )
      return {}

    # Check local / scopeguard-output cached audit bundles first to avoid redundant API calls
    candidate_bundles = [
        Path(f"scopeguard-output/{self.project_id}/audit_bundle_{self.project_id}.json"),
        Path(f"audit-output/{self.project_id}/audit_bundle_{self.project_id}.json"),
        Path(f"audit_bundle_{self.project_id}.json"),
    ]
    for local_bundle in candidate_bundles:
      if local_bundle.exists():
        try:
          data = json.loads(local_bundle.read_text(encoding="utf-8"))
          cached = data.get("testable_permissions", {})
          if isinstance(cached, list) and cached:
            norm = {
                it["name"]: {
                    "customRolesSupportLevel": it.get("customRolesSupportLevel", "SUPPORTED"),
                    "stage": it.get("stage", "GA"),
                }
                for it in cached
                if isinstance(it, dict) and it.get("name")
            }
            if norm:
              self.transport_log.append(
                  f"cache_hit: loaded {len(norm)} testable permissions from {local_bundle}."
              )
              return norm
          elif isinstance(cached, dict) and cached:
            self.transport_log.append(
                f"cache_hit: loaded {len(cached)} testable permissions from {local_bundle}."
            )
            return cached
        except (OSError, json.JSONDecodeError):
          pass

    resource = f"//cloudresourcemanager.googleapis.com/projects/{self.project_id}"
    try:
      raw_perms = self._run_gcloud_json(
          [
              "iam",
              "list-testable-permissions",
              resource,
              f"--project={self.project_id}",
          ],
          service_key="iam",
          timeout=60,
      )
      result: Dict[str, Dict[str, str]] = {}
      for item in raw_perms:
        name = item.get("name")
        if name:
          result[name] = {
              "customRolesSupportLevel": item.get(
                  "customRolesSupportLevel", "SUPPORTED"
              ),
              "stage": item.get("stage", "GA"),
          }
      self.transport_log.append(
          f"live_gcloud: fetched {len(result)} testable permissions for {self.project_id}."
      )
      return result
    except Exception as exc:  # pylint: disable=broad-except
      self.transport_log.append(
          f"fallback_offline: queryTestablePermissions failed ({exc}); using static rules."
      )
      return {}

  def describe_role_permissions(self, role_name: str) -> List[str]:
    """Expands a predefined or custom role into its includedPermissions list."""
    if self.offline:
      return STATIC_PREDEFINED_ROLE_MAP.get(role_name, [])

    try:
      if role_name.startswith("projects/"):
        parts = role_name.split("/")
        proj = parts[1]
        role_id = parts[3]
        info = self._run_gcloud_json(
            ["iam", "roles", "describe", role_id, f"--project={proj}"],
            service_key="iam",
        )
      else:
        info = self._run_gcloud_json(
            ["iam", "roles", "describe", role_name],
            service_key="iam",
        )
      return sorted(info.get("includedPermissions", []))
    except Exception as exc:  # pylint: disable=broad-except
      self.transport_log.append(
          f"role_describe_fallback ({role_name}): {exc}"
      )
      return STATIC_PREDEFINED_ROLE_MAP.get(role_name, [])

  def list_project_custom_roles(self) -> List[Dict[str, Any]]:
    """Lists existing custom roles in the target project when online."""
    if self.offline or not self.project_id:
      return []
    try:
      roles = self._run_gcloud_json(
          [
              "iam",
              "roles",
              "list",
              f"--project={self.project_id}",
              "--limit=200",
          ],
          service_key="iam",
      )
      detailed: List[Dict[str, Any]] = []
      for r in roles:
        if r.get("deleted"):
          continue
        r_name = r.get("name", "")
        perms = self.describe_role_permissions(r_name)
        detailed.append({
            "name": r_name,
            "role_id": r_name.split("/")[-1] if "/" in r_name else r_name,
            "title": r.get("title", ""),
            "description": r.get("description", ""),
            "stage": r.get("stage", "GA"),
            "includedPermissions": perms,
            "source": "gcp_project_live",
        })
      return detailed
    except Exception as exc:  # pylint: disable=broad-except
      self.transport_log.append(f"list_custom_roles_fallback: {exc}")
      return []


# ==============================================================================
# Curated Knowledge Base: Capabilities, Scopes, Predefined Roles & Escalations
# ==============================================================================

STATIC_PREDEFINED_ROLE_MAP: Dict[str, List[str]] = {
    "roles/bigquery.jobUser": [
        "bigquery.jobs.create",
        "bigquery.jobs.get",
        "bigquery.jobs.list",
        "bigquery.readsessions.create",
        "bigquery.readsessions.getData",
        "bigquery.readsessions.update",
        "resourcemanager.projects.get",
        "resourcemanager.projects.list",
    ],
    "roles/bigquery.dataViewer": [
        "bigquery.datasets.get",
        "bigquery.datasets.getIamPolicy",
        "bigquery.models.export",
        "bigquery.models.getData",
        "bigquery.models.getMetadata",
        "bigquery.models.list",
        "bigquery.routines.get",
        "bigquery.routines.list",
        "bigquery.tables.createSnapshot",
        "bigquery.tables.export",
        "bigquery.tables.get",
        "bigquery.tables.getData",
        "bigquery.tables.getIamPolicy",
        "bigquery.tables.list",
        "resourcemanager.projects.get",
        "resourcemanager.projects.list",
    ],
    "roles/bigquery.dataEditor": [
        "bigquery.datasets.get",
        "bigquery.tables.create",
        "bigquery.tables.delete",
        "bigquery.tables.export",
        "bigquery.tables.get",
        "bigquery.tables.getData",
        "bigquery.tables.list",
        "bigquery.tables.update",
        "bigquery.tables.updateData",
    ],
    "roles/storage.objectViewer": [
        "resourcemanager.projects.get",
        "resourcemanager.projects.list",
        "storage.objects.get",
        "storage.objects.list",
    ],
    "roles/storage.objectUser": [
        "storage.multipartUploads.abort",
        "storage.multipartUploads.create",
        "storage.multipartUploads.list",
        "storage.multipartUploads.listParts",
        "storage.objects.create",
        "storage.objects.delete",
        "storage.objects.get",
        "storage.objects.list",
        "storage.objects.update",
    ],
    "roles/secretmanager.secretAccessor": [
        "resourcemanager.projects.get",
        "resourcemanager.projects.list",
        "secretmanager.versions.access",
    ],
    "roles/pubsub.publisher": [
        "pubsub.topics.publish",
    ],
    "roles/pubsub.subscriber": [
        "pubsub.subscriptions.consume",
        "pubsub.topics.attachSubscription",
    ],
    "roles/run.invoker": [
        "run.routes.invoke",
    ],
    "roles/artifactregistry.reader": [
        "artifactregistry.dockerimages.get",
        "artifactregistry.dockerimages.list",
        "artifactregistry.files.get",
        "artifactregistry.files.list",
        "artifactregistry.packages.get",
        "artifactregistry.packages.list",
        "artifactregistry.repositories.downloadArtifacts",
        "artifactregistry.repositories.get",
        "artifactregistry.repositories.list",
        "artifactregistry.tags.get",
        "artifactregistry.tags.list",
        "artifactregistry.versions.get",
        "artifactregistry.versions.list",
    ],
}

CAPABILITY_CATALOG: Dict[str, Dict[str, Any]] = {
    "bq_job_run": {
        "service": "bigquery.googleapis.com",
        "title": "BigQuery Job Execution",
        "scope": "project",
        "resource_placeholder": "PROJECT_ID",
        "closest_predefined_role": "roles/bigquery.jobUser",
        "headless_permissions": [
            "bigquery.jobs.create",
        ],
        "console_ui_additions": [
            "bigquery.jobs.get",
            "bigquery.jobs.list",
        ],
        "optional_permissions": {
            "storage_read_api": [
                "bigquery.readsessions.create",
                "bigquery.readsessions.getData",
            ]
        },
        "keywords": [
            r"\bbq\b.*\bjobs?\b",
            r"\bbigquery\b.*\bjobs?\b",
            r"\brun\s+jobs?\b",
            r"\brun\s+queries\b",
            r"\bexecute\s+queries\b",
            r"\bquery\s+bigquery\b",
        ],
    },
    "bq_dataset_read": {
        "service": "bigquery.googleapis.com",
        "title": "BigQuery Dataset Table Reader",
        "scope": "bigquery_dataset",
        "resource_placeholder": "DATASET_ID",
        "closest_predefined_role": "roles/bigquery.dataViewer",
        "headless_permissions": [
            "bigquery.tables.getData",
        ],
        "console_ui_additions": [
            "bigquery.datasets.get",
            "bigquery.tables.get",
            "bigquery.tables.list",
        ],
        "optional_permissions": {
            "routines_and_models_read": [
                "bigquery.models.getData",
                "bigquery.models.getMetadata",
                "bigquery.models.list",
                "bigquery.routines.get",
                "bigquery.routines.list",
            ]
        },
        "keywords": [
            r"\bread\b.*\bbq\b",
            r"\bread\b.*\bbigquery\b",
            r"\bbq\s+tables?\b",
            r"\bbigquery\s+tables?\b",
            r"\bdataset\b.*\bread\b",
            r"\bread\b.*\bdataset\b",
            r"\bselect\b.*\bbigquery\b",
        ],
    },
    "bq_dataset_write": {
        "service": "bigquery.googleapis.com",
        "title": "BigQuery Dataset Table Writer",
        "scope": "bigquery_dataset",
        "resource_placeholder": "DATASET_ID",
        "closest_predefined_role": "roles/bigquery.dataEditor",
        "headless_permissions": [
            "bigquery.tables.create",
            "bigquery.tables.getData",
            "bigquery.tables.update",
            "bigquery.tables.updateData",
        ],
        "console_ui_additions": [
            "bigquery.datasets.get",
            "bigquery.tables.get",
            "bigquery.tables.list",
        ],
        "optional_permissions": {
            "table_delete": ["bigquery.tables.delete"]
        },
        "keywords": [
            r"\bwrite\b.*\bbq\b",
            r"\bwrite\b.*\bbigquery\b",
            r"\bload\b.*\bbigquery\b",
            r"\binsert\b.*\bbigquery\b",
            r"\bupdate\b.*\bbq\s+tables?\b",
        ],
    },
    "gcs_bucket_read": {
        "service": "storage.googleapis.com",
        "title": "GCS Bucket Object Reader",
        "scope": "storage_bucket",
        "resource_placeholder": "BUCKET_NAME",
        "closest_predefined_role": "roles/storage.objectViewer",
        "headless_permissions": [
            "storage.objects.get",
        ],
        "console_ui_additions": [
            "storage.buckets.get",
            "storage.objects.list",
        ],
        "optional_permissions": {},
        "keywords": [
            r"\bread\b.*\bbucket\b",
            r"\bread\b.*\bgcs\b",
            r"\bread\b.*\bstorage\b",
            r"\bdownload\b.*\bbucket\b",
            r"\bdownload\b.*\bgcs\b",
        ],
    },
    "gcs_bucket_write": {
        "service": "storage.googleapis.com",
        "title": "GCS Bucket Object Writer",
        "scope": "storage_bucket",
        "resource_placeholder": "BUCKET_NAME",
        "closest_predefined_role": "roles/storage.objectUser",
        "headless_permissions": [
            "storage.multipartUploads.abort",
            "storage.multipartUploads.create",
            "storage.multipartUploads.listParts",
            "storage.objects.create",
            "storage.objects.delete",
            "storage.objects.get",
        ],
        "console_ui_additions": [
            "storage.buckets.get",
            "storage.objects.list",
        ],
        "optional_permissions": {},
        "keywords": [
            r"\bwrite\b.*\bbucket\b",
            r"\bupload\b.*\bbucket\b",
            r"\bwrite\b.*\bgcs\b",
            r"\bupload\b.*\bgcs\b",
        ],
    },
    "secret_read": {
        "service": "secretmanager.googleapis.com",
        "title": "Secret Manager Payload Reader",
        "scope": "secretmanager_secret",
        "resource_placeholder": "SECRET_ID",
        "closest_predefined_role": "roles/secretmanager.secretAccessor",
        "headless_permissions": [
            "secretmanager.versions.access",
        ],
        "console_ui_additions": [
            "secretmanager.secrets.get",
            "secretmanager.versions.get",
            "secretmanager.versions.list",
        ],
        "optional_permissions": {},
        "keywords": [
            r"\bread\b.*\bsecrets?\b",
            r"\baccess\b.*\bsecrets?\b",
            r"\bsecret\s+manager\b.*\bread\b",
            r"\bfetch\b.*\bsecrets?\b",
        ],
    },
    "secret_rotate": {
        "service": "secretmanager.googleapis.com",
        "title": "Secret Manager Version Rotator",
        "scope": "secretmanager_secret",
        "resource_placeholder": "SECRET_ID",
        "closest_predefined_role": "roles/secretmanager.secretVersionManager",
        "headless_permissions": [
            "secretmanager.versions.add",
            "secretmanager.versions.destroy",
            "secretmanager.versions.disable",
            "secretmanager.versions.enable",
        ],
        "console_ui_additions": [
            "secretmanager.secrets.get",
            "secretmanager.versions.get",
            "secretmanager.versions.list",
        ],
        "optional_permissions": {},
        "keywords": [
            r"\brotate\b.*\bsecrets?\b",
            r"\bupdate\b.*\bsecrets?\b",
            r"\badd\s+secret\s+version\b",
        ],
    },
    "pubsub_publish": {
        "service": "pubsub.googleapis.com",
        "title": "Pub/Sub Topic Publisher",
        "scope": "pubsub_topic",
        "resource_placeholder": "TOPIC_ID",
        "closest_predefined_role": "roles/pubsub.publisher",
        "headless_permissions": [
            "pubsub.topics.publish",
        ],
        "console_ui_additions": [
            "pubsub.topics.get",
        ],
        "optional_permissions": {},
        "keywords": [
            r"\bpublish\b.*\bpubsub\b",
            r"\bpublish\b.*\btopics?\b",
            r"\bpub/sub\b.*\bpublish\b",
        ],
    },
    "pubsub_consume": {
        "service": "pubsub.googleapis.com",
        "title": "Pub/Sub Subscription Consumer",
        "scope": "pubsub_subscription",
        "resource_placeholder": "SUBSCRIPTION_ID",
        "closest_predefined_role": "roles/pubsub.subscriber",
        "headless_permissions": [
            "pubsub.subscriptions.consume",
        ],
        "console_ui_additions": [
            "pubsub.subscriptions.get",
        ],
        "optional_permissions": {},
        "keywords": [
            r"\bconsume\b.*\bpubsub\b",
            r"\bsubscribe\b.*\bpubsub\b",
            r"\bpull\b.*\bsubscriptions?\b",
            r"\bread\b.*\bsubscriptions?\b",
        ],
    },
    "cloudrun_invoke": {
        "service": "run.googleapis.com",
        "title": "Cloud Run Service Invoker",
        "scope": "cloudrun_service",
        "resource_placeholder": "SERVICE_NAME",
        "closest_predefined_role": "roles/run.invoker",
        "headless_permissions": [
            "run.routes.invoke",
        ],
        "console_ui_additions": [
            "run.services.get",
        ],
        "optional_permissions": {},
        "keywords": [
            r"\binvoke\b.*\bcloud\s*run\b",
            r"\bcall\b.*\bcloud\s*run\b",
        ],
    },
    "cloudrun_deploy": {
        "service": "run.googleapis.com",
        "title": "Cloud Run Service Deployer",
        "scope": "cloudrun_service",
        "resource_placeholder": "SERVICE_NAME",
        "closest_predefined_role": "roles/run.developer",
        "headless_permissions": [
            "run.operations.get",
            "run.services.create",
            "run.services.get",
            "run.services.update",
        ],
        "console_ui_additions": [
            "run.locations.list",
            "run.revisions.get",
            "run.revisions.list",
            "run.services.list",
        ],
        "optional_permissions": {
            "runtime_sa_attachment": ["iam.serviceAccounts.actAs"]
        },
        "keywords": [
            r"\bdeploy\b.*\bcloud\s*run\b",
            r"\bupdate\b.*\bcloud\s*run\b",
        ],
    },
    "artifactregistry_pull": {
        "service": "artifactregistry.googleapis.com",
        "title": "Artifact Registry Image/Package Reader",
        "scope": "artifactregistry_repository",
        "resource_placeholder": "REPOSITORY_ID",
        "closest_predefined_role": "roles/artifactregistry.reader",
        "headless_permissions": [
            "artifactregistry.repositories.downloadArtifacts",
        ],
        "console_ui_additions": [
            "artifactregistry.packages.list",
            "artifactregistry.repositories.get",
            "artifactregistry.tags.list",
            "artifactregistry.versions.list",
        ],
        "optional_permissions": {},
        "keywords": [
            r"\bpull\b.*\bartifact\s*registry\b",
            r"\bread\b.*\bartifact\s*registry\b",
            r"\bpull\b.*\bdocker\b",
            r"\bpull\b.*\bimages?\b",
        ],
    },
    "artifactregistry_push": {
        "service": "artifactregistry.googleapis.com",
        "title": "Artifact Registry Image/Package Pusher",
        "scope": "artifactregistry_repository",
        "resource_placeholder": "REPOSITORY_ID",
        "closest_predefined_role": "roles/artifactregistry.writer",
        "headless_permissions": [
            "artifactregistry.repositories.downloadArtifacts",
            "artifactregistry.repositories.uploadArtifacts",
        ],
        "console_ui_additions": [
            "artifactregistry.packages.list",
            "artifactregistry.repositories.get",
            "artifactregistry.tags.list",
            "artifactregistry.versions.list",
        ],
        "optional_permissions": {},
        "keywords": [
            r"\bpush\b.*\bartifact\s*registry\b",
            r"\bupload\b.*\bartifact\s*registry\b",
            r"\bpush\b.*\bdocker\b",
            r"\bpush\b.*\bimages?\b",
        ],
    },
    "kms_cmek_use": {
        "service": "cloudkms.googleapis.com",
        "title": "Cloud KMS CMEK Encrypter/Decrypter",
        "scope": "kms_cryptokey",
        "resource_placeholder": "KEY_NAME",
        "closest_predefined_role": "roles/cloudkms.cryptoKeyEncrypterDecrypter",
        "headless_permissions": [
            "cloudkms.cryptoKeyVersions.useToDecrypt",
            "cloudkms.cryptoKeyVersions.useToEncrypt",
        ],
        "console_ui_additions": [
            "cloudkms.cryptoKeys.get",
            "cloudkms.keyRings.get",
        ],
        "optional_permissions": {},
        "keywords": [
            r"\bkms\b.*\bencrypt\b",
            r"\bkms\b.*\bdecrypt\b",
            r"\bcmek\b",
        ],
    },
    "cloudsql_connect": {
        "service": "sqladmin.googleapis.com",
        "title": "Cloud SQL Client & IAM DB Login",
        "scope": "project",
        "resource_placeholder": "PROJECT_ID",
        "closest_predefined_role": "roles/cloudsql.client",
        "headless_permissions": [
            "cloudsql.instances.connect",
            "cloudsql.instances.get",
        ],
        "console_ui_additions": [
            "cloudsql.databases.list",
            "cloudsql.instances.list",
        ],
        "optional_permissions": {
            "iam_db_login": ["cloudsql.instances.login"]
        },
        "keywords": [
            r"\bconnect\b.*\bcloud\s*sql\b",
            r"\bcloud\s*sql\b.*\bclient\b",
            r"\bcloud\s*sql\b.*\bproxy\b",
        ],
    },
    "vertex_predict": {
        "service": "aiplatform.googleapis.com",
        "title": "Vertex AI Online Prediction & Gemini Caller",
        "scope": "project",
        "resource_placeholder": "PROJECT_ID",
        "closest_predefined_role": "roles/aiplatform.user",
        "headless_permissions": [
            "aiplatform.endpoints.predict",
        ],
        "console_ui_additions": [
            "aiplatform.endpoints.get",
            "aiplatform.endpoints.list",
            "aiplatform.models.get",
            "aiplatform.models.list",
        ],
        "optional_permissions": {},
        "keywords": [
            r"\bvertex\b",
            r"\bgemini\b",
            r"\baiplatform\b",
            r"\bmodel\s+inference\b",
        ],
    },
    "logging_write": {
        "service": "logging.googleapis.com",
        "title": "Cloud Logging Structured Log Writer",
        "scope": "project",
        "resource_placeholder": "PROJECT_ID",
        "closest_predefined_role": "roles/logging.logWriter",
        "headless_permissions": [
            "logging.logEntries.create",
        ],
        "console_ui_additions": [
            "logging.logEntries.list",
            "logging.logs.list",
        ],
        "optional_permissions": {},
        "keywords": [
            r"\bwrite\b.*\blogs?\b",
            r"\bemit\b.*\blogs?\b",
            r"\bcloud\s*logging\b",
        ],
    },
}

# Privilege escalation & unsupported permission rules (E1-E5)
PRIVILEGE_ESCALATION_RULES: Dict[str, Dict[str, str]] = {
    "iam.serviceAccounts.actAs": {
        "code": "E1",
        "severity": "CRITICAL",
        "reason": "Allows attaching a Service Account to a workload and inheriting all of its permissions.",
        "mitigation": "Bind ONLY on the specific target Service Account resource (never at the Project level).",
    },
    "iam.serviceAccounts.getAccessToken": {
        "code": "E1",
        "severity": "CRITICAL",
        "reason": "Allows minting OAuth2 access tokens directly for a target Service Account.",
        "mitigation": "Bind ONLY on the specific target Service Account resource.",
    },
    "iam.serviceAccounts.getOpenIdToken": {
        "code": "E1",
        "severity": "CRITICAL",
        "reason": "Allows minting OIDC tokens for a target Service Account.",
        "mitigation": "Bind ONLY on the specific target Service Account resource.",
    },
    "iam.serviceAccounts.signBlob": {
        "code": "E1",
        "severity": "CRITICAL",
        "reason": "Allows signing arbitrary blobs as a target Service Account.",
        "mitigation": "Bind ONLY on the specific target Service Account resource.",
    },
    "iam.serviceAccounts.signJwt": {
        "code": "E1",
        "severity": "CRITICAL",
        "reason": "Allows signing arbitrary JWTs as a target Service Account.",
        "mitigation": "Bind ONLY on the specific target Service Account resource.",
    },
    "iam.serviceAccountKeys.create": {
        "code": "E1",
        "severity": "CRITICAL",
        "reason": "Creates persistent downloadable JSON private keys for Service Accounts.",
        "mitigation": "Remove from custom role; use Workload Identity Federation or short-lived token impersonation.",
    },
    "resourcemanager.projects.setIamPolicy": {
        "code": "E2",
        "severity": "CRITICAL",
        "reason": "Allows granting arbitrary IAM roles (including roles/owner) across the entire project.",
        "mitigation": "Remove from operational custom roles or constrain with an IAM Condition on modifiedGrantsByRole.",
    },
    "iam.roles.update": {
        "code": "E2",
        "severity": "CRITICAL",
        "reason": "Allows a principal to inject arbitrary permissions into existing custom roles they already hold.",
        "mitigation": "Restrict to dedicated CI/CD Terraform automation; never grant to operational principals.",
    },
    "iam.roles.create": {
        "code": "E2",
        "severity": "HIGH",
        "reason": "Allows creating arbitrary new custom roles in the project.",
        "mitigation": "Restrict to dedicated CI/CD Terraform automation.",
    },
    "iam.serviceAccounts.setIamPolicy": {
        "code": "E2",
        "severity": "CRITICAL",
        "reason": "Allows granting TokenCreator or actAs on any Service Account.",
        "mitigation": "Remove from operational custom roles.",
    },
    "storage.buckets.setIamPolicy": {
        "code": "E2",
        "severity": "HIGH",
        "reason": "Allows modifying bucket ACLs to expose data externally.",
        "mitigation": "Omit from data reader/writer custom roles.",
    },
    "bigquery.datasets.update": {
        "code": "E2",
        "severity": "HIGH",
        "reason": "Allows modifying BigQuery dataset ACLs in addition to dataset metadata.",
        "mitigation": "Use bigquery.datasets.get for dataset readers/writers.",
    },
    "bigquery.tables.setIamPolicy": {
        "code": "E2",
        "severity": "HIGH",
        "reason": "Allows overriding table-level IAM policies.",
        "mitigation": "Omit from table reader/writer custom roles.",
    },
    "secretmanager.secrets.setIamPolicy": {
        "code": "E2",
        "severity": "HIGH",
        "reason": "Allows granting secret access to unauthorized principals.",
        "mitigation": "Omit from secret reader/rotator custom roles.",
    },
    "compute.instances.setMetadata": {
        "code": "E3",
        "severity": "HIGH",
        "reason": "Allows injecting SSH keys or startup-scripts onto VMs to execute as the VM Service Account.",
        "mitigation": "Omit from read/operator roles; use OS Login scoped to specific instances.",
    },
    "compute.projects.setCommonInstanceMetadata": {
        "code": "E3",
        "severity": "CRITICAL",
        "reason": "Allows injecting SSH keys or startup-scripts across all VMs in the project.",
        "mitigation": "Omit from operational roles.",
    },
    "cloudfunctions.functions.update": {
        "code": "E3",
        "severity": "HIGH",
        "reason": "Allows replacing function code executing under the function's runtime Service Account.",
        "mitigation": "Scope to specific function and pair with a dedicated least-privilege runtime SA.",
    },
    "run.services.update": {
        "code": "E3",
        "severity": "HIGH",
        "reason": "Allows replacing container image executing under the Cloud Run service's runtime Service Account.",
        "mitigation": "Bind at the Cloud Run Service resource level and pair with a dedicated single-service runtime SA.",
    },
    "bigquery.tables.export": {
        "code": "E4",
        "severity": "MEDIUM",
        "reason": "Allows bulk export of table data to external Cloud Storage buckets.",
        "mitigation": "Omit from standard SQL query reader roles (bigquery.tables.getData suffices for SELECT queries).",
    },
}

ORG_ONLY_PERMISSIONS: Set[str] = {
    "resourcemanager.projects.list",
    "resourcemanager.folders.get",
    "resourcemanager.folders.list",
    "resourcemanager.organizations.get",
    "orgpolicy.policy.get",
    "orgpolicy.policies.list",
}

STATIC_UNSUPPORTED_CUSTOM_ROLE_PERMISSIONS: Set[str] = {
    "bigquery.RowAccessPolicies.overrideTimeTravelRestrictions",
    "gkehub.fleet.get",
    "stackdriver.projects.edit",
}


def classify_permission_scope(permission: str) -> str:
  """Determines the lowest GCP resource hierarchy level where a permission is evaluated."""
  if permission in ORG_ONLY_PERMISSIONS:
    return "organization"

  # BigQuery: jobs and readsessions are evaluated at the execution Project level;
  # datasets, tables, routines, and models are evaluated at the Dataset (or Table) level.
  if permission.startswith(("bigquery.jobs.", "bigquery.readsessions.", "bigquery.reservations.", "bigquery.capacityCommitments.")):
    return "project"
  if permission.startswith(("bigquery.datasets.", "bigquery.tables.", "bigquery.models.", "bigquery.routines.")):
    return "bigquery_dataset"

  # Cloud Storage: bucket/object/multipart operations are evaluated at the Bucket level.
  if permission.startswith(("storage.objects.", "storage.multipartUploads.", "storage.buckets.get")):
    return "storage_bucket"

  # Secret Manager: secret and version operations (except secrets.create/list) are evaluated at the Secret level.
  if permission in ("secretmanager.secrets.create", "secretmanager.secrets.list"):
    return "project"
  if permission.startswith(("secretmanager.versions.", "secretmanager.secrets.")):
    return "secretmanager_secret"

  # Pub/Sub: topic vs subscription vs project list/create
  if permission in ("pubsub.topics.create", "pubsub.topics.list", "pubsub.subscriptions.create", "pubsub.subscriptions.list"):
    return "project"
  if permission.startswith("pubsub.topics."):
    return "pubsub_topic"
  if permission.startswith("pubsub.subscriptions."):
    return "pubsub_subscription"

  # Cloud Run: service-level invoke/get/update vs project-level create/list
  if permission in ("run.routes.invoke", "run.services.get", "run.services.update", "run.services.getIamPolicy"):
    return "cloudrun_service"
  if permission.startswith("run."):
    return "project"

  # Artifact Registry: repository-level operations vs project-level list/create
  if permission in ("artifactregistry.repositories.create", "artifactregistry.repositories.list"):
    return "project"
  if permission.startswith("artifactregistry."):
    return "artifactregistry_repository"

  # Cloud KMS: key-level encrypt/decrypt/get
  if permission.startswith(("cloudkms.cryptoKeyVersions.", "cloudkms.cryptoKeys.get")):
    return "kms_cryptokey"

  # Service Account resource-level impersonation permissions
  if permission in (
      "iam.serviceAccounts.actAs",
      "iam.serviceAccounts.getAccessToken",
      "iam.serviceAccounts.getOpenIdToken",
      "iam.serviceAccounts.signBlob",
      "iam.serviceAccounts.signJwt",
  ):
    return "iam_service_account"

  return "project"


def infer_capabilities_from_text(requirement_text: str) -> List[str]:
  """Matches a natural-language DevOps requirement to capability IDs."""
  text_lower = requirement_text.lower()
  matched: List[str] = []
  for cap_id, meta in CAPABILITY_CATALOG.items():
    for pattern in meta.get("keywords", []):
      if re.search(pattern, text_lower):
        matched.append(cap_id)
        break
  return sorted(set(matched))


def parse_simple_role_yaml(yaml_path: Path) -> Dict[str, Any]:
  """Parses a GCP custom role YAML file using Python stdlib only."""
  lines = yaml_path.read_text(encoding="utf-8").splitlines()
  title = ""
  description = ""
  stage = "GA"
  perms: List[str] = []
  in_perms = False
  for raw_line in lines:
    line = raw_line.strip()
    if not line or line.startswith("#"):
      continue
    if line.startswith("title:"):
      title = line.split(":", 1)[1].strip().strip('"').strip("'")
      in_perms = False
    elif line.startswith("description:"):
      description = line.split(":", 1)[1].strip().strip('"').strip("'")
      in_perms = False
    elif line.startswith("stage:"):
      stage = line.split(":", 1)[1].strip().strip('"').strip("'")
      in_perms = False
    elif line.startswith("includedPermissions:"):
      in_perms = True
    elif in_perms and line.startswith("-"):
      perm = line.lstrip("-").strip().strip('"').strip("'")
      if perm:
        perms.append(perm)
  return {
      "name": yaml_path.stem,
      "role_id": yaml_path.stem,
      "file_path": str(yaml_path),
      "title": title,
      "description": description,
      "stage": stage,
      "includedPermissions": sorted(set(perms)),
  }


def resolve_custom_roles_root(path: Optional[Path]) -> Optional[Path]:
  """Resolves the `custom-roles` directory from a user-supplied path.

  Accepts either the `custom-roles` directory itself or its parent (an audit
  output directory), so `--existing-roles-dir ./scopeguard-output` and
  `--existing-roles-dir ./scopeguard-output/custom-roles` both work.

  Args:
    path: User-supplied directory (may be None or non-existent).

  Returns:
    The directory holding role YAMLs, or None when nothing exists on disk.
  """
  if not path or not path.exists() or not path.is_dir():
    return None
  nested = path / "custom-roles"
  if nested.is_dir():
    return nested
  return path


def custom_role_yaml_files(
    path: Optional[Path],
) -> Tuple[List[Path], List[Path]]:
  """Lists Model A and Model B role YAML files, preferring the new layout.

  Model A comes from `custom-roles/personas/` (fallback: legacy root
  `custom-roles/*.yaml`); Model B from `custom-roles/capabilities/`
  (fallback: legacy `custom-roles/disjoint/`). The fallback only applies when
  the new directory is absent, so a migrated workspace never double-counts.

  Args:
    path: `custom-roles` directory or its parent.

  Returns:
    Tuple of (model_a_files, model_b_files), each sorted by name.
  """
  root = resolve_custom_roles_root(path)
  if root is None:
    return [], []
  personas_dir = root / PERSONAS_SUBDIR
  capabilities_dir = root / CAPABILITIES_SUBDIR
  model_a_dir = personas_dir if personas_dir.is_dir() else root
  model_b_dir = (
      capabilities_dir
      if capabilities_dir.is_dir()
      else root / LEGACY_DISJOINT_SUBDIR
  )
  model_a = sorted(model_a_dir.glob("*.yaml")) if model_a_dir.is_dir() else []
  model_b = sorted(model_b_dir.glob("*.yaml")) if model_b_dir.is_dir() else []
  return model_a, model_b


def load_existing_custom_roles(
    existing_roles_dir: Optional[Path],
    client: HybridGCPRoleArchitectClient,
) -> Dict[str, List[Dict[str, Any]]]:
  """Loads Model A and Model B capability custom roles from disk and live project.

  Args:
    existing_roles_dir: `custom-roles` directory (or its parent). New layout
      (`personas/`, `capabilities/`) is preferred; legacy root / `disjoint/`
      directories are read only when the new ones are absent.
    client: Hybrid client used to merge live project custom roles.

  Returns:
    Dict with `model_a` and `disjoint_model_b` lists of parsed roles.
  """
  model_a_roles: List[Dict[str, Any]] = []
  disjoint_roles: List[Dict[str, Any]] = []

  model_a_files, model_b_files = custom_role_yaml_files(existing_roles_dir)
  for yaml_file in model_a_files:
    try:
      parsed = parse_simple_role_yaml(yaml_file)
    except (OSError, UnicodeDecodeError) as exc:
      # A single unreadable file must not abort the whole design run.
      print(f"[Warn] Skipping unreadable role YAML {yaml_file}: {exc}", file=sys.stderr)
      continue
    parsed["source"] = "workspace_model_a"
    model_a_roles.append(parsed)

  seen_disjoint: Set[str] = set()
  for yaml_file in model_b_files:
    try:
      parsed = parse_simple_role_yaml(yaml_file)
    except (OSError, UnicodeDecodeError) as exc:
      print(f"[Warn] Skipping unreadable role YAML {yaml_file}: {exc}", file=sys.stderr)
      continue
    if parsed["role_id"] in seen_disjoint:
      continue
    seen_disjoint.add(parsed["role_id"])
    parsed["source"] = "workspace_disjoint_model_b"
    disjoint_roles.append(parsed)

  # Also merge live project custom roles if online
  live_roles = client.list_project_custom_roles()
  existing_ids = {r["role_id"] for r in model_a_roles}
  for lr in live_roles:
    if lr["role_id"] not in existing_ids:
      model_a_roles.append(lr)

  return {
      "model_a": model_a_roles,
      "disjoint_model_b": disjoint_roles,
  }


def slugify_camel(slug: str) -> str:
  """Converts a snake_case or hyphen-case string to lowerCamelCase for GCP role IDs."""
  parts = [p for p in re.split(r"[^a-zA-Z0-9]+", slug) if p]
  if not parts:
    return "customLeastPrivilegeRole"
  return parts[0].lower() + "".join(w.capitalize() for w in parts[1:])


def snake_case(slug: str) -> str:
  """Converts a string into clean snake_case."""
  cleaned = re.sub(r"[^a-zA-Z0-9]+", "_", slug).strip("_").lower()
  return cleaned or "custom_least_privilege_role"


def evaluate_existing_role_reuse(
    required_perms: Set[str],
    existing_roles: Dict[str, List[Dict[str, Any]]],
) -> Dict[str, Any]:
  """Checks Model A and Model B capability custom roles for reuse or delta creation."""
  exact_matches: List[Dict[str, Any]] = []
  superset_matches: List[Dict[str, Any]] = []
  partial_matches: List[Dict[str, Any]] = []

  for r in existing_roles.get("model_a", []):
    r_perms = set(r.get("includedPermissions", []))
    if not r_perms:
      continue
    if r_perms == required_perms:
      exact_matches.append({
          "role_id": r["role_id"],
          "title": r["title"],
          "source": r["source"],
          "permission_count": len(r_perms),
      })
    elif required_perms.issubset(r_perms):
      extra = sorted(r_perms - required_perms)
      superset_matches.append({
          "role_id": r["role_id"],
          "title": r["title"],
          "source": r["source"],
          "required_count": len(required_perms),
          "role_permission_count": len(r_perms),
          "excess_permission_count": len(extra),
          "excess_permissions_sample": extra[:10],
      })
    else:
      overlap = sorted(required_perms & r_perms)
      if overlap:
        partial_matches.append({
            "role_id": r["role_id"],
            "title": r["title"],
            "source": r["source"],
            "overlap_count": len(overlap),
            "overlap_permissions": overlap,
            "missing_permissions": sorted(required_perms - r_perms),
        })

  # Evaluate Model B capability (R_i n R_j = empty across all disjoint roles)
  disjoint_covered: Set[str] = set()
  disjoint_overlapping_roles: List[Dict[str, Any]] = []
  for dr in existing_roles.get("disjoint_model_b", []):
    dr_perms = set(dr.get("includedPermissions", []))
    overlap = sorted(required_perms & dr_perms)
    if overlap:
      disjoint_covered.update(overlap)
      disjoint_overlapping_roles.append({
          "role_id": dr["role_id"],
          "title": dr["title"],
          "overlap_permissions": overlap,
          "extra_in_disjoint_role": sorted(dr_perms - required_perms),
      })

  disjoint_uncovered_delta = sorted(required_perms - disjoint_covered)

  recommendation = "CREATE_NEW_SCOPED_ROLE"
  if exact_matches:
    recommendation = f"REUSE_EXACT_MATCH ({exact_matches[0]['role_id']})"
  elif superset_matches and superset_matches[0]["excess_permission_count"] <= 2:
    recommendation = (
        f"CONSIDER_SUPERSET_REUSE ({superset_matches[0]['role_id']}, "
        f"+{superset_matches[0]['excess_permission_count']} extra perms)"
    )

  return {
      "recommendation": recommendation,
      "exact_matches": exact_matches,
      "superset_matches": sorted(
          superset_matches, key=lambda x: x["excess_permission_count"]
      ),
      "partial_matches": sorted(
          partial_matches, key=lambda x: -x["overlap_count"]
      ),
      "disjoint_model_b_analysis": {
          "overlapping_disjoint_roles": disjoint_overlapping_roles,
          "already_covered_in_disjoint_pool": sorted(disjoint_covered),
          "net_new_disjoint_delta_permissions": disjoint_uncovered_delta,
      },
  }


def design_roles(args: argparse.Namespace) -> Dict[str, Any]:
  """Synthesizes scoped least-privilege custom roles from the input requirement."""
  client = HybridGCPRoleArchitectClient(
      project_id=args.project,
      offline=args.offline,
  )

  # 1. Resolve capabilities from explicit flag and/or natural language requirement
  explicit_caps = [
      c.strip() for c in (args.capabilities or "").split(",") if c.strip()
  ]
  inferred_caps = (
      infer_capabilities_from_text(args.requirement)
      if args.requirement
      else []
  )
  all_caps = sorted(set(explicit_caps + inferred_caps))

  # 2. Collect headless and console UI permissions per capability
  headless_perms: Set[str] = set()
  console_additions: Set[str] = set()
  optional_perms: Dict[str, List[str]] = {}
  closest_predefined_roles: Set[str] = set()

  for cap_id in all_caps:
    meta = CAPABILITY_CATALOG.get(cap_id)
    if not meta:
      print(
          f"[Warning] Unknown capability ID '{cap_id}' ignored. Use list-capabilities to view valid IDs.",
          file=sys.stderr,
      )
      continue
    headless_perms.update(meta.get("headless_permissions", []))
    console_additions.update(meta.get("console_ui_additions", []))
    for opt_k, opt_v in meta.get("optional_permissions", {}).items():
      optional_perms[f"{cap_id}.{opt_k}"] = opt_v
    if meta.get("closest_predefined_role"):
      closest_predefined_roles.add(meta["closest_predefined_role"])

  # 3. Include any explicit permissions or expand --from-roles
  if args.add_permissions:
    for p in args.add_permissions.split(","):
      if p.strip():
        headless_perms.add(p.strip())

  if args.from_roles:
    for r_name in args.from_roles.split(","):
      r_clean = r_name.strip()
      if r_clean:
        closest_predefined_roles.add(r_clean)
        expanded = client.describe_role_permissions(r_clean)
        for p in expanded:
          if p.endswith((".get", ".list")):
            console_additions.add(p)
          else:
            headless_perms.add(p)

  if args.include_storage_read_api:
    headless_perms.update([
        "bigquery.readsessions.create",
        "bigquery.readsessions.getData",
    ])

  # Determine target persona permissions
  persona = args.persona.lower()
  if persona == "headless":
    selected_perms = set(headless_perms)
  else:
    # Both 'console' and 'both' include the console UI metadata permissions in the primary role design,
    # while documenting the strict headless subset in the report.
    selected_perms = set(headless_perms | console_additions)

  # 4. Validate against testable permissions & E1-E5 security catalog
  testable_map = client.fetch_testable_permissions()
  valid_perms: Set[str] = set()
  excluded_perms: List[Dict[str, str]] = []
  testing_stage_perms: List[str] = []
  escalation_findings: List[Dict[str, str]] = []

  for perm in sorted(selected_perms):
    # Check E5 org-only permissions
    if perm in ORG_ONLY_PERMISSIONS:
      excluded_perms.append({
          "permission": perm,
          "reason": "E5: Organization/Folder-only permission (invalid in Project custom roles).",
      })
      continue
    if perm in STATIC_UNSUPPORTED_CUSTOM_ROLE_PERMISSIONS or perm.endswith(".serviceAgent"):
      excluded_perms.append({
          "permission": perm,
          "reason": "E5: customRolesSupportLevel is NOT_SUPPORTED.",
      })
      continue
    if testable_map and perm in testable_map:
      support = testable_map[perm].get("customRolesSupportLevel", "SUPPORTED")
      stage = testable_map[perm].get("stage", "GA")
      if support == "NOT_SUPPORTED":
        excluded_perms.append({
            "permission": perm,
            "reason": "E5: Live API reported customRolesSupportLevel=NOT_SUPPORTED.",
        })
        continue
      if stage in ("ALPHA", "BETA") or support == "TESTING":
        testing_stage_perms.append(perm)

    valid_perms.add(perm)

    # Check E1-E4 privilege escalation rules
    if perm in PRIVILEGE_ESCALATION_RULES:
      rule = PRIVILEGE_ESCALATION_RULES[perm]
      escalation_findings.append({
          "permission": perm,
          "code": rule["code"],
          "severity": rule["severity"],
          "reason": rule["reason"],
          "mitigation": rule["mitigation"],
      })

  # 5. Partition valid permissions by lowest GCP Resource Scope
  scoped_groups: Dict[str, List[str]] = {}
  for perm in sorted(valid_perms):
    scope = classify_permission_scope(perm)
    scoped_groups.setdefault(scope, []).append(perm)

  # 6. Load existing custom roles for anti-sprawl & disjoint Model B analysis
  existing_dir = Path(args.existing_roles_dir) if args.existing_roles_dir else None
  existing_roles = load_existing_custom_roles(existing_dir, client)

  # Build scoped custom role specifications. Role IDs follow the shared
  # ScopeGuard naming convention (lib/naming.py): one persona role per
  # (workload, resource scope), e.g. `sg_persona_jane_doe_bucket_reader`.
  # IDs are derived only from stable inputs so re-runs do not churn names.
  resolved_prefix = naming.role_prefix(args.role_prefix)
  workload = naming.workload_slug(args.principal or "user:jane.doe@example.com")
  scoped_role_specs: List[Dict[str, Any]] = []

  scope_metadata = {
      "project": {
          "label": "Project Level (Billing / Job Execution Scope)",
          "resource_placeholder": args.project or "YOUR_PROJECT_ID",
          "tf_binding_resource": "google_project_iam_member",
          "short_tag": "project_job_runner" if "bigquery.jobs.create" in valid_perms else "project_access",
      },
      "bigquery_dataset": {
          "label": "BigQuery Dataset Level (Data Plane Scope)",
          "resource_placeholder": args.dataset_id or "YOUR_DATASET_ID",
          "tf_binding_resource": "google_bigquery_dataset_iam_member",
          "short_tag": "bq_dataset_reader" if "bigquery.tables.updateData" not in valid_perms else "bq_dataset_writer",
      },
      "storage_bucket": {
          "label": "Cloud Storage Bucket Level (Data Plane Scope)",
          "resource_placeholder": args.bucket_name or "YOUR_BUCKET_NAME",
          "tf_binding_resource": "google_storage_bucket_iam_member",
          "short_tag": "gcs_bucket_access",
      },
      "secretmanager_secret": {
          "label": "Secret Manager Secret Level (Resource Scope)",
          "resource_placeholder": args.secret_id or "YOUR_SECRET_ID",
          "tf_binding_resource": "google_secret_manager_secret_iam_member",
          "short_tag": "secret_accessor",
      },
      "pubsub_topic": {
          "label": "Pub/Sub Topic Level (Resource Scope)",
          "resource_placeholder": args.topic_id or "YOUR_TOPIC_ID",
          "tf_binding_resource": "google_pubsub_topic_iam_member",
          "short_tag": "pubsub_publisher",
      },
      "pubsub_subscription": {
          "label": "Pub/Sub Subscription Level (Resource Scope)",
          "resource_placeholder": args.subscription_id or "YOUR_SUBSCRIPTION_ID",
          "tf_binding_resource": "google_pubsub_subscription_iam_member",
          "short_tag": "pubsub_subscriber",
      },
      "cloudrun_service": {
          "label": "Cloud Run Service Level (Resource Scope)",
          "resource_placeholder": args.service_name or "YOUR_CLOUD_RUN_SERVICE",
          "tf_binding_resource": "google_cloud_run_v2_service_iam_member",
          "short_tag": "cloudrun_access",
      },
      "artifactregistry_repository": {
          "label": "Artifact Registry Repository Level (Resource Scope)",
          "resource_placeholder": args.repository_id or "YOUR_REPOSITORY_ID",
          "tf_binding_resource": "google_artifact_registry_repository_iam_member",
          "short_tag": "artifact_repo_access",
      },
      "kms_cryptokey": {
          "label": "Cloud KMS CryptoKey Level (Resource Scope)",
          "resource_placeholder": "YOUR_KMS_KEY_ID",
          "tf_binding_resource": "google_kms_crypto_key_iam_member",
          "short_tag": "kms_key_operator",
      },
      "iam_service_account": {
          "label": "Target Service Account Resource Level (Impersonation Scope)",
          "resource_placeholder": "TARGET_RUNTIME_SA_EMAIL",
          "tf_binding_resource": "google_service_account_iam_member",
          "short_tag": "sa_impersonator",
      },
  }

  for scope_key, perms in sorted(scoped_groups.items()):
    s_meta = scope_metadata.get(
        scope_key,
        {
            "label": f"{scope_key} Scope",
            "resource_placeholder": "TARGET_RESOURCE",
            "tf_binding_resource": "google_project_iam_member",
            "short_tag": scope_key,
        },
    )
    role_id = naming.persona_role_id(
        f"{workload}_{s_meta['short_tag']}", prefix=resolved_prefix
    )
    # File slug == role ID so `gcloud iam roles create <id> --file=<id>.yaml`
    # and the workspace loaders (which key on the file stem) stay consistent.
    role_file_slug = role_id
    headless_in_scope = sorted(set(perms) & headless_perms)
    console_in_scope = sorted(set(perms) - set(headless_in_scope))

    reuse_analysis = evaluate_existing_role_reuse(set(perms), existing_roles)
    delta_perms = reuse_analysis.get("disjoint_model_b_analysis", {}).get(
        "net_new_disjoint_delta_permissions", []
    )
    # Model B delta role: named after WHAT it grants (capability convention).
    delta_role_id = ""
    if delta_perms:
      parts = naming.capability_name_parts(delta_perms)
      delta_role_id = naming.capability_role_id(
          parts["domain"],
          parts["access"],
          f"{workload}_{s_meta['short_tag']}",
          prefix=resolved_prefix,
      )
    description = (
        f"Least-privilege custom role scoped to {s_meta['label']} "
        f"for requirement: {args.requirement or ','.join(all_caps)}"
    )

    scoped_role_specs.append({
        "scope": scope_key,
        "scope_label": s_meta["label"],
        "target_resource": s_meta["resource_placeholder"],
        "tf_binding_resource": s_meta["tf_binding_resource"],
        "role_file_slug": role_file_slug,
        "role_id": role_id,
        "disjoint_delta_role_id": delta_role_id,
        "title": naming.persona_title(f"{workload} {s_meta['short_tag']}"),
        # GCP rejects descriptions over 256 characters.
        "description": description[: naming.DESCRIPTION_MAX_LEN],
        "stage": "GA",
        "included_permissions": perms,
        "strict_headless_permissions": headless_in_scope,
        "console_ui_extra_permissions": console_in_scope,
        "reuse_analysis": reuse_analysis,
    })

  # 7. Compare against predefined roles to quantify permission reduction
  predefined_union: Set[str] = set()
  for pr in closest_predefined_roles:
    predefined_union.update(client.describe_role_permissions(pr))

  predefined_count = len(predefined_union)
  custom_count = len(valid_perms)
  reduction_pct = (
      round((1.0 - (custom_count / predefined_count)) * 100.0, 1)
      if predefined_count > 0
      else 0.0
  )

  return {
      "generated_at": datetime.now(timezone.utc).isoformat(),
      "project_id": args.project or "YOUR_PROJECT_ID",
      "principal": args.principal or "user:jane.doe@example.com",
      "requirement": args.requirement or ", ".join(all_caps),
      "persona_mode": persona,
      "role_prefix": resolved_prefix,
      "matched_capabilities": all_caps,
      "transport_log": client.transport_log,
      "summary_metrics": {
          "total_custom_roles_required": len(scoped_role_specs),
          "total_selected_permissions": custom_count,
          "strict_headless_permission_count": len(valid_perms & headless_perms),
          "console_ui_metadata_permission_count": len(valid_perms - headless_perms),
          "closest_predefined_roles": sorted(closest_predefined_roles),
          "closest_predefined_permission_count": predefined_count,
          "attack_surface_reduction_pct": reduction_pct,
      },
      "scoped_custom_roles": scoped_role_specs,
      "optional_permission_bundles": optional_perms,
      "excluded_unsupported_permissions": excluded_perms,
      "testing_stage_permissions": testing_stage_perms,
      "privilege_escalation_findings": escalation_findings,
  }


def disjoint_delta_role_id(spec: Dict[str, Any], scoped_role: Dict[str, Any]) -> str:
  """Returns the Model B delta capability role ID for a scoped role.

  Uses the ID computed at design time; specs produced by older versions lack
  it, so the ID is re-derived with the shared naming convention.
  """
  if scoped_role.get("disjoint_delta_role_id"):
    return str(scoped_role["disjoint_delta_role_id"])
  delta = (
      scoped_role.get("reuse_analysis", {})
      .get("disjoint_model_b_analysis", {})
      .get("net_new_disjoint_delta_permissions", [])
  )
  parts = naming.capability_name_parts(delta or ["misc.resource.update"])
  return naming.capability_role_id(
      parts["domain"],
      parts["access"],
      f"delta_{scoped_role.get('role_file_slug', 'role')}",
      prefix=spec.get("role_prefix"),
  )


def generate_artifacts_from_spec(
    spec: Dict[str, Any],
    output_dir: Path,
) -> Dict[str, str]:
  """Writes role YAMLs, Markdown report, gcloud/bq script, Terraform HCL & rollback script."""
  output_dir.mkdir(parents=True, exist_ok=True)
  # Model A persona YAMLs -> custom-roles/personas/, Model B delta YAMLs ->
  # custom-roles/capabilities/ (same layout as gcp-iam-recommender-audit).
  roles_dir = output_dir / "custom-roles" / PERSONAS_SUBDIR
  roles_dir.mkdir(parents=True, exist_ok=True)
  disjoint_dir = output_dir / "custom-roles" / CAPABILITIES_SUBDIR
  disjoint_dir.mkdir(parents=True, exist_ok=True)

  project_id = spec.get("project_id", "YOUR_PROJECT_ID")
  principal = spec.get("principal", "user:jane.doe@example.com")
  requirement = spec.get("requirement", "Custom DevOps Access Requirement")
  metrics = spec.get("summary_metrics", {})
  scoped_roles = spec.get("scoped_custom_roles", [])

  created_files: Dict[str, str] = {}

  # 1. Write Custom Role YAML files (Model A + Model B capability Delta if applicable)
  for sr in scoped_roles:
    yaml_path = roles_dir / f"{sr['role_file_slug']}.yaml"
    yaml_lines = [
        f'title: "{sr["title"]}"',
        f'description: "{sr["description"]}"',
        f'stage: "{sr["stage"]}"',
        "includedPermissions:",
    ]
    for p in sr["included_permissions"]:
      yaml_lines.append(f"- {p}")
    yaml_path.write_text("\n".join(yaml_lines) + "\n", encoding="utf-8")
    created_files[f"yaml_{sr['role_file_slug']}"] = str(yaml_path)

    # Also write Model B capability Delta YAML if there are net-new permissions not in disjoint pool
    disjoint_info = sr.get("reuse_analysis", {}).get(
        "disjoint_model_b_analysis", {}
    )
    delta_perms = disjoint_info.get("net_new_disjoint_delta_permissions", [])
    if delta_perms:
      delta_slug = disjoint_delta_role_id(spec, sr)
      delta_path = disjoint_dir / f"{delta_slug}.yaml"
      delta_lines = [
          f'title: "{naming.capability_title(delta_slug)}"',
          (
              f'description: "Strictly disjoint delta permissions (R_i n R_j ='
              f' empty) for {sr["scope_label"]}"'
          ),
          'stage: "GA"',
          "includedPermissions:",
      ]
      for dp in delta_perms:
        delta_lines.append(f"- {dp}")
      delta_path.write_text("\n".join(delta_lines) + "\n", encoding="utf-8")
      created_files[f"disjoint_yaml_{delta_slug}"] = str(delta_path)

  # 2. Write Provisioning CLI Script (provision_roles_and_bindings.sh)
  prov_path = output_dir / "provision_roles_and_bindings.sh"
  prov_lines = [
      "#!/usr/bin/env bash",
      "# ==============================================================================",
      "# Generated by gcp-iam-role-architect",
      f"# Requirement: {requirement}",
      "# IMPORTANT: Review and obtain human approval before executing.",
      "# ==============================================================================",
      "set -euo pipefail",
      "",
      f'PROJECT_ID="{project_id}"',
      f'PRINCIPAL="{principal}"',
      "",
  ]
  for sr in scoped_roles:
    role_id = sr["role_id"]
    yaml_rel = f"custom-roles/{PERSONAS_SUBDIR}/{sr['role_file_slug']}.yaml"
    scope = sr["scope"]
    target_res = sr["target_resource"]

    prov_lines.extend([
        f"# --- Scope: {sr['scope_label']} ---",
        f'echo "Creating custom role {role_id} in project ${{PROJECT_ID}}..."',
        f'gcloud iam roles create "{role_id}" \\',
        '    --project="${PROJECT_ID}" \\',
        f'    --file="{yaml_rel}" \\',
        "    --quiet",
        "",
    ])

    if scope == "project":
      prov_lines.extend([
          f'echo "Binding {role_id} at the Project level..."',
          'gcloud projects add-iam-policy-binding "${PROJECT_ID}" \\',
          '    --member="${PRINCIPAL}" \\',
          f'    --role="projects/${{PROJECT_ID}}/roles/{role_id}" \\',
          '    --project="${PROJECT_ID}" \\',
          "    --quiet",
          "",
      ])
    elif scope == "bigquery_dataset":
      prov_lines.extend([
          f'DATASET_ID="{target_res}"',
          'echo "Snapshotting existing BigQuery Dataset ACLs before update..."',
          'bq --project_id="${PROJECT_ID}" show --format=prettyjson "${PROJECT_ID}:${DATASET_ID}" > "dataset_acl_backup_${DATASET_ID}.json"',
          'python3 -c "',
          "import json",
          "p = 'dataset_acl_backup_' + '${DATASET_ID}' + '.json'",
          "data = json.load(open(p))",
          "access = data.get('access', [])",
          "principal = '${PRINCIPAL}'",
          "entity_type = 'userByEmail' if not principal.startswith('group:') else 'groupByEmail'",
          "email = principal.split(':', 1)[-1]",
          f"entry = {{'role': 'projects/' + '${{PROJECT_ID}}' + '/roles/{role_id}', entity_type: email}}",
          "if entry not in access: access.append(entry)",
          "data['access'] = access",
          "json.dump(data, open('dataset_acl_updated_' + '${DATASET_ID}' + '.json', 'w'), indent=2)",
          '"',
          'bq --project_id="${PROJECT_ID}" update --source "dataset_acl_updated_${DATASET_ID}.json" "${PROJECT_ID}:${DATASET_ID}"',
          "",
      ])
    elif scope == "storage_bucket":
      prov_lines.extend([
          f'BUCKET_NAME="{target_res}"',
          'gcloud storage buckets add-iam-policy-binding "gs://${BUCKET_NAME}" \\',
          '    --member="${PRINCIPAL}" \\',
          f'    --role="projects/${{PROJECT_ID}}/roles/{role_id}" \\',
          '    --project="${PROJECT_ID}" \\',
          "    --quiet",
          "",
      ])
    elif scope == "secretmanager_secret":
      prov_lines.extend([
          f'SECRET_ID="{target_res}"',
          'gcloud secrets add-iam-policy-binding "${SECRET_ID}" \\',
          '    --member="${PRINCIPAL}" \\',
          f'    --role="projects/${{PROJECT_ID}}/roles/{role_id}" \\',
          '    --project="${PROJECT_ID}" \\',
          "    --quiet",
          "",
      ])
    elif scope == "pubsub_topic":
      prov_lines.extend([
          f'TOPIC_ID="{target_res}"',
          'gcloud pubsub topics add-iam-policy-binding "${TOPIC_ID}" \\',
          '    --member="${PRINCIPAL}" \\',
          f'    --role="projects/${{PROJECT_ID}}/roles/{role_id}" \\',
          '    --project="${PROJECT_ID}" \\',
          "    --quiet",
          "",
      ])
    elif scope == "pubsub_subscription":
      prov_lines.extend([
          f'SUBSCRIPTION_ID="{target_res}"',
          'gcloud pubsub subscriptions add-iam-policy-binding "${SUBSCRIPTION_ID}" \\',
          '    --member="${PRINCIPAL}" \\',
          f'    --role="projects/${{PROJECT_ID}}/roles/{role_id}" \\',
          '    --project="${PROJECT_ID}" \\',
          "    --quiet",
          "",
      ])
    elif scope == "cloudrun_service":
      prov_lines.extend([
          f'SERVICE_NAME="{target_res}"',
          'REGION="${REGION:-us-central1}"',
          'gcloud run services add-iam-policy-binding "${SERVICE_NAME}" \\',
          '    --region="${REGION}" \\',
          '    --member="${PRINCIPAL}" \\',
          f'    --role="projects/${{PROJECT_ID}}/roles/{role_id}" \\',
          '    --project="${PROJECT_ID}" \\',
          "    --quiet",
          "",
      ])
    elif scope == "artifactregistry_repository":
      prov_lines.extend([
          f'REPOSITORY_ID="{target_res}"',
          'LOCATION="${LOCATION:-us-central1}"',
          'gcloud artifacts repositories add-iam-policy-binding "${REPOSITORY_ID}" \\',
          '    --location="${LOCATION}" \\',
          '    --member="${PRINCIPAL}" \\',
          f'    --role="projects/${{PROJECT_ID}}/roles/{role_id}" \\',
          '    --project="${PROJECT_ID}" \\',
          "    --quiet",
          "",
      ])
    elif scope == "iam_service_account":
      prov_lines.extend([
          f'TARGET_SA="{target_res}"',
          'gcloud iam service-accounts add-iam-policy-binding "${TARGET_SA}" \\',
          '    --member="${PRINCIPAL}" \\',
          f'    --role="projects/${{PROJECT_ID}}/roles/{role_id}" \\',
          '    --project="${PROJECT_ID}" \\',
          "    --quiet",
          "",
      ])

  prov_path.write_text("\n".join(prov_lines) + "\n", encoding="utf-8")
  prov_path.chmod(0o755)
  created_files["provision_script"] = str(prov_path)

  # 3. Write Emergency Rollback Runbook (rollback_runbook.sh)
  rb_path = output_dir / "rollback_runbook.sh"
  rb_lines = [
      "#!/usr/bin/env bash",
      "# ==============================================================================",
      "# Emergency Rollback Runbook — Generated by gcp-iam-role-architect",
      f"# Requirement: {requirement}",
      "# Reverts resource-level IAM bindings and soft-deletes newly created custom roles.",
      "# ==============================================================================",
      "set -euo pipefail",
      "",
      f'PROJECT_ID="{project_id}"',
      f'PRINCIPAL="{principal}"',
      "",
  ]
  for sr in scoped_roles:
    role_id = sr["role_id"]
    scope = sr["scope"]
    target_res = sr["target_resource"]

    rb_lines.append(f"# --- Rollback Scope: {sr['scope_label']} ---")
    if scope == "project":
      rb_lines.extend([
          'gcloud projects remove-iam-policy-binding "${PROJECT_ID}" \\',
          '    --member="${PRINCIPAL}" \\',
          f'    --role="projects/${{PROJECT_ID}}/roles/{role_id}" \\',
          '    --project="${PROJECT_ID}" \\',
          "    --quiet",
      ])
    elif scope == "bigquery_dataset":
      rb_lines.extend([
          f'DATASET_ID="{target_res}"',
          'if [[ -f "dataset_acl_backup_${DATASET_ID}.json" ]]; then',
          '  bq --project_id="${PROJECT_ID}" update --source "dataset_acl_backup_${DATASET_ID}.json" "${PROJECT_ID}:${DATASET_ID}"',
          "fi",
      ])
    elif scope == "storage_bucket":
      rb_lines.extend([
          f'BUCKET_NAME="{target_res}"',
          'gcloud storage buckets remove-iam-policy-binding "gs://${BUCKET_NAME}" \\',
          '    --member="${PRINCIPAL}" \\',
          f'    --role="projects/${{PROJECT_ID}}/roles/{role_id}" \\',
          '    --project="${PROJECT_ID}" \\',
          "    --quiet",
      ])
    elif scope == "secretmanager_secret":
      rb_lines.extend([
          f'SECRET_ID="{target_res}"',
          'gcloud secrets remove-iam-policy-binding "${SECRET_ID}" \\',
          '    --member="${PRINCIPAL}" \\',
          f'    --role="projects/${{PROJECT_ID}}/roles/{role_id}" \\',
          '    --project="${PROJECT_ID}" \\',
          "    --quiet",
      ])
    elif scope == "pubsub_topic":
      rb_lines.extend([
          f'TOPIC_ID="{target_res}"',
          'gcloud pubsub topics remove-iam-policy-binding "${TOPIC_ID}" \\',
          '    --member="${PRINCIPAL}" \\',
          f'    --role="projects/${{PROJECT_ID}}/roles/{role_id}" \\',
          '    --project="${PROJECT_ID}" \\',
          "    --quiet",
      ])
    elif scope == "pubsub_subscription":
      rb_lines.extend([
          f'SUBSCRIPTION_ID="{target_res}"',
          'gcloud pubsub subscriptions remove-iam-policy-binding "${SUBSCRIPTION_ID}" \\',
          '    --member="${PRINCIPAL}" \\',
          f'    --role="projects/${{PROJECT_ID}}/roles/{role_id}" \\',
          '    --project="${PROJECT_ID}" \\',
          "    --quiet",
      ])
    rb_lines.extend([
        f'# Optional: Soft-delete custom role {role_id} (can be undeleted within 7 days via gcloud iam roles undelete)',
        f'# gcloud iam roles delete "{role_id}" --project="${{PROJECT_ID}}" --quiet',
        "",
    ])

  rb_path.write_text("\n".join(rb_lines) + "\n", encoding="utf-8")
  rb_path.chmod(0o755)
  created_files["rollback_script"] = str(rb_path)

  # 4. Write Terraform HCL (main.tf)
  tf_path = output_dir / "main.tf"
  tf_lines = [
      "# ==============================================================================",
      "# Terraform HCL — Generated by gcp-iam-role-architect",
      f"# Requirement: {requirement}",
      "# ==============================================================================",
      "",
      'variable "project_id" {',
      '  description = "Target Google Cloud Project ID"',
      "  type        = string",
      f'  default     = "{project_id}"',
      "}",
      "",
      'variable "principal_member" {',
      '  description = "Principal in type:identifier format (e.g., user:jane@example.com)"',
      "  type        = string",
      f'  default     = "{principal}"',
      "}",
      "",
  ]
  for sr in scoped_roles:
    tf_name = sr["role_file_slug"]
    role_id = sr["role_id"]
    scope = sr["scope"]
    target_res = sr["target_resource"]
    perms_formatted = ",\n    ".join(f'"{p}"' for p in sr["included_permissions"])

    tf_lines.extend([
        f'resource "google_project_iam_custom_role" "{tf_name}" {{',
        "  project     = var.project_id",
        f'  role_id     = "{role_id}"',
        f'  title       = "{sr["title"]}"',
        f'  description = "{sr["description"]}"',
        '  stage       = "GA"',
        "  permissions = [",
        f"    {perms_formatted}",
        "  ]",
        "}",
        "",
    ])

    if scope == "project":
      tf_lines.extend([
          f'resource "google_project_iam_member" "{tf_name}_binding" {{',
          "  project = var.project_id",
          f"  role    = google_project_iam_custom_role.{tf_name}.name",
          "  member  = var.principal_member",
          "}",
          "",
      ])
    elif scope == "bigquery_dataset":
      tf_lines.extend([
          f'resource "google_bigquery_dataset_iam_member" "{tf_name}_binding" {{',
          "  project    = var.project_id",
          f'  dataset_id = "{target_res}"',
          f"  role       = google_project_iam_custom_role.{tf_name}.name",
          "  member     = var.principal_member",
          "}",
          "",
      ])
    elif scope == "storage_bucket":
      tf_lines.extend([
          f'resource "google_storage_bucket_iam_member" "{tf_name}_binding" {{',
          f'  bucket = "{target_res}"',
          f"  role   = google_project_iam_custom_role.{tf_name}.name",
          "  member = var.principal_member",
          "}",
          "",
      ])
    elif scope == "secretmanager_secret":
      tf_lines.extend([
          f'resource "google_secret_manager_secret_iam_member" "{tf_name}_binding" {{',
          "  project   = var.project_id",
          f'  secret_id = "{target_res}"',
          f"  role      = google_project_iam_custom_role.{tf_name}.name",
          "  member    = var.principal_member",
          "}",
          "",
      ])
    elif scope == "pubsub_topic":
      tf_lines.extend([
          f'resource "google_pubsub_topic_iam_member" "{tf_name}_binding" {{',
          "  project = var.project_id",
          f'  topic   = "{target_res}"',
          f"  role    = google_project_iam_custom_role.{tf_name}.name",
          "  member  = var.principal_member",
          "}",
          "",
      ])
    elif scope == "pubsub_subscription":
      tf_lines.extend([
          f'resource "google_pubsub_subscription_iam_member" "{tf_name}_binding" {{',
          "  project      = var.project_id",
          f'  subscription = "{target_res}"',
          f"  role         = google_project_iam_custom_role.{tf_name}.name",
          "  member       = var.principal_member",
          "}",
          "",
      ])
    else:
      tf_lines.extend([
          f'# Bind google_project_iam_custom_role.{tf_name}.name on {scope} ({target_res}) using {sr["tf_binding_resource"]}',
          "",
      ])

  tf_path.write_text("\n".join(tf_lines) + "\n", encoding="utf-8")
  created_files["terraform_hcl"] = str(tf_path)

  # 5. Write Comprehensive Markdown Design Report (role_design_report.md)
  report_path = output_dir / "role_design_report.md"
  md = [
      "# GCP Least-Privilege Custom Role Design Report",
      "",
      f"- **Requirement**: `{requirement}`",
      f"- **Target Project**: `{project_id}`",
      f"- **Target Principal**: `{principal}`",
      f"- **Persona Sizing Mode**: `{spec.get('persona_mode', 'both')}`",
      f"- **Generated At**: `{spec.get('generated_at', '')}`",
      "",
      "---",
      "",
      "## 1. Executive Summary & Attack-Surface Reduction",
      "",
      "| Metric | Value |",
      "| :--- | :--- |",
      f"| **Scoped Custom Roles Required** | `{metrics.get('total_custom_roles_required', 0)}` (split by GCP Resource Hierarchy evaluation level) |",
      f"| **Total Permissions in Custom Role(s)** | `{metrics.get('total_selected_permissions', 0)}` (`{metrics.get('strict_headless_permission_count', 0)}` Headless API + `{metrics.get('console_ui_metadata_permission_count', 0)}` Console UI/CLI metadata) |",
      f"| **Closest Predefined Role(s)** | `{', '.join(metrics.get('closest_predefined_roles', [])) or 'N/A'}` (`{metrics.get('closest_predefined_permission_count', 0)}` total permissions) |",
      f"| **Permission Attack-Surface Reduction** | **`{metrics.get('attack_surface_reduction_pct', 0.0)}%` fewer permissions** than predefined roles |",
      "",
      "---",
      "",
      "## 2. Resource-Scoped Custom Role Architecture",
      "",
      "> [!IMPORTANT]",
      "> Google Cloud evaluates different permissions at different levels of the resource hierarchy. Binding data-plane permissions at the Project level grants access to **all** resources in the project. The roles below are split so each permission is bound at its **lowest valid resource boundary**.",
      "",
  ]

  for idx, sr in enumerate(scoped_roles, start=1):
    reuse = sr.get("reuse_analysis", {})
    disjoint = reuse.get("disjoint_model_b_analysis", {})
    md.extend([
        f"### 2.{idx} `{sr['role_id']}` — {sr['scope_label']}",
        f"- **Binding Resource Target**: `{sr['target_resource']}` (`{sr['scope']}`)",
        f"- **Custom Role YAML**: `custom-roles/{PERSONAS_SUBDIR}/{sr['role_file_slug']}.yaml`",
        f"- **Terraform Resource**: `{sr['tf_binding_resource']}`",
        f"- **Anti-Sprawl Recommendation**: `{reuse.get('recommendation', 'CREATE_NEW_SCOPED_ROLE')}`",
        "",
        "| Permission | Required For | Persona Tier |",
        "| :--- | :--- | :--- |",
    ])
    for p in sr["strict_headless_permissions"]:
      md.append(f"| `{p}` | Core API Execution / Data Plane | **Strict Headless & Console UI** |")
    for p in sr["console_ui_extra_permissions"]:
      md.append(f"| `{p}` | Schema / Metadata Inspection & UI Browsing | **Console UI / CLI Only** *(omit for strict headless SA)* |")
    md.append("")

    if reuse.get("superset_matches"):
      top_sup = reuse["superset_matches"][0]
      md.append(
          f"- **Existing Model A Superset Candidate**: `{top_sup['role_id']}` covers all required permissions plus `{top_sup['excess_permission_count']}` extra permissions."
      )
    if disjoint.get("overlapping_disjoint_roles"):
      ov_names = [
          f"`{d['role_id']}` ({len(d['overlap_permissions'])} perms)"
          for d in disjoint["overlapping_disjoint_roles"]
      ]
      md.append(
          f"- **Model B capability ($R_i \\cap R_j = \\emptyset$) Overlap**: {', '.join(ov_names)}."
      )
    if disjoint.get("net_new_disjoint_delta_permissions"):
      md.append(
          f"- **Model B capability Net-New Delta**: `{len(disjoint['net_new_disjoint_delta_permissions'])}` permissions written to `custom-roles/{CAPABILITIES_SUBDIR}/{disjoint_delta_role_id(spec, sr)}.yaml`."
      )
    md.append("")

  # Section 3: Security & Privilege Escalation Audit
  md.extend([
      "---",
      "",
      "## 3. Security Guardrails & Privilege-Escalation Audit (`E1`–`E5`)",
      "",
  ])
  esc = spec.get("privilege_escalation_findings", [])
  excl = spec.get("excluded_unsupported_permissions", [])
  if not esc and not excl:
    md.append(
        "- **Status**: `PASS` — Zero privilege-escalation primitives (`E1`–`E4`) or unsupported custom role permissions (`E5`) detected in the synthesized roles."
    )
  else:
    if esc:
      md.extend([
          "| Code | Severity | Permission | Risk & Mandatory Mitigation |",
          "| :--- | :--- | :--- | :--- |",
      ])
      for item in esc:
        md.append(
            f"| `{item['code']}` | **{item['severity']}** | `{item['permission']}` | {item['reason']} **Mitigation**: {item['mitigation']} |"
        )
      md.append("")
    if excl:
      md.append("### Automatically Excluded Invalid/Org-Only Permissions (`E5`)")
      for item in excl:
        md.append(f"- `{item['permission']}` — {item['reason']}")
      md.append("")

  # Section 4: Generated Deliverables
  md.extend([
      "---",
      "",
      "## 4. Generated Deliverables",
      "",
      "- **Custom Role YAMLs**: `custom-roles/personas/*.yaml` (Model A), `custom-roles/capabilities/*.yaml` (Model B delta)",
      "- **CLI Provisioning Script**: `provision_roles_and_bindings.sh`",
      "- **Terraform HCL**: `main.tf`",
      "- **Emergency Rollback Script**: `rollback_runbook.sh`",
  ])

  report_path.write_text("\n".join(md) + "\n", encoding="utf-8")
  created_files["report_markdown"] = str(report_path)

  # 6. Export Wiz / GitOps SARIF v2.1.0 pre-merge scan artifact
  sarif_results: List[Dict[str, Any]] = []
  for item in esc:
    sarif_results.append({
        "ruleId": f"SG-{item['code']}",
        "level": "error" if item["severity"] in ("CRITICAL", "HIGH") else "warning",
        "message": {
            "text": f"{item['permission']}: {item['reason']} Mitigation: {item['mitigation']}"
        },
        "locations": [{
            "physicalLocation": {"artifactLocation": {"uri": "main.tf"}},
        }],
    })
  for item in excl:
    sarif_results.append({
        "ruleId": "SG-E5",
        "level": "note",
        "message": {
            "text": f"Auto-stripped non-supported project permission {item['permission']}: {item['reason']}"
        },
        "locations": [{
            "physicalLocation": {"artifactLocation": {"uri": "main.tf"}},
        }],
    })
  sarif_doc = {
      "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
      "version": "2.1.0",
      "runs": [{
          "tool": {
              "driver": {
                  "name": "ScopeGuard Shift-Left Role Architect",
                  "version": "2.0.0",
              }
          },
          "results": sarif_results,
      }],
  }
  sarif_path = output_dir / "role_design.sarif.json"
  sarif_path.write_text(json.dumps(sarif_doc, indent=2) + "\n", encoding="utf-8")
  created_files["wiz_sarif_json"] = str(sarif_path)
  return created_files


def build_arg_parser() -> argparse.ArgumentParser:
  """Constructs the multi-command CLI parser."""
  parser = argparse.ArgumentParser(
      prog="role_architect_cli.py",
      description="GCP Least-Privilege Custom Role Architect CLI",
  )
  subparsers = parser.add_subparsers(dest="subcommand", required=True)

  # 1. list-capabilities
  p_list = subparsers.add_parser(
      "list-capabilities",
      help="Write the built-in DevOps capability catalog and resource scopes to a JSON file.",
  )
  p_list.add_argument(
      "--output",
      required=True,
      help="Output JSON file path.",
  )

  # Common arguments helper for design & full-design
  def add_design_args(subp: argparse.ArgumentParser) -> None:
    subp.add_argument(
        "--requirement",
        default="",
        help="Plain-English DevOps access requirement (e.g., 'read data from bq tables in a dataset and run jobs').",
    )
    subp.add_argument(
        "--capabilities",
        default="",
        help="Comma-separated capability IDs from list-capabilities (e.g., 'bq_dataset_read,bq_job_run').",
    )
    subp.add_argument(
        "--add-permissions",
        default="",
        help="Comma-separated explicit GCP IAM permissions to include.",
    )
    subp.add_argument(
        "--from-roles",
        default="",
        help="Comma-separated predefined/custom roles to inspect and slim down.",
    )
    subp.add_argument(
        "--persona",
        choices=["headless", "console", "both"],
        default="both",
        help="Target persona sizing: 'headless' (strict API minimum), 'console' (includes UI/CLI get/list), or 'both' (compares both).",
    )
    subp.add_argument(
        "--include-storage-read-api",
        action="store_true",
        help="Include BigQuery Storage Read API permissions (bigquery.readsessions.*).",
    )
    subp.add_argument(
        "--project",
        default="",
        help="Target GCP Project ID for live testable-permission validation and custom role deduplication.",
    )
    subp.add_argument(
        "--offline",
        action="store_true",
        help="Force offline catalog mode without calling live GCP APIs.",
    )
    subp.add_argument(
        "--principal",
        default="user:jane.doe@example.com",
        help="Target principal in type:identifier format (e.g., user:alice@example.com or serviceAccount:sa@proj.iam.gserviceaccount.com).",
    )
    subp.add_argument(
        "--role-prefix",
        default=None,
        help=(
            "Prefix for generated custom role IDs and YAML filenames "
            "(default: $SCOPEGUARD_ROLE_PREFIX or 'sg_')."
        ),
    )
    subp.add_argument(
        "--dataset-id",
        default="YOUR_DATASET_ID",
        help="Target BigQuery Dataset ID (if dataset-scoped permissions are present).",
    )
    subp.add_argument(
        "--bucket-name",
        default="YOUR_BUCKET_NAME",
        help="Target GCS Bucket name (if bucket-scoped permissions are present).",
    )
    subp.add_argument(
        "--secret-id",
        default="YOUR_SECRET_ID",
        help="Target Secret Manager Secret ID (if secret-scoped permissions are present).",
    )
    subp.add_argument(
        "--topic-id",
        default="YOUR_TOPIC_ID",
        help="Target Pub/Sub Topic ID.",
    )
    subp.add_argument(
        "--subscription-id",
        default="YOUR_SUBSCRIPTION_ID",
        help="Target Pub/Sub Subscription ID.",
    )
    subp.add_argument(
        "--service-name",
        default="YOUR_CLOUD_RUN_SERVICE",
        help="Target Cloud Run service name.",
    )
    subp.add_argument(
        "--repository-id",
        default="YOUR_REPOSITORY_ID",
        help="Target Artifact Registry repository ID.",
    )
    subp.add_argument(
        "--existing-roles-dir",
        default="./custom-roles",
        help=(
            "Path to existing workspace custom role YAMLs (the custom-roles/ dir or its parent) "
            "for anti-sprawl & Model B capability checks. Reads personas/ and capabilities/, "
            "falling back to legacy root *.yaml and disjoint/."
        ),
    )

  # 2. design
  p_design = subparsers.add_parser(
      "design",
      help="Decompose a requirement into resource-scoped least-privilege custom roles and write a JSON spec.",
  )
  add_design_args(p_design)
  p_design.add_argument(
      "--output",
      required=True,
      help="Path to write role_design_spec.json.",
  )

  # 3. generate-artifacts
  p_gen = subparsers.add_parser(
      "generate-artifacts",
      help="Generate Role YAMLs, gcloud/bq script, Terraform HCL, Rollback script, and Markdown report from a design spec.",
  )
  p_gen.add_argument(
      "--spec",
      required=True,
      help="Path to role_design_spec.json produced by 'design'.",
  )
  p_gen.add_argument(
      "--output-dir",
      required=True,
      help="Directory to write all generated deliverables.",
  )

  # 4. full-design
  p_full = subparsers.add_parser(
      "full-design",
      help="Run 'design' and 'generate-artifacts' end-to-end in one command.",
  )
  add_design_args(p_full)
  p_full.add_argument(
      "--output-dir",
      required=True,
      help="Directory to write role_design_spec.json and all generated deliverables.",
  )
  add_gcs_publish_arguments(p_full)

  # 5. troubleshoot-403 (Developer 403 PERMISSION_DENIED Minimal-Fix Debugger)
  p_403 = subparsers.add_parser(
      "troubleshoot-403",
      help=(
          "Parse a GCP 403 PERMISSION_DENIED error log or stack trace and emit "
          "the narrowest, resource-scoped least-privilege Terraform/CLI fix "
          "(with anti-sprawl Model B capability reuse and E1-E5 escalation checks)."
      ),
  )
  p_403.add_argument("--project", required=True, help="Target GCP Project ID.")
  p_403.add_argument(
      "--error-log",
      default="",
      help="Raw GCP 403 PERMISSION_DENIED error message or stack trace snippet.",
  )
  p_403.add_argument(
      "--error-file",
      default="",
      help="Optional file path containing the 403 error log.",
  )
  p_403.add_argument(
      "--principal",
      required=True,
      help="Impacted IAM principal (e.g., serviceAccount:app@proj.iam.gserviceaccount.com).",
  )
  p_403.add_argument(
      "--resource",
      default="",
      help="Optional target resource name (bucket, secret, dataset, or target SA email).",
  )
  p_403.add_argument(
      "--existing-roles-dir",
      default="./scopeguard-output",
      help="Optional directory to scan for existing Model B capability custom role reuse.",
  )
  p_403.add_argument(
      "--output-dir",
      required=True,
      help="Directory to write troubleshoot_403_fix.tf and troubleshoot_403_report.json.",
  )
  p_403.add_argument(
      "--role-prefix",
      default=None,
      help=(
          "Prefix for the generated fix role ID "
          "(default: $SCOPEGUARD_ROLE_PREFIX or 'sg_')."
      ),
  )

  return parser


def troubleshoot_403_error(
    project_id: str,
    error_text: str,
    principal: str,
    resource_hint: str = "",
    existing_roles_dir: Optional[Path] = None,
    output_dir: Optional[Path] = None,
    role_prefix: Optional[str] = None,
) -> Dict[str, Any]:
  """Extracts missing GCP permission(s) from a 403 error and builds a minimal scoped fix.

  Args:
    project_id: Target project ID.
    error_text: Raw 403 error / stack trace text.
    principal: Impacted IAM member.
    resource_hint: Optional resource name for the narrowest binding scope.
    existing_roles_dir: Audit output dir or custom-roles dir scanned for
      reusable Model B capability roles (capabilities/, legacy disjoint/).
    output_dir: Where to write the Terraform patch and JSON report.
    role_prefix: Optional role ID prefix (shared ScopeGuard naming convention).
  """
  perm_matches = sorted(
      set(
          re.findall(
              r"\b([a-z][a-z0-9]{1,30}\.[a-zA-Z0-9_]+\.[a-zA-Z0-9_]+)\b",
              error_text,
          )
      )
  )
  # Filter out common non-IAM dotted hostnames
  non_iam_prefixes = ("googleapis.", "iam.gserviceaccount", "cloud.google")
  missing_perms = [
      p
      for p in perm_matches
      if not any(p.startswith(pfx) for pfx in non_iam_prefixes)
      and not p.endswith(".com")
      and not p.endswith(".net")
  ]
  if not missing_perms:
    raise ValueError(
        "Could not detect a canonical GCP IAM permission (e.g., "
        "`secretmanager.versions.access` or `storage.objects.get`) in the provided 403 log."
    )

  # Infer narrowest resource scope from the first missing permission
  primary_perm = missing_perms[0]
  svc = primary_perm.split(".", 1)[0]
  scope_type = "project"
  tf_resource = "google_project_iam_member"
  res_name = resource_hint
  if svc == "secretmanager":
    scope_type = "secret"
    tf_resource = "google_secret_manager_secret_iam_member"
    if not res_name:
      m_sec = re.search(r"secrets/([a-zA-Z0-9_-]+)", error_text)
      res_name = m_sec.group(1) if m_sec else "TARGET_SECRET_ID"
  elif svc == "storage":
    scope_type = "bucket"
    tf_resource = "google_storage_bucket_iam_member"
    if not res_name:
      m_bkt = re.search(r"buckets?/([a-z0-9._-]+)", error_text)
      res_name = m_bkt.group(1) if m_bkt else "TARGET_BUCKET_NAME"
  elif svc == "bigquery" and "tables" in primary_perm:
    scope_type = "bigquery_dataset"
    tf_resource = "google_bigquery_dataset_iam_member"
    if not res_name:
      m_ds = re.search(r"datasets/([a-zA-Z0-9_]+)", error_text)
      res_name = m_ds.group(1) if m_ds else "TARGET_DATASET_ID"
  elif svc == "iam" and "serviceAccounts" in primary_perm:
    scope_type = "service_account"
    tf_resource = "google_service_account_iam_member"
    if not res_name:
      res_name = f"TARGET_SA@{project_id}.iam.gserviceaccount.com"

  # Check E1-E5 escalation guardrails
  esc_warnings = []
  for p in missing_perms:
    if p in PRIVILEGE_ESCALATION_RULES:
      rule = PRIVILEGE_ESCALATION_RULES[p]
      esc_warnings.append({"permission": p, **rule})

  # Check anti-sprawl reuse against existing Model B capability YAMLs
  reusable_roles: List[Dict[str, Any]] = []
  _, capability_files = custom_role_yaml_files(existing_roles_dir)
  legacy_files: List[Path] = []
  if existing_roles_dir and existing_roles_dir.is_dir():
    # Older layouts may hold disjoint_*.yaml deeper in the tree.
    legacy_files = sorted(existing_roles_dir.rglob("disjoint_*.yaml"))
  scan_files = sorted(set(capability_files) | set(legacy_files))
  for ypath in scan_files:
    try:
      perms_in_role = set(parse_simple_role_yaml(ypath)["includedPermissions"])
    except (OSError, UnicodeDecodeError) as exc:
      print(f"[Warn] Skipping unreadable role YAML {ypath}: {exc}", file=sys.stderr)
      continue
    # Exact permission match (substring matching could false-positive, e.g.
    # `storage.objects.get` inside `storage.objects.getIamPolicy`).
    covered = [p for p in missing_perms if p in perms_in_role]
    if covered:
      reusable_roles.append(
          {
              "yaml_file": str(ypath),
              "covered_permissions": covered,
              "full_match": len(covered) == len(missing_perms),
          }
      )

  # Capability-style ID: names WHAT the fix grants (e.g. sg_cap_secrets_fix403_read).
  fix_parts = naming.capability_name_parts(missing_perms)
  role_id = naming.capability_role_id(
      fix_parts["domain"], "fix403", fix_parts["access"], prefix=role_prefix
  )
  perms_hcl = "\n".join(f'    "{p}",' for p in missing_perms)
  if scope_type == "secret":
    binding_block = (
        f'resource "{tf_resource}" "fix_403_binding" {{\n'
        f'  project   = "{project_id}"\n'
        f'  secret_id = "{res_name}"\n'
        f"  role      = google_project_iam_custom_role.fix_403_role.id\n"
        f'  member    = "{principal}"\n'
        f"}}\n"
    )
    gcloud_cmd = (
        f"gcloud secrets add-iam-policy-binding {res_name} --project={project_id} "
        f'--member="{principal}" --role="projects/{project_id}/roles/{role_id}" --quiet'
    )
  elif scope_type == "bucket":
    binding_block = (
        f'resource "{tf_resource}" "fix_403_binding" {{\n'
        f'  bucket = "{res_name}"\n'
        f"  role   = google_project_iam_custom_role.fix_403_role.id\n"
        f'  member = "{principal}"\n'
        f"}}\n"
    )
    gcloud_cmd = (
        f"gcloud storage buckets add-iam-policy-binding gs://{res_name} --project={project_id} "
        f'--member="{principal}" --role="projects/{project_id}/roles/{role_id}" --quiet'
    )
  elif scope_type == "service_account":
    binding_block = (
        f'resource "{tf_resource}" "fix_403_binding" {{\n'
        f'  service_account_id = "projects/{project_id}/serviceAccounts/{res_name}"\n'
        f"  role               = google_project_iam_custom_role.fix_403_role.id\n"
        f'  member             = "{principal}"\n'
        f"}}\n"
    )
    gcloud_cmd = (
        f"gcloud iam service-accounts add-iam-policy-binding {res_name} --project={project_id} "
        f'--member="{principal}" --role="projects/{project_id}/roles/{role_id}" --quiet'
    )
  else:
    binding_block = (
        f'resource "{tf_resource}" "fix_403_binding" {{\n'
        f'  project = "{project_id}"\n'
        f"  role    = google_project_iam_custom_role.fix_403_role.id\n"
        f'  member  = "{principal}"\n'
        f"}}\n"
    )
    gcloud_cmd = (
        f"gcloud projects add-iam-policy-binding {project_id} --project={project_id} "
        f'--member="{principal}" --role="projects/{project_id}/roles/{role_id}" --quiet'
    )

  tf_patch = (
      f"# ScopeGuard Minimal 403 PERMISSION_DENIED Fix (Do NOT grant roles/editor or roles/*.admin)\n"
      f"# Missing Permission(s): {', '.join(missing_perms)}\n"
      f"# Narrowest Scope: {scope_type} ({res_name or project_id})\n\n"
      f'resource "google_project_iam_custom_role" "fix_403_role" {{\n'
      f'  project     = "{project_id}"\n'
      f'  role_id     = "{role_id}"\n'
      f'  title       = "Scoped Minimal Fix ({svc})"\n'
      f'  description = "Minimal custom role synthesized by ScopeGuard 403 debugger."\n'
      f"  permissions = [\n{perms_hcl}\n  ]\n"
      f"}}\n\n"
      + binding_block
  )

  result = {
      "project_id": project_id,
      "principal": principal,
      "missing_permissions": missing_perms,
      "recommended_scope": scope_type,
      "target_resource": res_name or project_id,
      "terraform_resource_type": tf_resource,
      "escalation_warnings": esc_warnings,
      "disjoint_role_reuse_matches": reusable_roles,
      "gcloud_apply_command": gcloud_cmd,
      "terraform_hcl": tf_patch,
      "why_not_predefined_admin": (
          f"Grants only {len(missing_perms)} exact permission(s) scoped to `{scope_type}` "
          f"instead of hundreds/thousands of project-wide permissions from `roles/{svc}.admin` or `roles/editor`."
      ),
  }

  if output_dir:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "troubleshoot_403_fix.tf").write_text(tf_patch + "\n", encoding="utf-8")
    (output_dir / "troubleshoot_403_report.json").write_text(
        json.dumps(result, indent=2) + "\n", encoding="utf-8"
    )
  return result


def design_id(spec: Dict[str, Any]) -> str:
  """Returns a stable identifier for a role design (used to dedupe GCS history).

  Prefers the first scoped role ID (unique per principal + scope), then a
  legacy `metadata.role_prefix`, then a constant default.
  """
  scoped = spec.get("scoped_custom_roles", spec.get("scoped_roles", [])) or []
  if scoped and scoped[0].get("role_id"):
    return str(scoped[0]["role_id"])
  return spec.get("metadata", {}).get("role_prefix") or "custom_design"


def build_architect_envelope_module(
    spec: Dict[str, Any],
    out_dir: Path,
    extra_designs: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
  """Packages role design specification and IaC artifacts for GCS envelope.

  Role YAML contents are embedded (not paths): `role_yamls` holds Model A
  persona YAMLs (`custom-roles/personas/`, legacy root fallback) and
  `disjoint_role_yamls` holds Model B delta YAMLs (`custom-roles/capabilities/`,
  legacy `disjoint/` fallback).
  """
  def _read_opt(p: Path) -> str:
    return p.read_text(encoding="utf-8") if p.exists() else ""

  def _read_json_opt(p: Path) -> Any:
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None

  model_a_files, model_b_files = custom_role_yaml_files(out_dir / "custom-roles")
  role_yamls: Dict[str, str] = {
      yfile.name: yfile.read_text(encoding="utf-8") for yfile in model_a_files
  }
  disjoint_role_yamls: Dict[str, str] = {
      yfile.name: yfile.read_text(encoding="utf-8") for yfile in model_b_files
  }

  primary_bundle = {
      "id": design_id(spec),
      "title": spec.get("input_summary", {}).get("requirement_text", "Custom Role Design")[:95],
      "spec": spec,
      "artifacts": {
          "main_tf": _read_opt(out_dir / "main.tf"),
          "provision_sh": _read_opt(out_dir / "provision_roles_and_bindings.sh"),
          "rollback_sh": _read_opt(out_dir / "rollback_runbook.sh"),
          "report_md": _read_opt(out_dir / "role_design_report.md"),
          "role_yamls": role_yamls,
          "disjoint_role_yamls": disjoint_role_yamls,
          "sarif": _read_json_opt(out_dir / "role_design.sarif.json"),
          "scc_findings": _read_json_opt(out_dir / "scc_findings_payload.json"),
      },
  }
  designs = [primary_bundle] + (extra_designs or [])
  scoped_roles = spec.get("scoped_custom_roles", spec.get("scoped_roles", []))
  total_perms = sum(len(r.get("included_permissions", [])) for r in scoped_roles)
  esc_findings = spec.get("privilege_escalation_findings", [])

  summary = {
      "designs_count": len(designs),
      "primary_scoped_roles_count": len(scoped_roles),
      "primary_total_permissions": total_perms,
      "escalation_warnings_count": len(esc_findings),
      "persona": spec.get("input_summary", {}).get("persona", "headless"),
  }
  return {
      "summary": summary,
      "payload": {"primary_design": primary_bundle, "designs": designs},
      "status": "COMPLETED",
  }


def main() -> int:
  parser = build_arg_parser()
  args = parser.parse_args()

  try:
    if args.subcommand == "list-capabilities":
      out_path = Path(args.output)
      out_path.parent.mkdir(parents=True, exist_ok=True)
      with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(CAPABILITY_CATALOG, fh, indent=2)
      print(f"Success! Capability catalog written to: {out_path}")
      return 0

    if args.subcommand == "design":
      spec = design_roles(args)
      out_path = Path(args.output)
      out_path.parent.mkdir(parents=True, exist_ok=True)
      with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(spec, fh, indent=2)
      print(f"Success! Role design specification written to: {out_path}")
      return 0

    if args.subcommand == "generate-artifacts":
      spec_path = Path(args.spec)
      spec = json.loads(spec_path.read_text(encoding="utf-8"))
      out_dir = Path(args.output_dir)
      created = generate_artifacts_from_spec(spec, out_dir)
      print(
          f"Success! Generated {len(created)} deliverables in: {out_dir} "
          f"(Report: {created.get('report_markdown')})"
      )
      return 0

    if args.subcommand == "full-design":
      proj_for_gcs = getattr(args, "project", "") or "unspecified-project"
      store = GCSAssessmentStore()
      gcs_check = None
      if not getattr(args, "offline", False) and getattr(args, "project", ""):
        gcs_check = run_skill_gcs_preflight(args, proj_for_gcs, store=store)

      out_dir = Path(args.output_dir)
      out_dir.mkdir(parents=True, exist_ok=True)
      spec = design_roles(args)
      spec_path = out_dir / "role_design_spec.json"
      with open(spec_path, "w", encoding="utf-8") as fh:
        json.dump(spec, fh, indent=2)
      created = generate_artifacts_from_spec(spec, out_dir)

      publish_info = None
      if gcs_check and getattr(args, "project", ""):
        live_etag = ""
        try:
          pol = ScopeGuardGCPClient().fetch_project_iam_policy(args.project)
          live_etag = pol.get("etag", "")
        except Exception:  # pylint: disable=broad-except
          pass
        # Preserve prior saved designs in role_architect if present
        prior_env = store.get_json_object(
            gcs_check["bucket"], f"{args.project}/latest.json"
        )
        prior_designs = (
            (prior_env or {})
            .get("modules", {})
            .get("role_architect", {})
            .get("payload", {})
            .get("designs", [])
        )
        new_id = design_id(spec)
        filtered_prior = [d for d in prior_designs if d.get("id") != new_id][:5]
        mod_entry = build_architect_envelope_module(
            spec, out_dir, extra_designs=filtered_prior
        )
        publish_info = store.publish_assessment_run(
            bucket=gcs_check["bucket"],
            region=gcs_check["region"],
            project_id=args.project,
            trigger_mode="role-architect",
            updated_modules={"role_architect": mod_entry},
            live_policy_etag=live_etag,
            local_output_dir=out_dir,
        )

      print(
          f"Success! Full role design completed in: {out_dir}\n"
          f"  - Spec JSON: {spec_path}\n"
          f"  - Report MD: {created.get('report_markdown')}\n"
          f"  - Provision Script: {created.get('provision_script')}\n"
          f"  - Terraform HCL: {created.get('terraform_hcl')}\n"
          f"  - Rollback Runbook: {created.get('rollback_script')}\n"
          f"  - GCS Publish: {json.dumps(publish_info)}"
      )
      return 0

    if args.subcommand == "troubleshoot-403":
      err_txt = args.error_log
      if args.error_file:
        err_txt = Path(args.error_file).read_text(encoding="utf-8")
      res = troubleshoot_403_error(
          project_id=args.project,
          error_text=err_txt,
          principal=args.principal,
          resource_hint=args.resource,
          existing_roles_dir=Path(args.existing_roles_dir),
          output_dir=Path(args.output_dir),
          role_prefix=args.role_prefix,
      )
      print(json.dumps(res, indent=2))
      return 0

  except Exception as exc:  # pylint: disable=broad-except
    print(f"[Error] {exc}", file=sys.stderr)
    return 1

  return 0


if __name__ == "__main__":
  sys.exit(main())
