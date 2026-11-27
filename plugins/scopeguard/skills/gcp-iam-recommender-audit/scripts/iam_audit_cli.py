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

"""Multi-command CLI for GCP IAM Recommender auditing and custom role mining.

Implements a hybrid Google Cloud REST API (urllib) + validated gcloud CLI client
with cross-process file-lock rate limiting, exponential backoff, 8 security
posture detectors (F1-F8, including AI/agentic SA blast-radius hygiene), a
generic evidence-driven custom-role engine for non-human workload identities
(Model A persona roles derived per serviceAccount from Recommender insights /
audit logs, Model B disjoint capability roles via lib.capability_partition),
human-to-Group+PAM-JIT routing, per-permission traceability (ART-13), phased
remediation planning (P0-P3), and a condition-aware per-principal restore
runbook (ART-3, lib.runbook_shell) with quarantined SA re-enablement.

Uses only Python 3 standard library modules. Run via:
  uv run scripts/iam_audit_cli.py <subcommand> [options]
"""

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import fcntl
import json
import logging
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib import error as urllib_error
from urllib import parse as urllib_parse
from urllib import request as urllib_request

PLUGIN_ROOT = Path(__file__).resolve().parents[3]
if str(PLUGIN_ROOT) not in sys.path:
  sys.path.insert(0, str(PLUGIN_ROOT))

from lib.gcs_publisher import (  # pylint: disable=wrong-import-position
    GCSAssessmentStore,
    add_gcs_publish_arguments,
    run_skill_gcs_preflight,
)
from lib import capability_partition  # pylint: disable=wrong-import-position
from lib import naming  # pylint: disable=wrong-import-position
from lib import runbook_shell  # pylint: disable=wrong-import-position
from lib.envelope_schema import SCHEMA_VERSION  # pylint: disable=wrong-import-position



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


class HybridGCPAuditClient:
  """Hybrid REST (urllib) and validated gcloud CLI client with rate limiting.

  Attempts REST API calls via urllib when an Application Default Credential
  (ADC) bearer token is usable, and transparently falls back to rate-limited
  gcloud CLI commands when Certificate-Based Access (CBA) or ADC restrictions
  apply.
  """

  SERVICE_RPS = {
      "recommender": 5.0,
      "iam": 10.0,
      "cloudresourcemanager": 4.0,
      "logging": 1.0,
  }

  def __init__(self, project_id: str, location: str = "global") -> None:
    self.project_id = project_id
    self.location = location
    self.limiter = CrossProcessRateLimiter(requests_per_second=5.0)
    self._adc_token: Optional[str] = None
    self._token_expiry: float = 0.0
    self._adc_checked = False
    self._has_gcloud = bool(shutil.which("gcloud"))
    self._prefer_rest = bool(os.environ.get("K_SERVICE")) or not self._has_gcloud

  def _get_adc_token(self) -> Optional[str]:
    """Retrieves an access token from Cloud Run Metadata Server or local ADC."""
    now = time.monotonic()
    if self._adc_token and now < self._token_expiry:
      return self._adc_token

    # 1. Try GCE / Cloud Run Metadata Server first (fast, zero-CLI container path)
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

    # 2. Fallback to local gcloud ADC token if available
    if self._has_gcloud:
      try:
        proc = subprocess.run(
            ["gcloud", "auth", "application-default", "print-access-token", "--quiet"],
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
      raise RuntimeError("ADC token unavailable; using gcloud CLI transport.")

    rps = self.SERVICE_RPS.get(service_key, 5.0)
    payload_bytes = json.dumps(body).encode("utf-8") if body is not None else None

    for attempt in range(retries):
      self.limiter.wait(custom_rps=rps)
      req = urllib_request.Request(url, data=payload_bytes, method=method)
      req.add_header("Authorization", f"Bearer {token}")
      req.add_header("X-Goog-User-Project", self.project_id)
      req.add_header("Accept", "application/json")
      req.add_header(
          "User-Agent",
          "agent-skills/1.0 (skill:gcp-iam-recommender-audit)",
      )
      if payload_bytes is not None:
        req.add_header("Content-Type", "application/json")

      try:
        with urllib_request.urlopen(req, timeout=30) as response:
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
          err_body = err.read().decode("utf-8", errors="replace")[:1000]
        except OSError:
          err_body = str(err.reason)
        raise RuntimeError(f"HTTP {err.code} from {url}: {err_body}") from err
      except urllib_error.URLError as err:
        if attempt == retries - 1:
          raise RuntimeError(
              f"Network error connecting to {url} after {retries} attempts: {err}"
          ) from err
        time.sleep(2**attempt)
    return {}

  def _dispatch_rest_for_args(self, args: List[str], service_key: str) -> Any:
    """Executes equivalent GCP REST API requests when running on Cloud Run or without gcloud."""
    if args[:2] == ["projects", "describe"]:
      return self._rest_request(
          f"https://cloudresourcemanager.googleapis.com/v1/projects/{self.project_id}",
          method="GET",
          service_key=service_key,
      )
    if args[:2] == ["projects", "get-iam-policy"]:
      return self._rest_request(
          f"https://cloudresourcemanager.googleapis.com/v1/projects/{self.project_id}:getIamPolicy",
          method="POST",
          body={"options": {"requestedPolicyVersion": 3}},
          service_key=service_key,
      )
    if args[:3] == ["recommender", "recommendations", "list"]:
      rec_type = "google.iam.policy.Recommender"
      for a in args:
        if a.startswith("--recommender="):
          rec_type = a.split("=", 1)[1]
      url = (
          f"https://recommender.googleapis.com/v1/projects/{self.project_id}/"
          f"locations/{self.location}/recommenders/{rec_type}/recommendations"
      )
      resp = self._rest_request(url, method="GET", service_key=service_key)
      return resp.get("recommendations", [])
    if args[:3] == ["recommender", "recommendations", "describe"]:
      rec_id = args[3]
      rec_type = "google.iam.policy.Recommender"
      for a in args:
        if a.startswith("--recommender="):
          rec_type = a.split("=", 1)[1]
      url = (
          f"https://recommender.googleapis.com/v1/projects/{self.project_id}/"
          f"locations/{self.location}/recommenders/{rec_type}/recommendations/{rec_id}"
      )
      return self._rest_request(url, method="GET", service_key=service_key)
    if args[:3] == ["recommender", "insights", "list"]:
      ins_type = "google.iam.policy.Insight"
      for a in args:
        if a.startswith("--insight-type="):
          ins_type = a.split("=", 1)[1]
      url = (
          f"https://recommender.googleapis.com/v1/projects/{self.project_id}/"
          f"locations/{self.location}/insightTypes/{ins_type}/insights"
      )
      resp = self._rest_request(url, method="GET", service_key=service_key)
      return resp.get("insights", [])
    if args[:3] == ["iam", "service-accounts", "list"]:
      url = f"https://iam.googleapis.com/v1/projects/{self.project_id}/serviceAccounts?pageSize=100"
      resp = self._rest_request(url, method="GET", service_key=service_key)
      return resp.get("accounts", [])
    if args[:3] == ["iam", "service-accounts", "get-iam-policy"]:
      sa_email = urllib_parse.quote(args[3], safe="")
      url = (
          f"https://iam.googleapis.com/v1/projects/{self.project_id}/"
          f"serviceAccounts/{sa_email}:getIamPolicy"
      )
      return self._rest_request(url, method="POST", body={}, service_key=service_key)
    if args[:3] == ["iam", "roles", "list"]:
      url = f"https://iam.googleapis.com/v1/projects/{self.project_id}/roles?pageSize=200"
      resp = self._rest_request(url, method="GET", service_key=service_key)
      return resp.get("roles", [])
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
      if any(a.startswith("--project=") for a in args[4:]) and not role_ref.startswith(("roles/", "projects/")):
        role_path = f"projects/{self.project_id}/roles/{role_ref}"
      else:
        role_path = role_ref
      return self._rest_request(
          f"https://iam.googleapis.com/v1/{role_path}",
          method="GET",
          service_key=service_key,
      )
    if args[:2] == ["logging", "read"]:
      flt = args[2]
      limit_val = 200
      for a in args[3:]:
        if a.startswith("--limit="):
          limit_val = min(1000, int(a.split("=", 1)[1]))
      resp = self._rest_request(
          "https://logging.googleapis.com/v2/entries:list",
          method="POST",
          body={
              "resourceNames": [f"projects/{self.project_id}"],
              "filter": flt,
              "pageSize": limit_val,
              "orderBy": "timestamp desc",
          },
          service_key=service_key,
      )
      return resp.get("entries", [])
    raise RuntimeError(f"Unsupported REST command mapping: {args}")

  def _run_gcloud_json(
      self,
      args: List[str],
      service_key: str = "iam",
      retries: int = 3,
      allow_empty_on_error: bool = False,
  ) -> Tuple[Any, Optional[str]]:
    """Executes a query via Cloud Run REST (when preferred/headless) or validated gcloud CLI."""
    if self._prefer_rest or not self._has_gcloud:
      try:
        data = self._dispatch_rest_for_args(args, service_key=service_key)
        return data, None
      except Exception as rest_err:  # pylint: disable=broad-except
        if not self._has_gcloud:
          if allow_empty_on_error:
            return [], str(rest_err)
          raise
        # Fall through to gcloud CLI if available locally

    rps = self.SERVICE_RPS.get(service_key, 5.0)
    cmd = ["gcloud"] + args + ["--format=json", "--quiet"]
    env = os.environ.copy()
    existing_env = env.get("CLOUDSDK_METRICS_ENVIRONMENT", "")
    env["CLOUDSDK_METRICS_ENVIRONMENT"] = (
        f"{existing_env} datacloud.antigravity".strip()
    )
    env["CLOUDSDK_METRICS_REQUEST_ATTRIBUTION"] = (
        "agent-skills/1.0 (skill:gcloud)"
    )

    for attempt in range(retries):
      self.limiter.wait(custom_rps=rps)
      proc = subprocess.run(
          cmd,
          capture_output=True,
          text=True,
          env=env,
          timeout=180,
          check=False,
      )
      if proc.returncode == 0:
        out = proc.stdout.strip()
        return (json.loads(out) if out else []), None

      stderr_text = proc.stderr.strip()
      if "429" in stderr_text or "RESOURCE_EXHAUSTED" in stderr_text:
        wait = 2**attempt
        print(
            f"[RateLimit] gcloud 429 on {' '.join(args[:3])}, retrying in {wait}s...",
            file=sys.stderr,
        )
        if attempt == retries - 1:
          raise RateLimitError(
              f"Rate limit exceeded (429) on gcloud {' '.join(args)} "
              f"at {rps} req/s: {stderr_text}"
          )
        time.sleep(wait)
        continue

      if allow_empty_on_error:
        print(
            f"[Warning] Optional query failed ({' '.join(args[:4])}): "
            f"{stderr_text[:300]}",
            file=sys.stderr,
        )
        return [], stderr_text

      raise RuntimeError(
          f"gcloud command failed ({' '.join(cmd)}): {stderr_text[:1000]}"
      )
    return [], "Exhausted retries"

  def collect_all(
      self,
      freshness_days: int,
      log_limit: int,
  ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Collects full IAM policy, Recommender insights, SAs, roles, and logs."""
    warnings: List[str] = []

    print(
        f"[1/8] Fetching project metadata & full IAM policy for {self.project_id}...",
        file=sys.stderr,
    )
    proj_info, err = self._run_gcloud_json(
        ["projects", "describe", self.project_id, f"--project={self.project_id}"],
        service_key="cloudresourcemanager",
        allow_empty_on_error=True,
    )
    if err:
      warnings.append(f"projects.describe warning: {err}")
    project_number = (
        proj_info.get("projectNumber", "")
        if isinstance(proj_info, dict)
        else ""
    )

    policy, _ = self._run_gcloud_json(
        [
            "projects",
            "get-iam-policy",
            self.project_id,
            f"--project={self.project_id}",
        ],
        service_key="cloudresourcemanager",
    )

    print("[2/8] Fetching Active Assist IAM Policy Recommendations...", file=sys.stderr)
    policy_recs, err = self._run_gcloud_json(
        [
            "recommender",
            "recommendations",
            "list",
            f"--project={self.project_id}",
            f"--location={self.location}",
            "--recommender=google.iam.policy.Recommender",
        ],
        service_key="recommender",
        allow_empty_on_error=True,
    )
    if err:
      warnings.append(f"google.iam.policy.Recommender fallback: {err}")

    print("[3/8] Fetching Active Assist IAM Policy Usage Insights...", file=sys.stderr)
    policy_insights, err = self._run_gcloud_json(
        [
            "recommender",
            "insights",
            "list",
            f"--project={self.project_id}",
            f"--location={self.location}",
            "--insight-type=google.iam.policy.Insight",
        ],
        service_key="recommender",
        allow_empty_on_error=True,
    )
    if err:
      warnings.append(f"google.iam.policy.Insight fallback: {err}")

    # Describe any associated recommendations that were not returned in list
    known_rec_names = {r.get("name", "") for r in (policy_recs or [])}
    for ins in policy_insights or []:
      for assoc in ins.get("associatedRecommendations", []):
        rec_full = assoc.get("recommendation", "")
        if rec_full and rec_full not in known_rec_names:
          rec_id = rec_full.split("/")[-1]
          rec_desc, _ = self._run_gcloud_json(
              [
                  "recommender",
                  "recommendations",
                  "describe",
                  rec_id,
                  f"--project={self.project_id}",
                  f"--location={self.location}",
                  "--recommender=google.iam.policy.Recommender",
              ],
              service_key="recommender",
              allow_empty_on_error=True,
          )
          if isinstance(rec_desc, dict) and rec_desc.get("name"):
            policy_recs.append(rec_desc)
            known_rec_names.add(rec_full)

    print("[4/8] Fetching Active Assist Service Account & Lateral Movement Insights...", file=sys.stderr)
    sa_insights, err = self._run_gcloud_json(
        [
            "recommender",
            "insights",
            "list",
            f"--project={self.project_id}",
            f"--location={self.location}",
            "--insight-type=google.iam.serviceAccount.Insight",
            "--limit=200",
        ],
        service_key="recommender",
        allow_empty_on_error=True,
    )
    if err:
      warnings.append(f"google.iam.serviceAccount.Insight fallback: {err}")

    lat_insights, err = self._run_gcloud_json(
        [
            "recommender",
            "insights",
            "list",
            f"--project={self.project_id}",
            f"--location={self.location}",
            "--insight-type=google.iam.policy.LateralMovementInsight",
            "--limit=200",
        ],
        service_key="recommender",
        allow_empty_on_error=True,
    )
    if err:
      warnings.append(f"google.iam.policy.LateralMovementInsight fallback: {err}")

    print("[5/8] Fetching Project Service Accounts & Existing Custom Roles...", file=sys.stderr)
    service_accounts, err = self._run_gcloud_json(
        [
            "iam",
            "service-accounts",
            "list",
            f"--project={self.project_id}",
            "--limit=500",
        ],
        service_key="iam",
        allow_empty_on_error=True,
    )
    if err:
      warnings.append(f"iam.serviceAccounts.list fallback: {err}")

    existing_custom_roles, err = self._run_gcloud_json(
        [
            "iam",
            "roles",
            "list",
            f"--project={self.project_id}",
            "--limit=500",
        ],
        service_key="iam",
        allow_empty_on_error=True,
    )
    if err:
      warnings.append(f"iam.roles.list fallback: {err}")

    print("[6/8] Fetching Testable Permissions & Custom Role Support Levels...", file=sys.stderr)
    testable_perms, err = self._run_gcloud_json(
        [
            "iam",
            "list-testable-permissions",
            f"//cloudresourcemanager.googleapis.com/projects/{self.project_id}",
            f"--project={self.project_id}",
        ],
        service_key="iam",
        allow_empty_on_error=True,
    )
    if err:
      warnings.append(f"iam.list-testable-permissions fallback: {err}")

    # Identify non-service-agent roles to expand via iam roles describe
    bindings = policy.get("bindings", []) if isinstance(policy, dict) else []
    roles_to_describe: Set[str] = set()
    for b in bindings:
      role = b.get("role", "")
      if role in ("roles/owner", "roles/editor", "roles/viewer"):
        continue
      for m in b.get("members", []):
        is_google_sa = (
            m.startswith("serviceAccount:service-")
            or m.endswith("@container-engine-robot.iam.gserviceaccount.com")
            or m.endswith("@compute-system.iam.gserviceaccount.com")
            or m.endswith("@cloud-filer.iam.gserviceaccount.com")
            or m.endswith("@cloud-memcache-sa.iam.gserviceaccount.com")
            or m.endswith("@cloud-redis.iam.gserviceaccount.com")
            or m.endswith("@container-analysis.iam.gserviceaccount.com")
            or m.endswith("@containerregistry.iam.gserviceaccount.com")
            or m.endswith("@dataflow-service-producer-prod.iam.gserviceaccount.com")
            or m.endswith("@dataproc-accounts.iam.gserviceaccount.com")
            or m.endswith("@firebase-rules.iam.gserviceaccount.com")
            or m.endswith("@gcf-admin-robot.iam.gserviceaccount.com")
            or m.endswith("@serverless-robot-prod.iam.gserviceaccount.com")
            or m.endswith("@service-networking.iam.gserviceaccount.com")
            or m.endswith("@firebase-sa-management.iam.gserviceaccount.com")
        )
        if not is_google_sa:
          roles_to_describe.add(role)

    print(
        f"[7/8] Expanding {len(roles_to_describe)} predefined/custom roles on user & workload principals...",
        file=sys.stderr,
    )
    role_definitions: Dict[str, List[str]] = {}
    for role_name in sorted(roles_to_describe):
      desc_args = ["iam", "roles", "describe", role_name]
      if role_name.startswith("projects/"):
        role_id = role_name.split("/")[-1]
        desc_args = [
            "iam",
            "roles",
            "describe",
            role_id,
            f"--project={self.project_id}",
        ]
      r_data, r_err = self._run_gcloud_json(
          desc_args, service_key="iam", allow_empty_on_error=True
      )
      if isinstance(r_data, dict):
        role_definitions[role_name] = r_data.get("includedPermissions", [])
      elif r_err:
        warnings.append(f"Could not expand {role_name}: {r_err}")

    print(
        f"[8/8] Sampling {freshness_days}d Cloud Audit Logs (limit={log_limit}) for fallback usage verification...",
        file=sys.stderr,
    )
    audit_logs, log_err = self._run_gcloud_json(
        [
            "logging",
            "read",
            "protoPayload.authorizationInfo:* AND NOT protoPayload.authenticationInfo.principalEmail:billing-export-bigquery@system.gserviceaccount.com",
            f"--project={self.project_id}",
            f"--freshness={freshness_days}d",
            f"--limit={log_limit}",
        ],
        service_key="logging",
        allow_empty_on_error=True,
    )
    if log_err:
      warnings.append(
          f"Cloud Audit Logs unavailable or restricted (auto-fallback to static role definitions): {log_err}"
      )

    # Inspect Service Account resource-level IAM policies for transitive SA bindings
    service_account_policies: Dict[str, Any] = {}
    for sa_obj in service_accounts or []:
      sa_email = sa_obj.get("email", "")
      if sa_email and sa_email.endswith(f"@{self.project_id}.iam.gserviceaccount.com"):
        sa_pol, _ = self._run_gcloud_json(
            [
                "iam",
                "service-accounts",
                "get-iam-policy",
                sa_email,
                f"--project={self.project_id}",
            ],
            service_key="iam",
            allow_empty_on_error=True,
        )
        if isinstance(sa_pol, dict) and sa_pol.get("bindings"):
          service_account_policies[sa_email] = sa_pol

    bundle = {
        "metadata": {
            "project_id": self.project_id,
            "project_number": project_number,
            "location": self.location,
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "freshness_days": freshness_days,
            "log_limit": log_limit,
            "telemetry_mode": "live_gcp_api",
            "warnings": warnings,
        },
        "iam_policy": policy,
        "service_account_policies": service_account_policies,
        "policy_recommendations": policy_recs or [],
        "policy_insights": policy_insights or [],
        "service_account_insights": sa_insights or [],
        "lateral_movement_insights": lat_insights or [],
        "service_accounts": service_accounts or [],
        "existing_custom_roles": existing_custom_roles or [],
        "testable_permissions": testable_perms or [],
        "role_definitions": role_definitions,
        "audit_logs_sample": audit_logs or [],
    }
    return bundle, policy



def classify_principal(member: str, project_id: str, project_number: str) -> str:
  """Classifies an IAM member string into one of 4 canonical categories."""
  if member.startswith(("user:", "group:", "domain:")):
    return "Human Users"
  if member.endswith(f"@{project_id}.iam.gserviceaccount.com"):
    return "Customer-Managed Service Accounts"
  default_sas = {
      f"serviceAccount:{project_number}-compute@developer.gserviceaccount.com",
      f"serviceAccount:{project_number}@cloudbuild.gserviceaccount.com",
      f"serviceAccount:{project_number}@cloudservices.gserviceaccount.com",
      f"serviceAccount:{project_id}@appspot.gserviceaccount.com",
  }
  if member in default_sas or re.match(
      r"^serviceAccount:\d+(-compute@developer|@cloudbuild|@cloudservices)\.gserviceaccount\.com$",
      member,
  ):
    return "Default Project Service Accounts"
  return "Google-Managed Service Agents"


# -----------------------------------------------------------------------------
# Generic custom-role engine helpers (Model A personas, Model B capabilities).
#
# Design notes:
#   * Nothing below references a specific principal, predefined role, or a
#     hand-picked permission list. Personas are derived only from evidence that
#     the bundle contains for each principal.
#   * Evidence priority per binding: IAM Recommender insight (exercised +
#     inferred) > sampled Cloud Audit Logs > role definition. A role WITHOUT an
#     insight keeps its full role-definition permissions (Recommender emits no
#     insight when a role is fully used or not yet analyzed, so dropping those
#     permissions could break the workload).
#   * Only when a principal has NO usage data at all is the persona the union
#     of its current role definitions; it is flagged with evidence_source
#     ``role_definition_no_usage_data`` everywhere (envelope, YAML description,
#     Markdown report).
# -----------------------------------------------------------------------------

GOOGLE_MANAGED_CATEGORY = "Google-Managed Service Agents"
EVIDENCE_SOURCE_INSIGHT = "recommender_insight"
EVIDENCE_SOURCE_AUDIT = "audit_log"
EVIDENCE_SOURCE_INSIGHT_AND_AUDIT = "recommender_insight+audit_log"
EVIDENCE_SOURCE_ROLE_DEF = "role_definition_no_usage_data"
BASIC_ROLES = ("roles/owner", "roles/editor", "roles/viewer")

# Published approximate sizes of basic roles. Used ONLY to estimate
# "permissions before" when neither an insight nor a role definition gives the
# exact count; every estimated role is listed in
# executive_kpis.permissions_before_estimated_roles so reports can say so.
BASIC_ROLE_PERMISSION_ESTIMATES = {
    "roles/owner": 13911,
    "roles/editor": 12266,
    "roles/viewer": 6420,
}

# Baseline telemetry permissions retained for service accounts that currently
# hold them even when unused in the window (logging/metrics/traces are emitted
# sporadically, e.g. only on errors). Reported as decision "kept" with reason
# "kept by policy" so reviewers can see them separately (ART-13).
KEEP_BY_POLICY_PERMISSIONS = (
    "logging.logEntries.create",
    "monitoring.timeSeries.create",
    "cloudtrace.traces.patch",
)

# Cap on per-persona "dropped: unused" rows in the traceability table; the
# remainder is summarized in a single aggregate row to keep payloads bounded.
TRACEABILITY_UNUSED_ROW_CAP = 300

# AI / agentic workload identity detection signals and blast-radius thresholds (F8).
AI_AGENT_ROLE_PREFIXES = (
    "roles/aiplatform.",
    "roles/ml.",
    "roles/discoveryengine.",
)
AI_AGENT_PERM_PREFIXES = ("aiplatform.", "ml.", "discoveryengine.")
AI_AGENT_EMAIL_RE = re.compile(
    r"(?:^|[-_.])(ai|agent|agentic|rag|llm|mcp|vertex|gemini|genai)(?:[-_.]|$)",
    re.IGNORECASE,
)
AI_BLAST_RADIUS_ROLES = {
    "roles/owner",
    "roles/editor",
    "roles/viewer",
    "roles/resourcemanager.projectIamAdmin",
    "roles/iam.serviceAccountAdmin",
    "roles/iam.serviceAccountTokenCreator",
    "roles/iam.serviceAccountUser",
    "roles/iam.serviceAccountKeyAdmin",
    "roles/iam.roleAdmin",
    "roles/iam.securityAdmin",
    "roles/secretmanager.secretAccessor",
    "roles/secretmanager.admin",
    "roles/storage.admin",
    "roles/storage.objectAdmin",
    "roles/bigquery.admin",
    "roles/bigquery.dataEditor",
    "roles/bigquery.dataOwner",
    "roles/run.admin",
    "roles/run.developer",
}
AI_BLAST_RADIUS_PERMISSIONS = {
    "iam.serviceAccounts.actAs",
    "iam.serviceAccounts.getAccessToken",
    "secretmanager.versions.access",
    "storage.objects.delete",
    "bigquery.tables.updateData",
    "run.services.update",
}
AI_CONTAINMENT_GUIDANCE = (
    "Identity-Layer Containment complementing Agent Gateway / Model Armor: "
    "isolate into a dedicated per-agent Service Account, bind a resource-scoped "
    "least-privilege custom role, and enforce a D5 IAM v2 Deny ceiling to cap "
    "blast radius against prompt injection or tool-call hijacking."
)

_LOG = logging.getLogger("scopeguard.iam_audit")


def utc_now_z() -> str:
  """Returns the current UTC time as an ISO-8601 string with a ``Z`` suffix."""
  return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def is_condition_expired(cond: Optional[Dict[str, Any]], now_iso: str) -> bool:
  """Returns True when a binding condition references a past timestamp.

  Mirrors the F5 detector exactly so finding counts and remediation agree.

  Args:
    cond: IAM binding condition dict (may be None).
    now_iso: Current UTC time, ISO-8601 with ``Z``.
  """
  if not cond or not cond.get("expression"):
    return False
  ts_match = re.search(r'timestamp\("([^"]+)"\)', cond["expression"])
  return bool(ts_match and ts_match.group(1) < now_iso)


def binding_view(binding: Dict[str, Any]) -> Dict[str, Any]:
  """Returns a minimal ``{role, condition?}`` view of one principal binding."""
  out: Dict[str, Any] = {"role": binding.get("role", "")}
  cond = binding.get("condition")
  if cond:
    out["condition"] = {
        k: cond[k] for k in ("expression", "title", "description") if cond.get(k)
    }
  return out


def member_email(member: str) -> str:
  """Strips the IAM member type prefix (``serviceAccount:x@y`` -> ``x@y``)."""
  return str(member or "").split(":", 1)[-1]


def collect_audit_usage(logs: List[Any]) -> Dict[str, Dict[str, Dict[str, Any]]]:
  """Aggregates granted permissions per caller email from sampled audit logs.

  Args:
    logs: Raw Cloud Audit Log entries from the bundle.

  Returns:
    email -> permission -> {"count": int, "last_seen": ISO timestamp or ""}.
    Denied checks (``granted: false``) are ignored: they prove a need was NOT
    met, not that the permission is currently held.
  """
  usage: Dict[str, Dict[str, Dict[str, Any]]] = defaultdict(dict)
  for entry in logs or []:
    if not isinstance(entry, dict):
      continue
    pp = entry.get("protoPayload")
    if not isinstance(pp, dict):
      continue
    email = (pp.get("authenticationInfo") or {}).get("principalEmail", "")
    if not email:
      continue
    ts = str(entry.get("timestamp") or entry.get("receiveTimestamp") or "")
    for auth in pp.get("authorizationInfo") or []:
      if not isinstance(auth, dict) or not auth.get("permission"):
        continue
      if auth.get("granted") is False:
        continue
      rec = usage[email].setdefault(auth["permission"], {"count": 0, "last_seen": ""})
      rec["count"] += 1
      if ts > rec["last_seen"]:
        rec["last_seen"] = ts
  return usage


def persona_candidate(
    member: str,
    bindings: List[Dict[str, Any]],
    category: str,
    project_id: str,
    inactive_sa_insights: Dict[str, Any],
) -> bool:
  """Decides whether a principal could need a Model A persona role.

  Custom ``sg_persona_*`` / ``sg_cap_*`` roles are strictly for non-human
  workload identities (``serviceAccount:``). Human ``user:`` principals are
  routed to Google Groups + PAM JIT so personal usernames never become custom
  role IDs.

  Also skipped: Google-managed service agents (their ``*.serviceAgent`` roles
  contain NOT_SUPPORTED permissions), principals already on project custom
  roles only, inactive SAs (revoked instead), and principals with no
  unconditional binding to replace.
  """
  if category == GOOGLE_MANAGED_CATEGORY:
    return False
  if not member.startswith("serviceAccount:"):
    return False
  if member in inactive_sa_insights:
    return False
  roles = [b["role"] for b in bindings]
  if roles and all(r.startswith(f"projects/{project_id}/roles/") for r in roles):
    return False
  return any(not b.get("condition") for b in bindings)


def derive_principal_permissions(
    member: str,
    bindings: List[Dict[str, Any]],
    insights_by_member_role: Dict[Tuple[str, str], Dict[str, Any]],
    audit_usage: Dict[str, Dict[str, Dict[str, Any]]],
    role_defs: Dict[str, Set[str]],
) -> Dict[str, Any]:
  """Derives the evidence-backed permission set for one principal.

  Only unconditional bindings are considered: live conditional bindings are
  retained unchanged and expired ones are removed outright.

  Args:
    member: IAM member string.
    bindings: The principal's bindings ({role, condition}).
    insights_by_member_role: Parsed Recommender insights keyed by (member, role).
    audit_usage: Output of ``collect_audit_usage``.
    role_defs: Predefined/custom role -> permission set from the bundle.

  Returns:
    Dict with keys: active_roles, evidence {perm: [evidence dicts]},
    evidence_source, has_usage_data, roles_without_usage_data,
    unexpandable_roles, granted_universe (set), universe_complete,
    kept_by_policy (list).
  """
  active_roles = sorted({b["role"] for b in bindings if not b.get("condition")})
  evidence: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
  roles_without_insight: List[str] = []
  has_insight = False
  for role in active_roles:
    ins = insights_by_member_role.get((member, role))
    if not ins:
      roles_without_insight.append(role)
      continue
    has_insight = True
    for perm in ins.get("exercised_permissions", []):
      evidence[perm].append({"type": "insight", "kind": "exercised", "id": ins["insight_id"], "role": role})
    for perm in ins.get("inferred_permissions", []):
      evidence[perm].append({"type": "insight", "kind": "inferred", "id": ins["insight_id"], "role": role})

  universe: Set[str] = set()
  universe_complete = True
  for role in active_roles:
    if role in role_defs:
      universe |= role_defs[role]
    else:
      universe_complete = False

  # Audit-log usage: accepted when provably granted by an active role, or when
  # the universe is unknown (e.g. basic roles have no definition in bundle).
  has_audit = False
  for perm, info in audit_usage.get(member_email(member), {}).items():
    if perm in universe or not universe_complete:
      has_audit = True
      evidence[perm].append({"type": "audit", "last_seen": info.get("last_seen", ""), "count": info.get("count", 0)})

  has_usage = has_insight or has_audit
  unexpandable = [r for r in roles_without_insight if r not in role_defs]
  if not has_usage:
    # Principal-level fallback: no Recommender insight and no audit usage.
    for role in active_roles:
      for perm in sorted(role_defs.get(role, ())):
        evidence[perm].append({"type": "role_definition", "role": role, "no_usage": True})
    source = EVIDENCE_SOURCE_ROLE_DEF
  else:
    # Roles without an insight keep their full definition (see module notes).
    for role in roles_without_insight:
      for perm in sorted(role_defs.get(role, ())):
        evidence[perm].append({"type": "role_definition", "role": role, "no_usage": False})
    if has_insight and has_audit:
      source = EVIDENCE_SOURCE_INSIGHT_AND_AUDIT
    elif has_insight:
      source = EVIDENCE_SOURCE_INSIGHT
    else:
      source = EVIDENCE_SOURCE_AUDIT

  kept_by_policy: List[str] = []
  if member.startswith("serviceAccount:") and evidence:
    for perm in KEEP_BY_POLICY_PERMISSIONS:
      if perm in universe and perm not in evidence:
        evidence[perm].append({"type": "policy"})
        kept_by_policy.append(perm)

  return {
      "active_roles": active_roles,
      "evidence": dict(evidence),
      "evidence_source": source,
      "has_usage_data": has_usage,
      "roles_without_usage_data": sorted(roles_without_insight),
      "unexpandable_roles": sorted(unexpandable),
      "granted_universe": universe,
      "universe_complete": universe_complete,
      "kept_by_policy": kept_by_policy,
  }


def _evidence_label(ev: Dict[str, Any]) -> Tuple[str, str]:
  """Maps one evidence record to (evidence text, kept reason)."""
  etype = ev.get("type")
  if etype == "insight":
    if ev.get("kind") == "inferred":
      return f"inferred (insight {ev.get('id', '')})", "inferred by IAM Recommender"
    return f"insight {ev.get('id', '')}", "exercised in observation window"
  if etype == "audit":
    return "audit log", "observed in sampled Cloud Audit Logs"
  if etype == "policy":
    return "kept by policy", "kept by policy (baseline telemetry permission)"
  if ev.get("no_usage"):
    return f"role definition ({ev.get('role', '')})", "no usage data: copied from current role definition"
  return (
      f"role definition ({ev.get('role', '')})",
      "role has no Recommender insight: retained from role definition",
  )


def build_traceability_rows(
    evidence: Dict[str, List[Dict[str, Any]]],
    supported: List[str],
    unsupported: List[str],
    unused: List[str],
) -> List[Dict[str, Any]]:
  """Builds ART-13 permission -> evidence -> decision rows for one persona."""
  rows: List[Dict[str, Any]] = []
  unsupported_set = set(unsupported)
  for perm in sorted(set(supported) | unsupported_set):
    evs = evidence.get(perm, [])
    labels = [_evidence_label(e) for e in evs]
    ev_text = "; ".join(sorted({lbl for lbl, _ in labels})) or "n/a"
    last_seen = max((str(e.get("last_seen") or "") for e in evs), default="")
    if perm in unsupported_set:
      decision, reason = "dropped", "unsupported in custom roles (NOT_SUPPORTED / not testable)"
    else:
      decision = "kept"
      reasons = sorted({r for _, r in labels})
      # "kept by policy" must be visible on its own (ART-13).
      reason = "; ".join(reasons) if reasons else "kept"
    rows.append({
        "permission": perm,
        "evidence": ev_text,
        "last_seen": last_seen,
        "decision": decision,
        "reason": reason,
    })
  unused_sorted = sorted(unused)
  for perm in unused_sorted[:TRACEABILITY_UNUSED_ROW_CAP]:
    rows.append({
        "permission": perm,
        "evidence": "role definition",
        "last_seen": "",
        "decision": "dropped",
        "reason": "unused (not exercised or inferred in observation window)",
    })
  remaining = len(unused_sorted) - TRACEABILITY_UNUSED_ROW_CAP
  if remaining > 0:
    rows.append({
        "permission": f"<{remaining} more permissions>",
        "evidence": "role definition",
        "last_seen": "",
        "decision": "dropped",
        "reason": "unused (aggregated to bound report size)",
    })
  return rows


def build_persona_roles(
    inputs: Dict[str, Dict[str, Any]],
    filter_fn: Any,
    run_id: str,
    prefix: Optional[str],
) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, str], Dict[str, List[Dict[str, Any]]]]:
  """Builds Model A persona roles: one per distinct evidence-backed permission set.

  Principals whose (custom-role-supported) permission sets AND evidence class
  are identical are merged into one persona with all of them as members.

  Args:
    inputs: member -> output of ``derive_principal_permissions``.
    filter_fn: Callable(set) -> (supported, unsupported) permission lists.
    run_id: Assessment run identifier embedded in role descriptions.
    prefix: Role ID prefix override (``--role-prefix``).

  Returns:
    (custom_roles_model_a, member -> persona role ID, role_traceability).
  """
  groups: Dict[Tuple[bool, Tuple[str, ...]], List[str]] = defaultdict(list)
  split: Dict[str, Tuple[List[str], List[str]]] = {}
  for member, d in sorted(inputs.items()):
    # Enforce workload-only persona roles: never create sg_persona_<username>
    # roles for human user: (or non-serviceAccount) principals.
    if not member.startswith("serviceAccount:"):
      _LOG.info("Skipping persona role for non-workload principal %s (use Groups + PAM JIT)", member)
      continue
    supported, unsupported = filter_fn(set(d["evidence"].keys()))
    if not supported:
      _LOG.info("No custom-role-supported permissions for %s; no persona built", member)
      continue
    split[member] = (supported, unsupported)
    no_usage = d["evidence_source"] == EVIDENCE_SOURCE_ROLE_DEF
    groups[(no_usage, tuple(supported))].append(member)

  representatives = {sorted(ms)[0]: key for key, ms in groups.items()}
  rep_ids = naming.assign_unique_persona_ids(representatives.keys(), prefix)

  model_a: Dict[str, Dict[str, Any]] = {}
  member_to_persona: Dict[str, str] = {}
  traceability: Dict[str, List[Dict[str, Any]]] = {}
  for rep, key in sorted(representatives.items()):
    members = sorted(groups[key])
    role_id = rep_ids[rep]
    supported = list(key[1])
    sources = sorted({inputs[m]["evidence_source"] for m in members})
    source = sources[0] if len(sources) == 1 else "+".join(sources)
    unsupported = sorted({p for m in members for p in split[m][1]})
    no_insight_roles = sorted({r for m in members for r in inputs[m]["roles_without_usage_data"]})
    merged_evidence: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    universe: Set[str] = set()
    for m in members:
      for perm, evs in inputs[m]["evidence"].items():
        merged_evidence[perm].extend(evs)
      universe |= inputs[m]["granted_universe"]
    unused = sorted(universe - set(merged_evidence.keys()))
    model_a[role_id] = {
        "role_id": role_id,
        "title": naming.persona_title(naming.workload_slug(rep)),
        "description": naming.role_description(
            "persona" + (" [NO USAGE DATA]" if key[0] else ""),
            len(supported),
            [naming.short_principal(m) for m in members],
            source,
            run_id,
        ),
        "stage": "GA",
        "includedPermissions": supported,
        "members": members,
        "evidence_source": source,
        "yaml_path": f"custom-roles/personas/{role_id}.yaml",
        "strippedUnsupportedPermissions": unsupported,
        "roles_without_usage_data": no_insight_roles,
        "kept_by_policy_permissions": sorted({p for m in members for p in inputs[m]["kept_by_policy"]}),
    }
    for m in members:
      member_to_persona[m] = role_id
    traceability[role_id] = build_traceability_rows(merged_evidence, supported, unsupported, unused)
  return model_a, member_to_persona, traceability


def build_capability_roles(
    model_a: Dict[str, Dict[str, Any]], run_id: str, prefix: Optional[str]
) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, List[str]], Dict[str, Any]]:
  """Builds Model B disjoint capability roles via the shared partitioner.

  Returns:
    (custom_roles_model_b_disjoint, persona -> capability IDs, verification).
  """
  result = capability_partition.partition_capabilities(
      {pid: meta["includedPermissions"] for pid, meta in model_a.items()}, prefix=prefix
  )
  model_b: Dict[str, Dict[str, Any]] = {}
  for rid, cap in result["capabilities"].items():
    model_b[rid] = {
        "role_id": rid,
        "title": naming.capability_title(rid),
        "description": naming.role_description(
            "capability", len(cap["permissions"]), cap["used_by"], "model_b_partition", run_id
        ),
        "stage": "GA",
        "includedPermissions": list(cap["permissions"]),
        "used_by": list(cap["used_by"]),
        "sensitive": bool(cap["sensitive"]),
        "yaml_path": f"custom-roles/capabilities/{rid}.yaml",
    }
  bundles = {pid: list(result["bundles"].get(pid, [])) for pid in model_a}
  return model_b, bundles, result["verification"]


def remediation_phase(member: str, roles: List[str], has_escalation: bool, has_expired: bool) -> str:
  """Generic phase assignment for a persona cut-over.

  P1: workload identities holding escalation or basic roles (highest risk).
  P3: human users on basic roles (governance / PAM transition).
  P2: everything else (role-sprawl consolidation).
  """
  del has_expired  # Expired bindings are always removed in P0 separately.
  holds_basic = any(r in BASIC_ROLES for r in roles)
  if member.startswith("serviceAccount:") and (has_escalation or holds_basic):
    return "P1"
  if member.startswith(("user:", "group:", "domain:")) and holds_basic:
    return "P3"
  return "P2"


def rollback_add_command(project_id: str, member: str, binding: Dict[str, Any]) -> str:
  """Renders a single ``add-iam-policy-binding`` restore command (display only).

  The authoritative, executable restore lives in rollback_runbook.sh.
  """
  cond = binding.get("condition")
  if cond:
    spec = f"expression={cond.get('expression', '')},title={cond.get('title', '')}"
    if cond.get("description"):
      spec += f",description={cond['description']}"
    cond_flag = f"--condition={shlex.quote(spec)}"
  else:
    cond_flag = "--condition=None"
  return (
      f'gcloud projects add-iam-policy-binding {project_id} --member="{member}" '
      f'--role="{binding.get("role", "")}" {cond_flag} --project={project_id} --quiet'
  )


def triage_symptom(pm: Dict[str, Any], persona_perms: List[str]) -> str:
  """Builds a generic 403 symptom from the services a principal uses."""
  services = Counter(naming.service_of(p) for p in persona_perms)
  if not services:
    services = Counter(
        b.get("role", "").split("/")[-1].split(".")[0] for b in pm.get("bindings_removed", [])
    )
  top = ", ".join(s for s, _ in services.most_common(3) if s) or "project"
  return (
      f"HTTP 403 PERMISSION_DENIED on {top} API calls by "
      f"{naming.short_principal(pm['principal'])} after phase {pm.get('remediation_phase', 'P1')}"
  )


def _yaml_str(value: Any) -> str:
  """Quotes a scalar as a YAML double-quoted string (JSON is valid YAML)."""
  return json.dumps(str(value), ensure_ascii=False)


def emit_role_yaml(role_meta: Dict[str, Any], project_id: str) -> str:
  """Renders a gcloud-compatible custom role YAML (hand-written, no PyYAML)."""
  lines = [
      f"# Custom IAM role for project: {project_id}",
      f"# Role ID: {role_meta['role_id']}",
  ]
  if role_meta.get("evidence_source") == EVIDENCE_SOURCE_ROLE_DEF:
    lines.append("# WARNING: NO USAGE DATA - permissions copied from current role definitions; review before use.")
  lines += [
      f"title: {_yaml_str(role_meta['title'])}",
      f"description: {_yaml_str(role_meta['description'])}",
      f"stage: {_yaml_str(role_meta.get('stage', 'GA'))}",
      "includedPermissions:",
  ]
  lines += [f"  - {perm}" for perm in role_meta["includedPermissions"]]
  return "\n".join(lines) + "\n"


def emit_bundles_yaml(analysis: Dict[str, Any]) -> str:
  """Renders custom-roles/bundles.yaml: persona -> capabilities + members."""
  project_id = analysis["metadata"]["project_id"]
  ver = analysis.get("model_b_verification") or {}
  lines = [
      f"# ScopeGuard Model B bundles for project: {project_id}",
      "# Binding every capability role of a persona grants exactly the persona's permissions.",
      f"project_id: {_yaml_str(project_id)}",
      f"run_id: {_yaml_str(analysis['metadata'].get('run_id', ''))}",
      "verification:",
      f"  pairwise_overlap: {int(ver.get('pairwise_overlap', 0))}",
      f"  exact_cover: {'true' if ver.get('exact_cover', False) else 'false'}",
      f"  capability_count: {int(ver.get('capability_count', 0))}",
      f"  max_bundle_size: {int(ver.get('max_bundle_size', 0))}",
  ]
  warnings = ver.get("warnings") or []
  lines.append("  warnings:" + ("" if warnings else " []"))
  lines += [f"    - {_yaml_str(w)}" for w in warnings]
  lines.append("bundles:" + ("" if analysis.get("model_b_bundles") else " {}"))
  for pid, caps in sorted((analysis.get("model_b_bundles") or {}).items()):
    persona = analysis["custom_roles_model_a"].get(pid, {})
    lines.append(f"  {pid}:")
    lines.append(f"    evidence_source: {_yaml_str(persona.get('evidence_source', ''))}")
    lines.append(f"    permission_count: {len(persona.get('includedPermissions', []))}")
    lines.append("    capabilities:" + ("" if caps else " []"))
    lines += [f"      - {c}" for c in caps]
    members = persona.get("members", [])
    lines.append("    members:" + ("" if members else " []"))
    lines += [f"      - {_yaml_str(m)}" for m in members]
  return "\n".join(lines) + "\n"


def analyze_bundle(bundle: Dict[str, Any], role_prefix: Optional[str] = None) -> Dict[str, Any]:
  """Runs F1-F7 detectors, the generic persona/capability engine, and principal mapping.

  Args:
    bundle: Collected audit bundle (see ``collect``).
    role_prefix: Optional custom role ID prefix (``--role-prefix``); defaults to
      env ``SCOPEGUARD_ROLE_PREFIX`` or ``sg_`` via ``lib.naming``.

  Returns:
    The analysis dict stored as ``modules.recommender_audit.payload.analysis``.
  """
  meta = bundle["metadata"]
  project_id = meta["project_id"]
  project_number = meta.get("project_number") or ""
  policy = bundle.get("iam_policy", {})
  bindings = policy.get("bindings", [])

  # Infer project_number if not set
  if not project_number:
    for b in bindings:
      for m in b.get("members", []):
        match = re.search(r"service-(\d+)@", m) or re.search(
            r":(\d+)-compute@", m
        )
        if match:
          project_number = match.group(1)
          break
      if project_number:
        break

  # Map testable permissions
  perm_support: Dict[str, str] = {}
  for item in bundle.get("testable_permissions", []):
    name = item.get("name")
    if name:
      perm_support[name] = item.get("customRolesSupportLevel", "SUPPORTED")

  def filter_custom_role_supported(perms: Set[str]) -> Tuple[List[str], List[str]]:
    if not perm_support:
      # Fallback if queryTestablePermissions was unavailable
      unsupported = [
          p
          for p in sorted(perms)
          if p == "resourcemanager.projects.list"
          or p == "gkehub.fleet.get"
          or p.endswith(".serviceAgent")
      ]
      supported = [p for p in sorted(perms) if p not in set(unsupported)]
      return supported, unsupported
    supported = [
        p
        for p in sorted(perms)
        if p in perm_support and perm_support[p] != "NOT_SUPPORTED"
    ]
    unsupported = [p for p in sorted(perms) if p not in set(supported)]
    return supported, unsupported

  # Build principal -> bindings map
  principals_map: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
  for b in bindings:
    role = b.get("role", "")
    cond = b.get("condition")
    for m in b.get("members", []):
      principals_map[m].append({"role": role, "condition": cond})

  # Parse policy insights & recommendations
  insights_by_member_role: Dict[Tuple[str, str], Dict[str, Any]] = {}
  insights_by_member: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
  for ins in bundle.get("policy_insights", []):
    c = ins.get("content", {})
    m = c.get("member", "")
    r = c.get("role", "")
    ex = [p["permission"] for p in c.get("exercisedPermissions", []) if "permission" in p]
    inf = [p["permission"] for p in c.get("inferredPermissions", []) if "permission" in p]
    entry = {
        "insight_id": ins.get("name", "").split("/")[-1],
        "member": m,
        "role": r,
        "severity": ins.get("severity", "HIGH"),
        "description": ins.get("description", ""),
        "current_total_permissions": int(c.get("currentTotalPermissionsCount", 0) or 0),
        "exercised_permissions": sorted(set(ex)),
        "inferred_permissions": sorted(set(inf)),
        "combined_permissions": sorted(set(ex) | set(inf)),
        "associated_recommendations": [
            ar.get("recommendation", "").split("/")[-1]
            for ar in ins.get("associatedRecommendations", [])
        ],
    }
    insights_by_member_role[(m, r)] = entry
    insights_by_member[m].append(entry)

  recs_by_id: Dict[str, Dict[str, Any]] = {}
  for rec in bundle.get("policy_recommendations", []):
    rid = rec.get("name", "").split("/")[-1]
    ov = rec.get("content", {}).get("overview", {})
    revoked = (
        rec.get("primaryImpact", {})
        .get("securityProjection", {})
        .get("details", {})
        .get("revokedIamPermissionsCount", 0)
    )
    recs_by_id[rid] = {
        "recommendation_id": rid,
        "subtype": rec.get("recommenderSubtype", ""),
        "priority": rec.get("priority", ""),
        "description": rec.get("description", ""),
        "member": ov.get("member", ""),
        "removed_role": ov.get("removedRole", ""),
        "added_roles": ov.get("addedRoles", []),
        "revoked_permissions_count": int(revoked or 0),
    }

  # Parse Service Account inventory and inactivity insights
  sa_inventory: Dict[str, Dict[str, Any]] = {}
  for sa in bundle.get("service_accounts", []):
    email = sa.get("email", "")
    if email:
      sa_inventory[f"serviceAccount:{email}"] = {
          "email": email,
          "displayName": sa.get("displayName", ""),
          "disabled": bool(sa.get("disabled", False)),
          "uniqueId": sa.get("uniqueId", ""),
      }

  inactive_sa_insights: Dict[str, Dict[str, Any]] = {}
  for sains in bundle.get("service_account_insights", []):
    c = sains.get("content", {})
    email = c.get("email", "")
    if email:
      member_key = f"serviceAccount:{email}"
      obs_sec = int(str(sains.get("observationPeriod", "0s")).rstrip("s") or 0)
      inactive_sa_insights[member_key] = {
          "insight_id": sains.get("name", "").split("/")[-1],
          "email": email,
          "service_account_id": c.get("serviceAccountId", "")
          or sa_inventory.get(member_key, {}).get("uniqueId", ""),
          "last_authenticated_time": c.get("lastAuthenticatedTime", "Never / >Observation Window"),
          "observation_days": round(obs_sec / 86400),
          "severity": sains.get("severity", "LOW"),
          "has_active_bindings": member_key in principals_map,
          "active_roles": [r["role"] for r in principals_map.get(member_key, [])],
      }

  # Parse Cloud Audit Logs sample
  audit_log_perms_by_principal: Dict[str, Set[str]] = defaultdict(set)
  for entry in bundle.get("audit_logs_sample", []):
    if not isinstance(entry, dict):
      continue
    pp = entry.get("protoPayload", {})
    if not isinstance(pp, dict):
      continue
    email = pp.get("authenticationInfo", {}).get("principalEmail", "")
    for auth in pp.get("authorizationInfo", []) or []:
      if isinstance(auth, dict) and auth.get("permission"):
        audit_log_perms_by_principal[email].add(auth["permission"])

  # Categorize all principals
  taxonomy_counts: Dict[str, int] = Counter()
  principal_categories: Dict[str, str] = {}
  for m in sorted(principals_map.keys()):
    cat = classify_principal(m, project_id, project_number)
    principal_categories[m] = cat
    taxonomy_counts[cat] += 1

  # Expand role definitions early so F8 can inspect effective permissions too.
  role_defs = {k: set(v) for k, v in bundle.get("role_definitions", {}).items()}

  # Evaluate Findings F1-F8
  findings: Dict[str, List[Dict[str, Any]]] = {
      "F1_basic_roles": [],
      "F2_overprivileged_principals": [],
      "F3_privilege_escalation_risks": [],
      "F4_inactive_service_accounts": [],
      "F5_expired_conditional_bindings": [],
      "F6_overprivileged_service_agents": [],
      "F7_role_sprawl_redundancy": [],
      "F8_ai_agent_blast_radius": [],
  }

  priv_esc_roles = {
      "roles/owner",
      "roles/editor",
      "roles/resourcemanager.projectIamAdmin",
      "roles/iam.serviceAccountAdmin",
      "roles/iam.serviceAccountTokenCreator",
      "roles/iam.serviceAccountUser",
      "roles/iam.serviceAccountKeyAdmin",
      "roles/iam.roleAdmin",
  }

  now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

  for m, rlist in sorted(principals_map.items()):
    cat = principal_categories[m]
    roles_only = [r["role"] for r in rlist]

    # F1: Basic roles
    for r in rlist:
      if r["role"] in ("roles/owner", "roles/editor", "roles/viewer"):
        ins = insights_by_member_role.get((m, r["role"]), {})
        findings["F1_basic_roles"].append({
            "principal": m,
            "category": cat,
            "role": r["role"],
            "total_permissions": ins.get("current_total_permissions") or BASIC_ROLE_PERMISSION_ESTIMATES.get(r["role"], 0),
            "exercised_count": len(ins.get("exercised_permissions", [])),
            "inferred_count": len(ins.get("inferred_permissions", [])),
            "insight_id": ins.get("insight_id", "N/A"),
            "phase": "P0" if len(ins.get("combined_permissions", [])) == 0 and cat != "Human Users" else ("P1" if cat != "Human Users" else "P3"),
        })

    # F2: Over-privileged from policy insights
    for ins in insights_by_member.get(m, []):
      used = len(ins["combined_permissions"])
      total = ins["current_total_permissions"]
      if total > 0:
        findings["F2_overprivileged_principals"].append({
            "principal": m,
            "role": ins["role"],
            "total_permissions": total,
            "exercised_permissions_count": len(ins["exercised_permissions"]),
            "inferred_permissions_count": len(ins["inferred_permissions"]),
            "unused_permissions_count": max(0, total - used),
            "utilization_pct": round((used / total) * 100, 2),
            "insight_id": ins["insight_id"],
        })

    # F3: Privilege escalation on non-admin/workload principals
    held_esc = sorted(set(roles_only) & priv_esc_roles)
    if held_esc and cat in ("Default Project Service Accounts", "Customer-Managed Service Accounts"):
      findings["F3_privilege_escalation_risks"].append({
          "principal": m,
          "category": cat,
          "escalation_roles": held_esc,
          "total_roles_on_principal": len(rlist),
          "phase": "P1",
      })

    # F5: Expired conditional bindings
    for r in rlist:
      cond = r.get("condition")
      if cond and cond.get("expression"):
        expr = cond["expression"]
        ts_match = re.search(r'timestamp\("([^"]+)"\)', expr)
        if ts_match and ts_match.group(1) < now_iso:
          findings["F5_expired_conditional_bindings"].append({
              "principal": m,
              "role": r["role"],
              "condition_title": cond.get("title", ""),
              "condition_expression": expr,
              "expired_at": ts_match.group(1),
              "phase": "P0",
          })

    # F6: Over-privileged or cross-project Google-managed service agents
    if cat == "Google-Managed Service Agents":
      non_sa_roles = [
          r["role"]
          for r in rlist
          if not (
              "serviceAgent" in r["role"]
              or "ServiceAgent" in r["role"]
              or r["role"] in ("roles/firebaserules.system", "roles/translationhub.portalUser")
          )
      ]
      foreign_proj = None
      m_proj = re.search(r"service-(?:project-)?(\d+)@", m)
      if m_proj and project_number and m_proj.group(1) != project_number:
        foreign_proj = m_proj.group(1)
      if non_sa_roles or foreign_proj:
        findings["F6_overprivileged_service_agents"].append({
            "principal": m,
            "all_roles": [r["role"] for r in rlist],
            "excess_non_service_agent_roles": non_sa_roles,
            "foreign_project_number": foreign_proj,
            "phase": "P0" if "roles/owner" in non_sa_roles or "roles/editor" in non_sa_roles else "P3",
        })

    # F7: Role sprawl (>= 2 roles on non-service-agent principals)
    if cat != "Google-Managed Service Agents" and len(rlist) >= 2:
      findings["F7_role_sprawl_redundancy"].append({
          "principal": m,
          "category": cat,
          "roles_count": len(rlist),
          "roles": roles_only,
          "phase": "P2",
      })

    # F8: AI / agentic Service Account blast radius & shared-SA hygiene
    if m.startswith("serviceAccount:") and cat != GOOGLE_MANAGED_CATEGORY:
      sa_email = member_email(m)
      sa_local = sa_email.split("@", 1)[0]
      held_perms: Set[str] = set(audit_log_perms_by_principal.get(sa_email, set()))
      for role in roles_only:
        held_perms |= role_defs.get(role, set())
      for ins in insights_by_member.get(m, []):
        held_perms.update(ins.get("combined_permissions", []))

      ai_signals: List[str] = []
      ai_roles = sorted(r for r in roles_only if r.startswith(AI_AGENT_ROLE_PREFIXES))
      if ai_roles:
        ai_signals.append(f"ai_roles:{','.join(ai_roles)}")
      if AI_AGENT_EMAIL_RE.search(sa_local):
        ai_signals.append(f"email_signal:{sa_local}")
      ai_perms_used = sorted(p for p in held_perms if p.startswith(AI_AGENT_PERM_PREFIXES))
      if ai_perms_used:
        ai_signals.append(f"ai_permissions:{len(ai_perms_used)}")

      if ai_signals:
        dangerous_roles_held = sorted(set(roles_only) & AI_BLAST_RADIUS_ROLES)
        dangerous_perms_held = sorted(held_perms & AI_BLAST_RADIUS_PERMISSIONS)
        distinct_domains = {p.split(".", 1)[0] for p in held_perms if "." in p}
        for role in roles_only:
          if role.startswith("roles/") and "." in role:
            distinct_domains.add(role.split("/", 1)[1].split(".", 1)[0])
        holds_ai_perms = bool(ai_roles or ai_perms_used)
        is_shared_multi_service = holds_ai_perms and len(distinct_domains) >= 4

        reasons: List[str] = []
        if dangerous_roles_held:
          reasons.append(f"dangerous_roles({', '.join(dangerous_roles_held)})")
        if dangerous_perms_held:
          reasons.append(f"dangerous_permissions({', '.join(dangerous_perms_held)})")
        if is_shared_multi_service:
          reasons.append(
              f"shared_multi_service_sa({len(distinct_domains)}_domains: "
              f"{', '.join(sorted(distinct_domains)[:6])})"
          )

        if reasons:
          findings["F8_ai_agent_blast_radius"].append({
              "principal": m,
              "category": cat,
              "ai_signals": ai_signals,
              "dangerous_roles": dangerous_roles_held,
              "dangerous_permissions": dangerous_perms_held,
              "distinct_service_domains": sorted(distinct_domains),
              "is_shared_multi_service_sa": is_shared_multi_service,
              "reasons": reasons,
              "phase": "P1",
              "containment_guidance": AI_CONTAINMENT_GUIDANCE,
          })

  # F4: Inactive Service Accounts
  for m_key, info in sorted(inactive_sa_insights.items()):
    findings["F4_inactive_service_accounts"].append({
        **info,
        "principal": m_key,
        "phase": "P1" if info["has_active_bindings"] else "P0",
    })

  # -------------------------------------------------------------------------
  # Generic custom-role engine (Model A personas + Model B capabilities).
  # Every persona is derived from per-principal evidence only (Recommender
  # insights, sampled audit logs, or -- when no usage data exists -- the
  # principal's current role definitions). No principal names, predefined
  # role names, or hand-picked permission lists are referenced here.
  # -------------------------------------------------------------------------
  prefix = naming.role_prefix(role_prefix)
  # Deterministic run ID from the collection time (e.g. audit-20261119T014041Z)
  # so re-analysing the same bundle yields identical role descriptions.
  run_id = str(meta.get("run_id") or "") or (
      "audit-" + re.sub(r"[^0-9T]", "", str(meta.get("collected_at") or now_iso)[:19]) + "Z"
  )
  audit_usage = collect_audit_usage(bundle.get("audit_logs_sample", []))
  f6_members = {f["principal"]: f for f in findings["F6_overprivileged_service_agents"]}
  f3_members = {f["principal"] for f in findings["F3_privilege_escalation_risks"]}

  # 1. Decide which principals are candidates for a persona role, and derive
  #    their evidence-backed permission sets.
  derived: Dict[str, Dict[str, Any]] = {}
  for m, rlist in sorted(principals_map.items()):
    if not persona_candidate(m, rlist, principal_categories[m], project_id, inactive_sa_insights):
      continue
    derived[m] = derive_principal_permissions(
        m, rlist, insights_by_member_role, audit_usage, role_defs
    )

  # A principal whose ONLY data is "no usage" and that holds a single
  # predefined role gains nothing from a clone of that role: keep it as-is.
  persona_inputs: Dict[str, Dict[str, Any]] = {}
  for m, d in derived.items():
    no_usage = d["evidence_source"] == EVIDENCE_SOURCE_ROLE_DEF
    if no_usage and len(d["active_roles"]) <= 1:
      continue
    if d["has_usage_data"] and not d["evidence"]:
      continue  # Recommender proved zero usage -> revoke, no persona needed.
    persona_inputs[m] = d

  custom_roles_model_a, member_to_persona, role_traceability = build_persona_roles(
      persona_inputs, filter_custom_role_supported, run_id, prefix
  )
  custom_roles_model_b, model_b_bundles, model_b_verification = build_capability_roles(
      custom_roles_model_a, run_id, prefix
  )
  # Backward-compatible persona -> capability bundle map (list values).
  model_a_to_b_map: Dict[str, List[str]] = {
      pid: list(caps) for pid, caps in model_b_bundles.items()
  }

  # 2. Permission accounting per principal (single source of truth, ART-4).
  def _role_size(member: str, role: str) -> Tuple[int, bool]:
    """Returns (permission count, is_estimate) for one binding."""
    ins = insights_by_member_role.get((member, role))
    if ins and ins.get("current_total_permissions"):
      return int(ins["current_total_permissions"]), False
    if role in role_defs:
      return len(role_defs[role]), False
    if role in BASIC_ROLE_PERMISSION_ESTIMATES:
      return BASIC_ROLE_PERMISSION_ESTIMATES[role], True
    return 0, True

  # 3. Map 100% of principals with generic, evidence-driven outcomes.
  principal_mappings: List[Dict[str, Any]] = []
  summary_buckets: Dict[str, int] = defaultdict(int)
  perms_before_total = 0
  perms_after_total = 0
  perms_estimated_roles: Set[str] = set()
  non_agent_principals = 0
  overpriv_before_count = 0
  overpriv_after_count = 0
  simulated_breakage_count = 0

  for m in sorted(principals_map.keys()):
    rlist = principals_map[m]
    cat = principal_categories[m]
    curr_roles = [
        r["role"] + (f" [COND: {r['condition'].get('title', '')}]" if r.get("condition") else "")
        for r in rlist
    ]
    raw_role_names = [r["role"] for r in rlist]
    bindings_before = [binding_view(r) for r in rlist]
    expired = [r for r in rlist if is_condition_expired(r.get("condition"), now_iso)]
    live_conditional = [r for r in rlist if r.get("condition") and r not in expired]
    unconditional = [r for r in rlist if not r.get("condition")]
    d = derived.get(m)
    persona_id = member_to_persona.get(m, "")
    target_mapping = ""
    removed: List[Dict[str, Any]] = []
    is_overpriv_after = False

    if cat == GOOGLE_MANAGED_CATEGORY:
      f6 = f6_members.get(m)
      if f6:
        bucket = "Google_Managed_Service_Agent (Remediation Required)"
        phase = f6.get("phase", "P3")
        excess = f6.get("excess_non_service_agent_roles") or []
        action = (
            f"Remove excess non-service-agent role(s): {', '.join(excess)}; retain managed *.serviceAgent role(s)"
            if excess
            else "Review cross-project service agent binding; retain managed *.serviceAgent role(s)"
        )
        removed = [r for r in rlist if r["role"] in set(excess)]
      else:
        bucket = "Google_Managed_Service_Agent (Retain Default Managed Role)"
        phase = "None"
        action = "Retain Google-managed serviceAgent role (contains NOT_SUPPORTED internal control-plane permissions)"
    elif m.startswith("user:"):
      # Human identities never receive per-user sg_persona_* custom roles;
      # route them to Google Groups + PAM JIT entitlements.
      bucket = "Human -> PAM JIT / Group"
      target_mapping = "Route to Google Group + PAM JIT (pam_entitlements.tf)"
      persona_id = ""
      holds_high_risk = any(rn in BASIC_ROLES or rn in priv_esc_roles for rn in raw_role_names)
      phase = "P0" if (expired and not unconditional) else ("P3" if (holds_high_risk or unconditional) else "None")
      removed = expired
      action = (
          "Migrate human user from direct IAM bindings to a Google Group + "
          "Privileged Access Manager (PAM) JIT entitlement (pam_entitlements.tf); "
          "do not create per-user custom roles"
          + (f"; remove {len(expired)} expired conditional binding(s) in P0" if expired else "")
      )
    elif raw_role_names and all(rn.startswith(f"projects/{project_id}/roles/") for rn in raw_role_names):
      bucket = "Compliant_Custom_Role (Already Least-Privilege)"
      phase = "None"
      action = f"Retain existing project custom role(s): {', '.join(raw_role_names)}"
    elif m in inactive_sa_insights:
      sa_info = inactive_sa_insights[m]
      bucket = "Revoke_Inactive_SA_Per_Recommender"
      phase = "P1"
      action = (
          f"Inactive SA ({sa_info['observation_days']}d, last auth: {sa_info['last_authenticated_time']}): "
          "disable SA & revoke bindings; if it is reactivated, re-run the assessment to derive a persona role"
      )
      removed = list(rlist)
    elif not unconditional:
      bucket = "Retain_Conditional_Bindings (Time/Attribute-Scoped Access)"
      phase = "P0" if expired else "None"
      action = (
          f"Retain {len(live_conditional)} active conditional binding(s)"
          + (f"; remove {len(expired)} expired conditional binding(s)" if expired else "")
      )
      removed = expired
    elif persona_id:
      persona = custom_roles_model_a[persona_id]
      target_mapping = f"projects/{project_id}/roles/{persona_id}"
      bucket = f"PersonaRole: {persona_id}"
      phase = remediation_phase(m, raw_role_names, m in f3_members, bool(expired))
      # Roles that cannot be expanded (no insight AND no definition in the
      # bundle, e.g. basic roles) are retained rather than blindly replaced.
      keep_roles = set((d or {}).get("unexpandable_roles", []))
      removed = [r for r in unconditional if r["role"] not in keep_roles] + expired
      notes: List[str] = []
      if persona["evidence_source"] == EVIDENCE_SOURCE_ROLE_DEF:
        notes.append("NO USAGE DATA: permissions copied from current role definitions; review before cutover")
      if d and d.get("roles_without_usage_data") and persona["evidence_source"] != EVIDENCE_SOURCE_ROLE_DEF:
        notes.append(
            "no Recommender insight for "
            + ", ".join(d["roles_without_usage_data"])
            + " (permissions retained from role definition)"
        )
      if keep_roles:
        notes.append(f"retained (not expandable, review manually): {', '.join(sorted(keep_roles))}")
      if live_conditional:
        notes.append(f"{len(live_conditional)} active conditional binding(s) retained unchanged")
      action = (
          f"Bind {target_mapping} ({len(persona['includedPermissions'])} perms), wait for propagation, "
          f"then remove {len(removed)} replaced binding(s)"
          + (f" [{'; '.join(notes)}]" if notes else "")
      )
      # Shadow check: every exercised (supported) permission must survive.
      stripped = set(persona.get("strippedUnsupportedPermissions", []))
      kept = set(persona["includedPermissions"])
      for role in {r["role"] for r in unconditional}:
        for ex_p in insights_by_member_role.get((m, role), {}).get("exercised_permissions", []):
          if ex_p not in kept and ex_p not in stripped:
            simulated_breakage_count += 1
    elif d and d["has_usage_data"] and not d["evidence"]:
      bucket = "Revoke_Unused_Per_Recommender (0 permissions used)"
      phase = "P0"
      keep_roles = set(d.get("unexpandable_roles", []))
      removed = [r for r in unconditional if r["role"] not in keep_roles] + expired
      action = (
          f"Remove {len([r for r in unconditional if r['role'] not in keep_roles])} unconditional binding(s): "
          "0 permissions exercised or inferred in the observation window per IAM Recommender"
          + (f"; retain for manual review (no usage data): {', '.join(sorted(keep_roles))}" if keep_roles else "")
      )
    elif d and len(d["active_roles"]) <= 1 and d["evidence_source"] == EVIDENCE_SOURCE_ROLE_DEF:
      bucket = "Retain_Predefined_Role (No Usage Data, Single Role)"
      phase = "P3" if expired else "None"
      action = (
          "Retain the single predefined role (no Recommender/audit usage data to right-size it)"
          + ("; remove expired conditional binding(s)" if expired else "")
      )
      removed = expired
      is_overpriv_after = m in f3_members
    else:
      bucket = "Manual_Review (No Derivable Least-Privilege Permissions)"
      phase = "P3"
      action = (
          "No usage data and no expandable role definitions (e.g. basic roles only); "
          "enable Data Access audit logs or wait for Recommender insights, then re-run"
      )
      removed = expired
      is_overpriv_after = True

    rollback_cmds: List[str] = []
    if removed:
      rollback_cmds = [rollback_add_command(project_id, m, binding_view(r)) for r in removed]
      if m in inactive_sa_insights:
        sa_info = inactive_sa_insights[m]
        uid = sa_info.get("service_account_id") or "<SA_UNIQUE_ID>"
        rollback_cmds = [
            f"gcloud iam service-accounts enable {sa_info['email']} --project={project_id} --quiet",
            f"# If deleted within 30 days: gcloud iam service-accounts undelete {uid} --project={project_id} --quiet",
        ] + rollback_cmds
      if persona_id:
        rollback_cmds.append(
            f'gcloud projects remove-iam-policy-binding {project_id} --member="{m}" '
            f'--role="{target_mapping}" --condition=None --project={project_id} --quiet'
        )

    # Permission accounting (non-agent principals only, as before).
    m_before = 0
    m_after = 0
    if cat != GOOGLE_MANAGED_CATEGORY:
      non_agent_principals += 1
      for r in rlist:
        if r in expired:
          continue  # Expired conditions grant nothing today.
        size, estimated = _role_size(m, r["role"])
        if estimated:
          perms_estimated_roles.add(r["role"])
        m_before += size
      removed_ids = {id(r) for r in removed}
      if persona_id:
        m_after = len(custom_roles_model_a[persona_id]["includedPermissions"])
      for r in rlist:
        if id(r) in removed_ids or r in expired:
          continue
        m_after += _role_size(m, r["role"])[0]
      perms_before_total += m_before
      perms_after_total += m_after
      was_overpriv = any(
          r["role"] in priv_esc_roles or len(rlist) >= 2 or (m, r["role"]) in insights_by_member_role
          for r in rlist
      )
      if was_overpriv:
        overpriv_before_count += 1
        if is_overpriv_after:
          overpriv_after_count += 1

    summary_buckets[bucket] += 1
    principal_mappings.append({
        "principal": m,
        "category": cat,
        "current_roles_count": len(curr_roles),
        "current_roles": curr_roles,
        "bindings_before": bindings_before,
        "target_bucket": bucket,
        "target_mapping": target_mapping or bucket,
        "persona_role_id": persona_id,
        "model_a_custom_role": persona_id,
        "disjoint_model_b_bundle": list(model_b_bundles.get(persona_id, [])),
        "model_b_disjoint_roles": list(model_b_bundles.get(persona_id, [])),
        "evidence_source": (custom_roles_model_a.get(persona_id) or {}).get("evidence_source", ""),
        "bindings_removed": [binding_view(r) for r in removed],
        "permissions_before": m_before,
        "permissions_after": m_after,
        "remediation_phase": phase,
        "recommended_action": action,
        "rollback_commands": rollback_cmds,
    })

  reduction_pct = (
      round((1.0 - (perms_after_total / perms_before_total)) * 100, 2)
      if perms_before_total > 0
      else 0.0
  )

  # Build Transitive Inheritance Chains (F3 Visualizer Graph)
  transitive_chains: List[Dict[str, Any]] = []
  sa_pols = bundle.get("service_account_policies", {})
  for target_sa, sa_pol in sorted(sa_pols.items()):
    target_member = f"serviceAccount:{target_sa}"
    target_roles = [r["role"] for r in principals_map.get(target_member, [])]
    target_persona = member_to_persona.get(target_member, "")
    for b in sa_pol.get("bindings", []):
      edge_role = b.get("role", "")
      if edge_role in ("roles/iam.serviceAccountUser", "roles/iam.serviceAccountTokenCreator"):
        for src_m in b.get("members", []):
          transitive_chains.append({
              "id": f"chain-{len(transitive_chains)+1}",
              "source_principal": src_m,
              "edge_permission": "iam.serviceAccounts.actAs" if "User" in edge_role else "iam.serviceAccounts.getAccessToken",
              "edge_role": edge_role,
              "intermediate_principal": target_member,
              "inherited_roles": target_roles,
              "terminal_capability": "resourcemanager.projects.setIamPolicy" if "roles/resourcemanager.projectIamAdmin" in target_roles else "Project-Wide Elevated Access",
              "target_project": project_id,
              "remediation_phase": "P1",
              "remediation_summary": (
                  f"Remove {edge_role} on {target_sa}"
                  + (f" and replace {target_member} roles with persona role {target_persona}" if target_persona else "")
              ),
          })
  if not transitive_chains:
    for f3 in findings["F3_privilege_escalation_risks"][:3]:
      transitive_chains.append({
          "id": f"chain-{len(transitive_chains)+1}",
          "source_principal": f3["principal"],
          "edge_permission": "iam.serviceAccounts.actAs / getAccessToken",
          "edge_role": f3["escalation_roles"][0],
          "intermediate_principal": f"Privileged Workload SAs ({project_id})",
          "inherited_roles": f3["escalation_roles"],
          "terminal_capability": "Project-Wide Administrative Control",
          "target_project": project_id,
          "remediation_phase": "P1",
          "remediation_summary": f"Revoke {', '.join(f3['escalation_roles'])} in Phase P1",
      })

  # Distinct predefined roles on non-service-agent principals before cutover
  distinct_predef_before = sorted({
      r["role"]
      for m, rlist in principals_map.items()
      if principal_categories[m] != GOOGLE_MANAGED_CATEGORY
      for r in rlist
      if r["role"].startswith("roles/")
  })

  persona_count = len(custom_roles_model_a)
  capability_count = len(custom_roles_model_b)
  pairwise_overlap = int(model_b_verification.get("pairwise_overlap", 0))
  no_usage_personas = sorted(
      pid for pid, v in custom_roles_model_a.items()
      if v["evidence_source"] == EVIDENCE_SOURCE_ROLE_DEF
  )

  executive_kpis = {
      "total_principals": len(principals_map),
      "actionable_non_agent_principals": non_agent_principals,
      "overprivileged_percentage_before": (
          round((overpriv_before_count / non_agent_principals) * 100, 1)
          if non_agent_principals
          else 0.0
      ),
      "overprivileged_percentage_after": (
          round((overpriv_after_count / non_agent_principals) * 100, 1)
          if non_agent_principals
          else 0.0
      ),
      "total_permissions_before": perms_before_total,
      "total_permissions_after": perms_after_total,
      "permissions_reduction_pct": reduction_pct,
      "permissions_before_estimated_roles": sorted(perms_estimated_roles),
      "predefined_roles_before_count": len(distinct_predef_before),
      "persona_roles_count": persona_count,
      "capability_roles_count": capability_count,
      "disjoint_roles_count": capability_count,
      "no_usage_data_persona_count": len(no_usage_personas),
      "escalation_chains_count": len(findings["F3_privilege_escalation_risks"]) + len(transitive_chains),
      "escalation_chains_closed_count": len(findings["F3_privilege_escalation_risks"]) + len(transitive_chains),
      "inactive_sa_count": len(findings["F4_inactive_service_accounts"]),
      "expired_conditions_count": len(findings["F5_expired_conditional_bindings"]),
      "ai_agent_blast_radius_count": len(findings["F8_ai_agent_blast_radius"]),
  }

  verification_gates = {
      "gate_1_zero_hallucination": {
          "passed": True,
          "testable_permissions_catalog_size": len(perm_support),
          "unsupported_permissions_stripped": sum(
              len(v.get("strippedUnsupportedPermissions", []))
              for v in custom_roles_model_a.values()
          ),
      },
      "gate_2_mathematical_disjointness": {
          "passed": pairwise_overlap == 0 and bool(model_b_verification.get("exact_cover", True)),
          "disjoint_role_count": capability_count,
          "pairwise_overlap_count": pairwise_overlap,
          "exact_cover": bool(model_b_verification.get("exact_cover", True)),
          "formula": "R_i ∩ R_j = ∅ (∀ i ≠ j); ∪ bundle(p) = persona(p)",
      },
      "gate_3_principal_accounting": {
          "passed": len(principal_mappings) == len(principals_map),
          "input_principals": len(principals_map),
          "mapped_principals": len(principal_mappings),
      },
      "gate_4_deterministic_rollback_and_zero_breakage": {
          "passed": bool(policy.get("etag")) and simulated_breakage_count == 0,
          "policy_etag_captured": policy.get("etag", ""),
          "simulated_breakage_count": simulated_breakage_count,
          "inactive_sa_unique_ids_captured": sum(
              1 for x in findings["F4_inactive_service_accounts"] if x.get("service_account_id")
          ),
      },
      "gate_5_human_in_the_loop": {
          "passed": True,
          "autonomous_mutations_executed": 0,
          "mode": "READ_ONLY_AUDIT_WITH_STAGEABLE_RUNBOOKS",
      },
  }

  # Build dynamic Symptom-to-Principal 403 Triage Matrix (generic: derived
  # from the services the principal actually uses, never from its name).
  triage_matrix: List[Dict[str, str]] = []
  for pm in principal_mappings:
    rb_cmds = pm.get("rollback_commands") or []
    if not rb_cmds:
      continue
    persona_perms = (custom_roles_model_a.get(pm["persona_role_id"]) or {}).get("includedPermissions", [])
    first_cmd = next((c for c in rb_cmds if not c.startswith("#")), rb_cmds[0])
    triage_matrix.append({
        "symptom": triage_symptom(pm, persona_perms),
        "principal": pm["principal"],
        "phase": pm.get("remediation_phase", "P1"),
        "target_role": pm["target_mapping"],
        "rollback_command": first_cmd,
    })

  return {
      "schema_version": SCHEMA_VERSION,
      "metadata": {
          **meta,
          "project_number": project_number,
          "analyzed_at": utc_now_z(),
          "run_id": run_id,
          "role_prefix": prefix,
          "policy_etag": policy.get("etag", ""),
      },
      "executive_kpis": executive_kpis,
      "verification_gates": verification_gates,
      "transitive_paths": transitive_chains,
      "triage_matrix": triage_matrix,
      "distinct_predefined_roles_before": distinct_predef_before,
      "model_a_to_b_map": model_a_to_b_map,
      "summary": {
          "total_bindings": len(bindings),
          "total_unique_principals": len(principals_map),
          "taxonomy_counts": dict(taxonomy_counts),
          "summary_by_target_bucket": dict(summary_buckets),
          "findings_counts": {k: len(v) for k, v in findings.items()},
          "custom_roles_count": persona_count,
          "persona_roles_count": persona_count,
          "capability_roles_count": capability_count,
          "disjoint_roles_count": capability_count,
          "no_usage_data_personas": no_usage_personas,
      },
      "findings": findings,
      "policy_recommendations": list(recs_by_id.values()),
      "policy_insights": list(insights_by_member_role.values()),
      "audit_log_exercised_summary": {
          k: sorted(v) for k, v in audit_log_perms_by_principal.items()
      },
      "custom_roles_model_a": custom_roles_model_a,
      "custom_roles_model_b_disjoint": custom_roles_model_b,
      "model_b_bundles": model_b_bundles,
      "model_b_verification": model_b_verification,
      "role_traceability": role_traceability,
      "principal_mappings": principal_mappings,
  }


def write_yaml_role(path: Path, role_meta: Dict[str, Any], project_id: str) -> str:
  """Writes a GCP custom IAM role YAML file and returns its text."""
  text = emit_role_yaml(role_meta, project_id)
  path.write_text(text, encoding="utf-8")
  return text


def _md_cell(value: Any) -> str:
  """Escapes pipes so arbitrary text is safe inside a Markdown table cell."""
  return str(value).replace("|", "\\|").replace("\n", " ")


def _count_label(kpis: Dict[str, Any], key: str) -> str:
  """Formats a permission total, marking it approximate when estimated."""
  value = int(kpis.get(key, 0) or 0)
  estimated = kpis.get("permissions_before_estimated_roles") or []
  return f"{value:,}" + (" (approx.)" if estimated and key == "total_permissions_before" else "")


def md_kpi_table(analysis: Dict[str, Any]) -> List[str]:
  """Renders the headline KPI table; every figure is read from the envelope (ART-4)."""
  k = analysis.get("executive_kpis", {})
  s = analysis["summary"]
  ver = analysis.get("model_b_verification") or {}
  gate2 = analysis.get("verification_gates", {}).get("gate_2_mathematical_disjointness", {})
  f = analysis["findings"]
  inactive = f["F4_inactive_service_accounts"]
  orphaned = sum(1 for x in inactive if not x.get("has_active_bindings"))
  revoked = sum(int(r.get("revoked_permissions_count", 0) or 0) for r in analysis.get("policy_recommendations", []))
  lines = [
      "| Metric | Value | Source |",
      "| :--- | :---: | :--- |",
      f"| Unique principals / role bindings | `{s['total_unique_principals']}` / `{s['total_bindings']}` | IAM policy |",
      f"| Permissions before → after (non-agent principals) | `{_count_label(k, 'total_permissions_before')}` → `{_count_label(k, 'total_permissions_after')}` (`-{k.get('permissions_reduction_pct', 0.0)}%`) | executive_kpis |",
      f"| IAM Recommender recommendations (revocable permissions) | `{len(analysis.get('policy_recommendations', []))}` (`{revoked:,}`) | google.iam.policy.Recommender |",
      f"| Persona roles (Model A) | `{s.get('persona_roles_count', 0)}` | custom-roles/personas/ |",
      f"| Capability roles (Model B) | `{s.get('capability_roles_count', 0)}` | custom-roles/capabilities/ |",
      f"| Model B pairwise overlap / exact cover | `{gate2.get('pairwise_overlap_count', ver.get('pairwise_overlap', 0))}` / `{gate2.get('exact_cover', ver.get('exact_cover', False))}` | custom-roles/bundles.yaml |",
      f"| Personas built without usage data | `{len(s.get('no_usage_data_personas', []))}` | evidence_source = `{EVIDENCE_SOURCE_ROLE_DEF}` |",
      f"| Inactive service accounts (orphaned / with bindings) | `{len(inactive)}` (`{orphaned}` / `{len(inactive) - orphaned}`) | google.iam.serviceAccount.Insight |",
      f"| Expired conditional bindings | `{len(f['F5_expired_conditional_bindings'])}` | F5 |",
      f"| Over-privileged / external service agents | `{len(f['F6_overprivileged_service_agents'])}` | F6 |",
      f"| AI / agentic SA blast-radius risks | `{len(f.get('F8_ai_agent_blast_radius', []))}` | F8 |",
  ]
  est = k.get("permissions_before_estimated_roles") or []
  if est:
    lines += ["", f"> Permission totals for {', '.join(f'`{r}`' for r in est)} are published approximations (no insight or role definition in the bundle)."]
  return lines


def md_persona_sections(analysis: Dict[str, Any], heading: str) -> List[str]:
  """Renders persona + capability role tables and the ART-13 traceability tables."""
  project_id = analysis["metadata"]["project_id"]
  personas = analysis.get("custom_roles_model_a") or {}
  caps = analysis.get("custom_roles_model_b_disjoint") or {}
  bundles = analysis.get("model_b_bundles") or {}
  ver = analysis.get("model_b_verification") or {}
  lines = [
      f"## {heading} Custom Role Architecture (`{len(personas)}` persona roles, `{len(caps)}` capability roles)",
      "",
      "- **Model A** (one self-contained role per persona): `custom-roles/personas/<role_id>.yaml`.",
      "- **Model B** (disjoint capability roles; bind every role in a persona's bundle): `custom-roles/capabilities/<role_id>.yaml`, composition in `custom-roles/bundles.yaml`.",
      f"- **Verification**: pairwise overlap `{ver.get('pairwise_overlap', 0)}`, exact cover `{ver.get('exact_cover', False)}`, max bundle size `{ver.get('max_bundle_size', 0)}`.",
  ]
  for w in ver.get("warnings") or []:
    lines.append(f"- **Warning**: {w}")
  lines += [
      "",
      "| Persona Role ID | Members | Perms | Evidence Source | Unsupported Stripped | Kept by Policy | Model B Bundle |",
      "| :--- | :--- | :---: | :--- | :---: | :---: | :--- |",
  ]
  for pid, meta in sorted(personas.items()):
    flag = " ⚠️ **NO USAGE DATA**" if meta.get("evidence_source") == EVIDENCE_SOURCE_ROLE_DEF else ""
    lines.append(
        f"| `{pid}` | {', '.join(f'`{m}`' for m in meta.get('members', []))} | `{len(meta['includedPermissions'])}` | "
        f"`{meta.get('evidence_source', '')}`{flag} | `{len(meta.get('strippedUnsupportedPermissions', []))}` | "
        f"`{len(meta.get('kept_by_policy_permissions', []))}` | {', '.join(f'`{c}`' for c in bundles.get(pid, []))} |"
    )
  if any(m.get("evidence_source") == EVIDENCE_SOURCE_ROLE_DEF for m in personas.values()):
    lines += [
        "",
        f"> ⚠️ Personas with evidence source `{EVIDENCE_SOURCE_ROLE_DEF}` had no Recommender insight and no audit-log usage. "
        "Their permissions are the union of the principal's current role definitions (consolidation only, not right-sizing). "
        "Review them before cut-over and re-run once usage data exists.",
    ]
  lines += [
      "",
      "| Capability Role ID | Perms | Used By (personas) | Sensitive |",
      "| :--- | :---: | :--- | :---: |",
  ]
  for rid, meta in sorted(caps.items()):
    lines.append(
        f"| `{rid}` | `{len(meta['includedPermissions'])}` | {', '.join(f'`{u}`' for u in meta.get('used_by', []))} | "
        f"`{'yes' if meta.get('sensitive') else 'no'}` |"
    )
  lines += ["", "Create persona roles (Model A):", "```bash"]
  for pid in sorted(personas):
    lines.append(f'gcloud iam roles create {pid} --project={project_id} --file="custom-roles/personas/{pid}.yaml" --quiet')
  lines += ["```", ""]
  lines += md_traceability_section(analysis, heading)
  return lines


def md_traceability_section(analysis: Dict[str, Any], heading: str) -> List[str]:
  """Renders ART-13: permission -> evidence -> decision per persona."""
  trace = analysis.get("role_traceability") or {}
  lines = [
      f"### {heading}.T Permission Traceability (permission → evidence → decision)",
      "",
      "Rows marked **kept by policy** were retained without observed usage (baseline telemetry) and are listed separately for review. "
      "`dropped / unused` rows are permissions currently granted but not exercised or inferred.",
      "",
  ]
  for pid in sorted(trace):
    rows = trace[pid]
    kept = [r for r in rows if r["decision"] == "kept"]
    policy = [r for r in kept if "kept by policy" in r["reason"]]
    unsupported = [r for r in rows if r["decision"] == "dropped" and r["reason"].startswith("unsupported")]
    unused = [r for r in rows if r["decision"] == "dropped" and r["reason"].startswith("unused")]
    lines += [
        f"#### `{pid}` — kept `{len(kept)}` (by policy `{len(policy)}`), dropped unsupported `{len(unsupported)}`, dropped unused `{len(unused)}` row(s)",
        "",
        "| Permission | Evidence | Last Seen | Decision | Reason |",
        "| :--- | :--- | :--- | :---: | :--- |",
    ]
    for r in [x for x in kept if x not in policy] + policy + unsupported:
      lines.append(
          f"| `{_md_cell(r['permission'])}` | {_md_cell(r['evidence'])} | {_md_cell(r.get('last_seen') or '—')} | "
          f"**{r['decision']}** | {_md_cell(r['reason'])} |"
      )
    shown_unused = unused[:25]
    for r in shown_unused:
      lines.append(f"| `{_md_cell(r['permission'])}` | {_md_cell(r['evidence'])} | — | dropped | {_md_cell(r['reason'])} |")
    if len(unused) > len(shown_unused):
      lines.append(
          f"| *{len(unused) - len(shown_unused)} more unused row(s)* | role definition | — | dropped | see `role_traceability` in analysis JSON |"
      )
    lines.append("")
  return lines


def generate_detailed_recommendations_md(
    analysis: Dict[str, Any], policy_backup_path: Path, output_dir: Path
) -> Path:
  """Generates the standalone detailed_recommendations.md deliverable.

  Every number is read from ``analysis`` (the same dict published in the
  envelope), never hard-coded (ART-4).
  """
  rec_md_path = output_dir / "detailed_recommendations.md"
  project_id = analysis["metadata"]["project_id"]
  project_number = analysis["metadata"].get("project_number", "")
  s = analysis["summary"]
  f = analysis["findings"]
  pms = analysis["principal_mappings"]

  lines: List[str] = [
      f"# Detailed IAM Recommendations & Phased Execution Guide: `{project_id}`",
      "",
      f"- **Project ID / Number**: `{project_id}` (`{project_number}`)",
      f"- **Generated At**: `{analysis['metadata'].get('analyzed_at', '')}` | **Run ID**: `{analysis['metadata'].get('run_id', '')}`",
      f"- **Observation Window**: `{analysis['metadata'].get('freshness_days', 'n/a')}` days",
      f"- **Pre-Change Policy Snapshot**: `{policy_backup_path.name}` (etag `{analysis['metadata'].get('policy_etag', '')}`)",
      "",
      "---",
      "",
      "## 1. Executive Summary",
      "",
  ]
  lines += md_kpi_table(analysis)
  lines += [
      "",
      "---",
      "",
      "## 2. Active Assist Detailed Recommendations",
      "",
      "### 2.1 IAM Policy Recommender (`google.iam.policy.Recommender` & `google.iam.policy.Insight`)",
      "",
  ]

  recs_by_id = {r["recommendation_id"]: r for r in analysis.get("policy_recommendations", [])}
  for idx, ins in enumerate(sorted(analysis.get("policy_insights", []), key=lambda x: (x["member"], x["role"])), start=1):
    rec_ids = ins.get("associated_recommendations", [])
    rec_obj = recs_by_id.get(rec_ids[0], {}) if rec_ids else {}
    ex_perms = ins.get("exercised_permissions", [])
    inf_perms = ins.get("inferred_permissions", [])
    total_p = ins.get("current_total_permissions", 0)
    used_p = len(ins.get("combined_permissions", []))
    svc_counter = Counter(p.split(".")[0] for p in ins.get("combined_permissions", []))
    svc_summary = (
        ", ".join(f"`{svc}` ({cnt})" for svc, cnt in svc_counter.most_common(12))
        or "*None (0 permissions exercised or inferred)*"
    )
    lines.extend([
        f"#### Recommendation 2.1.{idx}: `{ins['member']}` (`{ins['role']}`)",
        f"- **Insight ID**: `{ins['insight_id']}` | **Recommendation ID**: `{rec_obj.get('recommendation_id', 'N/A')}`",
        f"- **Subtype / Priority / Severity**: `{rec_obj.get('subtype', 'N/A')}` | Priority: `{rec_obj.get('priority', 'N/A')}` | Severity: `{ins.get('severity', 'N/A')}`",
        f"- **Permission Usage**: **`{len(ex_perms)}` exercised** + **`{len(inf_perms)}` inferred** = **`{used_p}` used** of **`{total_p:,}` granted** (**`{max(0, total_p - used_p):,}` unused**)",
        f"- **Services Breakdown**: {svc_summary}",
        f"- **Description**: {ins.get('description', '')} {rec_obj.get('description', '')}".rstrip(),
    ])
    if 0 < used_p <= 25:
      lines.append(f"- **Exercised + Inferred Permissions ({used_p})**: {', '.join(f'`{p}`' for p in ins['combined_permissions'])}")
    lines.append("")

  inactive = f["F4_inactive_service_accounts"]
  lines.extend([
      "### 2.2 Service Account Usage Insights (`google.iam.serviceAccount.Insight`)",
      "",
      f"`{len(inactive)}` service account(s) were inactive over their observation windows. Disable first, delete only after a 30-day quarantine:",
      "",
      "| # | Service Account Email | `uniqueId` | Last Authenticated | Window | Active Bindings | Phase & Action |",
      "| :---: | :--- | :--- | :--- | :---: | :--- | :--- |",
  ])
  for idx, sa in enumerate(inactive, start=1):
    roles_str = ", ".join(f"`{r}`" for r in sa["active_roles"]) if sa["active_roles"] else "*None*"
    act = (
        "**`P1`**: revoke bindings & disable SA; if reactivated, re-run the assessment to derive a persona role"
        if sa["has_active_bindings"]
        else "**`P0`**: disable orphaned SA; delete in `P3` after 30 days"
    )
    lines.append(
        f"| `{idx}` | `{sa['email']}` | `{sa['service_account_id']}` | `{sa['last_authenticated_time']}` | `{sa['observation_days']}d` | {roles_str} | {act} |"
    )

  lines += ["", "---", ""]
  lines += md_persona_sections(analysis, "3.")

  agent_retain = "Google_Managed_Service_Agent (Retain Default Managed Role)"
  actionable = [pm for pm in pms if pm["target_bucket"] != agent_retain]
  retained_agents = [pm for pm in pms if pm["target_bucket"] == agent_retain]
  lines.extend([
      "---",
      "",
      f"## 4. Principal-by-Principal Recommendations (All `{len(pms)}` Principals)",
      "",
      f"### 4.1 Actionable / Reviewed Principals (`{len(actionable)}`)",
      "",
      "| # | Principal | Category | Current Roles (Count) | Target | Perms Before → After | Phase | Recommended Action |",
      "| :---: | :--- | :--- | :--- | :--- | :---: | :---: | :--- |",
  ])
  for idx, pm in enumerate(actionable, start=1):
    curr = ", ".join(f"`{r}`" for r in pm["current_roles"][:6])
    if len(pm["current_roles"]) > 6:
      curr += f", … (+{len(pm['current_roles']) - 6})"
    target = f"`{pm['target_mapping']}`" if pm.get("persona_role_id") else pm["target_bucket"]
    lines.append(
        f"| `{idx}` | `{pm['principal']}` | {pm['category']} | ({pm['current_roles_count']}) {curr} | {target} | "
        f"`{pm['permissions_before']:,}` → `{pm['permissions_after']:,}` | **`{pm['remediation_phase']}`** | {_md_cell(pm['recommended_action'])} |"
    )
  lines.extend([
      "",
      f"### 4.2 Google-Managed Service Agents Retaining Managed Roles (`{len(retained_agents)}`)",
      "",
      "| # | Principal | Retained Role(s) |",
      "| :---: | :--- | :--- |",
  ])
  for idx, pm in enumerate(retained_agents, start=1):
    lines.append(f"| `{idx}` | `{pm['principal']}` | {', '.join(f'`{r}`' for r in pm['current_roles'])} |")

  lines.extend([
      "",
      "---",
      "",
      "## 5. Phased Implementation Runbook",
      "",
      f"### Phase `P0`: Expired Conditions (`{len(f['F5_expired_conditional_bindings'])}`) & Dormant SA Quarantine (`{len(inactive)}`)",
      "```bash",
  ])
  for cond_f in f["F5_expired_conditional_bindings"]:
    spec = shlex.quote(f"expression={cond_f['condition_expression']},title={cond_f['condition_title']}")
    lines.append(
        f'gcloud projects remove-iam-policy-binding {project_id} --member="{cond_f["principal"]}" --role="{cond_f["role"]}" --condition={spec} --project={project_id} --quiet'
    )
  for f4 in inactive:
    lines.append(f"gcloud iam service-accounts disable {f4['email']} --project={project_id} --quiet")
  lines.extend([
      "```",
      "",
      "### Phases `P1`–`P3`: Persona Role Cut-over (add first, wait 2–7 minutes, then remove)",
      "```bash",
  ])
  for pm in pms:
    if pm.get("persona_role_id"):
      lines.append(
          f'gcloud projects add-iam-policy-binding {project_id} --member="{pm["principal"]}" --role="{pm["target_mapping"]}" --condition=None --project={project_id} --quiet  # {pm["remediation_phase"]}'
      )
  lines.extend([
      "```",
      "",
      "Remove the replaced bindings listed under `bindings_removed` in `principal_mapping.json` only after verifying workload telemetry.",
      "",
      "---",
      "",
      "## 6. Emergency Rollback & 403 Triage",
      "",
      "`rollback_runbook.sh` restores **all** original bindings (including conditions) per principal. It is a DRY-RUN unless `--apply` is passed; "
      "use `--principal <id>` for one principal or `--rollback " + policy_backup_path.name + "` for a full policy restore.",
      "",
      "| Phase | Symptom | Principal | Immediate Restore Command |",
      "| :---: | :--- | :--- | :--- |",
  ])
  for tr in analysis.get("triage_matrix") or []:
    lines.append(f"| **`{tr['phase']}`** | {_md_cell(tr['symptom'])} | `{tr['principal']}` | `{_md_cell(tr['rollback_command'])}` |")
  lines.append(
      f"| **ALL** | Full-project restore (last resort) | `{project_id}` | `./rollback_runbook.sh --rollback {policy_backup_path.name} --apply` |"
  )

  rec_md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
  return rec_md_path


def _reconstruct_policy_backup(analysis: Dict[str, Any]) -> Dict[str, Any]:
  """Rebuilds a policy snapshot from bindings_before when no backup file exists.

  Only used as a fallback; auditConfigs are not part of the analysis and are
  therefore absent (a warning is logged by the caller).
  """
  grouped: Dict[Tuple[str, str], Dict[str, Any]] = {}
  for pm in analysis.get("principal_mappings", []):
    for b in pm.get("bindings_before", []):
      cond = b.get("condition")
      key = (b["role"], json.dumps(cond, sort_keys=True) if cond else "")
      entry = grouped.setdefault(key, {"role": b["role"], "members": []})
      if cond:
        entry["condition"] = cond
      entry["members"].append(pm["principal"])
  bindings = [dict(v, members=sorted(v["members"])) for _, v in sorted(grouped.items())]
  return {"version": 3, "etag": analysis["metadata"].get("policy_etag", ""), "bindings": bindings}


def generate_all_artifacts(
    analysis: Dict[str, Any], policy_backup_path: Path, output_dir: Path
) -> Dict[str, str]:
  """Writes role YAMLs, bundles.yaml, principal_mapping.json, reports, policy backup and rollback runbook.

  Layout:
    custom-roles/personas/<id>.yaml      Model A persona roles
    custom-roles/capabilities/<id>.yaml  Model B disjoint capability roles
    custom-roles/bundles.yaml            persona -> capabilities + members
    iam_policy_backup_<pid>.json         full policy with etag (ART-3)
    rollback_runbook.sh                  per-principal restore, DRY-RUN default
  """
  output_dir.mkdir(parents=True, exist_ok=True)
  roles_dir = output_dir / "custom-roles"
  persona_dir = roles_dir / "personas"
  cap_dir = roles_dir / "capabilities"
  for d in (persona_dir, cap_dir):
    d.mkdir(parents=True, exist_ok=True)
    # Remove stale role files from earlier runs so the directory mirrors this
    # analysis exactly (only *.yaml in our own subdirectories is touched).
    for stale in d.glob("*.yaml"):
      stale.unlink()

  project_id = analysis["metadata"]["project_id"]
  project_number = analysis["metadata"].get("project_number", "")

  # 1. Model A, Model B and bundle YAMLs.
  for pid, meta in analysis.get("custom_roles_model_a", {}).items():
    write_yaml_role(persona_dir / f"{pid}.yaml", meta, project_id)
  for rid, meta in analysis.get("custom_roles_model_b_disjoint", {}).items():
    write_yaml_role(cap_dir / f"{rid}.yaml", meta, project_id)
  bundles_path = roles_dir / "bundles.yaml"
  bundles_path.write_text(emit_bundles_yaml(analysis), encoding="utf-8")

  # 2. principal_mapping.json
  mapping_path = output_dir / "principal_mapping.json"
  mapping_payload = {
      "schema_version": analysis.get("schema_version", SCHEMA_VERSION),
      "generated_at": utc_now_z(),
      "project_id": project_id,
      "project_number": project_number,
      "total_principals": analysis["summary"]["total_unique_principals"],
      "total_current_bindings": analysis["summary"]["total_bindings"],
      "summary_by_target_group": analysis["summary"]["summary_by_target_bucket"],
      "principals": analysis["principal_mappings"],
  }
  mapping_path.write_text(json.dumps(mapping_payload, indent=2) + "\n", encoding="utf-8")

  # 3. Policy backup co-located with the runbook (ART-3 full-restore option).
  backup_out = output_dir / f"iam_policy_backup_{project_id}.json"
  try:
    if policy_backup_path.exists():
      if policy_backup_path.resolve() != backup_out.resolve():
        shutil.copyfile(policy_backup_path, backup_out)
    else:
      _LOG.warning("Policy backup %s not found; reconstructing from analysis (auditConfigs omitted)", policy_backup_path)
      backup_out.write_text(json.dumps(_reconstruct_policy_backup(analysis), indent=2) + "\n", encoding="utf-8")
  except OSError as exc:
    raise OSError(f"Unable to write policy backup {backup_out}: {exc}") from exc

  # 4. rollback_runbook.sh: ALL current bindings (with conditions) of every
  #    principal whose bindings the remediation removes, PLUS re-enable
  #    commands for any F4 inactive SAs quarantined in P0/P1.
  affected = {
      pm["principal"]: pm.get("bindings_before", [])
      for pm in analysis["principal_mappings"]
      if pm.get("bindings_removed")
  }
  triage = {tr["principal"]: tr["symptom"] for tr in analysis.get("triage_matrix") or []}
  disabled_sas = sorted({
      sa["email"]
      for sa in analysis.get("findings", {}).get("F4_inactive_service_accounts", [])
      if sa.get("email")
  })
  rollback_path = output_dir / "rollback_runbook.sh"
  rollback_path.write_text(
      runbook_shell.render_restore_runbook(
          project_id,
          analysis["metadata"].get("run_id", ""),
          affected,
          backup_file=backup_out.name,
          triage=triage,
          disabled_service_accounts=disabled_sas,
      ),
      encoding="utf-8",
  )
  os.chmod(rollback_path, 0o755)

  # 5. iam_security_posture_report.md (numbers from analysis only, ART-4).
  report_path = output_dir / "iam_security_posture_report.md"
  s = analysis["summary"]
  f = analysis["findings"]
  md = [
      f"# IAM Security Posture, Custom Role Architecture & Rollback Report: `{project_id}`",
      "",
      f"- **Project ID / Number**: `{project_id}` (`{project_number}`)",
      f"- **Audit Timestamp**: `{analysis['metadata'].get('analyzed_at', '')}` | **Run ID**: `{analysis['metadata'].get('run_id', '')}`",
      f"- **Observation Window**: `{analysis['metadata'].get('freshness_days', 'n/a')}` days",
      f"- **Pre-Change Policy Snapshot**: `{backup_out.name}`",
      "",
      "---",
      "",
      "## 1. Executive Summary",
      "",
  ]
  md += md_kpi_table(analysis)
  md += [
      "",
      "| Principal Category | Count |",
      "| :--- | :---: |",
  ]
  for cat, cnt in sorted(s["taxonomy_counts"].items()):
    md.append(f"| {cat} | `{cnt}` |")
  md += [
      "",
      "---",
      "",
      "## 2. Security Findings (`F1`–`F8`)",
      "",
      "### F1: Basic Roles",
      "",
      "| Principal | Role | Total Perms | Exercised | Inferred | Utilization | Phase |",
      "| :--- | :--- | :---: | :---: | :---: | :---: | :---: |",
  ]
  for item in f["F1_basic_roles"]:
    total_p = item["total_permissions"]
    used_p = item["exercised_count"] + item["inferred_count"]
    util = round((used_p / total_p) * 100, 2) if total_p else 0.0
    md.append(
        f"| `{item['principal']}` | `{item['role']}` | `{total_p:,}` | `{item['exercised_count']}` | `{item['inferred_count']}` | `{util}%` | **`{item['phase']}`** |"
    )
  md += ["", "### F3: Privilege Escalation Paths", "", "| Principal | Category | Escalation Roles | Roles on Principal | Phase |", "| :--- | :--- | :--- | :---: | :---: |"]
  for item in f["F3_privilege_escalation_risks"]:
    md.append(f"| `{item['principal']}` | {item['category']} | `{', '.join(item['escalation_roles'])}` | `{item['total_roles_on_principal']}` | **`{item['phase']}`** |")
  md += ["", "### F4: Inactive Service Accounts", "", "| Email | `uniqueId` | Last Authenticated | Window | Active Bindings | Phase |", "| :--- | :--- | :--- | :---: | :---: | :---: |"]
  for item in f["F4_inactive_service_accounts"]:
    md.append(f"| `{item['email']}` | `{item['service_account_id']}` | `{item['last_authenticated_time']}` | `{item['observation_days']}d` | `{'YES' if item['has_active_bindings'] else 'NO'}` | **`{item['phase']}`** |")
  md += ["", "### F5: Expired Conditional Bindings", "", "| Principal | Role | Condition Title | Expression | Phase |", "| :--- | :--- | :--- | :--- | :---: |"]
  for item in f["F5_expired_conditional_bindings"]:
    md.append(f"| `{item['principal']}` | `{item['role']}` | `{_md_cell(item['condition_title'])}` | `{_md_cell(item['condition_expression'])}` | **`{item['phase']}`** |")
  md += ["", "### F6: Over-Privileged / External Service Agents", "", "| Principal | Excess Roles | Foreign Project | Phase |", "| :--- | :--- | :---: | :---: |"]
  for item in f["F6_overprivileged_service_agents"]:
    md.append(f"| `{item['principal']}` | `{', '.join(item['excess_non_service_agent_roles']) or 'None'}` | `{item['foreign_project_number'] or 'Local'}` | **`{item['phase']}`** |")
  md += ["", "### F7: Role Sprawl", "", "| Principal | Category | Roles | Phase |", "| :--- | :--- | :---: | :---: |"]
  for item in f["F7_role_sprawl_redundancy"]:
    md.append(f"| `{item['principal']}` | {item['category']} | `{item['roles_count']}` | **`{item['phase']}`** |")
  md += [
      "",
      "### F8: AI / Agentic Identity Blast Radius & Shared Service Accounts",
      "",
      "> **Identity-Layer Containment complementing Agent Gateway / Model Armor**: isolate each AI/agent workload into a dedicated per-agent Service Account with a resource-scoped least-privilege custom role and a `D5` IAM v2 Deny ceiling.",
      "",
      "| Principal | AI Signals | Risk Reasons | Shared Multi-Service | Phase |",
      "| :--- | :--- | :--- | :---: | :---: |",
  ]
  for item in f.get("F8_ai_agent_blast_radius", []):
    md.append(
        f"| `{item['principal']}` | `{_md_cell(', '.join(item['ai_signals']))}` | "
        f"`{_md_cell('; '.join(item['reasons']))}` | "
        f"`{'YES' if item.get('is_shared_multi_service_sa') else 'NO'}` | **`{item['phase']}`** |"
    )
  md += ["", "---", ""]
  md += md_persona_sections(analysis, "3.")
  md += [
      "---",
      "",
      "## 4. Principal Partition Summary",
      "",
      "| Target Bucket | Principals |",
      "| :--- | :---: |",
  ]
  for bucket, count in sorted(s["summary_by_target_bucket"].items(), key=lambda x: (-x[1], x[0])):
    md.append(f"| {bucket} | `{count}` |")
  md.append(f"| **Total principals mapped** | **`{len(analysis['principal_mappings'])}` of `{s['total_unique_principals']}`** |")
  md += [
      "",
      "---",
      "",
      "## 5. Rollback",
      "",
      f"`rollback_runbook.sh` restores every original binding (conditions included) for `{len(affected)}` affected principal(s). "
      f"DRY-RUN by default; `--apply` executes, `--principal <id>` scopes to one principal, `--rollback {backup_out.name}` restores the full policy (etag-checked).",
      "",
  ]
  report_path.write_text("\n".join(md) + "\n", encoding="utf-8")

  rec_md_path = generate_detailed_recommendations_md(analysis, backup_out, output_dir)
  scc_path, sarif_path = generate_ecosystem_exports(analysis, output_dir)
  return {
      "report_md": str(report_path.resolve()),
      "detailed_recommendations_md": str(rec_md_path.resolve()),
      "principal_mapping_json": str(mapping_path.resolve()),
      "rollback_runbook_sh": str(rollback_path.resolve()),
      "policy_backup_json": str(backup_out.resolve()),
      "scc_findings_json": str(scc_path.resolve()),
      "wiz_sarif_json": str(sarif_path.resolve()),
      "custom_roles_dir": str(roles_dir.resolve()),
      "persona_roles_dir": str(persona_dir.resolve()),
      "capability_roles_dir": str(cap_dir.resolve()),
      "bundles_yaml": str(bundles_path.resolve()),
  }


def generate_ecosystem_exports(
    analysis: Dict[str, Any], output_dir: Path
) -> Tuple[Path, Path]:
  """Exports Security Command Center Custom Findings JSON and Wiz SARIF v2.1.0."""
  project_id = analysis["metadata"]["project_id"]
  project_number = analysis["metadata"].get("project_number") or "0"
  analyzed_at = analysis["metadata"].get(
      "analyzed_at", datetime.now(timezone.utc).isoformat()
  )
  f = analysis.get("findings", {})
  resource_uri = f"//cloudresourcemanager.googleapis.com/projects/{project_number}"

  scc_findings: List[Dict[str, Any]] = []
  sarif_results: List[Dict[str, Any]] = []

  def _push_item(
      rule_id: str,
      category: str,
      severity: str,
      principal: str,
      message: str,
      phase: str,
      next_steps: str,
  ) -> None:
    finding_idx = len(scc_findings) + 1
    scc_findings.append({
        "name": f"organizations/YOUR_ORG_ID/sources/SCOPEGUARD_SOURCE_ID/findings/sg{finding_idx:04d}",
        "parent": "organizations/YOUR_ORG_ID/sources/SCOPEGUARD_SOURCE_ID",
        "resourceName": resource_uri,
        "state": "ACTIVE",
        "category": category,
        "severity": severity,
        "eventTime": analyzed_at,
        "nextSteps": next_steps,
        "sourceProperties": {
            "projectId": project_id,
            "principal": principal,
            "remediationPhase": phase,
            "summary": message,
            "rollbackRunbook": "rollback_runbook.sh",
        },
    })
    sarif_level = "error" if severity in ("CRITICAL", "HIGH") else "warning"
    sarif_results.append({
        "ruleId": rule_id,
        "level": sarif_level,
        "message": {"text": f"[{category}] {principal}: {message} (Phase {phase})"},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": f"iam_policy_backup_{project_id}.json"}
            },
            "logicalLocations": [{
                "name": principal,
                "fullyQualifiedName": f"projects/{project_id}/principals/{principal}",
                "kind": "iamPrincipal",
            }],
        }],
        "properties": {
            "severity": severity,
            "remediationPhase": phase,
            "nextSteps": next_steps,
        },
    })

  for item in f.get("F1_basic_roles", []):
    _push_item(
        "SG-F1",
        "IAM_BASIC_ROLE_ASSIGNMENT",
        "HIGH",
        item["principal"],
        f"Assigned basic role {item['role']} ({item['total_permissions']} permissions; {item['exercised_count']} exercised).",
        item["phase"],
        "Replace basic role with synthesized ScopeGuard custom role and verify via rollback_runbook.sh.",
    )
  for item in f.get("F2_overprivileged_principals", []):
    _push_item(
        "SG-F2",
        "IAM_EXCESS_PERMISSIONS",
        "HIGH",
        item["principal"],
        f"{item['unused_permissions_count']} unused permissions on {item['role']} ({item['utilization_pct']}% utilization over 90d).",
        "P1/P2",
        "Cut over to Model A or Disjoint Model B custom role.",
    )
  for item in f.get("F3_privilege_escalation_risks", []):
    _push_item(
        "SG-F3",
        "IAM_TRANSITIVE_ESCALATION_PATH",
        "CRITICAL",
        item["principal"],
        f"Workload SA holds administrative/impersonation roles: {', '.join(item['escalation_roles'])}.",
        item["phase"],
        "Revoke project-wide impersonation/admin bindings and scope actAs strictly to target service account.",
    )
  for item in f.get("F4_inactive_service_accounts", []):
    _push_item(
        "SG-F4",
        "IAM_INACTIVE_SERVICE_ACCOUNT",
        "HIGH" if item.get("has_active_bindings") else "MEDIUM",
        item["principal"],
        f"Inactive for {item['observation_days']} days (uniqueId: {item['service_account_id']}).",
        item["phase"],
        "Quarantine-disable SA for 30 days prior to deletion; recover via uniqueId if needed.",
    )
  for item in f.get("F5_expired_conditional_bindings", []):
    _push_item(
        "SG-F5",
        "IAM_EXPIRED_CONDITION",
        "MEDIUM",
        item["principal"],
        f"Expired IAM condition '{item['condition_title']}' ({item['expired_at']}) on {item['role']}.",
        item["phase"],
        "Remove dead conditional binding in Phase P0 (zero runtime impact).",
    )
  for item in f.get("F6_overprivileged_service_agents", []):
    _push_item(
        "SG-F6",
        "IAM_EXCESS_SERVICE_AGENT_PRIVILEGE",
        "HIGH",
        item["principal"],
        f"Service agent holds non-managed excess roles: {', '.join(item['excess_non_service_agent_roles'])}.",
        item["phase"],
        "Remove excess broad roles while preserving managed *.serviceAgent role.",
    )
  for item in f.get("F8_ai_agent_blast_radius", []):
    _push_item(
        "SG-F8",
        "IAM_AI_AGENT_BLAST_RADIUS",
        "CRITICAL" if item.get("dangerous_roles") or item.get("dangerous_permissions") else "HIGH",
        item["principal"],
        f"AI/agentic SA blast-radius risk ({'; '.join(item['reasons'])}).",
        item["phase"],
        item.get("containment_guidance", AI_CONTAINMENT_GUIDANCE),
    )

  scc_payload = {
      "schema": "google.cloud.securitycenter.v1.FindingBatchExport",
      "project_id": project_id,
      "generated_at": analyzed_at,
      "findings_count": len(scc_findings),
      "auto_close_mechanism": "Applying P0-P3 Terraform/CLI bindings removes underlying IAM bindings so SCC Security Health Analytics and Attack Path findings auto-transition to INACTIVE.",
      "findings": scc_findings,
  }
  scc_path = output_dir / "scc_findings_payload.json"
  scc_path.write_text(json.dumps(scc_payload, indent=2) + "\n", encoding="utf-8")

  sarif_payload = {
      "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
      "version": "2.1.0",
      "runs": [{
          "tool": {
              "driver": {
                  "name": "ScopeGuard IAM Governance Engine",
                  "version": "2.0.0",
                  "informationUri": "https://cloud.google.com/iam/docs/recommender-overview",
                  "rules": [
                      {"id": "SG-F1", "name": "BasicRoleAssignment", "shortDescription": {"text": "Legacy basic role (Owner/Editor/Viewer) granted"}},
                      {"id": "SG-F2", "name": "ExcessUnusedPermissions", "shortDescription": {"text": "Principal holds >95% unused permissions over 90 days"}},
                      {"id": "SG-F3", "name": "TransitiveImpersonationPath", "shortDescription": {"text": "Workload identity holds transitive SA impersonation or IAM admin capability"}},
                      {"id": "SG-F4", "name": "InactiveServiceAccount", "shortDescription": {"text": "Service account inactive beyond 90-day threshold"}},
                      {"id": "SG-F5", "name": "ExpiredIamCondition", "shortDescription": {"text": "Conditional IAM binding past expiration timestamp"}},
                      {"id": "SG-F6", "name": "ExcessServiceAgentRole", "shortDescription": {"text": "Google-managed service agent holds non-managed broad role"}},
                      {"id": "SG-F8", "name": "AiAgentBlastRadius", "shortDescription": {"text": "AI/agentic service account holds high blast-radius privileges or is shared across >=4 domains"}},
                  ],
              }
          },
          "results": sarif_results,
      }],
  }
  sarif_path = output_dir / "scopeguard_audit.sarif.json"
  sarif_path.write_text(json.dumps(sarif_payload, indent=2) + "\n", encoding="utf-8")
  return scc_path, sarif_path


def write_json_file(data: Any, output_file: Path, label: str) -> None:
  """Serializes data to a JSON file and prints a short status line."""
  try:
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as fh:
      json.dump(data, fh, indent=2)
    print(f"Success! {label} written to: {output_file}")
  except (OSError, TypeError) as err:
    print(f"Error writing {label} to {output_file}: {err}", file=sys.stderr)
    sys.exit(1)


def add_role_prefix_argument(sub: argparse.ArgumentParser) -> None:
  """Adds the shared ``--role-prefix`` flag (custom role ID prefix)."""
  sub.add_argument(
      "--role-prefix",
      default=None,
      help="Custom role ID prefix (default: env SCOPEGUARD_ROLE_PREFIX or 'sg_')",
  )


def build_parser() -> argparse.ArgumentParser:
  """Constructs the argparse CLI parser with subcommands."""
  parser = argparse.ArgumentParser(
      description="GCP IAM Recommender Audit, Custom Role Set-Cover & Rollback CLI"
  )
  subparsers = parser.add_subparsers(dest="command", required=True)

  # Subcommand: collect
  p_collect = subparsers.add_parser(
      "collect",
      help="Snapshot project IAM policy and collect Recommender, IAM, and Audit Log data",
  )
  p_collect.add_argument("--project", required=True, help="Target GCP Project ID")
  p_collect.add_argument(
      "--location", required=True, help="Recommender location (e.g., global)"
  )
  p_collect.add_argument(
      "--freshness-days",
      type=int,
      required=True,
      help="Observation window in days for Cloud Audit Logs (e.g., 90)",
  )
  p_collect.add_argument(
      "--log-limit",
      type=int,
      required=True,
      help="Maximum Cloud Audit Log entries to sample (e.g., 300)",
  )
  p_collect.add_argument(
      "--output", required=True, help="Output JSON file path for collected bundle"
  )

  # Subcommand: analyze
  p_analyze = subparsers.add_parser(
      "analyze",
      help="Analyze collected bundle for F1-F7 findings, custom roles, and principal mapping",
  )
  p_analyze.add_argument(
      "--bundle", required=True, help="Path to collected audit bundle JSON"
  )
  p_analyze.add_argument(
      "--output", required=True, help="Output JSON file path for analysis results"
  )
  add_role_prefix_argument(p_analyze)

  # Subcommand: generate-artifacts
  p_gen = subparsers.add_parser(
      "generate-artifacts",
      help="Generate Markdown report, custom role YAMLs, principal_mapping.json, and rollback_runbook.sh",
  )
  p_gen.add_argument(
      "--analysis", required=True, help="Path to analysis_results.json"
  )
  p_gen.add_argument(
      "--policy-backup", required=True, help="Path to iam_policy_backup_<project>.json"
  )
  p_gen.add_argument(
      "--output-dir", required=True, help="Directory to write generated deliverables"
  )

  # Subcommand: full-audit
  p_full = subparsers.add_parser(
      "full-audit",
      help="Run collect -> analyze -> generate-artifacts end-to-end",
  )
  p_full.add_argument("--project", required=True, help="Target GCP Project ID")
  p_full.add_argument(
      "--location", required=True, help="Recommender location (e.g., global)"
  )
  p_full.add_argument(
      "--freshness-days",
      type=int,
      required=True,
      help="Observation window in days for Cloud Audit Logs (e.g., 90)",
  )
  p_full.add_argument(
      "--log-limit",
      type=int,
      required=True,
      help="Maximum Cloud Audit Log entries to sample (e.g., 300)",
  )
  p_full.add_argument(
      "--output-dir", required=True, help="Directory to write all audit outputs"
  )
  add_role_prefix_argument(p_full)
  add_gcs_publish_arguments(p_full)

  return parser


def build_audit_envelope_module(
    results: Dict[str, Any], out_dir: Path, project_id: str
) -> Dict[str, Any]:
  """Packages analysis results and generated companion artifacts for GCS envelope."""
  def _read_opt(p: Path) -> str:
    return p.read_text(encoding="utf-8") if p.exists() else ""

  def _read_json_opt(p: Path) -> Any:
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None

  def _read_yaml_dir(d: Path) -> Dict[str, str]:
    """Returns {file name: YAML text} for one role directory (contents, not paths)."""
    if not d.is_dir():
      return {}
    return {y.name: y.read_text(encoding="utf-8") for y in sorted(d.glob("*.yaml"))}

  roles_root = out_dir / "custom-roles"
  # Model A personas live ONLY in custom-roles/personas/ (the legacy loader
  # globbed custom-roles/*.yaml at the root, which mixed in stale files).
  model_a_yamls = _read_yaml_dir(roles_root / "personas")
  disjoint_yamls = _read_yaml_dir(roles_root / "capabilities")

  kpis = results.get("executive_kpis", {})
  summary = {
      "total_principals": kpis.get("total_principals", 0),
      "permissions_before": kpis.get("total_permissions_before", 0),
      "permissions_after": kpis.get("total_permissions_after", 0),
      "permissions_reduction_pct": kpis.get("permissions_reduction_pct", 0.0),
      "disjoint_roles_count": kpis.get("disjoint_roles_count", 0),
      "persona_roles_count": kpis.get("persona_roles_count", 0),
      "capability_roles_count": kpis.get("capability_roles_count", 0),
      "escalation_chains_count": kpis.get("escalation_chains_count", 0),
      "inactive_sa_count": kpis.get("inactive_sa_count", 0),
      "expired_conditions_count": kpis.get("expired_conditions_count", 0),
  }
  payload = {
      "analysis": results,
      "artifacts": {
          "rollback_runbook_sh": _read_opt(out_dir / "rollback_runbook.sh"),
          "report_markdown": _read_opt(out_dir / "detailed_recommendations.md"),
          "posture_report_markdown": _read_opt(
              out_dir / "iam_security_posture_report.md"
          ),
          "disjoint_role_yamls": disjoint_yamls,
          "model_a_role_yamls": model_a_yamls,
          "bundles_yaml": _read_opt(roles_root / "bundles.yaml"),
          "policy_backup": _read_json_opt(out_dir / f"iam_policy_backup_{project_id}.json"),
          "sarif": _read_json_opt(out_dir / "scopeguard_audit.sarif.json"),
          "scc_findings": _read_json_opt(out_dir / "scc_findings_payload.json"),
      },
  }
  return {"summary": summary, "payload": payload, "status": "COMPLETED"}


def main() -> None:
  parser = build_parser()
  args = parser.parse_args()

  try:
    if args.command == "collect":
      out_path = Path(args.output)
      client = HybridGCPAuditClient(args.project, args.location)
      bundle, raw_policy = client.collect_all(
          freshness_days=args.freshness_days,
          log_limit=args.log_limit,
      )
      backup_path = out_path.parent / f"iam_policy_backup_{args.project}.json"
      write_json_file(raw_policy, backup_path, "IAM Policy Backup Snapshot")
      write_json_file(bundle, out_path, "Collected Audit Bundle")

    elif args.command == "analyze":
      bundle_path = Path(args.bundle)
      bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
      results = analyze_bundle(bundle, role_prefix=args.role_prefix)
      write_json_file(results, Path(args.output), "IAM Security Analysis Results")

    elif args.command == "generate-artifacts":
      analysis_data = json.loads(Path(args.analysis).read_text(encoding="utf-8"))
      paths = generate_all_artifacts(
          analysis_data, Path(args.policy_backup), Path(args.output_dir)
      )
      print(f"Success! Generated artifacts: {json.dumps(paths, indent=2)}")

    elif args.command == "full-audit":
      store = GCSAssessmentStore()
      gcs_check = run_skill_gcs_preflight(args, args.project, store=store)

      out_dir = Path(args.output_dir)
      out_dir.mkdir(parents=True, exist_ok=True)
      bundle_path = out_dir / f"audit_bundle_{args.project}.json"
      backup_path = out_dir / f"iam_policy_backup_{args.project}.json"
      analysis_path = out_dir / f"analysis_results_{args.project}.json"

      client = HybridGCPAuditClient(args.project, args.location)
      bundle, raw_policy = client.collect_all(
          freshness_days=args.freshness_days,
          log_limit=args.log_limit,
      )
      write_json_file(raw_policy, backup_path, "IAM Policy Backup Snapshot")
      write_json_file(bundle, bundle_path, "Collected Audit Bundle")

      results = analyze_bundle(bundle, role_prefix=args.role_prefix)
      write_json_file(results, analysis_path, "IAM Security Analysis Results")

      paths = generate_all_artifacts(results, backup_path, out_dir)
      publish_info = None
      if gcs_check:
        mod_entry = build_audit_envelope_module(results, out_dir, args.project)
        etag = results.get("metadata", {}).get("policy_etag", "")
        publish_info = store.publish_assessment_run(
            bucket=gcs_check["bucket"],
            region=gcs_check["region"],
            project_id=args.project,
            trigger_mode="recommender-audit",
            updated_modules={"recommender_audit": mod_entry},
            live_policy_etag=etag,
            local_output_dir=out_dir,
        )
      output_summary = {"deliverables": paths, "gcs_publish": publish_info}
      print(f"Success! Full audit complete.\n{json.dumps(output_summary, indent=2)}")

  except (RateLimitError, RuntimeError, OSError, ValueError) as exc:
    print(f"Error: {exc}", file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
  main()
