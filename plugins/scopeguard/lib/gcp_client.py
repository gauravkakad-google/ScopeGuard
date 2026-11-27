#!/usr/bin/env python3
# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0

"""Shared Google Cloud REST and CLI transport client for ScopeGuard skills.

Supports zero-dependency execution via GCE/Cloud Run Metadata Server, Application
Default Credentials (ADC), or authenticated gcloud CLI tokens, with cross-process
rate limiting and exponential backoff.
"""

import fcntl
import json
import logging
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib import error as urllib_error
from urllib import parse as urllib_parse
from urllib import request as urllib_request

LOGGER = logging.getLogger("scopeguard.gcp_client")


class GCPHTTPError(Exception):
  """Structured HTTP error returned by a Google Cloud REST endpoint."""

  def __init__(self, status_code: int, message: str, body: str = "") -> None:
    super().__init__(f"HTTP {status_code}: {message}")
    self.status_code = status_code
    self.message = message
    self.body = body


class CrossProcessRateLimiter:
  """File-lock rate limiter safe across concurrent skill invocations."""

  LOCK_FILE = Path("/tmp/scopeguard_gcp_ratelimit.lock")

  def __init__(self, requests_per_second: float = 8.0) -> None:
    self.requests_per_second = max(requests_per_second, 0.2)
    self.delay = 1.0 / self.requests_per_second
    self.last_request_time = 0.0

  def wait(self, custom_rps: Optional[float] = None) -> None:
    """Waits until the minimum inter-request interval has elapsed."""
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


class ScopeGuardGCPClient:
  """Unified Google Cloud REST client with Metadata, ADC, and gcloud token resolution."""

  SERVICE_RPS = {
      "storage": 15.0,
      "iam": 10.0,
      "cloudresourcemanager": 5.0,
      "logging": 2.0,
      "asset": 4.0,
      "orgpolicy": 4.0,
      "serviceusage": 5.0,
      "bigquery": 5.0,
  }

  def __init__(self, quota_project: Optional[str] = None) -> None:
    self.quota_project = quota_project
    self.limiter = CrossProcessRateLimiter(requests_per_second=8.0)
    self._token: Optional[str] = None
    self._token_expiry: float = 0.0
    self._has_gcloud = bool(shutil.which("gcloud"))
    self._ssl_context = self._build_tls_context()

  @staticmethod
  def _build_tls_context() -> ssl.SSLContext:
    """Builds a strict TLS verification context supporting Linux and macOS system CAs."""
    for ca_candidate in (
        os.environ.get("SSL_CERT_FILE", ""),
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/ssl/cert.pem",
    ):
      if ca_candidate and Path(ca_candidate).is_file():
        return ssl.create_default_context(cafile=ca_candidate)
    return ssl.create_default_context()

  def get_access_token(self) -> str:
    """Resolves a valid OAuth2 access token from Metadata Server, ADC, or gcloud."""
    now = time.monotonic()
    if self._token and now < self._token_expiry:
      return self._token

    # 1. Cloud Run / GCE Metadata Server (fastest container path)
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
          self._token = tok
          self._token_expiry = now + max(30.0, ttl - 60.0)
          return self._token
    except (OSError, ValueError, urllib_error.URLError):
      pass

    # 2. Local gcloud ADC or active user credentials
    if self._has_gcloud:
      for cmd in (
          ["gcloud", "auth", "application-default", "print-access-token", "--quiet"],
          ["gcloud", "auth", "print-access-token", "--quiet"],
      ):
        try:
          proc = subprocess.run(
              cmd,
              capture_output=True,
              text=True,
              timeout=10,
              check=False,
          )
          if proc.returncode == 0 and proc.stdout.strip():
            self._token = proc.stdout.strip()
            self._token_expiry = now + 1500.0
            return self._token
        except (OSError, subprocess.SubprocessError):
          continue

    raise RuntimeError(
        "Unable to obtain Google Cloud access token. Authenticate via "
        "`gcloud auth login` or `gcloud auth application-default login`."
    )

  def request_raw(
      self,
      url: str,
      method: str = "GET",
      raw_body: Optional[bytes] = None,
      content_type: str = "application/json",
      extra_headers: Optional[Dict[str, str]] = None,
      service_key: str = "iam",
      retries: int = 3,
      include_quota_project: bool = False,
  ) -> Tuple[int, bytes, Dict[str, str]]:
    """Executes an authenticated HTTP request with retry/backoff."""
    token = self.get_access_token()
    rps = self.SERVICE_RPS.get(service_key, 8.0)

    for attempt in range(retries + 1):
      self.limiter.wait(rps)
      req = urllib_request.Request(url, data=raw_body, method=method)
      req.add_header("Authorization", f"Bearer {token}")
      if raw_body is not None:
        req.add_header("Content-Type", content_type)
      if include_quota_project and self.quota_project:
        req.add_header("X-Goog-User-Project", self.quota_project)
      if extra_headers:
        for hdr_k, hdr_v in extra_headers.items():
          req.add_header(hdr_k, hdr_v)

      try:
        tls_ctx = self._ssl_context if url.startswith("https://") else None
        with urllib_request.urlopen(req, timeout=30, context=tls_ctx) as resp:
          status = resp.getcode()
          resp_bytes = resp.read()
          headers = {k.lower(): v for k, v in resp.headers.items()}
          return status, resp_bytes, headers
      except urllib_error.HTTPError as http_err:
        err_bytes = http_err.read() if http_err.fp else b""
        err_text = err_bytes.decode("utf-8", errors="replace")
        if http_err.code in (429, 500, 502, 503, 504) and attempt < retries:
          time.sleep(min(8.0, 1.2 * (2**attempt)))
          continue
        raise GCPHTTPError(http_err.code, http_err.reason, err_text) from http_err
      except urllib_error.URLError as url_err:
        if attempt < retries:
          time.sleep(min(6.0, 1.0 * (2**attempt)))
          continue
        raise RuntimeError(f"Network error contacting {url}: {url_err}") from url_err

    raise RuntimeError(f"Exhausted retries contacting {url}")

  def request_json(
      self,
      url: str,
      method: str = "GET",
      body: Optional[Dict[str, Any]] = None,
      service_key: str = "iam",
      include_quota_project: bool = False,
  ) -> Dict[str, Any]:
    """Executes an authenticated JSON REST request and parses the JSON response."""
    raw = json.dumps(body).encode("utf-8") if body is not None else None
    _, resp_bytes, _ = self.request_raw(
        url=url,
        method=method,
        raw_body=raw,
        content_type="application/json; charset=utf-8",
        service_key=service_key,
        include_quota_project=include_quota_project,
    )
    if not resp_bytes:
      return {}
    return json.loads(resp_bytes.decode("utf-8"))

  def fetch_project_iam_policy(self, project_id: str) -> Dict[str, Any]:
    """Fetches the live project IAM policy (v3 condition-aware) including its etag."""
    url = (
        "https://cloudresourcemanager.googleapis.com/v1/projects/"
        f"{urllib_parse.quote(project_id, safe='')}:getIamPolicy"
    )
    return self.request_json(
        url=url,
        method="POST",
        body={"options": {"requestedPolicyVersion": 3}},
        service_key="cloudresourcemanager",
    )

  def fetch_service_accounts_with_keys(self, project_id: str) -> List[Dict[str, Any]]:
    """Lists customer-managed Service Accounts and their USER_MANAGED keys."""
    sa_url = (
        "https://iam.googleapis.com/v1/projects/"
        f"{urllib_parse.quote(project_id, safe='')}/serviceAccounts?pageSize=100"
    )
    resp = self.request_json(url=sa_url, method="GET", service_key="iam")
    accounts = resp.get("accounts", [])
    enriched: List[Dict[str, Any]] = []
    for sa in accounts:
      email = sa.get("email", "")
      if not email:
        continue
      user_keys: List[Dict[str, Any]] = []
      keys_url = (
          "https://iam.googleapis.com/v1/projects/"
          f"{urllib_parse.quote(project_id, safe='')}/serviceAccounts/"
          f"{urllib_parse.quote(email, safe='')}/keys?keyTypes=USER_MANAGED"
      )
      try:
        k_resp = self.request_json(url=keys_url, method="GET", service_key="iam")
        user_keys = k_resp.get("keys", [])
      except GCPHTTPError as exc:
        LOGGER.debug("Unable to list keys for %s: %s", email, exc)
      item = dict(sa)
      item["user_managed_keys"] = user_keys
      enriched.append(item)
    return enriched

  def fetch_cloud_audit_logs(
      self,
      project_id: str,
      max_entries: int = 500,
      freshness_days: int = 90,
      principal_email: str = "",
  ) -> List[Dict[str, Any]]:
    """Fetches paginated Cloud Audit Log entries with optional per-principal scoping."""
    import datetime
    import re

    since_utc = (
        datetime.datetime.now(datetime.timezone.utc)
        - datetime.timedelta(days=max(1, int(freshness_days)))
    ).strftime("%Y-%m-%dT%H:%M:%SZ")

    filter_parts = [
        'logName:"cloudaudit.googleapis.com"',
        'protoPayload.methodName!=""',
        "protoPayload.authorizationInfo.granted=true",
        f'timestamp>="{since_utc}"',
    ]
    if principal_email:
      clean_email = principal_email.strip()
      if re.match(r"^[a-zA-Z0-9._@+-]+$", clean_email):
        filter_parts.append(
            f'protoPayload.authenticationInfo.principalEmail="{clean_email}"'
        )
    filter_expr = " AND ".join(filter_parts)

    url = "https://logging.googleapis.com/v2/entries:list"
    entries: List[Dict[str, Any]] = []
    page_token = ""
    remaining = max(1, int(max_entries))

    while remaining > 0:
      body: Dict[str, Any] = {
          "resourceNames": [f"projects/{project_id}"],
          "filter": filter_expr,
          "orderBy": "timestamp desc",
          "pageSize": min(remaining, 1000),
      }
      if page_token:
        body["pageToken"] = page_token
      try:
        resp = self.request_json(
            url=url,
            method="POST",
            body=body,
            service_key="logging",
            include_quota_project=True,
        )
      except (GCPHTTPError, RuntimeError) as exc:
        LOGGER.warning("Cloud Audit Log query fallback triggered: %s", exc)
        break
      batch = resp.get("entries", [])
      if not batch:
        break
      entries.extend(batch)
      remaining -= len(batch)
      page_token = resp.get("nextPageToken", "")
      if not page_token:
        break
    return entries

  def fetch_audit_logs_per_principal(
      self,
      project_id: str,
      principal_emails: List[str],
      max_per_principal: int = 250,
      freshness_days: int = 90,
  ) -> List[Dict[str, Any]]:
    """Queries paginated Cloud Audit Logs per principal so noisy SAs never drown out quiet ones."""
    combined: List[Dict[str, Any]] = []
    seen_emails: set[str] = set()
    for raw in principal_emails:
      email = raw.split(":", 1)[1] if ":" in raw else raw
      email = email.strip()
      if not email or email in seen_emails:
        continue
      seen_emails.add(email)
      combined.extend(
          self.fetch_cloud_audit_logs(
              project_id=project_id,
              max_entries=max_per_principal,
              freshness_days=freshness_days,
              principal_email=email,
          )
      )
    return combined

  def query_bigquery_audit_permissions(
      self,
      project_id: str,
      bq_table: str,
      freshness_days: int = 90,
  ) -> List[Dict[str, Any]]:
    """Runs a single 90-day SQL aggregation against Cloud Logging Log Analytics / BQ Sink.

    Supports both Log Analytics `_AllLogs` (`proto_payload.audit_log.*`) and
    classic Cloud Audit Log BigQuery sinks (`protopayload_auditlog.*`).
    Returns `[{"principal_email": ..., "permission": ..., "call_count": ...}, ...]`.
    """
    import re

    clean_table = bq_table.strip().strip("`")
    if not re.match(r"^[a-zA-Z0-9_.-]+$", clean_table) or clean_table.count(".") < 2:
      raise ValueError(
          f"Invalid BigQuery table identifier '{bq_table}'. "
          "Expected format: project.dataset.table (e.g. my-proj.global._Default._AllLogs)."
      )

    days = max(1, min(365, int(freshness_days)))
    queries = [
        # 1. Cloud Logging Log Analytics linked dataset (`_AllLogs`)
        (
            "SELECT "
            "  proto_payload.audit_log.authentication_info.principal_email AS principal_email, "
            "  auth.permission AS permission, "
            "  COUNT(*) AS call_count "
            f"FROM `{clean_table}`, "
            "UNNEST(proto_payload.audit_log.authorization_info) AS auth "
            f"WHERE timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY) "
            "  AND auth.granted = TRUE "
            "  AND auth.permission IS NOT NULL "
            "  AND proto_payload.audit_log.authentication_info.principal_email IS NOT NULL "
            "GROUP BY 1, 2"
        ),
        # 2. Classic BigQuery Audit Log Export Sink (`cloudaudit_googleapis_com_*`)
        (
            "SELECT "
            "  protopayload_auditlog.authenticationInfo.principalEmail AS principal_email, "
            "  auth.permission AS permission, "
            "  COUNT(*) AS call_count "
            f"FROM `{clean_table}`, "
            "UNNEST(protopayload_auditlog.authorizationInfo) AS auth "
            f"WHERE timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY) "
            "  AND auth.granted = TRUE "
            "  AND auth.permission IS NOT NULL "
            "  AND protopayload_auditlog.authenticationInfo.principalEmail IS NOT NULL "
            "GROUP BY 1, 2"
        ),
    ]

    url = (
        "https://bigquery.googleapis.com/bigquery/v2/projects/"
        f"{urllib_parse.quote(project_id, safe='')}/queries"
    )
    last_err: Optional[Exception] = None
    for sql in queries:
      try:
        resp = self.request_json(
            url=url,
            method="POST",
            body={
                "query": sql,
                "useLegacySql": False,
                "timeoutMs": 60000,
                "maxResults": 10000,
            },
            service_key="bigquery",
            include_quota_project=True,
        )
        rows: List[Dict[str, Any]] = []
        for row in resp.get("rows", []):
          fvals = row.get("f", [])
          if len(fvals) < 3:
            continue
          email = str(fvals[0].get("v") or "").strip()
          perm = str(fvals[1].get("v") or "").strip()
          cnt = int(fvals[2].get("v") or 1)
          if email and perm:
            rows.append(
                {"principal_email": email, "permission": perm, "call_count": cnt}
            )
        return rows
      except (GCPHTTPError, RuntimeError) as exc:
        last_err = exc
        continue

    LOGGER.warning(
        "BigQuery audit permission query failed for %s: %s", clean_table, last_err
    )
    return []

  def fetch_project_ancestry(self, project_id: str) -> List[Dict[str, Any]]:
    """Fetches the Folder and Organization ancestry chain for a GCP project."""
    url = (
        "https://cloudresourcemanager.googleapis.com/v1/projects/"
        f"{urllib_parse.quote(project_id, safe='')}:getAncestry"
    )
    try:
      resp = self.request_json(
          url=url,
          method="POST",
          body={},
          service_key="cloudresourcemanager",
      )
      return resp.get("ancestor", [])
    except (GCPHTTPError, RuntimeError) as exc:
      LOGGER.warning("Ancestry lookup degraded for %s: %s", project_id, exc)
      return [{"resourceId": {"type": "project", "id": project_id}}]

  def list_folders(self, parent: str) -> List[Dict[str, Any]]:
    """Lists immediate child folders under an organization or folder (CRM v3)."""
    folders: List[Dict[str, Any]] = []
    page_token = ""
    while True:
      params = f"parent={urllib_parse.quote(parent, safe='')}&pageSize=100"
      if page_token:
        params += f"&pageToken={urllib_parse.quote(page_token, safe='')}"
      url = f"https://cloudresourcemanager.googleapis.com/v3/folders?{params}"
      resp = self.request_json(
          url=url, method="GET", service_key="cloudresourcemanager"
      )
      folders.extend(resp.get("folders", []))
      page_token = resp.get("nextPageToken", "")
      if not page_token:
        break
    return folders

  def list_active_projects(self, parent: str) -> List[Dict[str, Any]]:
    """Lists immediate ACTIVE child projects under an org or folder (CRM v3)."""
    projects: List[Dict[str, Any]] = []
    page_token = ""
    while True:
      params = f"parent={urllib_parse.quote(parent, safe='')}&pageSize=200"
      if page_token:
        params += f"&pageToken={urllib_parse.quote(page_token, safe='')}"
      url = f"https://cloudresourcemanager.googleapis.com/v3/projects?{params}"
      resp = self.request_json(
          url=url, method="GET", service_key="cloudresourcemanager"
      )
      for proj in resp.get("projects", []):
        if proj.get("state") == "ACTIVE":
          projects.append(proj)
      page_token = resp.get("nextPageToken", "")
      if not page_token:
        break
    return projects

  def discover_projects_in_scope(
      self,
      org_id: str = "",
      folder_id: str = "",
      max_projects: int = 50,
      exclude_projects: Optional[List[str]] = None,
      include_projects: Optional[List[str]] = None,
  ) -> Dict[str, Any]:
    """Recursively discovers ACTIVE GCP projects under an Organization or Folder.

    Walks the folder hierarchy via Cloud Resource Manager v3 (BFS) with graceful
    fallback to `projects:search` when folder listing permissions are limited.
    """
    if org_id:
      clean_id = org_id.replace("organizations/", "").strip()
      root_parent = f"organizations/{clean_id}"
      scope_type = "organization"
      scope_id = clean_id
    elif folder_id:
      clean_id = folder_id.replace("folders/", "").strip()
      root_parent = f"folders/{clean_id}"
      scope_type = "folder"
      scope_id = clean_id
    else:
      raise ValueError("Either org_id or folder_id must be provided.")

    excluded = {p.strip() for p in (exclude_projects or []) if p.strip()}
    included = {p.strip() for p in (include_projects or []) if p.strip()}

    discovered: List[Dict[str, Any]] = []
    seen_projects: set[str] = set()
    folders_visited: List[Dict[str, Any]] = []
    warnings: List[str] = []

    queue: List[Tuple[str, List[str]]] = [(root_parent, [root_parent])]
    visited_parents: set[str] = set()

    while queue and len(discovered) < max_projects:
      current_parent, path_chain = queue.pop(0)
      if current_parent in visited_parents:
        continue
      visited_parents.add(current_parent)

      # 1. List direct active projects under current_parent
      try:
        for proj in self.list_active_projects(current_parent):
          pid = proj.get("projectId", "")
          if not pid or pid in seen_projects or pid in excluded:
            continue
          if included and pid not in included:
            continue
          seen_projects.add(pid)
          discovered.append(
              {
                  "project_id": pid,
                  "display_name": proj.get("displayName", pid),
                  "parent": current_parent,
                  "folder_path": list(path_chain),
              }
          )
          if len(discovered) >= max_projects:
            break
      except (GCPHTTPError, RuntimeError) as exc:
        warnings.append(f"projects.list({current_parent}): {exc}")

      if len(discovered) >= max_projects:
        break

      # 2. Enqueue child folders for recursive traversal
      try:
        for folder in self.list_folders(current_parent):
          fname = folder.get("name", "")
          if not fname or fname in visited_parents:
            continue
          if folder.get("state", "ACTIVE") != "ACTIVE":
            continue
          folders_visited.append(
              {
                  "folder_resource": fname,
                  "folder_id": fname.replace("folders/", ""),
                  "display_name": folder.get("displayName", fname),
                  "parent": current_parent,
              }
          )
          queue.append((fname, path_chain + [fname]))
      except (GCPHTTPError, RuntimeError) as exc:
        warnings.append(f"folders.list({current_parent}): {exc}")

    # Fallback: if direct traversal returned 0 projects (e.g., restricted folder
    # permissions), try CRM v3 projects:search
    if not discovered:
      try:
        q = urllib_parse.quote(f"state:ACTIVE parent:{root_parent}", safe="")
        url = (
            "https://cloudresourcemanager.googleapis.com/v3/projects:search"
            f"?query={q}&pageSize={min(max_projects, 200)}"
        )
        resp = self.request_json(
            url=url, method="GET", service_key="cloudresourcemanager"
        )
        for proj in resp.get("projects", []):
          pid = proj.get("projectId", "")
          if not pid or pid in seen_projects or pid in excluded:
            continue
          if included and pid not in included:
            continue
          seen_projects.add(pid)
          discovered.append(
              {
                  "project_id": pid,
                  "display_name": proj.get("displayName", pid),
                  "parent": proj.get("parent", root_parent),
                  "folder_path": [root_parent],
              }
          )
      except (GCPHTTPError, RuntimeError) as exc:
        warnings.append(f"projects.search({root_parent}): {exc}")

    discovered.sort(key=lambda item: item["project_id"])
    return {
        "scope_type": scope_type,
        "scope_id": scope_id,
        "scope_resource": root_parent,
        "folders_discovered": folders_visited,
        "projects": discovered,
        "project_count": len(discovered),
        "warnings": warnings,
    }

  def list_enabled_services(self, project_id: str) -> set[str]:
    """Lists enabled GCP API service names (e.g. recommender.googleapis.com)."""
    enabled: set[str] = set()
    page_token = ""
    while True:
      params = "filter=state:ENABLED&pageSize=200"
      if page_token:
        params += f"&pageToken={urllib_parse.quote(page_token, safe='')}"
      url = (
          "https://serviceusage.googleapis.com/v1/projects/"
          f"{urllib_parse.quote(project_id, safe='')}/services?{params}"
      )
      resp = self.request_json(
          url=url,
          method="GET",
          service_key="serviceusage",
          include_quota_project=True,
      )
      for svc in resp.get("services", []):
        cfg_name = (svc.get("config") or {}).get("name", "")
        if not cfg_name:
          raw_name = svc.get("name", "")
          cfg_name = raw_name.rsplit("/", 1)[-1] if "/" in raw_name else raw_name
        if cfg_name:
          enabled.add(cfg_name)
      page_token = resp.get("nextPageToken", "")
      if not page_token:
        break
    return enabled

  def enable_services(self, project_id: str, service_ids: List[str]) -> Dict[str, Any]:
    """Enables one or more GCP APIs via Service Usage batchEnable (user-confirmed only)."""
    if not service_ids:
      return {"done": True, "enabled": []}
    url = (
        "https://serviceusage.googleapis.com/v1/projects/"
        f"{urllib_parse.quote(project_id, safe='')}/services:batchEnable"
    )
    resp = self.request_json(
        url=url,
        method="POST",
        body={"serviceIds": list(service_ids)},
        service_key="serviceusage",
        include_quota_project=True,
    )
    # Poll short LRO up to 30s so immediately-following calls see the enabled APIs
    op_name = resp.get("name", "")
    if op_name and not resp.get("done"):
      op_url = f"https://serviceusage.googleapis.com/v1/{op_name.lstrip('/')}"
      for _ in range(15):
        time.sleep(2.0)
        try:
          op_state = self.request_json(
              url=op_url,
              method="GET",
              service_key="serviceusage",
              include_quota_project=True,
          )
          if op_state.get("done"):
            return op_state
        except (GCPHTTPError, RuntimeError):
          break
    return resp
