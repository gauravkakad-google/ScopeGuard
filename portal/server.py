#!/usr/bin/env python3
# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0

"""ScopeGuard Stateless GCS-Backed Governance Viewer Server.

Serves the ScopeGuard single-page visual review portal and exposes strictly
read-only JSON APIs backed by the central GCS assessment bucket:
  - `GET /api/health`     -> Runtime identity, GCS bucket config, and project list
  - `GET /api/projects`   -> Lists `<project_id>/` folders in the GCS bucket
  - `GET /api/runs`       -> Lists immutable timestamped run files per project
  - `GET /api/assessment` -> Loads `latest.json` or a selected historical run
  - `GET /api/artifact`   -> Streams an allowlisted read-only run deliverable
                             (Markdown, CSV, JSONL, SARIF, manifest, SCC JSON)
  - `GET /api/findings`   -> Unified findings queue with stateless New / Open /
                             Regressed / Resolved status and a per-run trend,
                             derived by diffing the last N immutable run files
  - `GET /api/diff`       -> Run-to-run KPI and binding drift comparison
  - `GET /api/fleet`      -> Org / Folder rollup incl. stale and not-assessed
                             projects, category heatmap, and riskiest principals

Zero IAM scanning or CLI mutations occur in this web tier. On Cloud Run, the
runtime Service Account (`scopeguard-portal-sa`) requires only bucket-scoped
`storage.objects.list` and `storage.objects.get` permissions.
"""

from collections import OrderedDict
import datetime as _dt
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
import logging
import mimetypes
import os
from pathlib import Path
import re
import sys
import threading
from typing import Any, Dict, List, Optional
from urllib import error as urllib_error
from urllib import parse as urllib_parse
from urllib import request as urllib_request

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
LOGGER = logging.getLogger("scopeguard.viewer")

REPO_ROOT = Path(__file__).resolve().parent.parent
STATIC_DIR = Path(__file__).resolve().parent / "static"
PLUGIN_ROOT = REPO_ROOT / "plugins" / "scopeguard"

if str(PLUGIN_ROOT) not in sys.path:
  sys.path.insert(0, str(PLUGIN_ROOT))

from lib.config_store import load_saved_config, normalize_bucket_name  # pylint: disable=wrong-import-position
from lib.gcp_client import GCPHTTPError, ScopeGuardGCPClient  # pylint: disable=wrong-import-position
from lib.gcs_publisher import GCSAssessmentStore  # pylint: disable=wrong-import-position

PORTAL_DIR = Path(__file__).resolve().parent
if str(PORTAL_DIR) not in sys.path:
  sys.path.insert(0, str(PORTAL_DIR))

from lib import findings_engine  # pylint: disable=wrong-import-position

SAFE_ID_RE = re.compile(r"^[a-zA-Z0-9._:-]{2,128}$")
DEFAULT_PROJECT = os.environ.get("SCOPEGUARD_PROJECT_ID", "")

# History window for finding status / trend. Capped to bound GCS reads/latency.
HISTORY_DEFAULT_RUNS = 10
HISTORY_MAX_RUNS = 20
# Latest snapshots older than this are flagged as stale in the fleet view.
FLEET_STALE_DAYS = int(os.environ.get("SCOPEGUARD_STALE_DAYS", "14") or 14)


class _RunSummaryCache:
  """Thread-safe LRU cache of normalized run summaries.

  Timestamped run files under `<project>/runs/` are immutable once published,
  so caching their (small) normalized summaries is always safe and avoids
  re-downloading multi-MB envelopes on every page view. `latest.json` is
  mutable and is therefore never cached.
  """

  def __init__(self, max_entries: int = 128) -> None:
    self._max = max_entries
    self._data: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()
    self._lock = threading.Lock()

  def get(self, key: str) -> Optional[Dict[str, Any]]:
    with self._lock:
      if key in self._data:
        self._data.move_to_end(key)
        return self._data[key]
      return None

  def put(self, key: str, value: Dict[str, Any]) -> None:
    with self._lock:
      self._data[key] = value
      self._data.move_to_end(key)
      while len(self._data) > self._max:
        self._data.popitem(last=False)


RUN_SUMMARY_CACHE = _RunSummaryCache()


def _age_days(timestamp_utc: str) -> Optional[int]:
  """Returns whole days since a `YYYY-MM-DDTHH:MM:SSZ` timestamp, or None."""
  try:
    ts = _dt.datetime.strptime(timestamp_utc, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=_dt.timezone.utc
    )
  except (TypeError, ValueError):
    return None
  return max((_dt.datetime.now(_dt.timezone.utc) - ts).days, 0)


def resolve_viewer_bucket() -> Dict[str, str]:
  """Resolves the GCS assessment bucket from env var or `~/.scopeguard/config.json`."""
  env_bucket = os.environ.get("SCOPEGUARD_GCS_BUCKET", "").strip()
  env_region = os.environ.get("SCOPEGUARD_GCS_REGION", "asia-southeast1").strip()
  if env_bucket:
    return {
        "bucket": normalize_bucket_name(env_bucket),
        "region": env_region,
        "source": "environment",
    }
  saved = load_saved_config()
  if saved and saved.get("bucket"):
    return {
        "bucket": saved["bucket"],
        "region": saved.get("region", env_region),
        "source": "saved_config",
    }
  return {"bucket": "", "region": env_region, "source": "unconfigured"}


def detect_runtime_identity() -> Dict[str, Any]:
  """Detects Cloud Run service metadata or local viewer context."""
  k_service = os.environ.get("K_SERVICE", "")
  k_revision = os.environ.get("K_REVISION", "")
  if k_service:
    sa_email = "unknown"
    meta_url = (
        "http://metadata.google.internal/computeMetadata/v1/"
        "instance/service-accounts/default/email"
    )
    try:
      req = urllib_request.Request(meta_url, method="GET")
      req.add_header("Metadata-Flavor", "Google")
      with urllib_request.urlopen(req, timeout=1.5) as resp:
        sa_email = resp.read().decode("utf-8").strip()
    except (OSError, urllib_error.URLError):
      pass
    return {
        "environment": "cloud_run",
        "service_name": k_service,
        "revision": k_revision,
        "runtime_identity": sa_email,
        "viewer_mode": "PURE_GCS_STATELESS_VIEWER",
    }
  return {
      "environment": "local_workstation",
      "service_name": "scopeguard-viewer-local",
      "revision": "v2.1",
      "runtime_identity": "local-adc-gcs-reader",
      "viewer_mode": "PURE_GCS_STATELESS_VIEWER",
  }


class ScopeGuardViewerHandler(SimpleHTTPRequestHandler):
  """HTTP handler serving static SPA assets and read-only GCS JSON endpoints."""

  def __init__(self, *args: Any, **kwargs: Any) -> None:
    super().__init__(*args, directory=str(STATIC_DIR), **kwargs)

  def log_message(self, fmt: str, *args: Any) -> None:
    LOGGER.info("%s - %s", self.address_string(), fmt % args)

  def _send_json(
      self, payload: Dict[str, Any], status: int = HTTPStatus.OK
  ) -> None:
    body = json.dumps(payload).encode("utf-8")
    self.send_response(status)
    self.send_header("Content-Type", "application/json; charset=utf-8")
    self.send_header("Content-Length", str(len(body)))
    self.send_header("Cache-Control", "no-store, max-age=0")
    self.send_header("X-Content-Type-Options", "nosniff")
    self.end_headers()
    self.wfile.write(body)

  def do_GET(self) -> None:  # pylint: disable=invalid-name
    parsed = urllib_parse.urlparse(self.path)
    route = parsed.path
    query = urllib_parse.parse_qs(parsed.query)

    try:
      if route == "/api/health":
        self._handle_health()
        return
      if route == "/api/projects":
        self._handle_projects()
        return
      if route == "/api/runs":
        proj = (query.get("project") or [DEFAULT_PROJECT])[0].strip()
        self._handle_runs(proj)
        return
      if route == "/api/assessment":
        proj = (query.get("project") or [DEFAULT_PROJECT])[0].strip()
        run_ref = (query.get("run") or ["latest"])[0].strip()
        self._handle_assessment(proj, run_ref)
        return
      if route == "/api/recommendations.md":
        proj = (query.get("project") or [DEFAULT_PROJECT])[0].strip()
        run_ref = (query.get("run") or ["latest"])[0].strip()
        self._handle_recommendations_markdown(proj, run_ref)
        return
      if route == "/api/artifact":
        proj = (query.get("project") or [DEFAULT_PROJECT])[0].strip()
        run_ref = (query.get("run") or ["latest"])[0].strip()
        file_name = (query.get("file") or [""])[0].strip()
        inline = (query.get("inline") or ["0"])[0].strip() == "1"
        self._handle_artifact(proj, run_ref, file_name, inline)
        return
      if route == "/api/diff":
        proj = (query.get("project") or [DEFAULT_PROJECT])[0].strip()
        base_run = (query.get("base") or [""])[0].strip()
        target_run = (query.get("target") or ["latest"])[0].strip()
        self._handle_run_diff(proj, base_run, target_run)
        return
      if route == "/api/fleet":
        scope_filter = (query.get("scope") or ["all"])[0].strip()
        self._handle_fleet(scope_filter)
        return
      if route == "/api/findings":
        proj = (query.get("project") or [DEFAULT_PROJECT])[0].strip()
        run_ref = (query.get("run") or ["latest"])[0].strip()
        history_raw = (query.get("history") or [str(HISTORY_DEFAULT_RUNS)])[0].strip()
        self._handle_findings(proj, run_ref, history_raw)
        return
    except GCPHTTPError as gcp_err:
      LOGGER.error("GCS HTTP error on %s: %s", route, gcp_err)
      self._send_json(
          {
              "error": f"GCS storage error (HTTP {gcp_err.status_code})",
              "details": gcp_err.message,
          },
          status=HTTPStatus.BAD_GATEWAY,
      )
      return
    except Exception as exc:  # pylint: disable=broad-except
      LOGGER.exception("Unhandled viewer error on %s", route)
      self._send_json(
          {"error": "Internal viewer error", "details": str(exc)},
          status=HTTPStatus.INTERNAL_SERVER_ERROR,
      )
      return

    # Serve static SPA files
    if route in ("/", "/index.html"):
      self._serve_static_file(STATIC_DIR / "index.html")
      return

    clean_rel = route.lstrip("/")
    candidate = (STATIC_DIR / clean_rel).resolve()
    if candidate.is_relative_to(STATIC_DIR) and candidate.is_file():
      self._serve_static_file(candidate)
      return

    self._send_json({"error": "Not found"}, status=HTTPStatus.NOT_FOUND)

  def _serve_static_file(self, file_path: Path) -> None:
    mime_type, _ = mimetypes.guess_type(str(file_path))
    raw = file_path.read_bytes()
    self.send_response(HTTPStatus.OK)
    self.send_header(
        "Content-Type", f"{mime_type or 'application/octet-stream'}; charset=utf-8"
    )
    self.send_header("Content-Length", str(len(raw)))
    self.send_header("Cache-Control", "no-store, max-age=0")
    self.send_header("X-Content-Type-Options", "nosniff")
    self.end_headers()
    self.wfile.write(raw)

  def _get_store_and_bucket(self) -> tuple[Optional[GCSAssessmentStore], Dict[str, str]]:
    cfg = resolve_viewer_bucket()
    if not cfg["bucket"]:
      return None, cfg
    return GCSAssessmentStore(ScopeGuardGCPClient()), cfg

  def _handle_health(self) -> None:
    store, cfg = self._get_store_and_bucket()
    projects = []
    bucket_status = "UNCONFIGURED"
    if store and cfg["bucket"]:
      try:
        projects = store.list_projects(cfg["bucket"])
        bucket_status = "CONNECTED"
      except Exception as exc:  # pylint: disable=broad-except
        LOGGER.warning("Unable to list GCS projects during health check: %s", exc)
        bucket_status = f"ERROR: {exc}"

    default_proj = DEFAULT_PROJECT
    if projects and not any(p["project_id"] == default_proj for p in projects):
      default_proj = projects[0]["project_id"]

    self._send_json(
        {
            "status": "ok",
            "runtime": detect_runtime_identity(),
            "gcs_store": {
                "bucket": cfg["bucket"],
                "region": cfg["region"],
                "source": cfg["source"],
                "status": bucket_status,
            },
            "default_project": default_proj,
            "projects": projects,
        }
    )

  def _handle_projects(self) -> None:
    store, cfg = self._get_store_and_bucket()
    if not store:
      self._send_json({"bucket": "", "projects": [], "status": "BUCKET_UNCONFIGURED"})
      return
    projects = store.list_projects(cfg["bucket"])
    self._send_json(
        {"bucket": cfg["bucket"], "projects": projects, "status": "OK"}
    )

  def _handle_runs(self, project_id: str) -> None:
    if not SAFE_ID_RE.match(project_id):
      self._send_json(
          {"error": "Invalid project parameter"}, status=HTTPStatus.BAD_REQUEST
      )
      return
    store, cfg = self._get_store_and_bucket()
    if not store:
      self._send_json({"project_id": project_id, "runs": []})
      return
    runs = store.list_project_runs(cfg["bucket"], project_id)
    self._send_json(
        {"bucket": cfg["bucket"], "project_id": project_id, "runs": runs}
    )

  def _handle_assessment(self, project_id: str, run_ref: str) -> None:
    if not SAFE_ID_RE.match(project_id):
      self._send_json(
          {"error": "Invalid project parameter"}, status=HTTPStatus.BAD_REQUEST
      )
      return
    store, cfg = self._get_store_and_bucket()
    if not store:
      self._send_json(
          {
              "status": "BUCKET_UNCONFIGURED",
              "message": (
                  "No GCS assessment bucket configured yet. Run any ScopeGuard "
                  "skill in Antigravity to initialize the assessment bucket."
              ),
          },
          status=HTTPStatus.OK,
      )
      return

    if not run_ref or run_ref == "latest":
      obj_path = f"{project_id}/latest.json"
    else:
      clean_run = run_ref.replace(".json", "")
      if not SAFE_ID_RE.match(clean_run):
        self._send_json(
            {"error": "Invalid run identifier"}, status=HTTPStatus.BAD_REQUEST
        )
        return
      obj_path = f"{project_id}/runs/{clean_run}.json"

    envelope = store.get_json_object(cfg["bucket"], obj_path)
    if not envelope:
      self._send_json(
          {
              "status": "NO_ASSESSMENTS_FOR_PROJECT",
              "project_id": project_id,
              "bucket": cfg["bucket"],
              "object_checked": obj_path,
              "message": (
                  f"No assessment files found in gs://{cfg['bucket']}/{project_id}/. "
                  f"Run `scopeguard-orchestrator` in Antigravity for '{project_id}'."
              ),
          },
          status=HTTPStatus.OK,
      )
      return

    runs = store.list_project_runs(cfg["bucket"], project_id)
    self._send_json(
        {
            "status": "OK",
            "bucket": cfg["bucket"],
            "loaded_object": obj_path,
            "runs": runs,
            "envelope": envelope,
        }
    )

  def _handle_recommendations_markdown(self, project_id: str, run_ref: str) -> None:
    if not SAFE_ID_RE.match(project_id):
      self._send_json(
          {"error": "Invalid project parameter"}, status=HTTPStatus.BAD_REQUEST
      )
      return
    store, cfg = self._get_store_and_bucket()
    if not store:
      self._send_json(
          {"error": "Bucket unconfigured"}, status=HTTPStatus.NOT_FOUND
      )
      return
    if not run_ref or run_ref == "latest":
      obj_path = f"{project_id}/latest.json"
    else:
      clean_run = run_ref.replace(".json", "")
      if not SAFE_ID_RE.match(clean_run):
        self._send_json(
            {"error": "Invalid run identifier"}, status=HTTPStatus.BAD_REQUEST
        )
        return
      obj_path = f"{project_id}/runs/{clean_run}.json"

    envelope = store.get_json_object(cfg["bucket"], obj_path)
    if not envelope:
      self._send_json(
          {"error": "Assessment snapshot not found"}, status=HTTPStatus.NOT_FOUND
      )
      return

    md_text = envelope.get("master_recommendations_markdown") or (
        envelope.get("modules", {})
        .get("recommender_audit", {})
        .get("payload", {})
        .get("artifacts", {})
        .get("report_markdown", "")
    )
    raw = (md_text or "# No recommendations generated for this snapshot.\n").encode(
        "utf-8"
    )
    fname = f"scopeguard_recommendations_{project_id}_{envelope.get('run_id', 'latest')}.md"
    self.send_response(HTTPStatus.OK)
    self.send_header("Content-Type", "text/markdown; charset=utf-8")
    self.send_header("Content-Disposition", f'attachment; filename="{fname}"')
    self.send_header("Content-Length", str(len(raw)))
    self.send_header("Cache-Control", "no-store, max-age=0")
    self.send_header("X-Content-Type-Options", "nosniff")
    self.end_headers()
    self.wfile.write(raw)

  def _handle_artifact(
      self, project_id: str, run_ref: str, file_name: str, inline: bool = False
  ) -> None:
    """Streams an allowlisted read-only per-run deliverable from GCS.

    Args:
      project_id: Target GCP project ID (validated against SAFE_ID_RE).
      run_ref: Run identifier or `"latest"` (empty defaults to `"latest"`).
      file_name: Deliverable filename; must exist in RUN_OUTPUT_FILES.
      inline: When True, sets `Content-Disposition: inline`; otherwise forces
        an attachment download named `<project_id>_<file_name>`.
    """
    if not SAFE_ID_RE.match(project_id) or ".." in project_id:
      self._send_json(
          {"error": "Invalid project parameter"}, status=HTTPStatus.BAD_REQUEST
      )
      return

    # Strictly allowlist read-only audience docs and machine exports;
    # direct dictionary membership rejects path traversal ('..', '/') and
    # non-allowlisted files (e.g., executable .sh or .tf deliverables).
    content_type = GCSAssessmentStore.RUN_OUTPUT_FILES.get(file_name)
    if not content_type:
      self._send_json(
          {
              "error": "Invalid or disallowed artifact filename",
              "allowed_files": sorted(
                  GCSAssessmentStore.RUN_OUTPUT_FILES.keys()
              ),
          },
          status=HTTPStatus.BAD_REQUEST,
      )
      return

    if not run_ref or run_ref == "latest":
      obj_path = f"{project_id}/latest/{file_name}"
    else:
      clean_run = run_ref[:-5] if run_ref.endswith(".json") else run_ref
      if not SAFE_ID_RE.match(clean_run) or ".." in clean_run:
        self._send_json(
            {"error": "Invalid run identifier"}, status=HTTPStatus.BAD_REQUEST
        )
        return
      obj_path = f"{project_id}/runs/{clean_run}/{file_name}"

    store, cfg = self._get_store_and_bucket()
    if not store:
      self._send_json(
          {"error": "Bucket unconfigured"}, status=HTTPStatus.NOT_FOUND
      )
      return

    text = store.get_text_object(cfg["bucket"], obj_path)
    if text is None:
      self._send_json(
          {
              "error": "Artifact not found for this run",
              "hint": (
                  "Run a fresh v2.1 assessment to publish per-run "
                  "deliverables to GCS."
              ),
          },
          status=HTTPStatus.NOT_FOUND,
      )
      return

    raw = text.encode("utf-8")
    disposition = (
        "inline"
        if inline
        else f'attachment; filename="{project_id}_{file_name}"'
    )
    self.send_response(HTTPStatus.OK)
    self.send_header("Content-Type", content_type)
    self.send_header("Content-Disposition", disposition)
    self.send_header("Content-Length", str(len(raw)))
    self.send_header("Cache-Control", "no-store, max-age=0")
    self.send_header("X-Content-Type-Options", "nosniff")
    self.end_headers()
    self.wfile.write(raw)

  def _handle_run_diff(
      self, project_id: str, base_run: str, target_run: str
  ) -> None:
    """Computes run-to-run remediation burn-down and IAM drift diff from GCS."""
    if not SAFE_ID_RE.match(project_id):
      self._send_json(
          {"error": "Invalid project parameter"}, status=HTTPStatus.BAD_REQUEST
      )
      return
    store, cfg = self._get_store_and_bucket()
    if not store:
      self._send_json({"status": "BUCKET_UNCONFIGURED"}, status=HTTPStatus.OK)
      return

    runs = store.list_project_runs(cfg["bucket"], project_id)
    if len(runs) < 2:
      self._send_json(
          {
              "status": "INSUFFICIENT_RUNS",
              "message": "At least 2 historical runs in GCS are required to compute a diff.",
              "run_count": len(runs),
          },
          status=HTTPStatus.OK,
      )
      return

    # Resolve target (newest/selected) and base (prior snapshot)
    if not target_run or target_run == "latest":
      target_obj = f"{project_id}/latest.json"
      target_id = runs[0]["run_id"]
    else:
      clean_t = target_run.replace(".json", "")
      target_obj = f"{project_id}/runs/{clean_t}.json"
      target_id = clean_t

    if not base_run:
      # Pick the newest prior run whose run_id differs from target_id
      prior = next((r for r in runs if r["run_id"] != target_id), runs[-1])
      base_obj = prior["object_path"]
    else:
      clean_b = base_run.replace(".json", "")
      base_obj = f"{project_id}/runs/{clean_b}.json"

    base_env = store.get_json_object(cfg["bucket"], base_obj) or {}
    target_env = store.get_json_object(cfg["bucket"], target_obj) or {}

    def _extract_metrics(env: Dict[str, Any]) -> Dict[str, Any]:
      mods = env.get("modules", {})
      aud = mods.get("recommender_audit", {}).get("summary", {})
      comp = mods.get("compliance_mapper", {}).get("summary", {})
      git = mods.get("gitops_pr_guardrail", {}).get("summary", {})
      rem = mods.get("finding_remediator", {}).get("summary", {})
      pms = (
          mods.get("recommender_audit", {})
          .get("payload", {})
          .get("analysis", {})
          .get("principal_mappings", [])
      )
      bindings_set = set()
      for pm in pms:
        pr = pm.get("principal", "")
        for r in pm.get("current_roles", []):
          bindings_set.add(f"{pr} -> {r}")
      return {
          "run_id": env.get("run_id", ""),
          "timestamp_utc": env.get("timestamp_utc", ""),
          "trigger_mode": env.get("trigger_mode", ""),
          "policy_etag": env.get("live_policy_etag", ""),
          "total_principals": int(aud.get("total_principals", 0)),
          "permissions_before": int(aud.get("permissions_before", 0)),
          "permissions_after": int(aud.get("permissions_after", 0)),
          "escalation_chains": int(aud.get("escalation_chains_count", 0)),
          "compliance_before_pct": float(comp.get("overall_score_before_pct") or 0.0),
          "gitops_violations": int(git.get("total_violations", 0)),
          "inbound_findings_remediated": int(rem.get("findings_ingested", 0)),
          "bindings_set": bindings_set,
      }

    m_base = _extract_metrics(base_env)
    m_tgt = _extract_metrics(target_env)
    added_bindings = sorted(m_tgt["bindings_set"] - m_base["bindings_set"])
    removed_bindings = sorted(m_base["bindings_set"] - m_tgt["bindings_set"])

    self._send_json(
        {
            "status": "OK",
            "project_id": project_id,
            "base": {k: v for k, v in m_base.items() if k != "bindings_set"},
            "target": {k: v for k, v in m_tgt.items() if k != "bindings_set"},
            "deltas": {
                "permissions_before_delta": m_tgt["permissions_before"] - m_base["permissions_before"],
                "permissions_after_delta": m_tgt["permissions_after"] - m_base["permissions_after"],
                "escalation_chains_delta": m_tgt["escalation_chains"] - m_base["escalation_chains"],
                "compliance_before_delta_pct": round(
                    m_tgt["compliance_before_pct"] - m_base["compliance_before_pct"], 1
                ),
                "etag_changed": bool(
                    m_base["policy_etag"]
                    and m_tgt["policy_etag"]
                    and m_base["policy_etag"] != m_tgt["policy_etag"]
                ),
                "added_bindings": added_bindings,
                "removed_bindings": removed_bindings,
            },
        }
    )

  def _load_run_summary(
      self, store: GCSAssessmentStore, bucket: str, object_path: str, cacheable: bool
  ) -> Optional[Dict[str, Any]]:
    """Loads and normalizes one run envelope, using the immutable-run cache."""
    cache_key = f"{bucket}/{object_path}"
    if cacheable:
      cached = RUN_SUMMARY_CACHE.get(cache_key)
      if cached is not None:
        return cached
    env = store.get_json_object(bucket, object_path)
    if not env:
      return None
    try:
      summary = findings_engine.summarize_run(env)
    except Exception:  # pylint: disable=broad-except
      # A malformed historical run must not break the whole history view.
      LOGGER.exception("Failed to normalize findings for %s", object_path)
      return None
    if cacheable:
      RUN_SUMMARY_CACHE.put(cache_key, summary)
    return summary

  def _handle_findings(self, project_id: str, run_ref: str, history_raw: str) -> None:
    """Returns the unified findings queue for a run with stateless status/trend.

    Loads the selected run plus up to `history - 1` older immutable run files,
    normalizes each with `findings_engine`, and diffs finding IDs to derive
    New / Open / Regressed / Resolved status, first-seen age, and a trend.
    """
    if not SAFE_ID_RE.match(project_id):
      self._send_json({"error": "Invalid project parameter"}, status=HTTPStatus.BAD_REQUEST)
      return
    try:
      history_n = int(history_raw)
    except ValueError:
      history_n = HISTORY_DEFAULT_RUNS
    history_n = max(1, min(history_n, HISTORY_MAX_RUNS))

    clean_run = (run_ref or "latest").replace(".json", "")
    if clean_run != "latest" and not SAFE_ID_RE.match(clean_run):
      self._send_json({"error": "Invalid run identifier"}, status=HTTPStatus.BAD_REQUEST)
      return

    store, cfg = self._get_store_and_bucket()
    if not store:
      self._send_json({"status": "BUCKET_UNCONFIGURED", "findings": [], "trend": []})
      return
    bucket = cfg["bucket"]

    runs = store.list_project_runs(bucket, project_id)  # Newest first.
    start_idx = 0
    if clean_run != "latest":
      start_idx = next(
          (i for i, r in enumerate(runs) if r.get("run_id") == clean_run), -1
      )
      if start_idx < 0:
        self._send_json(
            {"error": f"Run '{clean_run}' not found for project"},
            status=HTTPStatus.NOT_FOUND,
        )
        return

    summaries: List[Dict[str, Any]] = []
    skipped: List[str] = []
    if runs:
      for r in runs[start_idx:start_idx + history_n]:
        obj = r.get("object_path") or f"{project_id}/runs/{r.get('run_id')}.json"
        summ = self._load_run_summary(store, bucket, obj, cacheable=True)
        if summ is None:
          skipped.append(str(r.get("run_id", obj)))
          continue
        summaries.append(summ)
    else:
      # Legacy buckets may only have latest.json (no run history yet).
      summ = self._load_run_summary(store, bucket, f"{project_id}/latest.json", cacheable=False)
      if summ:
        summaries.append(summ)

    if not summaries:
      self._send_json(
          {
              "status": "NO_ASSESSMENTS_FOR_PROJECT",
              "project_id": project_id,
              "findings": [],
              "resolved": [],
              "trend": [],
              "skipped_runs": skipped,
          }
      )
      return

    history = findings_engine.compute_history(summaries)
    LOGGER.info(
        "Findings for %s run=%s: %d open, %d resolved, window=%d run(s)",
        project_id, summaries[0].get("run_id"), len(history["findings"]),
        len(history["resolved"]), history["window_runs"],
    )
    self._send_json(
        {
            "status": "OK",
            "project_id": project_id,
            "run_id": summaries[0].get("run_id", ""),
            "timestamp_utc": summaries[0].get("timestamp_utc", ""),
            "history_requested": history_n,
            "skipped_runs": skipped,
            **history,
        }
    )

  def _handle_fleet(self, scope_filter: str) -> None:
    """Aggregates latest GCS assessments across an Organization, Folder, or all projects."""
    store, cfg = self._get_store_and_bucket()
    if not store:
      self._send_json(
          {
              "status": "BUCKET_UNCONFIGURED",
              "scope": scope_filter,
              "available_scopes": [],
              "aggregate_kpis": {},
              "projects": [],
          }
      )
      return

    proj_list = store.list_projects(cfg["bucket"])
    scope_rollups = store.list_scopes(cfg["bucket"])
    rollup_by_scope: Dict[str, Dict[str, Any]] = {}
    for r in scope_rollups:
      st = r.get("scope_type", "")
      sid = r.get("scope_id", "")
      if st and sid:
        rollup_by_scope[f"{st}:{sid}"] = r

    orgs_seen: Dict[str, int] = {}
    folders_seen: Dict[str, int] = {}
    all_project_rows: List[Dict[str, Any]] = []
    unassessed_rows: List[Dict[str, Any]] = []
    findings_by_project: Dict[str, List[Dict[str, Any]]] = {}

    for pinfo in proj_list:
      pid = pinfo["project_id"]
      env = store.get_json_object(cfg["bucket"], f"{pid}/latest.json")
      if not env:
        # Folder exists but no readable latest snapshot (e.g. failed publish).
        unassessed_rows.append(
            {"project_id": pid, "status": "NOT_ASSESSED", "reason": "No latest.json in bucket"}
        )
        continue

      # Normalized findings power the category heatmap and riskiest-principal
      # ranking. A malformed envelope degrades gracefully to zero findings.
      try:
        proj_findings = findings_engine.normalize_findings(env)
      except Exception:  # pylint: disable=broad-except
        LOGGER.exception("Failed to normalize fleet findings for %s", pid)
        proj_findings = []
      findings_by_project[pid] = proj_findings

      digest = env.get("recommendation_digest") or {}
      kpis = digest.get("executive_kpis") or {}
      phased = digest.get("phased_action_plan") or {}
      org_payload = (
          env.get("modules", {})
          .get("org_hierarchy_auditor", {})
          .get("payload", {})
      )
      ancestry_raw = (
          org_payload.get("ancestry_nodes") or org_payload.get("ancestry") or []
      )
      ancestry_strs: List[str] = []
      org_id = ""
      folder_ids: List[str] = []
      for item in ancestry_raw:
        if isinstance(item, dict):
          rid = item.get("resourceId") or item
          rtype = rid.get("type", "")
          rval = str(rid.get("id", ""))
          if rtype and rval:
            ancestry_strs.append(f"{rtype}:{rval}")
            if rtype == "organization":
              org_id = rval
            elif rtype == "folder":
              folder_ids.append(rval)
        elif isinstance(item, str):
          ancestry_strs.append(item)
          if item.startswith("organization:"):
            org_id = item.split(":", 1)[1]
          elif item.startswith("folder:"):
            folder_ids.append(item.split(":", 1)[1])

      if org_id:
        orgs_seen[org_id] = orgs_seen.get(org_id, 0) + 1
      for fid in folder_ids:
        folders_seen[fid] = folders_seen.get(fid, 0) + 1

      p0_items = phased.get("P0") or []
      p1_items = phased.get("P1") or []
      top_findings = [
          {
              "phase": "P0",
              "skill": it.get("skill", ""),
              "target": it.get("target", ""),
              "action": it.get("action", ""),
          }
          for it in p0_items[:5]
      ] + [
          {
              "phase": "P1",
              "skill": it.get("skill", ""),
              "target": it.get("target", ""),
              "action": it.get("action", ""),
          }
          for it in p1_items[:8]
      ]

      age = _age_days(str(env.get("timestamp_utc", "")))
      sev_counts: Dict[str, int] = {}
      cat_counts: Dict[str, int] = {}
      for f in proj_findings:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1
        cat_counts[f["category"]] = cat_counts.get(f["category"], 0) + 1

      all_project_rows.append(
          {
              "project_id": pid,
              "status": "OK",
              "run_id": env.get("run_id", ""),
              "timestamp_utc": env.get("timestamp_utc", ""),
              "age_days": age,
              "is_stale": age is not None and age > FLEET_STALE_DAYS,
              "trigger_mode": env.get("trigger_mode", ""),
              "org_id": org_id,
              "folder_ids": folder_ids,
              "folder_label": f"folder:{folder_ids[-1]}" if folder_ids else (
                  f"organization:{org_id}" if org_id else "(no ancestry)"
              ),
              "ancestry": ancestry_strs,
              "findings_total": len(proj_findings),
              "severity_counts": sev_counts,
              "category_counts": cat_counts,
              "kpis": {
                  "total_principals": int(kpis.get("total_principals") or 0),
                  "permissions_before": int(kpis.get("permissions_before") or 0),
                  "permissions_after": int(kpis.get("permissions_after") or 0),
                  "permissions_reduction_pct": float(kpis.get("permissions_reduction_pct") or 0),
                  "escalation_chains_count": int(kpis.get("escalation_chains_count") or 0),
                  "standing_privileged_humans_count": int(kpis.get("standing_privileged_humans_count") or 0),
                  "wif_migration_candidates": int(kpis.get("wif_migration_candidates") or 0),
                  "user_managed_keys_found": int(kpis.get("user_managed_keys_found") or 0),
                  "gitops_pr_verdict": str(kpis.get("gitops_pr_verdict", "N/A")),
                  "gitops_violations_count": int(kpis.get("gitops_violations_count") or 0),
                  "inbound_findings_remediated": int(kpis.get("inbound_findings_remediated") or 0),
                  "simulated_403_denials": int(kpis.get("simulated_403_denials") or 0),
                  "cutover_verdict": str(kpis.get("cutover_verdict", "N/A")),
                  "compliance_score_before_pct": float(kpis.get("compliance_score_before_pct") or 0),
                  "compliance_score_after_pct": float(kpis.get("compliance_score_after_pct") or 0),
              },
              "p0_count": len(p0_items),
              "p1_count": len(p1_items),
              "top_findings": top_findings,
          }
      )

    # Also surface any explicitly swept orgs/folders even if projects had limited ancestry
    for skey, rdoc in rollup_by_scope.items():
      if skey.startswith("organization:"):
        oid = skey.split(":", 1)[1]
        orgs_seen.setdefault(oid, int(rdoc.get("succeeded_count", 0)))
      elif skey.startswith("folder:"):
        fid = skey.split(":", 1)[1]
        folders_seen.setdefault(fid, int(rdoc.get("succeeded_count", 0)))

    available_scopes = [
        {
            "value": "all",
            "label": f"All Analyzed Projects ({len(all_project_rows)})",
            "scope_type": "all",
            "project_count": len(all_project_rows),
        }
    ]
    for oid, cnt in sorted(orgs_seen.items()):
      available_scopes.append(
          {
              "value": f"organization:{oid}",
              "label": f"Organization: {oid} ({cnt} project{'s' if cnt != 1 else ''})",
              "scope_type": "organization",
              "scope_id": oid,
              "project_count": cnt,
              "has_sweep_rollup": f"organization:{oid}" in rollup_by_scope,
          }
      )
    for fid, cnt in sorted(folders_seen.items()):
      available_scopes.append(
          {
              "value": f"folder:{fid}",
              "label": f"Folder: {fid} ({cnt} project{'s' if cnt != 1 else ''})",
              "scope_type": "folder",
              "scope_id": fid,
              "project_count": cnt,
              "has_sweep_rollup": f"folder:{fid}" in rollup_by_scope,
          }
      )

    # Filter projects by requested scope
    if scope_filter and scope_filter != "all":
      if scope_filter.startswith("organization:"):
        target_org = scope_filter.split(":", 1)[1]
        filtered = [p for p in all_project_rows if p["org_id"] == target_org]
      elif scope_filter.startswith("folder:"):
        target_folder = scope_filter.split(":", 1)[1]
        filtered = [p for p in all_project_rows if target_folder in p["folder_ids"]]
      else:
        filtered = all_project_rows
    else:
      filtered = all_project_rows

    # Surface projects that were discovered by an Org/Folder sweep but failed
    # or were never assessed, so coverage gaps are visible (not silently hidden).
    assessed_ids = {p["project_id"] for p in all_project_rows}
    gap_rows: Dict[str, Dict[str, Any]] = {}
    relevant_rollups = (
        [rollup_by_scope[scope_filter]]
        if scope_filter in rollup_by_scope
        else (list(rollup_by_scope.values()) if scope_filter in ("", "all") else [])
    )
    for rdoc in relevant_rollups:
      for pr in rdoc.get("projects") or []:
        pid = str(pr.get("project_id", ""))
        if not pid or pid in assessed_ids or str(pr.get("status")) == "OK":
          continue
        gap_rows[pid] = {
            "project_id": pid,
            "status": str(pr.get("status") or "NOT_ASSESSED"),
            "reason": str(pr.get("error") or pr.get("reason") or "Not assessed in sweep"),
            "folder_label": (pr.get("folder_path") or [pr.get("parent") or ""])[-1] or "(no ancestry)",
            "sweep_id": rdoc.get("sweep_id", ""),
        }
    if scope_filter in ("", "all"):
      for row in unassessed_rows:
        gap_rows.setdefault(row["project_id"], dict(row, folder_label="(unknown)"))

    ranked_principals = findings_engine.top_principals(
        [(p["project_id"], findings_by_project.get(p["project_id"], [])) for p in filtered],
        limit=10,
    )
    tot_principals = sum(p["kpis"]["total_principals"] for p in filtered)
    tot_before = sum(p["kpis"]["permissions_before"] for p in filtered)
    tot_after = sum(p["kpis"]["permissions_after"] for p in filtered)
    red_pct = round((1.0 - (tot_after / tot_before)) * 100.0, 1) if tot_before > 0 else 0.0
    avg_comp_before = (
        round(
            sum(p["kpis"]["compliance_score_before_pct"] for p in filtered) / len(filtered),
            1,
        )
        if filtered
        else 0.0
    )
    avg_comp_after = (
        round(
            sum(p["kpis"]["compliance_score_after_pct"] for p in filtered) / len(filtered),
            1,
        )
        if filtered
        else 0.0
    )

    self._send_json(
        {
            "status": "OK",
            "bucket": cfg["bucket"],
            "scope": scope_filter or "all",
            "available_scopes": available_scopes,
            "sweep_rollup": rollup_by_scope.get(scope_filter),
            "aggregate_kpis": {
                "projects_count": len(filtered),
                "total_principals": tot_principals,
                "permissions_before": tot_before,
                "permissions_after": tot_after,
                "permissions_reduction_pct": red_pct,
                "escalation_chains_count": sum(
                    p["kpis"]["escalation_chains_count"] for p in filtered
                ),
                "standing_privileged_humans_count": sum(
                    p["kpis"]["standing_privileged_humans_count"] for p in filtered
                ),
                "wif_migration_candidates": sum(
                    p["kpis"]["wif_migration_candidates"] for p in filtered
                ),
                "gitops_violations_count": sum(
                    p["kpis"]["gitops_violations_count"] for p in filtered
                ),
                "inbound_findings_remediated": sum(
                    p["kpis"]["inbound_findings_remediated"] for p in filtered
                ),
                "avg_compliance_before_pct": avg_comp_before,
                "avg_compliance_after_pct": avg_comp_after,
                "stale_projects_count": sum(1 for p in filtered if p.get("is_stale")),
                "not_assessed_count": len(gap_rows),
                "stale_threshold_days": FLEET_STALE_DAYS,
            },
            "projects": filtered,
            "unassessed_projects": sorted(gap_rows.values(), key=lambda r: r["project_id"]),
            "top_principals": ranked_principals,
            "category_labels": findings_engine.CATEGORY_LABELS,
        }
    )


def main() -> None:
  host = os.environ.get("HOST", "0.0.0.0")
  port = int(os.environ.get("PORT", "8080"))
  cfg = resolve_viewer_bucket()
  LOGGER.info(
      "Starting ScopeGuard Stateless GCS Viewer on http://%s:%d (bucket=%s)",
      host,
      port,
      cfg["bucket"] or "<unconfigured>",
  )
  server = ThreadingHTTPServer((host, port), ScopeGuardViewerHandler)
  try:
    server.serve_forever()
  except KeyboardInterrupt:
    LOGGER.info("Shutting down ScopeGuard Viewer.")
  finally:
    server.server_close()


if __name__ == "__main__":
  main()
