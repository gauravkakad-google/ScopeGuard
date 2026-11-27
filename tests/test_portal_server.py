#!/usr/bin/env python3
# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the portal `/api/artifact` endpoint and GCS text reader.

Pure stdlib + unittest.mock; zero live network, socket, or GCS calls.
"""

import importlib.util
import io
import json
import os
from pathlib import Path
import sys
from typing import Any, Dict, Optional, Tuple
import unittest
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
PLUGIN_ROOT = REPO_ROOT / "plugins" / "scopeguard"

if str(PLUGIN_ROOT) not in sys.path:
  sys.path.insert(0, str(PLUGIN_ROOT))

from lib.gcp_client import GCPHTTPError  # pylint: disable=wrong-import-position
from lib.gcs_publisher import GCSAssessmentStore  # pylint: disable=wrong-import-position


def _load_portal_server():
  """Loads portal/server.py as a module without starting the HTTP server."""
  spec = importlib.util.spec_from_file_location(
      "scopeguard_portal_server", REPO_ROOT / "portal" / "server.py"
  )
  mod = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(mod)
  return mod


portal_server = _load_portal_server()


def _invoke_get(
    path: str,
    store: Optional[Any],
    bucket: str = "test-scopeguard-bucket",
) -> Tuple[int, Dict[str, str], bytes]:
  """Invokes ScopeGuardViewerHandler.do_GET in-memory without opening sockets."""
  handler = portal_server.ScopeGuardViewerHandler.__new__(
      portal_server.ScopeGuardViewerHandler
  )
  handler.path = path
  handler.command = "GET"
  handler.request_version = "HTTP/1.1"
  handler.client_address = ("127.0.0.1", 0)
  handler.headers = {}
  handler.wfile = io.BytesIO()

  captured: Dict[str, Any] = {"status": None, "headers": {}}

  def _send_response(code: int, message: Optional[str] = None) -> None:
    del message
    captured["status"] = int(code)

  def _send_header(keyword: str, value: str) -> None:
    captured["headers"][keyword.lower()] = value

  def _end_headers() -> None:
    pass

  handler.send_response = _send_response
  handler.send_header = _send_header
  handler.end_headers = _end_headers
  handler._get_store_and_bucket = lambda: (  # pylint: disable=protected-access
      store,
      {"bucket": bucket, "region": "asia-southeast1", "source": "environment"},
  )

  handler.do_GET()
  return captured["status"], captured["headers"], handler.wfile.getvalue()


class TestGCSTextObject(unittest.TestCase):
  """Tests GCSAssessmentStore.get_text_object() 200, 404, and error paths."""

  def test_get_text_object_returns_utf8_text_on_200(self) -> None:
    mock_client = mock.MagicMock()
    mock_client.request_raw.return_value = (
        200,
        "# Executive Summary\nStatus: \u2705 OK\n".encode("utf-8"),
        {},
    )
    store = GCSAssessmentStore(gcp_client=mock_client)

    result = store.get_text_object(
        "gs://my-bucket/", "/demo-proj/latest/EXECUTIVE_SUMMARY.md"
    )

    self.assertEqual(result, "# Executive Summary\nStatus: \u2705 OK\n")
    mock_client.request_raw.assert_called_once_with(
        url=(
            "https://storage.googleapis.com/storage/v1/b/my-bucket/o/"
            "demo-proj%2Flatest%2FEXECUTIVE_SUMMARY.md?alt=media"
        ),
        method="GET",
        service_key="storage",
    )

  def test_get_text_object_returns_none_on_404(self) -> None:
    mock_client = mock.MagicMock()
    mock_client.request_raw.side_effect = GCPHTTPError(
        status_code=404, message="Not Found"
    )
    store = GCSAssessmentStore(gcp_client=mock_client)

    result = store.get_text_object(
        "my-bucket", "demo-proj/runs/run-1/EXECUTIVE_SUMMARY.md"
    )
    self.assertIsNone(result)

  def test_list_project_runs_ignores_nested_deliverables(self) -> None:
    """Nested JSON files under runs/<run_id>/ must not be treated as run envelopes."""
    mock_client = mock.MagicMock()
    mock_client.request_json.return_value = {
        "items": [
            {"name": "demo-proj/runs/20261124T053922Z_full-suite_887e89.json", "size": "1200"},
            {"name": "demo-proj/runs/20261124T053922Z_full-suite_887e89/manifest.json", "size": "400"},
            {"name": "demo-proj/runs/20261124T053922Z_full-suite_887e89/scopeguard.sarif.json", "size": "800"},
            {"name": "demo-proj/runs/20261124T053922Z_full-suite_887e89/scc_findings_import.json", "size": "600"},
            {"name": "demo-proj/runs/20261120T025637Z_full-suite_fb7d8e.json", "size": "1100"},
        ]
    }
    store = GCSAssessmentStore(gcp_client=mock_client)
    runs = store.list_project_runs("my-bucket", "demo-proj")

    self.assertEqual(
        [r["run_id"] for r in runs],
        ["20261124T053922Z_full-suite_887e89", "20261120T025637Z_full-suite_fb7d8e"],
    )
    called_url = mock_client.request_json.call_args.kwargs["url"]
    self.assertIn("delimiter=/", called_url)

  def test_get_text_object_reraises_non_404_errors(self) -> None:
    mock_client = mock.MagicMock()
    mock_client.request_raw.side_effect = GCPHTTPError(
        status_code=403, message="Forbidden"
    )
    store = GCSAssessmentStore(gcp_client=mock_client)

    with self.assertRaises(GCPHTTPError) as ctx:
      store.get_text_object("my-bucket", "demo-proj/latest/manifest.json")
    self.assertEqual(ctx.exception.status_code, 403)


class TestPortalHealthRevision(unittest.TestCase):
  """Verifies local fallback revision was bumped to v2.1."""

  def test_local_runtime_identity_reports_v2_1(self) -> None:
    with mock.patch.dict(os.environ, {}, clear=True):
      ident = portal_server.detect_runtime_identity()
    self.assertEqual(ident["environment"], "local_workstation")
    self.assertEqual(ident["revision"], "v2.1")


class TestPortalArtifactEndpoint(unittest.TestCase):
  """Tests allowlisting, headers, path resolution, and errors on /api/artifact."""

  def test_allowlisted_attachment_and_inline_headers(self) -> None:
    mock_store = mock.MagicMock()
    mock_store.get_text_object.return_value = "# Summary\nAll clear.\n"

    status, headers, body = _invoke_get(
        "/api/artifact?project=demo-proj&run=latest&file=EXECUTIVE_SUMMARY.md",
        store=mock_store,
    )
    self.assertEqual(status, 200)
    self.assertEqual(body.decode("utf-8"), "# Summary\nAll clear.\n")
    self.assertEqual(headers["content-type"], "text/markdown; charset=utf-8")
    self.assertEqual(headers["cache-control"], "no-store, max-age=0")
    self.assertEqual(headers["x-content-type-options"], "nosniff")
    self.assertEqual(
        headers["content-disposition"],
        'attachment; filename="demo-proj_EXECUTIVE_SUMMARY.md"',
    )
    mock_store.get_text_object.assert_called_once_with(
        "test-scopeguard-bucket", "demo-proj/latest/EXECUTIVE_SUMMARY.md"
    )

    # Inline mode sets Content-Disposition: inline
    mock_store.reset_mock()
    status_in, headers_in, _ = _invoke_get(
        "/api/artifact?project=demo-proj&file=EXECUTIVE_SUMMARY.md&inline=1",
        store=mock_store,
    )
    self.assertEqual(status_in, 200)
    self.assertEqual(headers_in["content-disposition"], "inline")
    self.assertEqual(headers_in["x-content-type-options"], "nosniff")
    mock_store.get_text_object.assert_called_once_with(
        "test-scopeguard-bucket", "demo-proj/latest/EXECUTIVE_SUMMARY.md"
    )

  def test_historical_run_strips_json_suffix_and_maps_content_types(self) -> None:
    for fname, expected_ctype in GCSAssessmentStore.RUN_OUTPUT_FILES.items():
      with self.subTest(file=fname):
        mock_store = mock.MagicMock()
        mock_store.get_text_object.return_value = "sample-content"

        status, headers, _ = _invoke_get(
            f"/api/artifact?project=prod-app&run=20261118T061500Z_full_9f8a1c.json&file={fname}",
            store=mock_store,
        )
        self.assertEqual(status, 200)
        self.assertEqual(headers["content-type"], expected_ctype)
        mock_store.get_text_object.assert_called_once_with(
            "test-scopeguard-bucket",
            f"prod-app/runs/20261118T061500Z_full_9f8a1c/{fname}",
        )

  def test_empty_file_returns_200_not_404(self) -> None:
    mock_store = mock.MagicMock()
    mock_store.get_text_object.return_value = ""

    status, headers, body = _invoke_get(
        "/api/artifact?project=demo-proj&run=latest&file=findings.jsonl",
        store=mock_store,
    )
    self.assertEqual(status, 200)
    self.assertEqual(body, b"")
    self.assertEqual(headers["content-type"], "application/x-ndjson")

  def test_path_traversal_and_non_allowlisted_files_rejected_400(self) -> None:
    bad_files = [
        "../secret",
        "..%2Fsecret",
        "foo/bar.json",
        "rollback_runbook.sh",
        "custom.tf",
        "latest.json",
        "",
    ]
    for bad in bad_files:
      with self.subTest(file=bad):
        mock_store = mock.MagicMock()
        status, _, body = _invoke_get(
            f"/api/artifact?project=demo-proj&run=latest&file={bad}",
            store=mock_store,
        )
        self.assertEqual(status, 400)
        payload = json.loads(body.decode("utf-8"))
        self.assertIn("error", payload)
        mock_store.get_text_object.assert_not_called()

  def test_missing_artifact_returns_404_with_hint(self) -> None:
    mock_store = mock.MagicMock()
    mock_store.get_text_object.return_value = None

    status, headers, body = _invoke_get(
        "/api/artifact?project=demo-proj&run=20261118T061500Z_full_9f8a1c&file=scopeguard.sarif.json",
        store=mock_store,
    )
    self.assertEqual(status, 404)
    self.assertEqual(headers["x-content-type-options"], "nosniff")
    payload = json.loads(body.decode("utf-8"))
    self.assertEqual(payload["error"], "Artifact not found for this run")
    self.assertIn("v2.1", payload["hint"])

  def test_invalid_project_returns_400(self) -> None:
    for bad_proj in ("../etc", "bad/proj", "x", "proj..escape", ""):
      with self.subTest(project=bad_proj):
        mock_store = mock.MagicMock()
        status, _, _ = _invoke_get(
            f"/api/artifact?project={bad_proj}&run=latest&file=README.md",
            store=mock_store,
        )
        self.assertEqual(status, 400)
        mock_store.get_text_object.assert_not_called()

  def test_invalid_run_returns_400(self) -> None:
    for bad_run in ("../other", "bad/run", "..", ".json", "x"):
      with self.subTest(run=bad_run):
        mock_store = mock.MagicMock()
        status, _, _ = _invoke_get(
            f"/api/artifact?project=demo-proj&run={bad_run}&file=README.md",
            store=mock_store,
        )
        self.assertEqual(status, 400)
        mock_store.get_text_object.assert_not_called()


if __name__ == "__main__":
  unittest.main()
