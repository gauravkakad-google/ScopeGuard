#!/usr/bin/env python3
# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the portal findings engine (stateless finding normalization,
status inference and fleet ranking). Pure stdlib; no GCP or network calls."""

import importlib.util
from pathlib import Path
import re
import unittest

REPO_ROOT = Path(__file__).resolve().parent.parent


def _load_engine():
  """Loads lib/findings_engine.py without requiring a package layout."""
  spec = importlib.util.spec_from_file_location(
      "findings_engine", REPO_ROOT / "plugins" / "scopeguard" / "lib" / "findings_engine.py"
  )
  mod = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(mod)
  return mod


fe = _load_engine()


def _finding(fid, module_key="recommender_audit", severity="HIGH", principal="user:a@x.com"):
  """Builds a minimal normalized finding for history tests."""
  return {
      "id": fid,
      "module_key": module_key,
      "severity": severity,
      "priority": "P1",
      "category": "excess_permissions",
      "principal": principal,
      "principal_type": fe.classify_principal(principal),
  }


def _summary(ts, findings, executed=("recommender_audit",)):
  """Builds a minimal `summarize_run`-shaped dict."""
  return {
      "run_id": ts,
      "timestamp_utc": ts,
      "trigger_mode": "full",
      "executed_modules": list(executed),
      "findings": findings,
      "kpis": {},
  }


class TestStableIds(unittest.TestCase):
  """Finding ids must be deterministic so status can be diffed across runs."""

  def test_deterministic_and_formatted(self):
    a = fe.stable_finding_id("proj", "excess_permissions", "user:a@x.com", "roles/owner")
    b = fe.stable_finding_id("proj", "excess_permissions", "user:a@x.com", "roles/owner")
    self.assertEqual(a, b)
    self.assertRegex(a, r"^SG-[0-9A-F]{10}$")

  def test_distinct_inputs_distinct_ids(self):
    a = fe.stable_finding_id("proj", "excess_permissions", "user:a@x.com")
    b = fe.stable_finding_id("proj2", "excess_permissions", "user:a@x.com")
    self.assertNotEqual(a, b)


class TestClassifyPrincipal(unittest.TestCase):
  """Principal typing drives drawer chips and queue filters."""

  def test_cases(self):
    cases = {
        "user:alice@corp.com": "Human",
        "group:admins@corp.com": "Group",
        "domain:corp.com": "Domain",
        "principalSet://iam.googleapis.com/x": "Federated",
        "serviceAccount:app@p.iam.gserviceaccount.com": "Service account",
        "serviceAccount:123-compute@developer.gserviceaccount.com": "Default SA",
        "serviceAccount:service-123@gcp-sa-pubsub.iam.gserviceaccount.com": "Service agent",
        "": "None",
        "allUsers": "Other",
    }
    for member, expected in cases.items():
      with self.subTest(member=member):
        self.assertEqual(fe.classify_principal(member), expected)


class TestReplayConfidence(unittest.TestCase):
  """A PASS verdict on zero observed calls must never be graded trustworthy."""

  def test_zero_calls_is_low(self):
    self.assertEqual(fe.replay_confidence({"replayed_api_calls": 0}, {"telemetry_source": "bigquery"}), "Low")

  def test_bigquery_is_high(self):
    self.assertEqual(fe.replay_confidence({"replayed_api_calls": 5}, {"telemetry_source": "BigQuery sink"}), "High")

  def test_log_limit_hit_is_low(self):
    self.assertEqual(
        fe.replay_confidence({"replayed_api_calls": 500}, {"telemetry_source": "logging_api", "log_limit_hit": True}),
        "Low",
    )

  def test_logging_api_volume_is_medium(self):
    self.assertEqual(fe.replay_confidence({"replayed_api_calls": 50}, {"telemetry_source": "logging_api"}), "Medium")


class TestNormalize(unittest.TestCase):
  """Normalization must tolerate empty / partial envelopes."""

  def test_empty_envelope(self):
    self.assertEqual(fe.normalize_findings({}), [])
    self.assertEqual(fe.normalize_findings({"modules": {"recommender_audit": None}}), [])

  def test_summarize_empty_envelope(self):
    s = fe.summarize_run({"run_id": "r1", "modules": {"a": {"status": "OK"}, "b": {"status": "NOT_RUN"}}})
    self.assertEqual(s["executed_modules"], ["a"])
    self.assertEqual(s["findings"], [])

  def test_sort_orders_by_severity(self):
    items = [_finding("SG-1", severity="LOW"), _finding("SG-2", severity="CRITICAL")]
    self.assertEqual(fe.sort_findings(items)[0]["id"], "SG-2")


class TestComputeHistory(unittest.TestCase):
  """Stateless New / Open / Regressed / Resolved inference from run diffs."""

  def test_single_run_all_open(self):
    h = fe.compute_history([_summary("2026-11-03T00:00:00Z", [_finding("SG-A")])])
    self.assertEqual(h["findings"][0]["status"], "Open")
    self.assertEqual(h["resolved"], [])

  def test_new_open_regressed_resolved(self):
    newest = _summary("2026-11-03T00:00:00Z", [_finding("SG-OPEN"), _finding("SG-NEW"), _finding("SG-REG")])
    prev = _summary("2026-11-02T00:00:00Z", [_finding("SG-OPEN"), _finding("SG-GONE")])
    oldest = _summary("2026-11-01T00:00:00Z", [_finding("SG-OPEN"), _finding("SG-REG")])
    h = fe.compute_history([newest, prev, oldest])
    status = {f["id"]: f["status"] for f in h["findings"]}
    self.assertEqual(status, {"SG-OPEN": "Open", "SG-NEW": "New", "SG-REG": "Regressed"})
    self.assertEqual([f["id"] for f in h["resolved"]], ["SG-GONE"])
    open_f = next(f for f in h["findings"] if f["id"] == "SG-OPEN")
    self.assertEqual(open_f["age_days"], 2)
    self.assertEqual(open_f["runs_seen"], 3)
    # Trend is oldest-first.
    self.assertEqual([t["total"] for t in h["trend"]], [2, 2, 3])

  def test_partial_run_does_not_claim_resolution(self):
    newest = _summary("2026-11-03T00:00:00Z", [], executed=("breakglass_simulator",))
    prev = _summary("2026-11-02T00:00:00Z", [_finding("SG-X", module_key="recommender_audit")])
    h = fe.compute_history([newest, prev])
    self.assertEqual(h["resolved"], [])

  def test_empty(self):
    self.assertEqual(fe.compute_history([])["window_runs"], 0)


class TestTopPrincipals(unittest.TestCase):
  """Fleet top-10 aggregates across projects and ranks by severity weight."""

  def test_ranking(self):
    rows = [
        ("p1", [_finding("SG-1", severity="CRITICAL", principal="user:bad@x.com")]),
        ("p2", [_finding("SG-2", severity="CRITICAL", principal="user:bad@x.com"),
                _finding("SG-3", severity="LOW", principal="user:ok@x.com")]),
    ]
    ranked = fe.top_principals(rows, limit=10)
    self.assertEqual(ranked[0]["principal"], "user:bad@x.com")
    self.assertEqual(sorted(ranked[0]["projects"]), ["p1", "p2"])


if __name__ == "__main__":
  unittest.main()
