#!/usr/bin/env python3
# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0

"""Tests for audience reports, exports, artifact index, bundles and redaction.

Covers ART-5 (EXECUTIVE_SUMMARY / REMEDIATION_PLAN / EVIDENCE + master report),
ART-6 (README.md + manifest.json), ART-7 (CSV / JSONL / SCC import / SARIF),
ART-9 (bundles), ART-12 (schema 2.1, tolerant of 2.0) and ART-14 (redaction).
Pure stdlib; no GCP or network calls.
"""

import csv
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

REPO_ROOT = Path(__file__).resolve().parent.parent
PLUGIN_ROOT = REPO_ROOT / "plugins" / "scopeguard"
if str(PLUGIN_ROOT) not in sys.path:
  sys.path.insert(0, str(PLUGIN_ROOT))

from lib import artifact_index  # pylint: disable=wrong-import-position
from lib import envelope_schema  # pylint: disable=wrong-import-position
from lib import exports  # pylint: disable=wrong-import-position
from lib import recommendation_synthesizer as rs  # pylint: disable=wrong-import-position

# Optional local v2.0 envelope path for regression checks (unset in CI/public repos).
_DEMO_ENV = os.environ.get("SCOPEGUARD_DEMO_ENVELOPE", "").strip()
DEMO_ENVELOPE = Path(_DEMO_ENV) if _DEMO_ENV else None
PID = "acme-prod"
SA = f"serviceAccount:etl-runner@{PID}.iam.gserviceaccount.com"
USER = "user:alice@corp.example.com"


def _module(summary, payload, status="COMPLETED"):
  """Wraps a summary/payload pair in the envelope module shape."""
  return {"status": status, "summary": summary, "payload": payload, "freshness": "CURRENT"}


def synthetic_envelope():
  """Builds a schema-2.1 envelope that exercises the new contract keys."""
  persona_id = "sg_persona_etl_runner"
  analysis = {
      "metadata": {"project_id": PID, "project_number": "123456789012"},
      "findings": {
          "F1_basic_roles": [{
              "principal": USER, "role": "roles/owner", "exercised_count": 4,
              "total_permissions": 9000, "phase": "P0", "insight_id": "insight-1",
          }],
          "F2_overprivileged_principals": [{
              "principal": SA, "role": "roles/editor", "exercised_count": 12,
              "total_permissions": 5000, "phase": "P1",
          }],
      },
      "principal_mappings": [
          {"principal": SA, "persona_role_id": persona_id,
           "labels": {"owner": "data-platform"},
           "recommended_action": "Swap roles/editor for the persona role."},
          {"principal": USER, "recommended_action": "Move owner to PAM."},
      ],
      "custom_roles_model_a": {
          persona_id: {
              "role_id": persona_id,
              "includedPermissions": ["bigquery.jobs.create", "storage.objects.get"],
              "members": [SA], "evidence_source": "audit_logs",
              "yaml_path": f"custom-roles/personas/{persona_id}.yaml",
          }
      },
      "custom_roles_model_b_disjoint": {
          "sg_cap_bigquery_job": {"role_id": "sg_cap_bigquery_job",
                                  "includedPermissions": ["bigquery.jobs.create"]},
          "sg_cap_storage_read": {"role_id": "sg_cap_storage_read",
                                  "includedPermissions": ["storage.objects.get"]},
      },
      "model_b_bundles": {persona_id: ["sg_cap_bigquery_job", "sg_cap_storage_read"]},
      "model_b_verification": {"exact_cover": True, "pairwise_overlap": 0,
                               "over_grant": [], "under_grant": [],
                               "capability_count": 2, "max_bundle_size": 2},
  }
  return {
      "schema_version": envelope_schema.SCHEMA_VERSION,
      "run_id": "20261120T000000Z_full-suite_abc123",
      "project_id": PID,
      "project_number": "123456789012",
      "timestamp_utc": "2026-11-20T00:00:00Z",
      "modules": {
          "recommender_audit": _module({"total_principals": 2}, {"analysis": analysis}),
          "gitops_pr_guardrail": _module(
              {"verdict": "SCAN_ERROR"},
              {"error": "plan json unreadable", "violations": [],
               "coverage": {"warnings": ["plan_json missing resource_changes"]}},
              status="FAILED",
          ),
          "jit_pam_architect": _module(
              {"pam_entitlements_not_ready": 1, "self_approval_conflicts": 1}, {}
          ),
          "deny_policy_architect": _module(
              {"breakglass_source": "default_placeholder", "breakglass_supplied": False}, {}
          ),
          "finding_remediator": _module(
              {"remediation_readiness": "HOLD_SIMULATED_403"},
              {"plans": [
                  {"status": "HOLD_SIMULATED_403", "principal": SA,
                   "simulated_403_display": "3 of 120 replayed calls"},
                  {"status": "NO_CHANGE_NEEDED", "principal": USER},
              ]},
          ),
      },
  }


def gitops_envelope():
  """Envelope with a gitops SARIF run and a matching violation."""
  env = synthetic_envelope()
  env["modules"]["gitops_pr_guardrail"] = _module(
      {"verdict": "FAIL"},
      {
          "violations": [{"rule_id": "G6_PUBLIC_PRINCIPAL", "severity": "CRITICAL",
                          "file": "main.tf", "line": 7,
                          "resource": "google_project_iam_member.pub",
                          "principal": "allUsers"}],
          "sarif": {
              "version": "2.1.0",
              "runs": [{"tool": {"driver": {"name": "scopeguard-gitops-guardrail",
                                            "rules": [{"id": "G6_PUBLIC_PRINCIPAL"}]}},
                        "results": [{"ruleId": "G6_PUBLIC_PRINCIPAL",
                                     "message": {"text": "public principal"}}]}],
          },
      },
  )
  return env


class CsvInjectionTest(unittest.TestCase):
  """Formula-injection guard for spreadsheet exports."""

  def test_dangerous_prefixes_are_neutralised(self):
    for raw in ("=cmd|' /C calc'!A0", "+1+1", "-2+3", "@SUM(A1)", "\tx", "\rx"):
      self.assertTrue(exports.csv_safe(raw).startswith("'"), raw)

  def test_safe_values_untouched(self):
    self.assertEqual(exports.csv_safe("roles/editor"), "roles/editor")
    self.assertEqual(exports.csv_safe(None), "")

  def test_written_csv_is_guarded(self):
    findings = [{"id": "x1", "title": "=HYPERLINK(\"http://evil\")", "severity": "HIGH",
                 "principal": "@attacker", "priority": "P1"}]
    with tempfile.TemporaryDirectory() as tmp:
      path = Path(tmp) / "findings.csv"
      exports.write_findings_csv(findings, path, "run-1")
      with path.open(encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    self.assertEqual(len(rows), 1)
    for cell in rows[0].values():
      self.assertFalse(cell[:1] in ("=", "+", "-", "@", "\t", "\r"), cell)


class RedactionTest(unittest.TestCase):
  """ART-14: stable hashing of identities, originals untouched."""

  def test_user_and_sa_redaction(self):
    text = f"{USER} and {SA} on projects/123456789012"
    out = exports.redact_text(text, salt="s")
    self.assertNotIn("alice", out)
    self.assertNotIn("123456789012", out)
    self.assertIn("user:h", out)                 # type prefix kept
    self.assertIn("etl-runner@", out)            # SA account id kept
    self.assertNotIn(f"@{PID}.", out)            # SA project part hashed
    self.assertEqual(out, exports.redact_text(text, salt="s"))  # stable

  def test_service_agent_domain_kept(self):
    out = exports.redact_text(
        "serviceAccount:service-123456789012@gcp-sa-pubsub.iam.gserviceaccount.com", salt="s"
    )
    self.assertIn("gcp-sa-pubsub", out)
    self.assertNotIn("123456789012", out)

  def test_json_stays_valid_and_originals_untouched(self):
    doc = {"principal": USER, "count": 3, "nested": [SA]}
    with tempfile.TemporaryDirectory() as tmp:
      root = Path(tmp)
      src = root / "findings.json"
      original = json.dumps(doc)
      src.write_text(original, encoding="utf-8")
      (root / "apply.sh").write_text(f"echo {USER}\n", encoding="utf-8")
      written = exports.write_shareable_copy(root, ["findings.json", "apply.sh"], salt="s")
      self.assertEqual(src.read_text(encoding="utf-8"), original)
      self.assertEqual(len(written), 1)  # scripts are never shared
      shared = json.loads((root / "shareable" / "findings.json").read_text(encoding="utf-8"))
    self.assertEqual(shared["count"], 3)
    self.assertNotIn("alice", json.dumps(shared))


class SarifAndSccTest(unittest.TestCase):
  """ART-7: SARIF 2.1.0 shape and SCC custom-source import file."""

  def test_unified_sarif_merges_gitops(self):
    env = gitops_envelope()
    sarif = exports.build_unified_sarif(env, exports.build_findings(env))
    self.assertEqual(sarif["version"], "2.1.0")
    self.assertGreaterEqual(len(sarif["runs"]), 2)
    self.assertIn("schema_version", sarif["properties"])
    sg_run = sarif["runs"][0]
    for result in sg_run["results"]:
      self.assertIn("ruleId", result)
      self.assertIn("scopeguardFindingId/v1", result["partialFingerprints"])
      # gitops IaC violations come from the merged gitops run, not duplicated.
      self.assertNotIn("iac_violation", result["ruleId"])
    self.assertEqual(sarif["runs"][1]["results"][0]["ruleId"], "G6_PUBLIC_PRINCIPAL")

  def test_scc_import_shape(self):
    env = synthetic_envelope()
    doc = exports.build_scc_import(env, exports.build_findings(env))
    self.assertTrue(doc["findings"])
    for item in doc["findings"]:
      finding = item.get("finding", item)
      self.assertEqual(finding["state"], "ACTIVE")
      self.assertEqual(
          finding["resourceName"],
          "//cloudresourcemanager.googleapis.com/projects/123456789012",
      )
      for key in ("category", "severity", "eventTime", "sourceProperties"):
        self.assertIn(key, finding)
      self.assertTrue(finding["eventTime"].endswith("Z"))


class SynthesizerTest(unittest.TestCase):
  """ART-5: audience documents render for old and new envelopes."""

  def _check_docs(self, env):
    docs = rs.render_audience_documents(env)
    pid = env.get("project_id")
    for name in ("EXECUTIVE_SUMMARY.md", "REMEDIATION_PLAN.md", "EVIDENCE.md",
                 f"scopeguard_recommendations_{pid}.md"):
      self.assertIn(name, docs)
      self.assertTrue(docs[name].strip(), name)
    return docs

  def test_synthetic_v21_envelope(self):
    env = synthetic_envelope()
    docs = self._check_docs(env)
    master = docs[f"scopeguard_recommendations_{PID}.md"]
    self.assertIn("Capability roles (Model B)", master)
    self.assertIn("sg_persona_etl_runner", master)
    self.assertIn("Exact cover", master)
    plan = docs["REMEDIATION_PLAN.md"]
    self.assertIn("Batch P2-1", plan)
    self.assertIn("custom-roles/personas/sg_persona_etl_runner.yaml", plan)
    self.assertNotIn("`0` simulated 403s", master)

  def test_demo_v20_envelope(self):
    if not DEMO_ENVELOPE or not DEMO_ENVELOPE.exists():
      self.skipTest("SCOPEGUARD_DEMO_ENVELOPE not set")
    env = json.loads(DEMO_ENVELOPE.read_text(encoding="utf-8"))
    self._check_docs(env)

  def test_schema_versions(self):
    self.assertEqual(envelope_schema.SCHEMA_VERSION, "2.1")
    self.assertTrue(envelope_schema.is_supported_schema("2.0"))
    self.assertTrue(envelope_schema.is_supported_schema("2.1"))


class ManifestAndFinalizeTest(unittest.TestCase):
  """ART-6/9/14: README + manifest, bundles and shareable copies end to end."""

  def test_finalize_run_outputs(self):
    env = synthetic_envelope()
    with tempfile.TemporaryDirectory() as tmp:
      root = Path(tmp)
      (root / "finding-remediation").mkdir()
      (root / "finding-remediation" / "remediation_commands.sh").write_text(
          "#!/bin/bash\necho dry-run\n", encoding="utf-8")
      (root / "deny-policies").mkdir()
      (root / "deny-policies" / "deny_policy_v2.json").write_text("{}", encoding="utf-8")
      report = artifact_index.finalize_run_outputs(env, root, bundle_by="owner", redact=True)
      self.assertEqual(report.get("errors"), [])

      for name in ("EXECUTIVE_SUMMARY.md", "REMEDIATION_PLAN.md", "EVIDENCE.md",
                   "findings.csv", "findings.jsonl", "scc_findings_import.json",
                   "scopeguard.sarif.json", "README.md", "manifest.json"):
        self.assertTrue((root / name).is_file(), name)

      manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
      self.assertEqual(manifest["schema_version"], "2.1")
      self.assertEqual(manifest["run_id"], env["run_id"])
      self.assertTrue(manifest["generated_at"].endswith("Z"))
      by_path = {f["path"]: f for f in manifest["files"]}
      for rel, entry in by_path.items():
        digest = hashlib.sha256((root / rel).read_bytes()).hexdigest()
        self.assertEqual(entry["sha256"], digest, rel)
      sh = by_path["finding-remediation/remediation_commands.sh"]
      self.assertTrue(sh["applies_changes"])
      self.assertEqual(sh["group"], "Apply")
      self.assertIn("deny-policies/deny_policy_v2.json", manifest["schema_version_exempt"])
      self.assertEqual(artifact_index.verify_manifest(root), [])
      self.assertIn("⚠️", (root / "README.md").read_text(encoding="utf-8"))

      # Bundles: owner label from principal_mappings, else "unassigned".
      bundle_dirs = {p.name for p in (root / "bundles").iterdir() if p.is_dir()}
      self.assertIn("data-platform", bundle_dirs)
      self.assertIn("unassigned", bundle_dirs)
      self.assertTrue((root / "bundles" / "data-platform" / "manifest.json").is_file())

      # Shareable copies are redacted; originals keep the real identities.
      shared_csv = (root / "shareable" / "findings.csv").read_text(encoding="utf-8")
      self.assertNotIn("alice@corp.example.com", shared_csv)
      self.assertIn("alice@corp.example.com",
                    (root / "findings.csv").read_text(encoding="utf-8"))

  def test_tampered_file_detected(self):
    with tempfile.TemporaryDirectory() as tmp:
      root = Path(tmp)
      (root / "a.md").write_text("hello\n", encoding="utf-8")
      artifact_index.write_artifact_index(root, run_id="r1", project_id=PID)
      (root / "a.md").write_text("tampered\n", encoding="utf-8")
      self.assertTrue(artifact_index.verify_manifest(root))


if __name__ == "__main__":
  unittest.main()
