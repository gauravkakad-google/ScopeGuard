#!/usr/bin/env python3
# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0

"""Unit and smoke tests for ScopeGuard production plugin & portal."""

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

REPO_ROOT = Path(__file__).resolve().parent.parent
PLUGIN_ROOT = REPO_ROOT / "plugins" / "scopeguard"
if str(PLUGIN_ROOT) not in sys.path:
  sys.path.insert(0, str(PLUGIN_ROOT))


def _load_module(rel_path: str, name: str):
  spec = importlib.util.spec_from_file_location(name, REPO_ROOT / rel_path)
  mod = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(mod)
  return mod


class TestScopeGuardProductionSuite(unittest.TestCase):
  """Verifies core modules, schemas, and guardrails with zero GCP network calls."""

  def test_plugin_manifest_and_all_skills_present(self):
    manifest = json.loads((PLUGIN_ROOT / "plugin.json").read_text(encoding="utf-8"))
    self.assertEqual(manifest["name"], "scopeguard")
    skills = sorted((PLUGIN_ROOT / "skills").glob("*/SKILL.md"))
    self.assertEqual(len(skills), 11)

  def test_api_preflight_stage_resolution(self):
    from lib.api_preflight import resolve_required_apis_for_stages

    apis_basic = resolve_required_apis_for_stages(
        stages=["recommender_audit", "org_hierarchy_auditor"],
        include_live_scc=False,
        include_gcs=True,
    )
    self.assertIn("recommender.googleapis.com", apis_basic)
    self.assertIn("orgpolicy.googleapis.com", apis_basic)
    self.assertIn("storage.googleapis.com", apis_basic)
    self.assertNotIn("securitycenter.googleapis.com", apis_basic)

    apis_scc = resolve_required_apis_for_stages(
        stages=["finding_remediator"],
        include_live_scc=True,
        include_gcs=False,
    )
    self.assertIn("securitycenter.googleapis.com", apis_scc)
    self.assertNotIn("storage.googleapis.com", apis_scc)

  def test_gitops_guardrail_detects_violations_and_generates_patch(self):
    gitops = _load_module(
        "plugins/scopeguard/skills/gcp-iam-gitops-pr-guardrail/scripts/gitops_guardrail_cli.py",
        "test_gitops_mod",
    )
    with tempfile.TemporaryDirectory() as tmp:
      tf_dir = Path(tmp) / "tf"
      tf_dir.mkdir()
      (tf_dir / "main.tf").write_text(
          'resource "google_project_iam_member" "bad_editor" {\n'
          '  project = "my-gcp-project"\n'
          '  role    = "roles/editor"\n'
          '  member  = "serviceAccount:app@my-gcp-project.iam.gserviceaccount.com"\n'
          "}\n",
          encoding="utf-8",
      )
      out_dir = Path(tmp) / "out"
      res = gitops.run_gitops_guardrail("my-gcp-project", tf_dir, output_dir=out_dir)
      self.assertEqual(res["summary"]["pr_gate_verdict"], "BLOCK_MERGE")
      self.assertGreaterEqual(res["summary"]["total_violations"], 1)
      self.assertTrue((out_dir / "remediated_patch.tf").exists())

  def test_finding_remediator_normalizes_scc_and_wiz_examples(self):
    rem = _load_module(
        "plugins/scopeguard/skills/gcp-iam-finding-remediator/scripts/finding_remediator_cli.py",
        "test_rem_mod",
    )
    scc_doc = json.loads(
        (REPO_ROOT / "examples/sample-findings/scc_example_finding.json").read_text(
            encoding="utf-8"
        )
    )
    wiz_doc = json.loads(
        (REPO_ROOT / "examples/sample-findings/wiz_example_attack_path.json").read_text(
            encoding="utf-8"
        )
    )
    norm_scc = rem.normalize_inbound_finding(scc_doc, "scc")
    norm_wiz = rem.normalize_inbound_finding(wiz_doc, "wiz")
    self.assertEqual(norm_scc["source_platform"], "Google Cloud SCC")
    self.assertIn("cicd-deployer-sa", norm_scc["principal"])
    self.assertEqual(norm_wiz["source_platform"], "Wiz")
    self.assertIn("app-runtime-sa", norm_wiz["principal"])

  def test_role_architect_troubleshoot_403(self):
    arch = _load_module(
        "plugins/scopeguard/skills/gcp-iam-role-architect/scripts/role_architect_cli.py",
        "test_arch_mod",
    )
    with tempfile.TemporaryDirectory() as tmp:
      res = arch.troubleshoot_403_error(
          project_id="my-gcp-project",
          principal="serviceAccount:app@my-gcp-project.iam.gserviceaccount.com",
          error_text=(
              "403 PERMISSION_DENIED: Permission 'secretmanager.versions.access' "
              "denied on resource 'projects/my-gcp-project/secrets/app-cfg/versions/latest'"
          ),
          output_dir=Path(tmp),
      )
      self.assertEqual(res["missing_permissions"], ["secretmanager.versions.access"])
      self.assertEqual(res["recommended_scope"], "secret")
      self.assertEqual(res["target_resource"], "app-cfg")
      self.assertTrue((Path(tmp) / "troubleshoot_403_fix.tf").exists())

  def test_bigquery_audit_table_validation_blocks_sql_injection(self):
    from lib.gcp_client import ScopeGuardGCPClient

    client = ScopeGuardGCPClient(quota_project="my-gcp-project")
    with self.assertRaises(ValueError):
      client.query_bigquery_audit_permissions(
          "my-gcp-project", "my-proj.ds.tbl; DROP TABLE users--"
      )
    with self.assertRaises(ValueError):
      client.query_bigquery_audit_permissions("my-gcp-project", "invalid_table")


if __name__ == "__main__":
  unittest.main()
