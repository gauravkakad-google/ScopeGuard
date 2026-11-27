#!/usr/bin/env python3
# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0

"""Tests for the GitOps PR guardrail (ART-10): plan JSON, HCL fallback, G5, coverage."""

from datetime import datetime, timedelta, timezone
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

_CLI = (PLUGIN_ROOT / "skills" / "gcp-iam-gitops-pr-guardrail" / "scripts"
        / "gitops_guardrail_cli.py")
_spec = importlib.util.spec_from_file_location("gitops_guardrail_under_test", _CLI)
gitops = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gitops)

NOW = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)


def _iso(ts: datetime) -> str:
  return ts.strftime("%Y-%m-%dT%H:%M:%SZ")


def _synthetic_plan() -> dict:
  """Plan with a module + for_each binding, a deletion, an update and an SA key."""
  owners = ["user:alice@example.com", "group:ops@example.com"]
  return {
      "format_version": "1.2",
      "terraform_version": "1.7.5",
      "planned_values": {"root_module": {"child_modules": []}},
      "resource_changes": [
          {
              # module + for_each instance granting roles/owner to a member list.
              "address": 'module.iam.google_project_iam_binding.this["owners"]',
              "module_address": "module.iam",
              "mode": "managed",
              "type": "google_project_iam_binding",
              "name": "this",
              "index": "owners",
              "change": {
                  "actions": ["create"],
                  "before": None,
                  "after": {"project": "p1", "role": "roles/owner",
                            "members": owners, "condition": []},
                  "after_unknown": {"members": [False, False]},
              },
          },
          {
              # Nested module, folder-level, expired condition + public principal.
              "address": 'module.org.module.folders.google_folder_iam_member.m["x"]',
              "module_address": "module.org.module.folders",
              "mode": "managed",
              "type": "google_folder_iam_member",
              "name": "m",
              "index": "x",
              "change": {
                  "actions": ["create"],
                  "before": None,
                  "after": {
                      "folder": "folders/123", "role": "roles/storage.admin",
                      "member": "allUsers",
                      "condition": [{
                          "title": "temp",
                          "expression": 'request.time < timestamp("'
                                        + _iso(NOW - timedelta(days=3)) + '")',
                      }],
                  },
                  "after_unknown": {},
              },
          },
          {
              # Deletion of an owner grant must NOT be flagged.
              "address": "google_organization_iam_member.legacy_owner",
              "mode": "managed",
              "type": "google_organization_iam_member",
              "name": "legacy_owner",
              "change": {
                  "actions": ["delete"],
                  "before": {"org_id": "999", "role": "roles/owner",
                             "member": "user:bob@example.com"},
                  "after": None,
              },
          },
          {
              # Update: only the newly added member should be evaluated.
              "address": "google_project_iam_binding.editors",
              "mode": "managed",
              "type": "google_project_iam_binding",
              "name": "editors",
              "change": {
                  "actions": ["update"],
                  "before": {"project": "p1", "role": "roles/editor",
                             "members": ["user:old@example.com",
                                         "user:gone@example.com"]},
                  "after": {"project": "p1", "role": "roles/editor",
                            "members": ["user:old@example.com",
                                        "user:new@example.com"]},
                  "after_unknown": {},
              },
          },
          {
              # Authoritative policy with policy_data JSON (SA scope).
              "address": "google_service_account_iam_policy.sa",
              "mode": "managed",
              "type": "google_service_account_iam_policy",
              "name": "sa",
              "change": {
                  "actions": ["create"],
                  "before": None,
                  "after": {
                      "service_account_id": "projects/p1/serviceAccounts/a@p1.iam.gserviceaccount.com",
                      "policy_data": json.dumps({"bindings": [{
                          "role": "roles/iam.serviceAccountTokenCreator",
                          "members": ["serviceAccount:ci@p1.iam.gserviceaccount.com"],
                      }]}),
                  },
                  "after_unknown": {},
              },
          },
          {
              # Computed member -> skipped with a reason.
              "address": "google_project_iam_member.computed",
              "mode": "managed",
              "type": "google_project_iam_member",
              "name": "computed",
              "change": {
                  "actions": ["create"],
                  "before": None,
                  "after": {"project": "p1", "role": "roles/viewer"},
                  "after_unknown": {"member": True},
              },
          },
          {
              # Unchanged grant: not evaluated by default.
              "address": "google_project_iam_member.unchanged",
              "mode": "managed",
              "type": "google_project_iam_member",
              "name": "unchanged",
              "change": {
                  "actions": ["no-op"],
                  "before": {"project": "p1", "role": "roles/owner", "member": "user:x@example.com"},
                  "after": {"project": "p1", "role": "roles/owner", "member": "user:x@example.com"},
              },
          },
          {
              "address": "google_service_account_key.k",
              "mode": "managed",
              "type": "google_service_account_key",
              "name": "k",
              "change": {"actions": ["create"], "before": None,
                         "after": {"service_account_id": "sa-1"}},
          },
          {
              "address": "google_storage_bucket.b",
              "mode": "managed",
              "type": "google_storage_bucket",
              "name": "b",
              "change": {"actions": ["create"], "before": None, "after": {"name": "b"}},
          },
      ],
  }


class TestPlanJsonMode(unittest.TestCase):
  """Plan mode resolves modules/for_each and respects change actions."""

  def setUp(self):
    self.tmp = tempfile.TemporaryDirectory()
    self.addCleanup(self.tmp.cleanup)
    self.plan = Path(self.tmp.name) / "plan.json"
    self.plan.write_text(json.dumps(_synthetic_plan(), indent=2), encoding="utf-8")
    self.out = Path(self.tmp.name) / "out"
    self.res = gitops.run_gitops_guardrail(
        "p1", Path(self.tmp.name), output_dir=self.out, plan_json=self.plan, now=NOW)
    self.viols = self.res["payload"]["violations"]

  def _by_rule(self, rule_id):
    return [v for v in self.viols if v["rule_id"] == rule_id]

  def test_module_for_each_binding_flags_every_member(self):
    g1 = [v for v in self._by_rule("G1_BASIC_ROLE_BLOCKED")
          if v["resource"] == 'module.iam.google_project_iam_binding.this["owners"]']
    self.assertEqual({v["principal"] for v in g1},
                     {"user:alice@example.com", "group:ops@example.com"})
    self.assertTrue(all(v["input_source"] == "plan_json" for v in g1))
    self.assertGreater(g1[0]["line"], 1)  # located in the pretty-printed plan

  def test_deletion_not_flagged_and_reported_as_removed(self):
    self.assertFalse([v for v in self.viols if "legacy_owner" in v["resource"]])
    removed = self.res["payload"]["removed_grants"]
    self.assertIn({"resource": "google_organization_iam_member.legacy_owner",
                   "role": "roles/owner", "principal": "user:bob@example.com"}, removed)
    self.assertIn("user:gone@example.com", {r["principal"] for r in removed})

  def test_update_only_flags_added_member(self):
    eds = [v for v in self.viols if v["resource"] == "google_project_iam_binding.editors"]
    self.assertEqual([v["principal"] for v in eds], ["user:new@example.com"])

  def test_folder_nested_module_rules(self):
    folder = [v for v in self.viols if "google_folder_iam_member" in v["resource"]]
    rules = {v["rule_id"] for v in folder}
    self.assertEqual(rules, {"G4_UNSCOPED_PROJECT_DATA_ROLE", "G6_PUBLIC_PRINCIPAL",
                             "G5_STALE_CONDITION_WINDOW"})
    self.assertEqual(folder[0]["scope"], "folder")

  def test_policy_data_and_sa_key(self):
    g3 = self._by_rule("G3_TRANSITIVE_ESCALATION_EDGE")
    self.assertEqual(g3[0]["resource"], "google_service_account_iam_policy.sa")
    self.assertEqual(g3[0]["scope"], "service_account")
    self.assertEqual(len(self._by_rule("G2_STATIC_SA_KEY")), 1)

  def test_unchanged_skipped_by_default_and_included_on_request(self):
    self.assertFalse([v for v in self.viols if "unchanged" in v["resource"]])
    res = gitops.run_gitops_guardrail("p1", Path(self.tmp.name), plan_json=self.plan,
                                      include_unchanged=True, now=NOW)
    self.assertTrue([v for v in res["payload"]["violations"]
                     if v["resource"] == "google_project_iam_member.unchanged"])

  def test_coverage_counts(self):
    cov = self.res["payload"]["coverage"]
    self.assertEqual(cov["input_mode"], "plan_json")
    self.assertEqual(cov["files_scanned"], 1)
    self.assertEqual(cov["resources_seen"], 9)
    # binding(for_each), folder member, editors update, SA policy, SA key.
    self.assertEqual(cov["resources_parsed"], 5)
    self.assertEqual(cov["resources_skipped_count"], 2)  # deletion + computed
    self.assertEqual(cov["resources_unchanged_not_evaluated"], 1)
    self.assertEqual(cov["resources_non_iam_ignored"], 1)
    self.assertEqual(cov["grants_evaluated"], 5)
    reasons = " ".join(s["reason"] for s in cov["resources_skipped"])
    self.assertIn("deleted in plan", reasons)
    self.assertIn("member is computed", reasons)
    self.assertFalse(any("Regex" in w for w in cov["warnings"]))
    self.assertEqual(self.res["summary"]["pr_gate_verdict"], "BLOCK_MERGE")

  def test_outputs_sarif_and_schema(self):
    for name in ("gitops_guardrail_results.json", "gitops_guardrail_report.md",
                 "gitops_guardrail.sarif.json", "scopeguard-iam-guardrail.yml",
                 "remediated_patch.tf"):
      self.assertTrue((self.out / name).exists(), name)
    results = json.loads((self.out / "gitops_guardrail_results.json").read_text())
    self.assertEqual(results["schema_version"], gitops.SCHEMA_VERSION)
    self.assertEqual(results["generated_at"], "2026-06-01T12:00:00Z")
    sarif = json.loads((self.out / "gitops_guardrail.sarif.json").read_text())
    self.assertEqual(sarif["version"], "2.1.0")
    self.assertIn("$schema", sarif)
    run = sarif["runs"][0]
    rule_ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
    self.assertEqual(len(rule_ids), len(set(rule_ids)))
    for result in run["results"]:
      self.assertIn(result["ruleId"], rule_ids)
      self.assertEqual(rule_ids[result["ruleIndex"]], result["ruleId"])
      self.assertIn(result["level"], ("error", "warning", "note"))
      self.assertGreaterEqual(
          result["locations"][0]["physicalLocation"]["region"]["startLine"], 1)
    self.assertEqual(run["properties"]["coverage"]["input_mode"], "plan_json")
    self.assertTrue(run["invocations"][0]["startTimeUtc"].endswith("Z"))
    md = (self.out / "gitops_guardrail_report.md").read_text()
    self.assertIn("## Coverage", md)

  def test_invalid_plan_reports_scan_error(self):
    bad = Path(self.tmp.name) / "tfplan"
    bad.write_bytes(b"PK\x03\x04binary planfile")
    res = gitops.run_gitops_guardrail("p1", Path(self.tmp.name), plan_json=bad, now=NOW)
    self.assertEqual(res["status"], "FAILED")
    self.assertEqual(res["summary"]["pr_gate_verdict"], "SCAN_ERROR")
    self.assertIn("terraform show -json", res["payload"]["error"])

  def test_planned_values_fallback_walks_child_modules(self):
    doc = {"planned_values": {"root_module": {"resources": [], "child_modules": [{
        "address": "module.a", "resources": [], "child_modules": [{
            "address": "module.a.module.b",
            "resources": [{
                "address": 'module.a.module.b.google_organization_iam_binding.x[0]',
                "mode": "managed", "type": "google_organization_iam_binding",
                "name": "x", "index": 0,
                "values": {"org_id": "1", "role": "roles/editor",
                           "members": ["user:z@example.com"]},
            }]}]}]}}}
    p = Path(self.tmp.name) / "pv.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    res = gitops.run_gitops_guardrail("p1", Path(self.tmp.name), plan_json=p, now=NOW)
    g1 = [v for v in res["payload"]["violations"] if v["rule_id"] == "G1_BASIC_ROLE_BLOCKED"]
    self.assertEqual(len(g1), 1)
    self.assertEqual(g1[0]["scope"], "organization")


class TestRegexFallback(unittest.TestCase):
  """HCL fallback parses members lists, folder/org resources and states coverage."""

  HCL = '''
# resource "google_project_iam_member" "commented_out" { role = "roles/owner" }
resource "google_project_iam_binding" "owners" {
  project = "p1"
  role    = "roles/owner"
  members = [
    "user:alice@example.com", # inline comment
    "group:ops@example.com",
    var.extra_member,
  ]
}

resource "google_organization_iam_member" "org_editor" {
  org_id = "999"
  role   = "roles/editor"
  member = "user:carol@example.com"
}

resource "google_folder_iam_binding" "dyn" {
  for_each = toset(var.roles)
  folder   = "folders/1"
  role     = each.value
  members  = ["user:d@example.com"]
}

resource "google_project_iam_policy" "authoritative" {
  project     = "p1"
  policy_data = data.google_iam_policy.admin.policy_data
}

data "google_iam_policy" "admin" {
  binding {
    role    = "roles/secretmanager.admin"
    members = ["serviceAccount:app@p1.iam.gserviceaccount.com"]
  }
}

module "iam" {
  source = "./modules/iam"
}
'''

  def setUp(self):
    self.tmp = tempfile.TemporaryDirectory()
    self.addCleanup(self.tmp.cleanup)
    self.dir = Path(self.tmp.name)
    (self.dir / "main.tf").write_text(self.HCL, encoding="utf-8")
    self.res = gitops.run_gitops_guardrail("p1", self.dir, now=NOW)
    self.viols = self.res["payload"]["violations"]
    self.cov = self.res["payload"]["coverage"]

  def test_members_list_parsed(self):
    owners = [v for v in self.viols if v["resource"] == "google_project_iam_binding.owners"]
    self.assertEqual({v["principal"] for v in owners},
                     {"user:alice@example.com", "group:ops@example.com"})
    self.assertEqual(owners[0]["line"], 3)
    self.assertFalse([v for v in self.viols if "commented_out" in v["resource"]])

  def test_org_resource_and_policy_document(self):
    org = [v for v in self.viols if v["resource"] == "google_organization_iam_member.org_editor"]
    self.assertEqual(org[0]["rule_id"], "G1_BASIC_ROLE_BLOCKED")
    self.assertEqual(org[0]["scope"], "organization")
    doc = [v for v in self.viols if v["resource"] == "data.google_iam_policy.admin"]
    self.assertEqual(doc[0]["rule_id"], "G4_UNSCOPED_PROJECT_DATA_ROLE")
    self.assertEqual(doc[0]["scope"], "project")

  def test_coverage_reports_skips_and_warning(self):
    cov = self.cov
    self.assertEqual(cov["input_mode"], "regex_hcl")
    self.assertEqual(cov["files_scanned"], 1)
    self.assertEqual(cov["resources_seen"], 5)
    # owners, org_editor, authoritative (via data), data doc.
    self.assertEqual(cov["resources_parsed"], 4)
    skipped = {s["resource"]: s["reason"] for s in cov["resources_skipped"]}
    self.assertIn("google_folder_iam_binding.dyn", skipped)
    self.assertIn("for_each", skipped["google_folder_iam_binding.dyn"])
    self.assertIn("module.iam", skipped)
    self.assertEqual(cov["resources_skipped_count"], 2)
    partial = " ".join(p["reason"] for p in cov["resources_partially_evaluated"])
    self.assertIn("var.extra_member", partial)
    self.assertTrue(any("Regex/HCL fallback" in w for w in cov["warnings"]))
    sarif_cov = self.res["payload"]["sarif"]["runs"][0]["properties"]["coverage"]
    self.assertEqual(sarif_cov["resources_skipped_count"], 2)

  def test_legacy_single_file_member_still_detected(self):
    f = self.dir / "single.tf"
    f.write_text('resource "google_project_iam_member" "bad_editor" {\n'
                 '  project = "p1"\n  role    = "roles/editor"\n'
                 '  member  = "serviceAccount:app@p1.iam.gserviceaccount.com"\n}\n',
                 encoding="utf-8")
    res = gitops.run_gitops_guardrail("p1", f, now=NOW)
    self.assertEqual(res["summary"]["pr_gate_verdict"], "BLOCK_MERGE")
    self.assertEqual(res["summary"]["total_violations"], 1)


class TestG5RelativeDates(unittest.TestCase):
  """G5 is computed against the scan time, not hard-coded years."""

  def _scan(self, expr, max_days=90):
    hcl = ('resource "google_project_iam_member" "c" {\n'
           '  project = "p1"\n  role    = "roles/viewer"\n'
           '  member  = "user:a@example.com"\n'
           '  condition {\n    title      = "t"\n'
           f'    expression = "{expr}"\n  }}\n}}\n')
    with tempfile.TemporaryDirectory() as tmp:
      p = Path(tmp) / "c.tf"
      p.write_text(hcl, encoding="utf-8")
      res = gitops.run_gitops_guardrail("p1", p, max_expiry_days=max_days, now=NOW)
    return [v["rule_id"] for v in res["payload"]["violations"]]

  def _expr(self, ts, op="<"):
    return f'request.time {op} timestamp(\\"{_iso(ts)}\\")'

  def test_expired_upper_bound_flagged(self):
    self.assertEqual(self._scan(self._expr(NOW - timedelta(hours=1))),
                     ["G5_STALE_CONDITION_WINDOW"])

  def test_near_future_expiry_clean(self):
    self.assertEqual(self._scan(self._expr(NOW + timedelta(days=30))), [])

  def test_far_future_expiry_flagged_and_configurable(self):
    far = self._expr(NOW + timedelta(days=200))
    self.assertEqual(self._scan(far), ["G5_LONG_LIVED_CONDITION_WINDOW"])
    self.assertEqual(self._scan(far, max_days=365), [])

  def test_past_start_time_is_not_stale(self):
    self.assertEqual(self._scan(self._expr(NOW - timedelta(days=400), op=">")), [])

  def test_year_2025_not_special_when_in_future(self):
    # A 2025 timestamp would have been flagged by the old hard-coded rule;
    # relative to a 2024 scan time it is a valid, near-future expiry.
    early_now = datetime(2025, 1, 1, tzinfo=timezone.utc)
    grant = gitops._make_grant(  # pylint: disable=protected-access
        address="a", res_type="google_project_iam_member", role="roles/viewer",
        members=["user:a@example.com"],
        condition_expr='request.time < timestamp("2025-02-01T00:00:00Z")',
        file="f", line=1, change_action="create", source="plan_json", scope="project")
    self.assertEqual(gitops.evaluate_grant(grant, early_now, 90), [])
    self.assertEqual(
        [f["rule_id"] for f in gitops.evaluate_grant(grant, NOW, 90)],
        ["G5_STALE_CONDITION_WINDOW"])

  def test_reverse_comparison_detected(self):
    ts = _iso(NOW - timedelta(days=1))
    parsed = gitops.analyze_condition_timestamps(f'timestamp("{ts}") > request.time')
    self.assertEqual(parsed[0][2], "upper")


class TestCiGateAndPrComment(unittest.TestCase):
  """Tests Shift-Left CI exit-code gating (--fail-on) and PR comment Markdown."""

  def _write_tf(self, directory: Path, name: str, content: str) -> Path:
    p = directory / name
    p.write_text(content, encoding="utf-8")
    return p

  def test_fail_on_exit_codes_via_cli_and_helper(self):
    with tempfile.TemporaryDirectory() as tmp:
      root = Path(tmp)
      out = root / "out"
      # CRITICAL violation (roles/owner)
      crit_tf = self._write_tf(
          root,
          "crit.tf",
          'resource "google_project_iam_member" "owner" {\n'
          '  project = "p1"\n  role    = "roles/owner"\n'
          '  member  = "user:alice@example.com"\n}\n',
      )
      # Default --fail-on=NONE exits 0 even with CRITICAL findings.
      rc_none = gitops.main([
          "--project=p1", f"--scan-path={crit_tf}", f"--output-dir={out}",
          "--local-only",
      ])
      self.assertEqual(rc_none, 0)
      # --fail-on=HIGH exits 2 on CRITICAL finding.
      rc_high = gitops.main([
          "--project=p1", f"--scan-path={crit_tf}", f"--output-dir={out}",
          "--local-only", "--fail-on=HIGH",
      ])
      self.assertEqual(rc_high, 2)
      # --fail-on=CRITICAL exits 2 on CRITICAL finding.
      rc_crit = gitops.main([
          "--project=p1", f"--scan-path={crit_tf}", f"--output-dir={out}",
          "--local-only", "--fail-on=CRITICAL",
      ])
      self.assertEqual(rc_crit, 2)

      # MEDIUM-only violation (expired condition on roles/viewer).
      med_tf = self._write_tf(
          root,
          "med.tf",
          'resource "google_project_iam_member" "stale" {\n'
          '  project = "p1"\n  role    = "roles/viewer"\n'
          '  member  = "user:alice@example.com"\n'
          '  condition {\n    title = "old"\n'
          '    expression = "request.time < timestamp(\\"2020-01-01T00:00:00Z\\")"\n'
          '  }\n}\n',
      )
      # Below HIGH threshold -> exit 0.
      self.assertEqual(
          gitops.main([
              "--project=p1", f"--scan-path={med_tf}", f"--output-dir={out}",
              "--local-only", "--fail-on=HIGH",
          ]),
          0,
      )
      # Meets MEDIUM threshold -> exit 2.
      self.assertEqual(
          gitops.main([
              "--project=p1", f"--scan-path={med_tf}", f"--output-dir={out}",
              "--local-only", "--fail-on=MEDIUM",
          ]),
          2,
      )
      # ANY with >= 1 violation -> exit 2.
      self.assertEqual(
          gitops.main([
              "--project=p1", f"--scan-path={med_tf}", f"--output-dir={out}",
              "--local-only", "--fail-on=ANY",
          ]),
          2,
      )

      # Clean file -> exit 0 even with --fail-on=ANY.
      clean_tf = self._write_tf(
          root,
          "clean.tf",
          'resource "google_project_iam_member" "ok" {\n'
          '  project = "p1"\n  role    = "roles/viewer"\n'
          '  member  = "user:alice@example.com"\n}\n',
      )
      self.assertEqual(
          gitops.main([
              "--project=p1", f"--scan-path={clean_tf}", f"--output-dir={out}",
              "--local-only", "--fail-on=ANY",
          ]),
          0,
      )

      # Invalid plan JSON -> SCAN_ERROR -> exit 3 when --fail-on != NONE.
      bad_plan = root / "bad_plan.json"
      bad_plan.write_text("{not-valid-json", encoding="utf-8")
      self.assertEqual(
          gitops.main([
              "--project=p1", f"--plan-json={bad_plan}", f"--output-dir={out}",
              "--local-only", "--fail-on=HIGH",
          ]),
          3,
      )

  def test_pr_comment_md_written_to_output_dir_and_custom_path(self):
    with tempfile.TemporaryDirectory() as tmp:
      root = Path(tmp)
      out = root / "out"
      custom_comment = root / "nested" / "pr_comment.md"
      tf = self._write_tf(
          root,
          "bad.tf",
          'resource "google_project_iam_member" "bad_owner" {\n'
          '  project = "p1"\n  role    = "roles/owner"\n'
          '  member  = "serviceAccount:app@p1.iam.gserviceaccount.com"\n}\n',
      )
      rc = gitops.main([
          "--project=p1", f"--scan-path={tf}", f"--output-dir={out}",
          f"--pr-comment-md={custom_comment}", "--local-only", "--fail-on=HIGH",
      ])
      self.assertEqual(rc, 2)
      default_comment = out / "gitops_pr_comment.md"
      self.assertTrue(default_comment.is_file())
      self.assertTrue(custom_comment.is_file())
      text = custom_comment.read_text(encoding="utf-8")
      self.assertEqual(text, default_comment.read_text(encoding="utf-8"))
      self.assertIn("BLOCK_MERGE", text)
      self.assertIn("G1_BASIC_ROLE_BLOCKED", text)
      self.assertIn("google_project_iam_member.bad_owner", text)
      self.assertIn("bad.tf:1", text)
      self.assertIn("```hcl", text)
      self.assertIn("customLeastPrivilegeRole", text)


class TestOrchestratorAndUnifiedIntegration(unittest.TestCase):
  """Tests orchestrator fast-path/pass-through guards and unified F8/WIF/confidence."""

  def test_principal_filter_and_kwarg_guard(self):
    pipe_path = (
        PLUGIN_ROOT / "skills" / "scopeguard-orchestrator" / "scripts"
        / "scopeguard_pipeline.py"
    )
    spec = importlib.util.spec_from_file_location("scopeguard_pipeline_test", pipe_path)
    pipe = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(pipe)

    analysis = {
        "metadata": {"policy_etag": "etag-123", "project_id": "p1"},
        "principal_mappings": [
            {"principal": "serviceAccount:target@p1.iam.gserviceaccount.com",
             "persona_role_id": "sg_persona_target"},
            {"principal": "user:other@example.com", "persona_role_id": "sg_persona_other"},
        ],
        "findings": {
            "F1_basic_roles": [
                {"principal": "serviceAccount:target@p1.iam.gserviceaccount.com", "role": "roles/editor"},
                {"principal": "user:other@example.com", "role": "roles/owner"},
            ],
        },
        "custom_roles_model_a": {
            "sg_persona_target": {"role_id": "sg_persona_target", "members": ["serviceAccount:target@p1.iam.gserviceaccount.com"]},
            "sg_persona_other": {"role_id": "sg_persona_other", "members": ["user:other@example.com"]},
        },
        "summary": {"total_principals": 2},
    }
    filtered = pipe._filter_analysis_for_principal(  # pylint: disable=protected-access
        analysis, "serviceAccount:target@p1.iam.gserviceaccount.com"
    )
    self.assertEqual(filtered["metadata"]["policy_etag"], "etag-123")
    self.assertEqual(len(filtered["principal_mappings"]), 1)
    self.assertEqual(len(filtered["findings"]["F1_basic_roles"]), 1)
    self.assertEqual(list(filtered["custom_roles_model_a"].keys()), ["sg_persona_target"])
    self.assertEqual(filtered["summary"]["total_principals"], 1)

    def _stub(project_id, analysis_data):
      return (project_id, analysis_data)

    guarded = pipe._filter_supported_kwargs(  # pylint: disable=protected-access
        _stub, {"project_id": "p1", "analysis_data": {}, "policy_data": {"etag": "x"}}
    )
    self.assertNotIn("policy_data", guarded)
    self.assertEqual(set(guarded.keys()), {"project_id", "analysis_data"})

  def test_unified_f8_wif_confidence_and_attack_path(self):
    from lib import findings_engine as fe  # pylint: disable=import-outside-toplevel
    from lib import recommendation_synthesizer as rs  # pylint: disable=import-outside-toplevel

    env = {
        "schema_version": "2.1",
        "run_id": "r1",
        "project_id": "p1",
        "timestamp_utc": "2026-11-23T00:00:00Z",
        "modules": {
            "recommender_audit": {
                "status": "COMPLETED",
                "freshness": "CURRENT",
                "summary": {"total_principals": 1},
                "payload": {
                    "analysis": {
                        "findings": {
                            "F8_ai_agent_blast_radius": [{
                                "principal": "serviceAccount:ai-agent@p1.iam.gserviceaccount.com",
                                "severity": "CRITICAL",
                                "roles": ["roles/editor"],
                                "signals": ["vertex-ai-agent"],
                            }],
                        },
                        "principal_mappings": [],
                    }
                },
            },
            "breakglass_simulator": {
                "status": "COMPLETED",
                "freshness": "CURRENT",
                "summary": {
                    "simulated_403_denials": 0,
                    "cutover_verdict": "SAFE_TO_CUTOVER",
                    "audit_log_confidence": "LOW",
                    "recommended_cutover": "CANARY_DUAL_BIND",
                },
                "payload": {},
            },
            "federation_architect": {
                "status": "COMPLETED",
                "freshness": "CURRENT",
                "summary": {"user_managed_keys_found": 0, "wif_migration_candidates": 0},
                "payload": {
                    "existing_wif_audit": {
                        "findings": [{
                            "provider": "github-provider",
                            "rule_id": "WIF_NO_ATTRIBUTE_CONDITION",
                            "severity": "HIGH",
                            "title": "WIF provider missing CEL attribute_condition",
                        }]
                    }
                },
            },
            "finding_remediator": {
                "status": "COMPLETED",
                "freshness": "CURRENT",
                "summary": {"findings_ingested": 1},
                "payload": {
                    "remediation_plans": [{
                        "source_platform": "Wiz",
                        "finding_id": "wiz-42",
                        "severity": "CRITICAL",
                        "principal": "serviceAccount:ai-agent@p1.iam.gserviceaccount.com",
                        "replacement_role": "projects/p1/roles/sg_persona_ai",
                        "replacement_permissions_count": 5,
                        "simulated_403_denials": 0,
                        "status": "READY",
                        "attack_path_summary": "Internet -> Cloud Run -> ai-agent SA -> BigQuery exfil",
                        "choke_point": "roles/editor on ai-agent SA",
                    }]
                },
            },
        },
    }
    findings = fe.normalize_findings(env)
    cats = {f["category"]: f for f in findings}
    self.assertIn("ai_agent_blast_radius", cats)
    self.assertEqual(cats["ai_agent_blast_radius"]["severity"], "CRITICAL")
    self.assertEqual(cats["ai_agent_blast_radius"]["priority"], "P1")
    self.assertEqual(
        cats["ai_agent_blast_radius"]["deliverable"],
        "custom-roles/personas/ + deny-policies/deny_policies.tf (D5)",
    )
    self.assertIn("wif_provider_misconfig", cats)
    self.assertEqual(cats["wif_provider_misconfig"]["severity"], "HIGH")
    self.assertEqual(cats["wif_provider_misconfig"]["priority"], "P1")
    self.assertEqual(
        cats["wif_provider_misconfig"]["deliverable"],
        "federation-wif/WIF_MIGRATION.md",
    )

    docs = rs.render_audience_documents(env, findings)
    exec_md = docs["EXECUTIVE_SUMMARY.md"]
    plan_md = docs["REMEDIATION_PLAN.md"]
    self.assertIn("LOW", exec_md)
    self.assertIn("CANARY_DUAL_BIND", exec_md)
    self.assertIn("--canary", exec_md)
    self.assertIn("AI agent blast-radius findings (F8)", exec_md)
    self.assertIn("Existing WIF provider misconfigurations", exec_md)
    self.assertIn("choke point", exec_md.lower())
    self.assertIn("LOW", plan_md)
    self.assertIn("CANARY_DUAL_BIND", plan_md)
    self.assertIn("--canary", plan_md)
    self.assertIn("choke point", plan_md.lower())


if __name__ == "__main__":
  unittest.main()
