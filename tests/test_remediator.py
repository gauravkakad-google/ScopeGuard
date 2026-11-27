#!/usr/bin/env python3
# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0

"""Tests for the finding remediator deliverables (ART-1, ART-2, ART-4, ART-8).

All tests use synthetic findings, policies and fake clients: zero GCP calls.
"""

import datetime
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = Path(__file__).resolve().parent.parent
PLUGIN_ROOT = REPO_ROOT / "plugins" / "scopeguard"
SCRIPTS = PLUGIN_ROOT / "skills" / "gcp-iam-finding-remediator" / "scripts"
for _p in (PLUGIN_ROOT, SCRIPTS):
  if str(_p) not in sys.path:
    sys.path.insert(0, str(_p))

from lib.envelope_schema import SCHEMA_VERSION  # noqa: E402


def _load_cli():
  spec = importlib.util.spec_from_file_location(
      "test_remediator_cli_mod", SCRIPTS / "finding_remediator_cli.py"
  )
  mod = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(mod)
  return mod


REM = _load_cli()
import remediator_verify  # noqa: E402  (importable once the CLI put SCRIPTS on sys.path)

PROJECT = "my-gcp-project"
SA = "serviceAccount:cicd-deployer-sa@my-gcp-project.iam.gserviceaccount.com"
SA2 = "serviceAccount:app-runtime-sa@my-gcp-project.iam.gserviceaccount.com"
ROLE_ID = "sg_persona_cicd_deployer"
NEW_ROLE = f"projects/{PROJECT}/roles/{ROLE_ID}"
COND = {"title": "until_2030", "expression": 'request.time < timestamp("2030-01-01T00:00:00Z")'}


def _findings():
  """Two synthetic findings: one with role evidence, one without."""
  scc = {
      "name": "organizations/1/sources/2/findings/scc-finding-001",
      "category": "OVERPRIVILEGED_SERVICE_ACCOUNT",
      "severity": "HIGH",
      "sourceProperties": {
          "Principal": SA,
          "Roles": ["roles/run.developer", "roles/iam.serviceAccountUser", "roles/cloudbuild.builds.editor"],
          "Recommendation": "Replace with least privilege.",
      },
  }
  wiz = {
      "id": "wiz-issue-002",
      "source": "Wiz",
      "severity": "CRITICAL",
      "control": {"id": "WC-1", "name": "Broad admin roles"},
      "entitySnapshot": {"externalId": SA2},
      "roles": ["roles/storage.admin"],
  }
  return [REM.normalize_inbound_finding(scc, "scc"), REM.normalize_inbound_finding(wiz, "wiz")]


def _policy(etag="BwAssess"):
  return {
      "etag": etag,
      "version": 3,
      "bindings": [
          {"role": "roles/run.developer", "members": [SA]},
          {"role": "roles/iam.serviceAccountUser", "members": [SA], "condition": COND},
          {"role": "roles/storage.admin", "members": [SA2]},
      ],
  }


def _analysis():
  return {
      "principal_mappings": [
          {"principal": SA, "persona_role_id": ROLE_ID, "target_mapping": NEW_ROLE},
      ],
      "custom_roles_model_a": {
          ROLE_ID: {
              "role_id": ROLE_ID,
              "title": "SG Persona · Cicd Deployer",
              "description": "Least privilege for CI/CD",
              "stage": "GA",
              "includedPermissions": ["run.services.get", "cloudbuild.builds.create"],
          }
      },
  }


def _simulation(denials=0):
  return {
      "status": "COMPLETED",
      "summary": {"simulated_403_denials": 23, "cutover_verdict": "HOLD_REQUIRES_PERMISSION_DELTA"},
      "payload": {"principal_replays": [{
          "principal": SA, "simulated_403_denials": denials, "verdict": "PASS" if not denials else "HOLD",
          "replay_coverage_pct": 97.5, "replayed_api_calls": 120,
          "uncovered_permissions": ["run.services.delete"] if denials else [],
          "proposed_model_a_role": ROLE_ID,
      }]},
  }


class _FakeClient:
  """Fake ScopeGuardGCPClient for verify-mode tests."""

  def __init__(self, policy=None, policy_exc=None, log_entries=None, log_exc=None):
    self.policy, self.policy_exc = policy, policy_exc
    self.log_entries, self.log_exc = log_entries or [], log_exc
    self.log_requests = []

  def fetch_project_iam_policy(self, project_id):
    if self.policy_exc:
      raise self.policy_exc
    return self.policy

  def request_json(self, url, method="GET", body=None, service_key="iam", include_quota_project=False):
    self.log_requests.append({"url": url, "method": method, "body": body})
    if self.log_exc:
      raise self.log_exc
    return {"entries": self.log_entries}


class TestRemediatorArtifacts(unittest.TestCase):
  """ART-1 / ART-2 / ART-4 / ART-8 generation."""

  def setUp(self):
    self.tmp = Path(tempfile.mkdtemp())
    self.out = self.tmp / "finding-remediation"

  def tearDown(self):
    shutil.rmtree(self.tmp, ignore_errors=True)

  def _run(self, **kw):
    return REM.run_finding_remediator(
        project_id=PROJECT, inbound_findings=_findings(), analysis_data=kw.pop("analysis", _analysis()),
        policy_data=kw.pop("policy", _policy()), gcp_client=None, output_dir=self.out, **kw
    )

  def test_terraform_module_complete_and_non_authoritative(self):
    self._run(simulation_data=_simulation())
    tf = self.out / "terraform"
    for name in ("versions.tf", "variables.tf", "main.tf", "README.md", "old_bindings_import.tf.example"):
      self.assertTrue((tf / name).is_file(), name)
    self.assertTrue((self.out / "remediation_patch.tf").is_file())
    self.assertFalse((self.out / "remediated_patch.tf").exists())
    main = (tf / "main.tf").read_text(encoding="utf-8")
    self.assertIn('resource "google_project_iam_custom_role"', main)
    self.assertIn('resource "google_project_iam_member"', main)
    self.assertIn("depends_on = [google_project_iam_custom_role.", main)
    self.assertIn('"run.services.get"', main)
    # The new grant inherits nothing broader: old bindings differ in condition -> unconditional.
    for path in list(tf.glob("*.tf")) + [self.out / "remediation_patch.tf"]:
      text = path.read_text(encoding="utf-8")
      self.assertNotIn("google_project_iam_binding", text, path.name)
      self.assertNotIn("google_project_iam_policy", text, path.name)
    self.assertIn('required_providers', (tf / "versions.tf").read_text(encoding="utf-8"))
    self.assertIn('variable "project_id"', (tf / "variables.tf").read_text(encoding="utf-8"))
    readme = (tf / "README.md").read_text(encoding="utf-8")
    self.assertIn("removed {", readme)
    self.assertIn("terraform state rm", readme)
    self.assertIn("terraform import google_project_iam_custom_role.", readme)
    # Old conditional binding is importable with its condition title.
    imp = (tf / "old_bindings_import.tf.example").read_text(encoding="utf-8")
    self.assertIn(f"{PROJECT} roles/iam.serviceAccountUser {SA} until_2030", imp)
    self.assertIn("condition {", imp)

  def test_authoritative_opt_in_writes_warning(self):
    res = self._run(authoritative=True)
    main = (self.out / "terraform" / "main.tf").read_text(encoding="utf-8")
    self.assertIn('resource "google_project_iam_binding"', main)
    self.assertNotIn("google_project_iam_policy", main)
    self.assertIn("AUTHORITATIVE", main)
    self.assertTrue((self.out / "AUTHORITATIVE_TERRAFORM_WARNING.md").is_file())
    self.assertEqual(res["summary"]["terraform_mode"], "authoritative")

  def test_hcl_escaping_blocks_interpolation(self):
    import remediator_terraform  # pylint: disable=import-outside-toplevel
    self.assertEqual(remediator_terraform.hcl_str('a"${b}%{c}\n'), '"a\\"$${b}%%{c}\\n"')
    self.assertTrue(remediator_terraform.tf_name("123-abc").startswith("r_"))

  def test_runbook_syntax_dry_run_default_and_etag(self):
    self._run(simulation_data=_simulation())
    sh = self.out / "remediation_commands.sh"
    self.assertTrue(os.stat(sh).st_mode & stat.S_IXUSR)
    text = sh.read_text(encoding="utf-8")
    self.assertEqual(subprocess.run(["bash", "-n", str(sh)], check=False).returncode, 0)
    self.assertIn("APPLY=0", text)
    self.assertIn("EXPECTED_ETAG=BwAssess", text)
    self.assertIn("add_scc-finding-001", text.replace("add_scc_finding_001", "add_scc-finding-001"))
    self.assertIn("custom-roles/personas/sg_persona_cicd_deployer.yaml", text)
    self.assertTrue((self.out / "custom-roles" / "personas" / f"{ROLE_ID}.yaml").is_file())
    # Conditional old binding is removed with its condition, not --condition=None.
    self.assertIn("--condition-from-file", text)
    # Add must come before remove in main().
    self.assertLess(text.index('"add_${id'), text.index('"remove_${id'))

  def test_runbook_dry_run_executes_no_mutation(self):
    """Runs the script with a fake gcloud: default mode must not mutate IAM."""
    self._run(simulation_data=_simulation())
    fake_bin = self.tmp / "bin"
    fake_bin.mkdir()
    calls = self.tmp / "gcloud_calls.log"
    gcloud = fake_bin / "gcloud"
    gcloud.write_text(
        "#!/usr/bin/env bash\n"
        f"echo \"$*\" >> {json.dumps(str(calls))}\n"
        "case \"$*\" in\n"
        "  *get-iam-policy*) echo BwAssess ;;\n"
        "  *get-value*) echo tester@example.com ;;\n"
        "  *roles\\ describe*) exit 1 ;;\n"
        "esac\n",
        encoding="utf-8",
    )
    gcloud.chmod(0o755)
    env = dict(os.environ, PATH=f"{fake_bin}:{os.environ.get('PATH', '')}")
    proc = subprocess.run(
        ["bash", str(self.out / "remediation_commands.sh")],
        env=env, capture_output=True, text=True, timeout=60, check=False,
    )
    self.assertEqual(proc.returncode, 0, proc.stderr)
    self.assertIn("[dry-run]", proc.stdout)
    logged = calls.read_text(encoding="utf-8")
    for verb in ("add-iam-policy-binding", "remove-iam-policy-binding", "set-iam-policy", "roles create"):
      self.assertNotIn(verb, logged)

  def test_ticket_note_contains_finding_id_and_real_simulator_numbers(self):
    res = self._run(simulation_data=_simulation(denials=0))
    md = (self.out / "ticket_proposed_remediation.md").read_text(encoding="utf-8")
    self.assertIn("scc-finding-001", md)
    self.assertIn("wiz-issue-002", md)
    self.assertIn("PROPOSED", md)
    self.assertIn("<JIRA/SNOW-ID>", md)
    self.assertIn("**Rollback**", md)
    self.assertIn("--verify", md)
    self.assertIn("120 replayed", md)
    self.assertIn("23 simulated HTTP 403(s) project-wide", md)
    self.assertFalse((self.out / "ticket_closure_notes.md").exists())
    doc = json.loads((self.out / "finding_remediations.json").read_text(encoding="utf-8"))
    self.assertEqual(doc["schema_version"], SCHEMA_VERSION)
    self.assertTrue(doc["generated_at"].endswith("Z"))
    self.assertEqual(doc["live_policy_etag"], "BwAssess")
    self.assertEqual(res["summary"]["simulated_403_denials"], 0)

  def test_art4_not_run_and_hold(self):
    res = self._run()  # no simulator data
    self.assertIsNone(res["summary"]["simulated_403_denials"])
    self.assertTrue(res["summary"]["simulated_403_display"].startswith("n/a (not run:"))
    md = (self.out / "ticket_proposed_remediation.md").read_text(encoding="utf-8")
    self.assertIn("n/a (not run:", md)
    self.assertNotIn("`0` simulated", md)
    shutil.rmtree(self.out)
    res = self._run(simulation_data=_simulation(denials=4))
    plan = next(p for p in res["payload"]["remediation_plans"] if p["finding_id"] == "scc-finding-001")
    self.assertEqual(plan["status"], "HOLD_SIMULATED_403")
    self.assertEqual(plan["simulated_403_denials"], 4)
    self.assertEqual(res["summary"]["remediation_readiness"], "HOLD_SIMULATED_403")

  def test_no_evidence_blocks_without_fabricated_roles(self):
    res = self._run(simulation_data=_simulation())
    wiz = next(p for p in res["payload"]["remediation_plans"] if p["finding_id"] == "wiz-issue-002")
    self.assertEqual(wiz["status"], "BLOCKED_NO_ROLE_EVIDENCE")
    self.assertEqual(wiz["add_bindings"], [])
    main = (self.out / "terraform" / "main.tf").read_text(encoding="utf-8")
    self.assertNotIn("app-runtime-sa", main)
    self.assertNotIn("customLeastPrivilegeWorkload", main)

  def test_role_yaml_on_disk_is_preferred(self):
    personas = self.tmp / "custom-roles" / "personas"
    personas.mkdir(parents=True)
    (personas / f"{ROLE_ID}.yaml").write_text(
        f"# Role ID: {ROLE_ID}\ntitle: \"From YAML\"\ndescription: \"yaml desc\"\nstage: \"GA\"\n"
        "includedPermissions:\n  - run.services.update\n",
        encoding="utf-8",
    )
    self._run(analysis={"principal_mappings": [{"principal": SA, "persona_role_id": ROLE_ID}]})
    main = (self.out / "terraform" / "main.tf").read_text(encoding="utf-8")
    self.assertIn('"From YAML"', main)
    self.assertIn('"run.services.update"', main)
    sh = (self.out / "remediation_commands.sh").read_text(encoding="utf-8")
    self.assertIn(f"../custom-roles/personas/{ROLE_ID}.yaml", sh)

  def test_invalid_principal_is_rejected(self):
    bad = [{"source_platform": "Wiz", "finding_id": "x", "principal": 'user:a$(rm -rf /)@b.com',
            "offending_roles": ["roles/owner"], "severity": "HIGH", "title": "t"}]
    res = REM.run_finding_remediator(PROJECT, bad, _analysis(), _policy(), None, self.out)
    self.assertEqual(res["payload"]["remediation_plans"][0]["status"], "BLOCKED_INVALID_INPUT")
    # The shared runbook template legitimately contains `rm -rf "${WORK_DIR}"`
    # in its cleanup trap, so assert on the injected payload itself.
    sh = (self.out / "remediation_commands.sh").read_text(encoding="utf-8")
    self.assertNotIn("$(rm -rf /)", sh)
    self.assertNotIn("a$(rm", sh)


class TestRemediatorVerify(unittest.TestCase):
  """ART-8 --verify logic with fake policy / logging."""

  def setUp(self):
    self.tmp = Path(tempfile.mkdtemp())
    REM.run_finding_remediator(PROJECT, _findings(), _analysis(), _policy(), None, self.tmp)

  def tearDown(self):
    shutil.rmtree(self.tmp, ignore_errors=True)

  def test_verified_after_apply(self):
    applied = {"etag": "BwAfter", "bindings": [
        {"role": NEW_ROLE, "members": [SA]},
        {"role": "roles/storage.admin", "members": [SA2]},
    ]}
    client = _FakeClient(policy=applied)
    out = REM.run_verify_mode(PROJECT, self.tmp, client, hours=6)
    res = next(r for r in out["results"] if r["finding_id"] == "scc-finding-001")
    self.assertEqual(res["overall"], "VERIFIED", res)
    self.assertEqual(out["summary"]["skipped"], 1)  # blocked Wiz finding
    body = client.log_requests[0]["body"]
    self.assertIn("protoPayload.status.code=7", body["filter"])
    self.assertIn("cicd-deployer-sa@my-gcp-project.iam.gserviceaccount.com", body["filter"])
    note = (self.tmp / "ticket_verification_note.md").read_text(encoding="utf-8")
    self.assertIn("scc-finding-001", note)
    self.assertIn("VERIFIED", note)
    doc = json.loads((self.tmp / "ticket_verification_note.json").read_text(encoding="utf-8"))
    self.assertEqual(doc["schema_version"], SCHEMA_VERSION)

  def test_failed_when_not_applied_and_denials(self):
    client = _FakeClient(policy=_policy(), log_entries=[{"protoPayload": {"methodName": "run.services.get"}}])
    out = REM.run_verify_mode(PROJECT, self.tmp, client)
    res = next(r for r in out["results"] if r["finding_id"] == "scc-finding-001")
    self.assertEqual(res["overall"], "FAILED")
    self.assertEqual(res["checks"]["old_roles_absent"]["status"], "FAIL")
    self.assertEqual(res["checks"]["new_bindings_present"]["status"], "FAIL")
    self.assertEqual(res["checks"]["etag_changed"]["status"], "FAIL")
    self.assertEqual(res["checks"]["no_recent_permission_denied"]["status"], "FAIL")

  def test_missing_permissions_degrade_gracefully(self):
    from lib.gcp_client import GCPHTTPError  # pylint: disable=import-outside-toplevel
    client = _FakeClient(policy_exc=GCPHTTPError(403, "Forbidden"), log_exc=GCPHTTPError(403, "Forbidden"))
    out = REM.run_verify_mode(PROJECT, self.tmp, client)
    res = next(r for r in out["results"] if r["finding_id"] == "scc-finding-001")
    self.assertEqual(res["overall"], "PARTIALLY_VERIFIED")
    for chk in res["checks"].values():
      self.assertEqual(chk["status"], "NOT_VERIFIED")
      self.assertIn("not verified", chk["detail"])

  def test_missing_plan_file_does_not_crash(self):
    empty = self.tmp / "empty"
    out = REM.run_verify_mode(PROJECT, empty, _FakeClient(policy=_policy()))
    self.assertTrue(out["plan_load_error"])
    self.assertTrue((empty / "ticket_verification_note.md").is_file())

  def test_group_member_logs_not_verified(self):
    chk = remediator_verify.query_permission_denied(
        _FakeClient(), PROJECT, "group:devs@example.com", 24,
        now=datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc),
    )
    self.assertEqual(chk["status"], "NOT_VERIFIED")

  def test_closed_loop_verification_note_fields(self):
    sim = _simulation(denials=0)
    sim["summary"]["audit_log_confidence"] = "HIGH"
    REM.run_finding_remediator(
        PROJECT, _findings(), _analysis(), _policy(), None, self.tmp, simulation_data=sim
    )
    applied = {"etag": "BwAfter", "bindings": [
        {"role": NEW_ROLE, "members": [SA]},
        {"role": "roles/storage.admin", "members": [SA2]},
    ]}
    out = REM.run_verify_mode(PROJECT, self.tmp, _FakeClient(policy=applied), hours=12)
    self.assertEqual(out["audit_log_confidence"], "HIGH")
    self.assertEqual(out["overall_status"], "VERIFIED")
    note = (self.tmp / "ticket_verification_note.md").read_text(encoding="utf-8")
    self.assertIn("Inbound SCC/Wiz Finding IDs", note)
    self.assertIn("`scc-finding-001` (Google Cloud SCC)", note)
    self.assertIn("`wiz-issue-002` (Wiz)", note)
    self.assertIn("Audit Log Confidence", note)
    self.assertIn("`HIGH`", note)
    self.assertIn("<!-- Paste PR URL -->", note)
    self.assertIn("Copy-Pasteable Ticket Verification Status", note)
    self.assertIn("Verification Status: VERIFIED | Finding: scc-finding-001 (Google Cloud SCC)", note)


class TestAttackPathAndCanary(unittest.TestCase):
  """Tests SCC/Wiz attack-path choke-point selection and dual-bind canary cutover."""

  def setUp(self):
    self.tmp = Path(tempfile.mkdtemp())
    self.out = self.tmp / "finding-remediation"

  def tearDown(self):
    shutil.rmtree(self.tmp, ignore_errors=True)

  def test_scc_toxic_combination_choke_point_prefers_non_critical_impersonation(self):
    scc_tc = {
        "finding": {
            "name": "organizations/1/sources/2/findings/scc-tc-001",
            "category": "TOXIC_COMBINATION",
            "severity": "CRITICAL",
            "toxicCombination": {"attackExposureScore": 9.8},
            "sourceProperties": {
                "Principal": SA,
                "Roles": ["roles/editor"],
                "Recommendation": "Break the toxic combination.",
            },
        },
        "attackPath": {
            "nodes": [
                {"id": "vm-1", "displayName": "public-web-vm", "resourceType": "compute.googleapis.com/Instance"},
                {"id": "sa-1", "displayName": SA, "resourceType": "iam.googleapis.com/ServiceAccount", "roles": ["roles/editor"]},
                {"id": "sa-admin", "displayName": "prod-admin-sa@my-gcp-project.iam.gserviceaccount.com", "resourceType": "iam.googleapis.com/ServiceAccount"},
            ],
            "edges": [
                {"source": "public-web-vm", "destination": SA, "edgeType": "ATTACHED_SA", "critical": True},
                {
                    "source": SA,
                    "destination": "prod-admin-sa@my-gcp-project.iam.gserviceaccount.com",
                    "permission": "iam.serviceAccounts.actAs",
                    "critical": False,
                },
            ],
        },
    }
    norm = REM.normalize_inbound_finding(scc_tc)
    self.assertEqual(norm["source_platform"], "Google Cloud SCC")
    self.assertEqual(norm["finding_id"], "scc-tc-001")
    self.assertEqual(norm["attack_exposure_score"], 9.8)

    policy = {"etag": "BwTC1", "version": 3, "bindings": [{"role": "roles/editor", "members": [SA]}]}
    res = REM.run_finding_remediator(
        PROJECT, [norm], _analysis(), policy, None, self.out, simulation_data=_simulation(0)
    )
    plan = res["payload"]["remediation_plans"][0]
    aps = plan["attack_path_summary"]
    self.assertIsNotNone(aps)
    self.assertEqual(aps["source_tool"], "Google Cloud SCC")
    self.assertEqual(aps["inbound_finding_id"], "scc-tc-001")
    self.assertEqual(aps["choke_point_strategy"], "sever_impersonation_edge")
    self.assertIn("iam.serviceAccounts.actAs", aps["choke_point_edge"])
    self.assertEqual(aps["attack_exposure_score"], 9.8)
    self.assertEqual(len(aps["hops"]), 3)
    md = (self.out / "ticket_proposed_remediation.md").read_text(encoding="utf-8")
    self.assertIn("**Attack-Path Choke-Point**", md)
    self.assertIn("iam.serviceAccounts.actAs", md)
    self.assertIn("9.8", md)

  def test_wiz_attack_path_falls_back_to_broad_role_when_impersonation_is_critical(self):
    wiz_ap = {
        "issueId": "wiz-ap-007",
        "source": "Wiz",
        "severity": "CRITICAL",
        "control": {"id": "WC-AP-1", "name": "VM to Project Owner via SA"},
        "entitySnapshot": {"externalId": SA},
        "roles": ["roles/owner"],
        "graph": {
            "nodes": [
                {"id": "n1", "name": "internet-vm", "type": "VM"},
                {"id": "n2", "name": SA, "type": "SERVICE_ACCOUNT", "roles": ["roles/owner"]},
                {"id": "n3", "name": "prod-target-sa", "type": "SERVICE_ACCOUNT"},
            ],
            "edges": [
                {
                    "source": SA,
                    "target": "prod-target-sa",
                    "permission": "iam.serviceAccounts.getAccessToken",
                    "isCritical": True,
                }
            ],
        },
    }
    norm = REM.normalize_inbound_finding(wiz_ap)
    self.assertEqual(norm["source_platform"], "Wiz")
    self.assertEqual(norm["finding_id"], "wiz-ap-007")
    policy = {"etag": "BwWiz1", "version": 3, "bindings": [{"role": "roles/owner", "members": [SA]}]}
    res = REM.run_finding_remediator(PROJECT, [norm], _analysis(), policy, None, self.out)
    plan = res["payload"]["remediation_plans"][0]
    aps = plan["attack_path_summary"]
    self.assertIsNotNone(aps)
    self.assertEqual(aps["source_tool"], "Wiz")
    self.assertEqual(aps["inbound_finding_id"], "wiz-ap-007")
    self.assertEqual(aps["choke_point_strategy"], "replace_broad_role_with_persona")
    self.assertIn("roles/owner", aps["choke_point_edge"])
    self.assertIn(ROLE_ID, aps["choke_point_edge"])
    md = (self.out / "ticket_proposed_remediation.md").read_text(encoding="utf-8")
    self.assertIn("**Attack-Path Choke-Point**", md)
    self.assertIn(ROLE_ID, md)

  def test_canary_flag_generates_dual_bind_scripts_and_docs(self):
    res = REM.run_finding_remediator(
        PROJECT, _findings(), _analysis(), _policy(), None, self.out,
        simulation_data=_simulation(0), canary=True,
    )
    self.assertTrue(res["summary"]["canary_mode"])
    self.assertEqual(res["summary"]["canary_reason"], "explicit_flag")
    step1 = self.out / "canary_step1_bind_least_privilege.sh"
    step2 = self.out / "canary_step2_remove_broad_role.sh"
    for script in (step1, step2):
      self.assertTrue(script.is_file(), script.name)
      self.assertTrue(os.stat(script).st_mode & stat.S_IXUSR)
      self.assertEqual(subprocess.run(["bash", "-n", str(script)], check=False).returncode, 0)
      text = script.read_text(encoding="utf-8")
      self.assertIn("APPLY=0", text)
    s1_text = step1.read_text(encoding="utf-8")
    s2_text = step2.read_text(encoding="utf-8")
    self.assertIn("add-iam-policy-binding", s1_text)
    self.assertNotIn("remove-iam-policy-binding", s1_text)
    self.assertIn("roles create", s1_text)
    self.assertIn("remove-iam-policy-binding", s2_text)
    self.assertNotIn("add-iam-policy-binding", s2_text)
    ticket_md = (self.out / "ticket_proposed_remediation.md").read_text(encoding="utf-8")
    tf_readme = (self.out / "terraform" / "README.md").read_text(encoding="utf-8")
    self.assertIn("Dual-Bind Canary Cutover", ticket_md)
    self.assertIn("canary_step1_bind_least_privilege.sh", ticket_md)
    self.assertIn("canary_step2_remove_broad_role.sh", ticket_md)
    self.assertIn("Dual-Bind Canary Cutover", tf_readme)
    self.assertIn("canary_step1_bind_least_privilege.sh", tf_readme)

  def test_auto_canary_when_audit_log_confidence_is_low(self):
    low_sim = _simulation(0)
    low_sim["summary"]["audit_log_confidence"] = "LOW"
    res = REM.run_finding_remediator(
        PROJECT, _findings(), _analysis(), _policy(), None, self.out,
        simulation_data=low_sim, canary=False,
    )
    self.assertTrue(res["summary"]["canary_mode"])
    self.assertEqual(res["summary"]["canary_reason"], "auto_low_audit_log_confidence")
    self.assertEqual(res["summary"]["audit_log_confidence"], "LOW")
    step1 = self.out / "canary_step1_bind_least_privilege.sh"
    step2 = self.out / "canary_step2_remove_broad_role.sh"
    self.assertTrue(step1.is_file())
    self.assertTrue(step2.is_file())
    self.assertEqual(subprocess.run(["bash", "-n", str(step1)], check=False).returncode, 0)
    self.assertEqual(subprocess.run(["bash", "-n", str(step2)], check=False).returncode, 0)
    ticket_md = (self.out / "ticket_proposed_remediation.md").read_text(encoding="utf-8")
    self.assertIn("audit_log_confidence == LOW", ticket_md)
    tf_readme = (self.out / "terraform" / "README.md").read_text(encoding="utf-8")
    self.assertIn("audit_log_confidence == LOW", tf_readme)

  def test_fetch_live_wiz_returns_empty_without_env_vars(self):
    from unittest import mock
    with mock.patch.dict("os.environ", {"WIZ_CLIENT_ID": "", "WIZ_CLIENT_SECRET": "", "WIZ_API_URL": ""}, clear=False):
      self.assertEqual(REM.fetch_live_wiz_iam_findings(PROJECT), [])

  def test_fetch_live_wiz_parses_iam_issues_and_filters_project(self):
    import io
    from unittest import mock

    class _FakeResp:
      def __init__(self, payload):
        self._buf = io.BytesIO(json.dumps(payload).encode("utf-8"))
      def read(self):
        return self._buf.read()
      def __enter__(self):
        return self
      def __exit__(self, *args):
        return False

    gql_data = {
        "data": {
            "issues": {
                "nodes": [
                    {
                        "id": "wiz-live-1",
                        "severity": "HIGH",
                        "control": {"id": "WC-1", "name": "Overprivileged IAM Service Account"},
                        "entitySnapshot": {
                            "name": SA,
                            "type": "SERVICE_ACCOUNT",
                            "subscriptionExternalId": PROJECT,
                        },
                    },
                    {
                        "id": "wiz-other-proj",
                        "severity": "HIGH",
                        "control": {"id": "WC-2", "name": "IAM Admin Role"},
                        "entitySnapshot": {
                            "name": "other-sa",
                            "type": "SERVICE_ACCOUNT",
                            "subscriptionExternalId": "other-project",
                        },
                    },
                ]
            }
        }
    }
    env = {
        "WIZ_CLIENT_ID": "cid",
        "WIZ_CLIENT_SECRET": "csec",
        "WIZ_API_URL": "https://api.us1.app.wiz.io/graphql",
    }
    with mock.patch.dict("os.environ", env, clear=False), \
         mock.patch.object(REM.urllib_request, "urlopen", side_effect=[
             _FakeResp({"access_token": "tok-123"}),
             _FakeResp(gql_data),
         ]):
      findings = REM.fetch_live_wiz_iam_findings(PROJECT)
    self.assertEqual(len(findings), 1)
    self.assertEqual(findings[0]["finding_id"], "wiz-live-1")
    self.assertEqual(findings[0]["source_platform"], "Wiz")

  def test_fetch_live_wiz_degrades_gracefully_on_http_error(self):
    from unittest import mock
    env = {
        "WIZ_CLIENT_ID": "cid",
        "WIZ_CLIENT_SECRET": "csec",
        "WIZ_API_URL": "https://api.us1.app.wiz.io/graphql",
    }
    with mock.patch.dict("os.environ", env, clear=False), \
         mock.patch.object(REM.urllib_request, "urlopen", side_effect=OSError("network down")):
      self.assertEqual(REM.fetch_live_wiz_iam_findings(PROJECT), [])


if __name__ == "__main__":
  unittest.main()
