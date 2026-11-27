# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0

"""Tests for role naming, exact capability partitioning and runbook rendering."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "plugins", "scopeguard"))

from lib import capability_partition  # pylint: disable=g-import-not-at-top
from lib import naming  # pylint: disable=g-import-not-at-top
from lib import runbook_shell  # pylint: disable=g-import-not-at-top

_FIXTURE = os.path.join(_ROOT, "tests", "fixtures", "model_a_personas.json")


def _load_personas():
  with open(_FIXTURE, encoding="utf-8") as fh:
    return json.load(fh)


class NamingTest(unittest.TestCase):
  """Role ID grammar, prefixes and access-word mapping."""

  def test_prefix_resolution_and_sanitising(self):
    self.assertEqual(naming.role_prefix(), "sg_")
    self.assertEqual(naming.role_prefix("Acme-Sec"), "acme_sec_")
    os.environ["SCOPEGUARD_ROLE_PREFIX"] = "corp"
    try:
      self.assertEqual(naming.role_prefix(), "corp_")
    finally:
      del os.environ["SCOPEGUARD_ROLE_PREFIX"]

  def test_persona_ids_are_valid_and_clipped(self):
    rid = naming.persona_role_id(naming.workload_slug(
        "serviceAccount:data-pipeline-worker-sa@p.iam.gserviceaccount.com"))
    self.assertEqual(rid, "sg_persona_data_pipeline_worker")
    long_rid = naming.persona_role_id("x" * 200)
    self.assertLessEqual(len(long_rid), 64)
    self.assertTrue(naming.is_valid_role_id(long_rid))
    self.assertNotIn("-", rid)

  def test_persona_id_collisions_are_resolved(self):
    ids = naming.assign_unique_persona_ids([
        "user:ops@corp.com", "serviceAccount:ops@p.iam.gserviceaccount.com"])
    self.assertEqual(len(set(ids.values())), 2)
    for rid in ids.values():
      self.assertTrue(naming.is_valid_role_id(rid))

  def test_access_words(self):
    cases = {
        "bigquery.tables.getData": "read",
        "resourcemanager.projects.getIamPolicy": "audit",
        "cloudsql.instances.connect": "connect",
        "aiplatform.endpoints.predict": "invoke",
        "bigquery.jobs.create": "write",
        "run.services.setIamPolicy": "admin",
        "iam.serviceAccounts.actAs": "impersonate",
    }
    for perm, word in cases.items():
      self.assertEqual(naming.access_of(perm), word, perm)


class PartitionTest(unittest.TestCase):
  """Exact cover / disjointness on the real demo persona set."""

  def setUp(self):
    self.personas = _load_personas()
    self.result = capability_partition.partition_capabilities(self.personas)

  def test_exact_cover_and_disjoint(self):
    ver = self.result["verification"]
    self.assertEqual(ver["pairwise_overlap"], 0)
    self.assertTrue(ver["exact_cover"])
    self.assertEqual(ver["over_grant"], {})
    self.assertEqual(ver["under_grant"], {})

  def test_pipeline_worker_bundle_grants_exactly_its_needs(self):
    """Old Model B over-granted this persona by 9 permissions."""
    bundle = self.result["bundles"]["customBatchPipelineWorker"]
    granted = set()
    for rid in bundle:
      granted |= set(self.result["capabilities"][rid]["permissions"])
    self.assertEqual(granted, set(self.personas["customBatchPipelineWorker"]))

  def test_ids_valid_unique_and_deterministic(self):
    ids = list(self.result["capabilities"])
    self.assertEqual(len(ids), len(set(ids)))
    for rid in ids:
      self.assertTrue(naming.is_valid_role_id(rid), rid)
      self.assertTrue(rid.startswith("sg_cap_"), rid)
    again = capability_partition.partition_capabilities(dict(reversed(list(self.personas.items()))))
    self.assertEqual(list(again["capabilities"]), ids)

  def test_sensitive_permissions_are_isolated(self):
    personas = {
        "a": ["iam.serviceAccounts.actAs", "run.services.get"],
        "b": ["iam.serviceAccounts.actAs", "run.services.get", "secretmanager.versions.access"],
    }
    res = capability_partition.partition_capabilities(personas)
    for cap in res["capabilities"].values():
      sens = [p for p in cap["permissions"] if p in naming.SENSITIVE_CAPABILITIES]
      if sens:
        self.assertEqual(len(cap["permissions"]), len(sens))
        self.assertTrue(cap["sensitive"])
    self.assertIn("sg_cap_sa_impersonate", res["capabilities"])
    self.assertIn("sg_cap_secrets_read", res["capabilities"])


@unittest.skipUnless(shutil.which("bash"), "bash not available")
class RunbookTest(unittest.TestCase):
  """Generated scripts must be valid Bash and safe by default."""

  def _bash_n(self, script):
    with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as fh:
      fh.write(script)
      path = fh.name
    try:
      proc = subprocess.run(["bash", "-n", path], capture_output=True, text=True, check=False)
      self.assertEqual(proc.returncode, 0, proc.stderr)
    finally:
      os.unlink(path)

  def test_change_runbook(self):
    script = runbook_shell.render_change_runbook(
        "proj-1", "run-1", "Test",
        changes=[{
            "id": "F-001", "title": "Replace editor", "principal": "user:a@b.com",
            "add": [{"role": "projects/proj-1/roles/sg_persona_a"},
                    {"role": "roles/viewer", "condition": {
                        "title": "t", "expression": "request.time < timestamp('2030-01-01T00:00:00Z') && 'a,b' != \"$(x)\""}}],
            "remove": [{"role": "roles/editor"}],
            "verify": "check app",
        }],
        expected_etag="BwX=",
        roles_to_create=[{"role_id": "sg_persona_a", "yaml_path": "custom-roles/personas/sg_persona_a.yaml"}],
    )
    self._bash_n(script)
    self.assertIn("APPLY=0", script)
    self.assertIn("--condition=None", script)
    self.assertIn("--condition-from-file", script)
    self.assertIn("<<'SG_COND_JSON'", script)

  def test_untrusted_text_cannot_inject_commands(self):
    """Titles/members with $(...), backticks or newlines must stay inert."""
    evil = "x$(touch /tmp/sg_pwned)`id`\nUSAGE\ntouch /tmp/sg_pwned2"
    script = runbook_shell.render_change_runbook(
        "proj-1", "run-1", evil,
        changes=[{"id": "F-1", "title": evil, "principal": "user:a@b.com",
                  "add": [], "remove": [{"role": "roles/editor"}], "verify": evil}])
    self._bash_n(script)
    for line in script.splitlines():
      self.assertNotEqual(line.strip(), "touch /tmp/sg_pwned2")
      if line.lstrip().startswith("log ") and "$(touch" in line:
        self.assertIn("'", line)  # Single-quoted => no command substitution.

  def test_restore_runbook_and_dry_run_execution(self):
    script = runbook_shell.render_restore_runbook(
        "proj-1", "run-1",
        {"user:ops@a.com": [{"role": "roles/editor"}],
         "serviceAccount:ops@p.iam.gserviceaccount.com": [{"role": "roles/viewer"}]},
        backup_file="iam_policy_backup_proj-1.json")
    self._bash_n(script)
    self.assertIn("restore_ops_2", script)  # Collision-safe function names.
    # Dry run with a stub gcloud on PATH: nothing may be executed for real.
    tmp = tempfile.mkdtemp()
    try:
      stub = os.path.join(tmp, "gcloud")
      with open(stub, "w", encoding="utf-8") as fh:
        fh.write("#!/usr/bin/env bash\necho tester@example.com\n")
      os.chmod(stub, 0o755)
      path = os.path.join(tmp, "rb.sh")
      with open(path, "w", encoding="utf-8") as fh:
        fh.write(script)
      env = dict(os.environ, PATH=tmp + os.pathsep + os.environ.get("PATH", ""))
      proc = subprocess.run(["bash", path], capture_output=True, text=True, env=env, check=False)
      self.assertEqual(proc.returncode, 0, proc.stderr)
      self.assertIn("[dry-run]", proc.stdout)
      self.assertIn("add-iam-policy-binding", proc.stdout)
    finally:
      shutil.rmtree(tmp, ignore_errors=True)

  def test_restore_runbook_re_enables_disabled_service_accounts(self):
    """Quarantined/disabled SAs must be re-enabled in dry-run-aware rollback."""
    orphan_sa = "orphan-worker@proj-1.iam.gserviceaccount.com"
    bound_sa = "stale-worker@proj-1.iam.gserviceaccount.com"
    script = runbook_shell.render_restore_runbook(
        "proj-1", "run-2",
        {f"serviceAccount:{bound_sa}": [{"role": "roles/viewer"}]},
        backup_file="iam_policy_backup_proj-1.json",
        disabled_service_accounts=[orphan_sa, f"serviceAccount:{bound_sa}"],
    )
    self._bash_n(script)
    self.assertIn("re_enable_disabled_service_accounts", script)
    self.assertIn("gcloud iam service-accounts enable", script)
    self.assertIn(orphan_sa, script)
    self.assertIn(bound_sa, script)

    # Also verify script works when ONLY disabled SAs exist (0 removed bindings).
    sa_only_script = runbook_shell.render_restore_runbook(
        "proj-1", "run-3",
        {},
        backup_file="iam_policy_backup_proj-1.json",
        disabled_service_accounts=[orphan_sa],
    )
    self._bash_n(sa_only_script)

    tmp = tempfile.mkdtemp()
    try:
      stub = os.path.join(tmp, "gcloud")
      with open(stub, "w", encoding="utf-8") as fh:
        fh.write("#!/usr/bin/env bash\necho tester@example.com\n")
      os.chmod(stub, 0o755)
      env = dict(os.environ, PATH=tmp + os.pathsep + os.environ.get("PATH", ""))
      for name, content in (("rb_full.sh", script), ("rb_sa_only.sh", sa_only_script)):
        path = os.path.join(tmp, name)
        with open(path, "w", encoding="utf-8") as fh:
          fh.write(content)
        proc = subprocess.run(["bash", path], capture_output=True, text=True, env=env, check=False)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("[dry-run]", proc.stdout)
        self.assertIn("gcloud iam service-accounts enable", proc.stdout)
        self.assertIn(orphan_sa, proc.stdout)
    finally:
      shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
  unittest.main()
