#!/usr/bin/env python3
# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0

"""Tests for ART-11: PAM approver guardrails, Deny break-glass/observe-first,
and WIF CI snippets. Uses synthetic inputs only (zero GCP network calls)."""

import importlib.util
import json
from pathlib import Path
import re
import sys
import tempfile
import unittest

REPO_ROOT = Path(__file__).resolve().parent.parent
PLUGIN_ROOT = REPO_ROOT / "plugins" / "scopeguard"
if str(PLUGIN_ROOT) not in sys.path:
  sys.path.insert(0, str(PLUGIN_ROOT))

SKILLS = PLUGIN_ROOT / "skills"
ISO_Z = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def _load(rel: str, name: str):
  """Loads a CLI script as a module by file path."""
  spec = importlib.util.spec_from_file_location(name, SKILLS / rel)
  mod = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(mod)
  return mod


pam = _load("gcp-iam-jit-pam-architect/scripts/jit_pam_architect_cli.py", "t_pam")
deny = _load("gcp-iam-deny-policy-architect/scripts/deny_policy_cli.py", "t_deny")
fed = _load("gcp-iam-federation-architect/scripts/federation_architect_cli.py", "t_fed")

from lib.envelope_schema import SCHEMA_VERSION  # pylint: disable=wrong-import-position

POLICY = {
    "etag": "BwX1",
    "bindings": [
        {"role": "roles/owner", "members": ["user:admin@corp.com"]},
        {"role": "roles/iam.securityAdmin", "members": ["user:alice@corp.com"]},
        {"role": "roles/viewer", "members": ["user:bob@corp.com"]},
    ],
}

SA_INVENTORY = [
    {
        "email": "cicd-deployer@p1.iam.gserviceaccount.com",
        "user_managed_keys": [
            {"name": "projects/p1/serviceAccounts/x/keys/abc123",
             "validAfterTime": "2020-01-01T00:00:00Z"}
        ],
    },
    {"email": "web@p1.iam.gserviceaccount.com"},
]


class TestPamApprover(unittest.TestCase):
  """PAM separation-of-duties guardrails."""

  def test_self_approval_flagged_and_removed(self):
    with tempfile.TemporaryDirectory() as tmp:
      out = Path(tmp)
      res = pam.run_jit_pam_architect(
          "p1", policy_data=POLICY, approver_principal="user:admin@corp.com",
          output_dir=out, notification_emails=["sec@corp.com"],
      )
      ents = {e["eligible_requester"]: e for e in res["payload"]["entitlements"]}
      admin = ents["user:admin@corp.com"]
      self.assertTrue(admin["self_approval_detected"])
      self.assertEqual(admin["readiness"], pam.NOT_READY_APPROVER)
      self.assertNotIn("user:admin@corp.com", admin["approver_principals"])
      self.assertIn(pam.PLACEHOLDER_APPROVER, admin["approver_principals"])
      self.assertTrue(any("SELF-APPROVAL" in w for w in admin["warnings"]))
      # alice is approved by admin (distinct) -> READY
      self.assertEqual(ents["user:alice@corp.com"]["readiness"], pam.READY)
      self.assertEqual(res["summary"]["self_approval_conflicts"], 1)

      tf = (out / "pam_entitlements.tf").read_text(encoding="utf-8")
      self.assertIn("!!! NOT READY: approver required", tf)
      self.assertIn("additional_notification_targets", tf)
      self.assertIn("requester_justification_config", tf)
      md = (out / "pam_rollout.md").read_text(encoding="utf-8")
      self.assertIn("SELF-APPROVAL", md)
      spec = json.loads((out / "jit_pam_spec.json").read_text(encoding="utf-8"))
      self.assertEqual(spec["schema_version"], SCHEMA_VERSION)
      self.assertRegex(spec["generated_at"], ISO_Z)

  def test_missing_approver_uses_placeholder_not_ready(self):
    res = pam.run_jit_pam_architect("p1", policy_data=POLICY)
    for e in res["payload"]["entitlements"]:
      self.assertEqual(e["readiness"], pam.NOT_READY_APPROVER)
      self.assertEqual(e["approver_principals"], [pam.PLACEHOLDER_APPROVER])
      self.assertTrue(e["justification_required"])
      self.assertIn(e["max_request_duration"], ("3600s", "14400s"))
      self.assertIn("admin_email_recipients", e["notification_recipients"])
    self.assertTrue(res["summary"]["approver_placeholder_used"])

  def test_distinct_group_is_ready_and_bare_email_normalized(self):
    res = pam.run_jit_pam_architect(
        "p1", policy_data=POLICY, approver_principal="pam-approvers@corp.com",
        notification_emails=["sec@corp.com"],
    )
    for e in res["payload"]["entitlements"]:
      self.assertEqual(e["readiness"], pam.READY)
      self.assertEqual(e["approver_principals"], ["group:pam-approvers@corp.com"])
    self.assertEqual(res["summary"]["pam_entitlements_not_ready"], 0)


class TestDenyPolicy(unittest.TestCase):
  """Deny break-glass exceptions, syntax and observe-first guide."""

  def test_breakglass_principals_in_every_rule(self):
    with tempfile.TemporaryDirectory() as tmp:
      out = Path(tmp)
      res = deny.run_deny_policy_architect(
          "p1", policy_data=POLICY, output_dir=out,
          breakglass_principals=[
              "user:bg-admin@corp.com",
              "group:breakglass@corp.com",
              "serviceAccount:tf@p1.iam.gserviceaccount.com",
          ],
      )
      expected = [
          "principal://goog/subject/bg-admin@corp.com",
          "principalSet://goog/group/breakglass@corp.com",
          "principal://iam.googleapis.com/projects/-/serviceAccounts/tf@p1.iam.gserviceaccount.com",
      ]
      for rule in res["payload"]["iam_v2_policy_json"]["rules"]:
        self.assertEqual(rule["denyRule"]["exceptionPrincipals"], expected)
        self.assertEqual(rule["denyRule"]["deniedPrincipals"], [deny.ALL_PRINCIPALS])
      self.assertTrue(res["summary"]["breakglass_supplied"])
      self.assertEqual(res["summary"]["syntax_errors_count"], 0)
      self.assertFalse(any("No --breakglass-principal" in w
                           for w in res["payload"]["warnings"]))

      gcloud_body = json.loads((out / "deny_policy_v2.json").read_text(encoding="utf-8"))
      self.assertNotIn("schema_version", gcloud_body)  # must stay API-clean
      spec = json.loads((out / "deny_policy_spec.json").read_text(encoding="utf-8"))
      self.assertEqual(spec["schema_version"], SCHEMA_VERSION)
      self.assertRegex(spec["generated_at"], ISO_Z)
      tf = (out / "deny_policies.tf").read_text(encoding="utf-8")
      self.assertIn("urlencode(", tf)
      self.assertNotIn("encode_uri_component", tf)
      md = (out / "deny_rollout.md").read_text(encoding="utf-8")
      self.assertIn("Observe first", md)
      self.assertIn("troubleshoot-policy iam", md)
      self.assertIn("resourcemanager.projects.setIamPolicy", md)

  def test_warns_when_no_breakglass(self):
    res = deny.run_deny_policy_architect("p1", policy_data=POLICY)
    self.assertFalse(res["summary"]["breakglass_supplied"])
    self.assertTrue(any("No --breakglass-principal" in w
                        for w in res["payload"]["warnings"]))
    self.assertIn("principal://goog/subject/admin@corp.com",
                  res["payload"]["breakglass_exception_principals"])

  def test_v2_syntax_validation(self):
    errs = deny.validate_deny_rules([{
        "rule_id": "X", "denied_principals": ["allUsers"],
        "exception_principals": [], "denied_permissions": ["iam.roles.delete"],
    }])
    self.assertEqual(len(errs), 2)
    with self.assertRaises(ValueError):
      deny.to_v2_principal("domain:corp.com")

  def test_validate_deny_rules_rejects_unsupported_and_passes_d1_to_d5(self):
    unsupported_errs = deny.validate_deny_rules([{
        "rule_id": "D2_BAD",
        "denied_principals": [deny.ALL_PRINCIPALS],
        "exception_principals": ["principal://goog/subject/bg@corp.com"],
        "denied_permissions": ["logging.googleapis.com/buckets.delete"],
    }])
    self.assertEqual(len(unsupported_errs), 1)
    self.assertIn("DENY_SUPPORTED_PERMISSIONS", unsupported_errs[0])

    res = deny.run_deny_policy_architect(
        "p1",
        policy_data=POLICY,
        breakglass_principals=["group:breakglass@corp.com"],
        ai_agent_principals=["serviceAccount:rag-agent@p1.iam.gserviceaccount.com"],
    )
    rules = res["payload"]["rules"]
    rule_ids = [r["rule_id"] for r in rules]
    self.assertEqual(
        rule_ids,
        [
            "D1_DENY_STATIC_SA_KEYS",
            "D2_PROTECT_AUDIT_SINKS",
            "D3_ENFORCE_GITOPS_IAM_MUTATIONS",
            "D4_GUARD_STORAGE_POLICY_EXPOSURE",
            "D5_CONTAIN_AI_AGENT_BLAST_RADIUS",
        ],
    )
    # D2 must use buckets.update (supported), never buckets.delete (unsupported).
    d2 = next(r for r in rules if r["rule_id"] == "D2_PROTECT_AUDIT_SINKS")
    self.assertIn("logging.googleapis.com/buckets.update", d2["denied_permissions"])
    self.assertNotIn("logging.googleapis.com/buckets.delete", d2["denied_permissions"])
    # Every permission emitted across D1-D5 must pass validate_deny_rules.
    self.assertEqual(deny.validate_deny_rules(rules), [])
    self.assertEqual(res["summary"]["syntax_errors_count"], 0)
    for r in rules:
      for perm in r["denied_permissions"]:
        self.assertIn(perm, deny.DENY_SUPPORTED_PERMISSIONS)

  def test_d5_triggers_from_cli_flag_and_analysis_data(self):
    analysis_fixture = {
        "F8_ai_agent_blast_radius": [
            {"principal": "serviceAccount:f8-bot@p1.iam.gserviceaccount.com"}
        ],
        "principals": [
            {
                "principal": "serviceAccount:vertex-runner@p1.iam.gserviceaccount.com",
                "roles": ["roles/aiplatform.user"],
            },
            {
                "principal": "serviceAccount:mcp-tool-sa@p1.iam.gserviceaccount.com",
                "roles": ["roles/viewer"],
            },
            {
                "principal": "serviceAccount:billing-export@p1.iam.gserviceaccount.com",
                "roles": ["roles/bigquery.dataViewer"],
            },
        ],
    }
    with tempfile.TemporaryDirectory() as tmp:
      out = Path(tmp)
      res = deny.run_deny_policy_architect(
          "p1",
          policy_data=POLICY,
          output_dir=out,
          breakglass_principals=["group:breakglass@corp.com"],
          analysis_data=analysis_fixture,
          ai_agent_principals=["serviceAccount:llm-cli@p1.iam.gserviceaccount.com"],
      )
      d5 = next(
          r for r in res["payload"]["rules"]
          if r["rule_id"] == "D5_CONTAIN_AI_AGENT_BLAST_RADIUS"
      )
      expected_agents = {
          "principal://iam.googleapis.com/projects/-/serviceAccounts/llm-cli@p1.iam.gserviceaccount.com",
          "principal://iam.googleapis.com/projects/-/serviceAccounts/f8-bot@p1.iam.gserviceaccount.com",
          "principal://iam.googleapis.com/projects/-/serviceAccounts/vertex-runner@p1.iam.gserviceaccount.com",
          "principal://iam.googleapis.com/projects/-/serviceAccounts/mcp-tool-sa@p1.iam.gserviceaccount.com",
      }
      self.assertEqual(set(d5["denied_principals"]), expected_agents)
      self.assertEqual(
          d5["exception_principals"],
          ["principalSet://goog/group/breakglass@corp.com"],
      )
      self.assertEqual(
          set(d5["denied_permissions"]),
          {
              "cloudresourcemanager.googleapis.com/projects.setIamPolicy",
              "iam.googleapis.com/serviceAccountKeys.create",
              "iam.googleapis.com/roles.update",
              "logging.googleapis.com/sinks.delete",
              "apikeys.googleapis.com/keys.create",
          },
      )
      self.assertTrue(res["summary"]["d5_ai_agent_containment_active"])
      self.assertEqual(res["summary"]["ai_agent_principals_contained"], 4)
      self.assertEqual(deny.validate_deny_rules(res["payload"]["rules"]), [])
      md = (out / "deny_rollout.md").read_text(encoding="utf-8")
      self.assertIn("Agent Gateway", md)
      self.assertIn("Model Armor", md)
      self.assertIn("D5_CONTAIN_AI_AGENT_BLAST_RADIUS", md)


class TestWifSnippets(unittest.TestCase):
  """WIF CI snippet generation and anti-spoofing conditions."""

  def test_snippets_and_conditions(self):
    with tempfile.TemporaryDirectory() as tmp:
      out = Path(tmp)
      res = fed.run_federation_architect(
          "p1", sa_inventory=SA_INVENTORY, github_org="acme",
          github_repo="acme/infra", github_ref="refs/heads/main",
          gitlab_project="acme-grp/infra", project_number="123456",
          output_dir=out,
      )
      gh = (out / "ci" / "github-actions-wif.yml").read_text(encoding="utf-8")
      self.assertIn("google-github-actions/auth@v2", gh)
      self.assertIn("id-token: write", gh)
      self.assertIn("workload_identity_provider: 'projects/123456/locations/global/"
                    "workloadIdentityPools/scopeguard-cicd-oidc-pool/providers/"
                    "github-actions-provider'", gh)
      self.assertIn("service_account: 'cicd-deployer@p1.iam.gserviceaccount.com'", gh)
      gl = (out / "ci" / "gitlab-ci-wif.yml").read_text(encoding="utf-8")
      self.assertIn("id_tokens:", gl)
      self.assertIn("aud: https://iam.googleapis.com/projects/123456/", gl)
      self.assertIn("create-cred-config", gl)
      tf = (out / "wif_federation.tf").read_text(encoding="utf-8")
      self.assertIn("assertion.repository_owner == 'acme'", tf)
      self.assertIn("assertion.repository == 'acme/infra'", tf)
      self.assertIn("assertion.ref == 'refs/heads/main'", tf)
      self.assertIn("assertion.project_path == 'acme-grp/infra'", tf)
      self.assertIn("attribute.project_path/acme-grp/infra", tf)
      self.assertIn("Anti-spoofing", (out / "WIF_MIGRATION.md").read_text(encoding="utf-8"))
      runbook = (out / "retire_sa_keys.sh").read_text(encoding="utf-8")
      self.assertIn("DRY_RUN=1", runbook)
      audit = json.loads((out / "federation_audit.json").read_text(encoding="utf-8"))
      self.assertEqual(audit["schema_version"], SCHEMA_VERSION)
      self.assertRegex(audit["generated_at"], ISO_Z)
      self.assertEqual(res["payload"]["warnings"], [])

  def test_placeholder_warnings(self):
    res = fed.run_federation_architect(
        "p1", sa_inventory=[], github_org="acme", github_repo="other/repo"
    )
    w = " ".join(res["payload"]["warnings"])
    self.assertIn("not owned by --github-org", w)
    self.assertIn("--gitlab-project", w)
    self.assertIn("--project-number", w)
    self.assertIn("gitlab_ci", res["payload"]["ci_snippets"])

  def test_existing_wif_audit_detects_hygiene_risks_offline(self):
    wif_fixture = [
        {
            "name": "projects/123456/locations/global/workloadIdentityPools/legacy-pool",
            "state": "ACTIVE",
            "providers": [
                {
                    # CRITICAL: empty attributeCondition
                    "name": "projects/123456/locations/global/workloadIdentityPools/legacy-pool/providers/open-gh",
                    "state": "ACTIVE",
                    "attributeCondition": "",
                    "oidc": {"issuerUri": "https://token.actions.githubusercontent.com"},
                },
                {
                    # HIGH: broad org trust (repository_owner only, no repo/ref pin)
                    "name": "projects/123456/locations/global/workloadIdentityPools/legacy-pool/providers/org-wide-gh",
                    "state": "ACTIVE",
                    "attributeCondition": "assertion.repository_owner == 'acme'",
                    "oidc": {"issuerUri": "https://token.actions.githubusercontent.com"},
                },
                {
                    # MEDIUM: custom OIDC issuer without allowedAudiences (has condition)
                    "name": "projects/123456/locations/global/workloadIdentityPools/legacy-pool/providers/custom-idp",
                    "state": "ACTIVE",
                    "attributeCondition": "assertion.sub == 'svc-billing'",
                    "oidc": {"issuerUri": "https://oidc.internal.acme.example"},
                },
                {
                    # CLEAN: pinned owner + repo + ref
                    "name": "projects/123456/locations/global/workloadIdentityPools/legacy-pool/providers/hardened-gh",
                    "state": "ACTIVE",
                    "attributeCondition": (
                        "assertion.repository_owner == 'acme' && "
                        "assertion.repository == 'acme/infra' && "
                        "assertion.ref == 'refs/heads/main'"
                    ),
                    "oidc": {"issuerUri": "https://token.actions.githubusercontent.com"},
                },
                {
                    # DELETED: must be skipped
                    "name": "projects/123456/locations/global/workloadIdentityPools/legacy-pool/providers/deleted-prov",
                    "state": "DELETED",
                    "attributeCondition": "",
                    "oidc": {"issuerUri": "https://token.actions.githubusercontent.com"},
                },
            ],
        }
    ]
    with tempfile.TemporaryDirectory() as tmp:
      out = Path(tmp)
      res = fed.run_federation_architect(
          "p1",
          sa_inventory=SA_INVENTORY,
          github_org="acme",
          github_repo="acme/infra",
          github_ref="refs/heads/main",
          gitlab_project="acme-grp/infra",
          project_number="123456",
          output_dir=out,
          existing_wif_pools=wif_fixture,
      )
      wif_audit = res["payload"]["existing_wif_audit"]
      self.assertEqual(wif_audit["collection_status"], "FIXTURE")
      self.assertEqual(wif_audit["summary"]["pools_scanned"], 1)
      self.assertEqual(wif_audit["summary"]["providers_scanned"], 4)
      self.assertEqual(wif_audit["summary"]["total_findings"], 3)
      self.assertEqual(wif_audit["summary"]["critical_count"], 1)
      self.assertEqual(wif_audit["summary"]["high_count"], 1)
      self.assertEqual(wif_audit["summary"]["medium_count"], 1)

      by_prov = {f["provider_id"]: f for f in wif_audit["findings"]}
      self.assertEqual(by_prov["open-gh"]["rule_id"], "WIF_MISSING_ATTRIBUTE_CONDITION")
      self.assertEqual(by_prov["open-gh"]["severity"], "CRITICAL")
      self.assertIn("attribute_condition", by_prov["open-gh"]["terraform_hardening_snippet"])
      self.assertEqual(by_prov["org-wide-gh"]["rule_id"], "WIF_BROAD_ORG_TRUST")
      self.assertEqual(by_prov["org-wide-gh"]["severity"], "HIGH")
      self.assertEqual(by_prov["custom-idp"]["rule_id"], "WIF_UNRESTRICTED_ISSUER")
      self.assertEqual(by_prov["custom-idp"]["severity"], "MEDIUM")
      self.assertIn("allowed_audiences", by_prov["custom-idp"]["terraform_hardening_snippet"])
      self.assertNotIn("hardened-gh", by_prov)
      self.assertNotIn("deleted-prov", by_prov)

      # Persisted in federation_audit.json and WIF_MIGRATION.md
      audit_json = json.loads((out / "federation_audit.json").read_text(encoding="utf-8"))
      self.assertEqual(
          audit_json["payload"]["existing_wif_audit"]["summary"]["total_findings"], 3
      )
      md = (out / "WIF_MIGRATION.md").read_text(encoding="utf-8")
      self.assertIn("WIF_MISSING_ATTRIBUTE_CONDITION", md)
      self.assertIn("WIF_BROAD_ORG_TRUST", md)
      self.assertIn("WIF_UNRESTRICTED_ISSUER", md)
      self.assertIn("Terraform Hardening Snippets", md)

  def test_collect_existing_wif_pools_degrades_on_403(self):
    class _DeniedClient:
      def request_json(self, **_kwargs):
        raise fed.GCPHTTPError(403, "Forbidden", "Permission denied")

    pools, status, note = fed.collect_existing_wif_pools("p1", _DeniedClient())
    self.assertEqual(pools, [])
    self.assertEqual(status, "DEGRADED_PERMISSION_DENIED")
    self.assertIn("403", note or "")


if __name__ == "__main__":
  unittest.main()
