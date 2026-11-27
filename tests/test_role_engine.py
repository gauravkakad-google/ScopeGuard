# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0

"""Tests for the generic persona / capability role engine (iam_audit_cli).

All inputs are synthetic and deliberately use generic principal names so the
engine is proven to derive personas from evidence, never from hard-coded
service-account or role names.
"""

import copy
import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_PLUGIN = _ROOT / "plugins" / "scopeguard"
sys.path.insert(0, str(_PLUGIN))

from lib import naming  # pylint: disable=g-import-not-at-top,wrong-import-position


def _load(name: str, rel: str):
  """Imports a skill script as a module without executing its CLI."""
  spec = importlib.util.spec_from_file_location(name, _PLUGIN / "skills" / rel)
  mod = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(mod)
  return mod


audit = _load(
    "iam_audit_cli_under_test",
    "gcp-iam-recommender-audit/scripts/iam_audit_cli.py",
)
architect = _load(
    "role_architect_cli_under_test",
    "gcp-iam-role-architect/scripts/role_architect_cli.py",
)
simulator = _load(
    "breakglass_simulator_cli_under_test",
    "gcp-iam-breakglass-simulator/scripts/breakglass_simulator_cli.py",
)

PID = "proj-x"
SVC_A = f"serviceAccount:svc-alpha@{PID}.iam.gserviceaccount.com"
SVC_B = f"serviceAccount:svc-beta@{PID}.iam.gserviceaccount.com"
SVC_MULTI = f"serviceAccount:svc-multi@{PID}.iam.gserviceaccount.com"     # 2 roles, no usage data -> fallback persona
SVC_SINGLE = f"serviceAccount:svc-single@{PID}.iam.gserviceaccount.com"   # 1 role, no usage data -> retain predefined
SVC_INACTIVE = f"serviceAccount:svc-stale@{PID}.iam.gserviceaccount.com"  # inactive SA -> F4 + rollback re-enable
USER_MULTI = "user:carol@example.com"   # human -> PAM JIT / Group (no sg_persona_*)
USER_SINGLE = "user:dave@example.com"   # human -> PAM JIT / Group (no sg_persona_*)
AGENT = "serviceAccount:service-123@gcp-sa-storage.iam.gserviceaccount.com"
UNSUPPORTED = "resourcemanager.projects.list"

STORAGE_ADMIN = [
    "storage.buckets.delete", "storage.buckets.get", "storage.buckets.list",
    "storage.objects.create", "storage.objects.delete", "storage.objects.get",
    UNSUPPORTED,
]
LOGGING_VIEWER = ["logging.logEntries.list", "logging.logs.list"]
PUBSUB_VIEWER = ["pubsub.topics.get", "pubsub.topics.list"]


def _insight(member: str, role: str, iid: str):
  """Recommender policy insight: 2 exercised (+1 unsupported) and 1 inferred."""
  return {
      "name": f"projects/123/locations/global/insightTypes/google.iam.policy.Insight/insights/{iid}",
      "severity": "HIGH",
      "content": {
          "member": member,
          "role": role,
          "currentTotalPermissionsCount": len(STORAGE_ADMIN),
          "exercisedPermissions": [
              {"permission": "storage.objects.get"},
              {"permission": "storage.buckets.get"},
              {"permission": UNSUPPORTED},
          ],
          "inferredPermissions": [{"permission": "storage.objects.create"}],
      },
  }


def synthetic_bundle():
  """Builds a minimal audit bundle exercising every persona-engine branch."""
  all_perms = sorted(set(STORAGE_ADMIN + LOGGING_VIEWER + PUBSUB_VIEWER))
  return {
      "metadata": {
          "project_id": PID,
          "project_number": "123",
          "collected_at": "2026-01-02T03:04:05Z",
      },
      "iam_policy": {
          "etag": "BwTestEtag=",
          "version": 3,
          "bindings": [
              {"role": "roles/storage.admin", "members": [SVC_A, SVC_B]},
              {"role": "roles/logging.viewer", "members": [SVC_MULTI, USER_MULTI]},
              {"role": "roles/pubsub.viewer", "members": [SVC_MULTI, SVC_SINGLE, USER_MULTI, USER_SINGLE, SVC_INACTIVE]},
              {
                  "role": "roles/storage.objectViewer",
                  "members": [SVC_A],
                  "condition": {
                      "title": "temp",
                      "expression": 'request.time < timestamp("2099-01-01T00:00:00Z")',
                  },
              },
              {"role": "roles/storage.serviceAgent", "members": [AGENT]},
          ],
      },
      "role_definitions": {
          "roles/storage.admin": STORAGE_ADMIN,
          "roles/logging.viewer": LOGGING_VIEWER,
          "roles/pubsub.viewer": PUBSUB_VIEWER,
      },
      "testable_permissions": [
          {"name": p, "customRolesSupportLevel": "NOT_SUPPORTED" if p == UNSUPPORTED else "SUPPORTED"}
          for p in all_perms
      ],
      "policy_insights": [
          _insight(SVC_A, "roles/storage.admin", "ins-a"),
          _insight(SVC_B, "roles/storage.admin", "ins-b"),
      ],
      "policy_recommendations": [],
      "service_accounts": [
          {"email": SVC_A.split(":", 1)[1], "uniqueId": "1"},
          {"email": SVC_B.split(":", 1)[1], "uniqueId": "2"},
          {"email": SVC_MULTI.split(":", 1)[1], "uniqueId": "3"},
          {"email": SVC_SINGLE.split(":", 1)[1], "uniqueId": "4"},
          {"email": SVC_INACTIVE.split(":", 1)[1], "uniqueId": "5"},
      ],
      "service_account_insights": [
          {
              "name": "projects/123/locations/global/insightTypes/google.iam.serviceAccount.Insight/insights/sa-ins-1",
              "severity": "LOW",
              "observationPeriod": "7776000s",
              "content": {
                  "email": SVC_INACTIVE.split(":", 1)[1],
                  "serviceAccountId": "5",
                  "lastAuthenticatedTime": "Never",
              },
          }
      ],
      "audit_logs_sample": [],
  }


class PersonaDerivationTest(unittest.TestCase):
  """Generic derivation: evidence -> personas, merging, fallback flagging."""

  @classmethod
  def setUpClass(cls):
    cls._saved_prefix = os.environ.pop("SCOPEGUARD_ROLE_PREFIX", None)
    cls.analysis = audit.analyze_bundle(synthetic_bundle())

  @classmethod
  def tearDownClass(cls):
    if cls._saved_prefix is not None:
      os.environ["SCOPEGUARD_ROLE_PREFIX"] = cls._saved_prefix

  def _pm(self, member):
    return next(p for p in self.analysis["principal_mappings"] if p["principal"] == member)

  def test_identical_usage_merges_into_one_persona(self):
    model_a = self.analysis["custom_roles_model_a"]
    merged = [r for r in model_a.values() if SVC_A in r["members"]]
    self.assertEqual(len(merged), 1)
    role = merged[0]
    self.assertEqual(role["members"], sorted([SVC_A, SVC_B]))
    # Representative = sorted-first member, named via the shared convention.
    self.assertEqual(role["role_id"], naming.persona_role_id(naming.workload_slug(SVC_A)))
    self.assertEqual(
        role["includedPermissions"],
        ["storage.buckets.get", "storage.objects.create", "storage.objects.get"],
    )
    self.assertEqual(role["evidence_source"], audit.EVIDENCE_SOURCE_INSIGHT)
    self.assertIn(UNSUPPORTED, role["strippedUnsupportedPermissions"])
    self.assertLessEqual(len(role["description"]), naming.DESCRIPTION_MAX_LEN)
    self.assertEqual(self._pm(SVC_A)["persona_role_id"], role["role_id"])
    self.assertEqual(self._pm(SVC_B)["persona_role_id"], role["role_id"])

  def test_no_usage_multi_role_falls_back_to_role_definitions(self):
    pm = self._pm(SVC_MULTI)
    role = self.analysis["custom_roles_model_a"][pm["persona_role_id"]]
    self.assertEqual(role["evidence_source"], "role_definition_no_usage_data")
    self.assertEqual(role["includedPermissions"], sorted(LOGGING_VIEWER + PUBSUB_VIEWER))
    self.assertIn("NO USAGE DATA", role["description"])
    self.assertIn(role["role_id"], self.analysis["summary"]["no_usage_data_personas"])
    self.assertEqual(pm["evidence_source"], "role_definition_no_usage_data")

  def test_single_role_without_usage_keeps_predefined(self):
    pm = self._pm(SVC_SINGLE)
    self.assertFalse(pm.get("persona_role_id"))
    self.assertIn("Retain_Predefined_Role", pm["target_bucket"])

  def test_human_users_routed_to_pam_jit_no_persona_role(self):
    """Human user: principals must never receive sg_persona_* custom roles."""
    for human in (USER_MULTI, USER_SINGLE):
      pm = self._pm(human)
      self.assertEqual(pm["persona_role_id"], "")
      self.assertEqual(pm["model_a_custom_role"], "")
      self.assertEqual(pm["target_bucket"], "Human -> PAM JIT / Group")
      self.assertEqual(
          pm["target_mapping"],
          "Route to Google Group + PAM JIT (pam_entitlements.tf)",
      )
    for rid, role in self.analysis["custom_roles_model_a"].items():
      self.assertFalse(rid.endswith("carol") or rid.endswith("dave"), rid)
      for member in role["members"]:
        self.assertTrue(member.startswith("serviceAccount:"), member)

  def test_service_agent_gets_no_persona(self):
    pm = self._pm(AGENT)
    self.assertFalse(pm.get("persona_role_id"))
    for role in self.analysis["custom_roles_model_a"].values():
      self.assertNotIn(AGENT, role["members"])

  def test_traceability_rows_cover_kept_and_dropped(self):
    pid = self._pm(SVC_A)["persona_role_id"]
    rows = {r["permission"]: r for r in self.analysis["role_traceability"][pid]}
    self.assertEqual(rows["storage.objects.get"]["decision"], "kept")
    self.assertIn("insight ins-a", rows["storage.objects.get"]["evidence"])
    self.assertIn("inferred", rows["storage.objects.create"]["evidence"])
    self.assertEqual(rows[UNSUPPORTED]["decision"], "dropped")
    self.assertIn("unsupported", rows[UNSUPPORTED]["reason"])
    self.assertEqual(rows["storage.buckets.delete"]["decision"], "dropped")
    self.assertIn("unused", rows["storage.buckets.delete"]["reason"])

  def test_envelope_keys_and_model_b_verification(self):
    a = self.analysis
    for key in (
        "custom_roles_model_a", "custom_roles_model_b_disjoint", "model_b_bundles",
        "model_b_verification", "role_traceability", "principal_mappings",
        "model_a_to_b_map", "summary", "verification_gates", "executive_kpis",
    ):
      self.assertIn(key, a)
    ver = a["model_b_verification"]
    self.assertTrue(ver["exact_cover"])
    self.assertEqual(ver["pairwise_overlap"], 0)
    gate2 = a["verification_gates"]["gate_2_mathematical_disjointness"]
    self.assertEqual(gate2["pairwise_overlap_count"], 0)
    self.assertTrue(gate2["passed"])
    self.assertEqual(a["summary"]["persona_roles_count"], len(a["custom_roles_model_a"]))
    self.assertEqual(a["summary"]["capability_roles_count"], len(a["custom_roles_model_b_disjoint"]))
    self.assertEqual(set(a["model_b_bundles"]), set(a["custom_roles_model_a"]))
    self.assertEqual(a["model_a_to_b_map"], a["model_b_bundles"])
    # Bundles reconstruct each persona exactly (exact cover, per persona).
    caps = a["custom_roles_model_b_disjoint"]
    for pid, bundle in a["model_b_bundles"].items():
      union = sorted({p for c in bundle for p in caps[c]["includedPermissions"]})
      self.assertEqual(union, a["custom_roles_model_a"][pid]["includedPermissions"])
    for rid in list(a["custom_roles_model_a"]) + list(caps):
      self.assertTrue(naming.is_valid_role_id(rid), rid)
    pm = self._pm(SVC_A)
    for key in ("persona_role_id", "target_mapping", "disjoint_model_b_bundle",
                "bindings_before", "rollback_commands"):
      self.assertIn(key, pm)
    # Conditional binding is captured in bindings_before for rollback.
    self.assertTrue(any(b.get("condition") for b in pm["bindings_before"]))

  def test_role_prefix_is_honoured(self):
    analysis = audit.analyze_bundle(synthetic_bundle(), role_prefix="acme")
    self.assertTrue(analysis["custom_roles_model_a"])
    for rid in list(analysis["custom_roles_model_a"]) + list(analysis["custom_roles_model_b_disjoint"]):
      self.assertTrue(rid.startswith("acme_"), rid)


class ArtifactGenerationTest(unittest.TestCase):
  """Files on disk, rollback runbook (ART-3) and single-source numbers (ART-4)."""

  def setUp(self):
    self._saved_prefix = os.environ.pop("SCOPEGUARD_ROLE_PREFIX", None)
    self.tmp = tempfile.TemporaryDirectory()
    self.out = Path(self.tmp.name) / "out"
    bundle = synthetic_bundle()
    self.analysis = audit.analyze_bundle(copy.deepcopy(bundle))
    self.backup = Path(self.tmp.name) / "backup.json"
    self.backup.write_text(json.dumps(bundle["iam_policy"]), encoding="utf-8")
    audit.generate_all_artifacts(self.analysis, self.backup, self.out)

  def tearDown(self):
    self.tmp.cleanup()
    if self._saved_prefix is not None:
      os.environ["SCOPEGUARD_ROLE_PREFIX"] = self._saved_prefix

  def test_role_yaml_layout(self):
    roles = self.out / "custom-roles"
    personas = sorted(p.stem for p in (roles / "personas").glob("*.yaml"))
    caps = sorted(p.stem for p in (roles / "capabilities").glob("*.yaml"))
    self.assertEqual(personas, sorted(self.analysis["custom_roles_model_a"]))
    self.assertEqual(caps, sorted(self.analysis["custom_roles_model_b_disjoint"]))
    # Nothing but bundles.yaml at the root (no legacy Model A files).
    stray = [p.name for p in roles.glob("*.yaml") if p.name != "bundles.yaml"]
    self.assertEqual(stray, [])
    self.assertFalse((roles / "disjoint").exists())
    bundles = (roles / "bundles.yaml").read_text(encoding="utf-8")
    for pid in self.analysis["custom_roles_model_a"]:
      self.assertIn(pid, bundles)
    for rid in personas + caps:
      self.assertTrue(naming.is_valid_role_id(rid), rid)

  def test_rollback_runbook_and_policy_backup(self):
    runbook = self.out / "rollback_runbook.sh"
    self.assertTrue(runbook.exists())
    self.assertEqual(stat.S_IMODE(runbook.stat().st_mode), 0o755)
    res = subprocess.run(["bash", "-n", str(runbook)], capture_output=True, text=True, check=False)
    self.assertEqual(res.returncode, 0, res.stderr)
    text = runbook.read_text(encoding="utf-8")
    # Every principal losing bindings is restorable, with ALL its current
    # bindings (including retained conditional ones) listed for restore.
    affected = [p for p in self.analysis["principal_mappings"] if p.get("bindings_removed")]
    self.assertTrue(affected)
    for pm in affected:
      self.assertIn(pm["principal"].split(":", 1)[1], text)
      for b in pm["bindings_before"]:
        self.assertIn(b["role"], text)
    # Quarantined F4 inactive SA must have a re-enable command in rollback_runbook.sh.
    self.assertIn("gcloud iam service-accounts enable", text)
    self.assertIn(SVC_INACTIVE.split(":", 1)[1], text)
    backup = self.out / f"iam_policy_backup_{PID}.json"
    self.assertTrue(backup.exists())
    self.assertEqual(json.loads(backup.read_text(encoding="utf-8"))["etag"], "BwTestEtag=")

  def test_envelope_artifacts_are_contents(self):
    mod = audit.build_audit_envelope_module(self.analysis, self.out, PID)
    art = mod["payload"]["artifacts"]
    self.assertEqual(set(art["model_a_role_yamls"]),
                     {f"{r}.yaml" for r in self.analysis["custom_roles_model_a"]})
    self.assertEqual(set(art["disjoint_role_yamls"]),
                     {f"{r}.yaml" for r in self.analysis["custom_roles_model_b_disjoint"]})
    for text in list(art["model_a_role_yamls"].values()) + list(art["disjoint_role_yamls"].values()):
      self.assertIn("includedPermissions:", text)
    for pid in self.analysis["custom_roles_model_a"]:
      self.assertIn(pid, art["bundles_yaml"])
    self.assertTrue(art["rollback_runbook_sh"].startswith("#!"))
    self.assertEqual(art["policy_backup"]["etag"], "BwTestEtag=")
    self.assertEqual(mod["summary"]["persona_roles_count"],
                     self.analysis["executive_kpis"].get("persona_roles_count"))

  def test_markdown_numbers_come_from_envelope(self):
    md = (self.out / "detailed_recommendations.md").read_text(encoding="utf-8")
    k = self.analysis["executive_kpis"]
    s = self.analysis["summary"]
    self.assertIn(f"{int(k['total_permissions_before']):,}", md)
    self.assertIn(f"{int(k['total_permissions_after']):,}", md)
    self.assertIn(f"`{s['persona_roles_count']}`", md)
    self.assertIn(f"`{s['capability_roles_count']}`", md)
    # Traceability (ART-13) and the no-usage fallback flag are rendered.
    self.assertIn("traceability", md.lower())
    self.assertIn("role_definition_no_usage_data", md)


class RoleArchitectLoaderTest(unittest.TestCase):
  """role_architect_cli reads the new layout and falls back to the legacy one."""

  class _OfflineClient:
    """Stub client: no live project custom roles."""

    def list_project_custom_roles(self):
      return []

  @staticmethod
  def _write(path: Path, perms):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        'title: "t"\ndescription: "d"\nstage: "GA"\nincludedPermissions:\n'
        + "".join(f"- {p}\n" for p in perms),
        encoding="utf-8",
    )

  def test_new_layout_preferred_over_legacy(self):
    with tempfile.TemporaryDirectory() as tmp:
      root = Path(tmp) / "custom-roles"
      self._write(root / "personas" / "sg_persona_x.yaml", ["a.b.get"])
      self._write(root / "capabilities" / "sg_cap_a_read.yaml", ["a.b.get"])
      self._write(root / "stale_root.yaml", ["z.z.get"])         # ignored
      self._write(root / "disjoint" / "old_cap.yaml", ["z.z.get"])  # ignored
      # Parent dir (audit output) and custom-roles dir both resolve.
      for given in (Path(tmp), root):
        roles = architect.load_existing_custom_roles(given, self._OfflineClient())
        self.assertEqual([r["role_id"] for r in roles["model_a"]], ["sg_persona_x"])
        self.assertEqual([r["role_id"] for r in roles["disjoint_model_b"]], ["sg_cap_a_read"])

  def test_legacy_layout_fallback(self):
    with tempfile.TemporaryDirectory() as tmp:
      root = Path(tmp) / "custom-roles"
      self._write(root / "legacy_role.yaml", ["a.b.get"])
      self._write(root / "disjoint" / "disjoint_legacy.yaml", ["a.b.list"])
      roles = architect.load_existing_custom_roles(root, self._OfflineClient())
      self.assertEqual([r["role_id"] for r in roles["model_a"]], ["legacy_role"])
      self.assertEqual([r["role_id"] for r in roles["disjoint_model_b"]], ["disjoint_legacy"])

  def test_missing_dir_is_empty(self):
    roles = architect.load_existing_custom_roles(Path("/nonexistent/sg"), self._OfflineClient())
    self.assertEqual(roles, {"model_a": [], "disjoint_model_b": []})


class F8AiAgentBlastRadiusTest(unittest.TestCase):
  """F8 detector for AI/agentic SAs with dangerous blast radius or shared multi-service scope."""

  def _ai_bundle(self):
    ai_risky = f"serviceAccount:rag-agent-runner@{PID}.iam.gserviceaccount.com"
    ai_shared = f"serviceAccount:shared-platform@{PID}.iam.gserviceaccount.com"
    ai_clean = f"serviceAccount:vertex-infer-only@{PID}.iam.gserviceaccount.com"
    return {
        "metadata": {
            "project_id": PID,
            "project_number": "123",
            "collected_at": "2026-01-02T03:04:05Z",
        },
        "iam_policy": {
            "etag": "BwAiTest=",
            "version": 3,
            "bindings": [
                {"role": "roles/aiplatform.user", "members": [ai_risky, ai_shared, ai_clean]},
                {"role": "roles/secretmanager.secretAccessor", "members": [ai_risky]},
                {"role": "roles/iam.serviceAccountUser", "members": [ai_risky]},
                {"role": "roles/logging.viewer", "members": [ai_shared]},
                {"role": "roles/pubsub.viewer", "members": [ai_shared]},
                {"role": "roles/monitoring.viewer", "members": [ai_shared]},
            ],
        },
        "role_definitions": {
            "roles/aiplatform.user": ["aiplatform.endpoints.predict"],
            "roles/secretmanager.secretAccessor": ["secretmanager.versions.access"],
            "roles/iam.serviceAccountUser": ["iam.serviceAccounts.actAs"],
            "roles/logging.viewer": ["logging.logEntries.list"],
            "roles/pubsub.viewer": ["pubsub.topics.get"],
            "roles/monitoring.viewer": ["monitoring.timeSeries.list"],
        },
        "testable_permissions": [],
        "policy_insights": [],
        "policy_recommendations": [],
        "service_accounts": [],
        "service_account_insights": [],
        "audit_logs_sample": [],
    }, ai_risky, ai_shared, ai_clean

  def test_f8_flags_risky_and_shared_ai_sas_only(self):
    bundle, ai_risky, ai_shared, ai_clean = self._ai_bundle()
    res = audit.analyze_bundle(bundle)
    f8 = {item["principal"]: item for item in res["findings"]["F8_ai_agent_blast_radius"]}
    self.assertIn(ai_risky, f8)
    self.assertIn("secretmanager.versions.access", f8[ai_risky]["dangerous_permissions"])
    self.assertIn("iam.serviceAccounts.actAs", f8[ai_risky]["dangerous_permissions"])
    self.assertIn("Agent Gateway", f8[ai_risky]["containment_guidance"])
    self.assertIn("Model Armor", f8[ai_risky]["containment_guidance"])
    self.assertIn("D5", f8[ai_risky]["containment_guidance"])

    self.assertIn(ai_shared, f8)
    self.assertTrue(f8[ai_shared]["is_shared_multi_service_sa"])
    self.assertGreaterEqual(len(f8[ai_shared]["distinct_service_domains"]), 4)

    # Minimal single-purpose inference SA must NOT be flagged.
    self.assertNotIn(ai_clean, f8)


class BreakglassAuditLogConfidenceTest(unittest.TestCase):
  """auditConfigs Data Access visibility -> HIGH / MEDIUM / LOW confidence & cutover strategy."""

  class _StubGCPClient:
    """Offline stub returning no live audit logs."""

    def fetch_audit_logs_per_principal(self, **_kwargs):
      return []

    def fetch_cloud_audit_logs(self, *_args, **_kwargs):
      return []

  def _sim_analysis(self, extra_exercised=None):
    proposed = ["storage.objects.get", "secretmanager.versions.access", "aiplatform.endpoints.predict"]
    exercised = list(proposed) + list(extra_exercised or [])
    return {
        "custom_roles_model_a": {
            "sg_persona_worker": {
                "role_id": "sg_persona_worker",
                "includedPermissions": proposed,
                "strippedUnsupportedPermissions": [],
            }
        },
        "custom_roles_model_b_disjoint": {},
        "model_a_to_b_map": {},
        "policy_recommendations": [
            {"principal": SVC_A, "exercised_permissions": exercised},
        ],
        "principal_mappings": [
            {
                "principal": SVC_A,
                "taxonomy": "Customer-Managed Service Accounts",
                "remediation_phase": "P2",
                "model_a_custom_role": "sg_persona_worker",
                "model_b_disjoint_roles": [],
                "target_mapping": f"projects/{PID}/roles/sg_persona_worker",
            }
        ],
    }

  def test_confidence_high_with_all_services(self):
    policy = {
        "auditConfigs": [
            {
                "service": "allServices",
                "auditLogConfigs": [
                    {"logType": "ADMIN_READ"},
                    {"logType": "DATA_READ"},
                    {"logType": "DATA_WRITE"},
                ],
            }
        ]
    }
    res = simulator.run_breakglass_simulation(
        project_id=PID,
        analysis_data=self._sim_analysis(),
        gcp_client=self._StubGCPClient(),
        policy_data=policy,
    )
    self.assertEqual(res["summary"]["audit_log_confidence"], "HIGH")
    self.assertEqual(res["summary"]["missing_data_access_services"], [])
    self.assertEqual(res["summary"]["recommended_cutover"], "DIRECT")
    self.assertEqual(res["payload"]["audit_log_confidence_warning"], "")

  def test_confidence_medium_partial_coverage(self):
    policy = {
        "auditConfigs": [
            {
                "service": "storage.googleapis.com",
                "auditLogConfigs": [{"logType": "DATA_READ"}, {"logType": "DATA_WRITE"}],
            },
            {
                "service": "secretmanager.googleapis.com",
                "auditLogConfigs": [{"logType": "ADMIN_READ"}],
            },
        ]
    }
    res = simulator.run_breakglass_simulation(
        project_id=PID,
        analysis_data=self._sim_analysis(),
        gcp_client=self._StubGCPClient(),
        policy_data=policy,
    )
    self.assertEqual(res["summary"]["audit_log_confidence"], "MEDIUM")
    self.assertEqual(
        res["summary"]["missing_data_access_services"],
        ["aiplatform.googleapis.com", "secretmanager.googleapis.com"],
    )
    self.assertEqual(res["summary"]["recommended_cutover"], "CANARY_DUAL_BIND")
    self.assertIn("WARNING", res["payload"]["audit_log_confidence_warning"])

  def test_confidence_low_when_audit_configs_absent_and_markdown_emitted(self):
    with tempfile.TemporaryDirectory() as tmp:
      out_dir = Path(tmp)
      res = simulator.run_breakglass_simulation(
          project_id=PID,
          analysis_data=self._sim_analysis(),
          bundle_data={"iam_policy": {"etag": "Bw1=", "bindings": []}},
          gcp_client=self._StubGCPClient(),
          output_dir=out_dir,
      )
      self.assertEqual(res["summary"]["audit_log_confidence"], "LOW")
      self.assertEqual(
          res["summary"]["missing_data_access_services"],
          ["aiplatform.googleapis.com", "secretmanager.googleapis.com", "storage.googleapis.com"],
      )
      self.assertEqual(res["summary"]["recommended_cutover"], "CANARY_DUAL_BIND")
      self.assertIn("CANARY_DUAL_BIND", res["payload"]["audit_log_confidence_warning"])
      md_path = out_dir / "breakglass_simulation_report.md"
      self.assertTrue(md_path.exists())
      md_text = md_path.read_text(encoding="utf-8")
      self.assertIn("LOW", md_text)
      self.assertIn("CANARY_DUAL_BIND", md_text)

  def test_recommended_cutover_hold_when_403s_detected(self):
    policy = {
        "auditConfigs": [
            {
                "service": "allServices",
                "auditLogConfigs": [{"logType": "DATA_READ"}, {"logType": "DATA_WRITE"}],
            }
        ]
    }
    res = simulator.run_breakglass_simulation(
        project_id=PID,
        analysis_data=self._sim_analysis(extra_exercised=["bigquery.tables.getData"]),
        gcp_client=self._StubGCPClient(),
        policy_data=policy,
    )
    self.assertEqual(res["summary"]["audit_log_confidence"], "HIGH")
    self.assertGreater(res["summary"]["simulated_403_denials"], 0)
    self.assertEqual(res["summary"]["recommended_cutover"], "HOLD")


if __name__ == "__main__":
  unittest.main()
