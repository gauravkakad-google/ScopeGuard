---
name: gcp-iam-breakglass-simulator
description: >-
  Dry-runs and validates proposed least-privilege IAM custom roles (Model A persona
  roles and Model B capability bundles) by replaying historical Cloud Audit Log activity
  and generating Policy Simulator verification commands before production cutover.
  Computes per-principal replay pass rates, simulated HTTP 403 denial counts, uncovered
  method-to-permission gaps, and cutover readiness verdicts, then publishes results to
  the ScopeGuard GCS assessment store.
---

# GCP IAM Breakglass & Policy Replay Simulator Skill

## Overview

Before cutting production workloads over from broad predefined roles (`roles/editor`, `roles/aiplatform.admin`, `roles/storage.admin`) to minimal custom roles in Phase `P2`, SRE and Cloud Security teams need deterministic proof that **zero legitimate production API calls will fail with `403 PERMISSION_DENIED`**.

This skill executes a non-disruptive shadow replay:
1. **Mandatory GCS Assessment Store Pre-Check**: Verifies `~/.scopeguard/config.json` (or prompts on first run for `<project_id>_scopeguard_assessments` and region) and checks bucket existence/permissions in `<1s`.
2. **Cloud Audit Log Ingestion & Method Mapping**: Queries `cloudaudit.googleapis.com` (`Admin Activity` + `Data Access`) and maps observed `protoPayload.serviceName` + `protoPayload.methodName` invocations (plus Active Assist exercised permissions) to canonical IAM permissions.
3. **Shadow Role Replay (`Model A` Personas & `Model B` Capability Bundles)**: Evaluates every observed historical API operation per principal against its proposed `sg_persona_*` role or `sg_cap_*` bundle (from the audit's `principal_mapping`) to verify 100% coverage (`simulated_403_denials == 0`). Verdict: `READY_FOR_ZERO_DOWNTIME_CUTOVER` or `HOLD_REQUIRES_PERMISSION_DELTA`.
4. **Audit-Log Visibility & Simulation Confidence (`auditConfigs` Check)**: Inspects `policy_data.auditConfigs` (or `bundle.iam_policy.auditConfigs`) for `DATA_READ` and `DATA_WRITE` coverage on data/secret/KMS/AI services touched by proposed roles (`storage.googleapis.com`, `secretmanager.googleapis.com`, `cloudkms.googleapis.com`, `aiplatform.googleapis.com`, `bigquery.googleapis.com`, accounting for `allServices`). Emits `audit_log_confidence` (`HIGH` / `MEDIUM` / `LOW`), `missing_data_access_services`, `recommended_cutover` (`DIRECT` if `HIGH` and `0` 403s, `CANARY_DUAL_BIND` if `MEDIUM`/`LOW` and `0` 403s, `HOLD` if `>0` 403s), and an explicit operator warning whenever confidence is not `HIGH` so missing Data Access logs are never mistaken for proof of zero breakage.
5. **Policy Troubleshooter & Policy Simulator Commands**: Generates copy-pasteable `gcloud policy-troubleshoot iam` and `gcloud policy-simulator replays` verification commands for high-criticality principals.

## Quick Start

```bash
python3 plugins/scopeguard/skills/gcp-iam-breakglass-simulator/scripts/breakglass_simulator_cli.py \
  --project=my-gcp-project \
  --lookback-days=90 \
  --output-dir=./scopeguard-output/my-gcp-project/simulator
```

Optional: `--analysis-json` / `--bundle-json` (reuse audit outputs instead of re-collecting), `--policy-json` (local `iam_policy_backup_<project>.json` for `auditConfigs` confidence evaluation), `--audit-bq-table=<proj>.<dataset>._AllLogs` (full Log Analytics coverage), `--log-limit`. Outputs `breakglass_simulation.json` (pass to `gcp-iam-finding-remediator --simulation-file` for real simulated-403 numbers), `breakglass_simulation_report.md`, and `verify_policy_troubleshooter.sh`.

If `BUCKET_CONFIG_REQUIRED` (`exit code 20`) or `BUCKET_NOT_FOUND` (`exit code 21`) is returned on first run, ask the user to confirm the GCS bucket name and region, then re-run with `--bucket <BUCKET> --region <REGION> --save-bucket-config` (and `--ensure-bucket` if creating a new bucket).

## Mandatory Post-Execution Output (Option A)

Upon completion, automatically publish `<artifact_dir>/scopeguard_recommendations_<project_id>.md` (`UserFacing: true`) from `<output_dir>/scopeguard_recommendations_<project_id>.md` and present the cutover readiness verdict, per-principal simulated HTTP 403 results, and clickable `file://` links (`verify_policy_troubleshooter.sh`) directly in chat.
