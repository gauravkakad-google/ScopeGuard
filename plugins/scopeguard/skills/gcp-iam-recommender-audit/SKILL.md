---
name: gcp-iam-recommender-audit
description: >-
  Audits any Google Cloud project's IAM posture using Active Assist (Recommender API),
  IAM API, Resource Manager API, and Cloud Audit Logs. Validates 100% of principals and
  role bindings, identifies security findings (over-privileged principals, basic roles,
  privilege-escalation paths, inactive service accounts, expired conditional bindings,
  and excess service agent roles), synthesizes a minimal set of custom roles (default 1-to-1 persona
  Model A sg_persona_* roles plus non-overlapping Model B sg_cap_* capability bundles) mapped across all principals,
  and produces a phased implementation roadmap (P0-P3) with service blast-radius impact
  analysis and an automated emergency rollback runbook.
---

# GCP IAM Recommender & Minimal Custom Role Audit Skill

## Overview

Given a target Google Cloud `PROJECT_ID`, this skill performs an end-to-end IAM security posture assessment and role-mining optimization:

1. **100% Principal & Binding Validation**: Snapshots the project IAM policy (`getIamPolicy` with `etag` for rollback) and classifies every principal into `Human Users`, `Customer-Managed Service Accounts`, `Default Project Service Accounts`, or `Google-Managed Service Agents`.
2. **Active Assist & Security Posture Audit (`F1`–`F8`)**: Queries `google.iam.policy.Recommender`, `google.iam.policy.Insight`, `google.iam.serviceAccount.Insight`, `google.iam.policy.LateralMovementInsight`, `iam service-accounts`, and 90-day Cloud Audit Logs to detect basic roles (`F1`), unused permissions (`F2`), privilege-escalation chains (`F3`), inactive/orphaned service accounts (`F4`), expired conditional bindings (`F5`), over-privileged/external service agents (`F6`), role sprawl (`F7`), and AI/agentic Service Account blast-radius / shared-SA risks (`F8`, framed as **Identity-Layer Containment complementing Agent Gateway / Model Armor** via dedicated per-agent SA + resource-scoped role + `D5` IAM v2 Deny ceiling).
3. **Minimal Custom Role Set-Cover (`Model A` Personas & `Model B` Capabilities — Workload Identities Only)**: Expands predefined roles and filters candidate permissions against `iam list-testable-permissions` (`customRolesSupportLevel != NOT_SUPPORTED`) strictly for non-human workload identities (`serviceAccount:`). Human `user:` principals never receive `sg_persona_<username>` custom roles and are routed to **Google Groups + PAM JIT** (`Human -> PAM JIT / Group`, `pam_entitlements.tf`). Generates:
   - **Model A — persona roles, default (`custom-roles/personas/<id>.yaml`)**: One self-contained role per workload persona, ID `sg_persona_<workload>`, title `SG Persona · <Workload>`.
   - **Model B — capability roles (`custom-roles/capabilities/<id>.yaml` + `custom-roles/bundles.yaml`)**: IDs `sg_cap_<domain>_<access>[_<qualifier>]`, title `SG Capability · <X>`. Capabilities are pairwise disjoint ($R_i \cap R_j = \emptyset$); `bundles.yaml` lists each persona's capability set and members as an exact cover (no over-grant, no under-grant). Sensitive permissions (e.g. `iam.serviceAccounts.actAs`, token/key creation, secret access, IAM policy/role admin) are isolated in visibly named roles such as `sg_cap_sa_impersonate`. ID collisions are qualified by resource noun → secondary domain → both → short hash.
   - **Naming**: prefix precedence `--role-prefix` > `$SCOPEGUARD_ROLE_PREFIX` > `sg_`; IDs are `[A-Za-z0-9_.]`, ≤64 chars. Personas built without Active Assist usage data are flagged in `summary.no_usage_data_personas` (`evidence_source: role_definition_no_usage_data`). Every role carries traceability (source predefined roles, members, evidence) in `analysis_results.json` → `role_traceability`. Legacy `custom-roles/*.yaml` / `custom-roles/disjoint/` layouts are still read as a fallback; envelope schema `2.1` (`2.0` still supported).
4. **Phased Remediation Roadmap (`P0`–`P3`) & Service Impact Analysis**: Organizes all actions into `P0` (Immediate Zero-Impact Hygiene), `P1` (Inactive SAs, AI/Agent Blast-Radius Containment & Privilege-Escalation Removal), `P2` (Custom Role Cutover), and `P3` (Human Group/PAM JIT Migration, Breakglass & Service Agent Scoping), detailing blast radius and affected GCP services per phase.
5. **Detailed Recommendations Markdown Document (`detailed_recommendations.md`, legacy — superseded at pipeline level by `REMEDIATION_PLAN.md`)**: Generates an exhaustive standalone Markdown specification containing Active Assist recommendation breakdowns (`rec_id`, `etag`, exercised/inferred permissions), complete custom role specifications (Model A personas and Model B capabilities, with a role traceability section), all 100% principal-to-role mappings, copy-pasteable `P0`–`P3` CLI runbooks with blast-radius impact assessments, and rollback instructions.
6. **Emergency Rollback Runbook (`rollback_runbook.sh`)**: Generates a **dry-run-by-default** rollback script (`--apply [--yes]`, `--principal <member>`, `--rollback iam_policy_backup_<pid>.json [--force-rollback]` for a full `set-iam-policy` restore) containing granular per-principal restore commands for all current bindings (including IAM conditions), dry-run-aware `gcloud iam service-accounts enable` commands for every `F4` quarantined/disabled Service Account so `P0`/`P1` quarantine is 1-command reversible, a Symptom-to-Principal Triage Matrix for HTTP `403 PERMISSION_DENIED` errors, and a full-project policy restore command.
7. **Cloud Run Metadata REST Transport, 5 Verification Gates & Ecosystem Exports**: Automatically switches between `gcloud` CLI locally and GCE Metadata Server REST APIs when running inside Cloud Run; inspects individual Service Account resource IAM policies (`getIamPolicy`); computes `executive_kpis`, `transitive_paths`, and `verification_gates` (`simulated_breakage_count == 0`). When run via the orchestrator, canonical exports are `scc_findings_import.json` (file only — no SCC API write-back) and `scopeguard.sarif.json`; this module's own `scc_findings_payload.json` / `scopeguard_audit.sarif.json` are legacy and kept for compatibility.

---

## Dependencies

This skill builds upon and must be used in coordination with the following installed skills:

- **`gcloud`**: Mandatory for leaf-level command validation (`gcloud help <leaf_command>`), `--project` and `--quiet` flag enforcement, data reduction (`--format`, `--limit`, `--filter`), and strict human-in-the-loop authorization before any IAM mutation.
- **`enforcing-resource-attribution`**: Required when executing `gcloud` commands directly in the terminal (`CLOUDSDK_METRICS_ENVIRONMENT` and `CLOUDSDK_METRICS_REQUEST_ATTRIBUTION`). Never include tracking prefixes in generated user scripts or runbooks.
- **`retrieving-developer-knowledge`**: Used to look up official Google Cloud documentation for newly introduced predefined roles or service agent requirements.
- **`uv`**: Required to execute `./scripts/iam_audit_cli.py` via `uv run`.

---

## Quick Start & Mandatory GCS Pre-Check

Before running any IAM collection, `full-audit` automatically runs a `<1s` **GCS Assessment Store Pre-Check**:
- **First Run (`exit code 20`, `BUCKET_CONFIG_REQUIRED`)**: Ask the user to confirm the GCS bucket name (default: `<project_id>_scopeguard_assessments`, or a custom bucket name) and region (default: `asia-southeast1`, or a custom region). Then pass `--bucket <BUCKET> --region <REGION> --save-bucket-config` (and `--ensure-bucket` if creating a new bucket).
- **Subsequent Runs**: Automatically reuses the saved bucket from `~/.scopeguard/config.json`, verifies the bucket exists and is writable, writes a new immutable run file to `gs://<bucket>/<project_id>/runs/<UTC_timestamp>_recommender-audit_<id>.json`, and updates `<project_id>/latest.json` (marking any non-executed skills carried forward from prior runs as `CARRIED_FORWARD_PROBABLY_STALE` or `STALE_POLICY_DRIFT`).

```bash
python3 plugins/scopeguard/skills/gcp-iam-recommender-audit/scripts/iam_audit_cli.py full-audit \
  --project=my-gcp-project \
  --location=global \
  --freshness-days=90 \
  --log-limit=200 \
  --role-prefix=sg_ \
  --output-dir=./scopeguard-output/my-gcp-project
```
*(`--role-prefix` is optional — defaults to `$SCOPEGUARD_ROLE_PREFIX` or `sg_`. Pass `--local-only` only when explicitly skipping GCS publishing.)*

---

## Utility Scripts

The multi-command CLI script [iam_audit_cli.py](./scripts/iam_audit_cli.py) supports four subcommands. All subcommands write structured output to files (never dumping large payloads to stdout) and require explicit limit/window arguments.

### 1. `collect` — Snapshot Policy & Fetch Recommender/IAM Data
Collects the raw IAM policy, Active Assist recommendations/insights, service accounts, testable permissions, predefined role definitions, and 90-day audit logs. Also saves an immutable `iam_policy_backup_<project>.json` file for emergency rollback.

```bash
uv run .agents/skills/gcp-iam-recommender-audit/scripts/iam_audit_cli.py collect \
  --project=YOUR_PROJECT_ID \
  --location=global \
  --freshness-days=90 \
  --log-limit=300 \
  --output=./audit-output/YOUR_PROJECT_ID/audit_bundle.json
```

### 2. `analyze` — Run Security Detectors (`F1`–`F7`) & Custom Role Mining
Evaluates all principals against findings `F1`–`F7` (see [security_findings_catalog.md](./references/security_findings_catalog.md)), computes both **Model A** persona roles and **Model B** disjoint capability roles + bundles, and maps 100% of principals to their target state. Accepts `--role-prefix`.

```bash
uv run .agents/skills/gcp-iam-recommender-audit/scripts/iam_audit_cli.py analyze \
  --bundle=./audit-output/YOUR_PROJECT_ID/audit_bundle.json \
  --output=./audit-output/YOUR_PROJECT_ID/analysis_results.json
```

### 3. `generate-artifacts` — Produce Report, Detailed Recommendations Doc, Role YAMLs & Rollback Runbook
Generates `iam_security_posture_report.md`, `detailed_recommendations.md`, custom role YAML files (`custom-roles/personas/*.yaml`, `custom-roles/capabilities/*.yaml`, `custom-roles/bundles.yaml`), `principal_mapping.json`, `iam_policy_backup_<project>.json` (with `etag`), and `rollback_runbook.sh` following [report_and_rollback_template.md](./references/report_and_rollback_template.md).

```bash
uv run .agents/skills/gcp-iam-recommender-audit/scripts/iam_audit_cli.py generate-artifacts \
  --analysis=./audit-output/YOUR_PROJECT_ID/analysis_results.json \
  --policy-backup=./audit-output/YOUR_PROJECT_ID/iam_policy_backup_YOUR_PROJECT_ID.json \
  --output-dir=./audit-output/YOUR_PROJECT_ID
```

### 4. `full-audit` — Run All Three Steps Sequentially
Executes `collect` $\rightarrow$ `analyze` $\rightarrow$ `generate-artifacts` in one command.

---

## Workflow

When the user asks to analyze a GCP project's IAM Recommender findings, audit its IAM posture, or design minimal custom roles:

1. **Mandatory `gcloud` 4-Step Plan First**:
   - Present the 4-step validation plan from [gcloud_command_patterns.md](./references/gcloud_command_patterns.md) (`Step 1: Syntax Validation via gcloud help <leaf_command>`, `Step 2: Parameter Verification`, `Step 3: Dry-Run Command Proposal`, `Step 4: Command Proposal & Authorization`).
2. **Execute Read-Only Audit via `iam_audit_cli.py`**:
   - Run `uv run .../scripts/iam_audit_cli.py full-audit` with the target `--project` and `--output-dir`.
   - If optional sources (such as Cloud Audit Logs or Lateral Movement Insights) have 0 entries or permission restrictions, the script automatically falls back to static predefined-role consolidation and logs the fallback in `analysis_results.json`.
3. **Present the Report, Detailed Recommendations Doc, Phased `P0`–`P3` Plan, Impact Assessment & Rollback Playbook**:
   - Link all generated files (`iam_security_posture_report.md`, `detailed_recommendations.md`, `principal_mapping.json`, `custom-roles/personas/*.yaml`, `custom-roles/capabilities/*.yaml`, `custom-roles/bundles.yaml`, `rollback_runbook.sh`, and `iam_policy_backup_<project>.json`). Call out any `no_usage_data_personas`.
   - Clearly summarize the `100%` principal mapping ($y_1 + y_2 + \dots = N$ total principals), the `P0`–`P3` execution phases with service blast-radius warnings, and the rollback procedures.
4. **Enforce Strict Human-in-the-Loop Gate Before Any Mutation**:
   - **NEVER** execute `gcloud iam roles create`, `gcloud projects add-iam-policy-binding`, `gcloud projects remove-iam-policy-binding`, `gcloud projects set-iam-policy`, or `gcloud iam service-accounts disable/delete` autonomously. Always ask the user for explicit approval first.

---

## Rate Limiting

`scripts/iam_audit_cli.py` enforces cross-process file-lock rate limiting (`/tmp/gcp_iam_audit_ratelimit.lock` + `time.monotonic()`) with exponential backoff (`2**attempt` seconds) on HTTP `429` (`RateLimitError`) and `5xx` responses:
- **Recommender API (`recommender.googleapis.com`)**: `5` requests/sec (`0.20s` interval)
- **IAM API (`iam.googleapis.com`)**: `10` requests/sec (`0.10s` interval)
- **Cloud Resource Manager API (`cloudresourcemanager.googleapis.com`)**: `4` requests/sec (`0.25s` interval)
- **Cloud Logging API (`logging.googleapis.com`)**: `1` request/sec (`1.00s` interval)

---

## Common Mistakes

1. **Including `NOT_SUPPORTED` or Org-Only Permissions in Custom Roles**:
   - Predefined roles often contain `resourcemanager.projects.list` (valid only in Organization/Folder custom roles) or `*.serviceAgent` / `gkehub.fleet.get` (`NOT_SUPPORTED` in custom roles). Always filter permissions against `iam list-testable-permissions` on the project resource before writing custom role YAMLs.
2. **Replacing Google-Managed Service Agent Roles with Custom Roles**:
   - Never replace `roles/<service>.serviceAgent` on `service-<PROJECT_NUMBER>@*.iam.gserviceaccount.com` principals with custom roles; GCP control planes require those managed roles. Only strip *excess* roles (such as `roles/owner`, `roles/editor`, `roles/storage.admin`, or expired `roles/secretmanager.admin` conditions) from service agents.
3. **Deleting Inactive Service Accounts Without a Quarantine Disable Period**:
   - A service account inactive for 90 days may still be used by a quarterly or annual batch job. Always **disable** (`gcloud iam service-accounts disable`) in `P0`/`P1` for a 14–30 day quarantine window and record the 21-digit `uniqueId` so `gcloud iam service-accounts enable` or `undelete` can recover a broken service immediately.

---

## Mandatory Post-Execution Output (Option A)

Never end the turn by only stating that the audit completed or uploaded to GCS. Automatically:
1. **Publish a Side-Pane Antigravity Artifact** (`<artifact_dir>/scopeguard_recommendations_<project_id>.md`, `UserFacing: true`) using the synthesized `<output_dir>/scopeguard_recommendations_<project_id>.md` (and `detailed_recommendations.md`).
2. **Present an Executive & Phased (`P0`–`P3`) Recommendation Summary in Chat** from `recommendation_digest` in CLI `stdout`, naming specific principals, Model A persona / Model B capability roles, clickable `file://` links to `custom-roles/`, `rollback_runbook.sh`, and the GCS snapshot URI.
