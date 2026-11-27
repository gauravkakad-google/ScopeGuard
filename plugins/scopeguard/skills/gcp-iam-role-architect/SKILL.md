---
name: gcp-iam-role-architect
description: >-
  Translates any plain-English DevOps access requirement into strictly least-privilege
  Google Cloud custom roles and resource-scoped IAM bindings. Automatically splits
  permissions by their lowest GCP evaluation scope (Project vs. Dataset, Bucket,
  Secret, Topic, Subscription, Cloud Run Service, Artifact Registry Repo, KMS Key,
  or Service Account), distinguishes Headless Service Account vs. Interactive Console
  UI personas, validates permissions against live iam list-testable-permissions
  (with automatic offline fallback), checks for privilege-escalation primitives
  (E1-E5) and anti-sprawl reuse against existing Model A persona and Model B capability custom
  roles, and generates Custom Role YAMLs, gcloud/bq CLI scripts, Terraform HCL,
  and an emergency rollback runbook.
---

# GCP Least-Privilege Custom Role Architect Skill

## Overview

When a DevOps or Cloud Security engineer receives a new access requirement (e.g., *"give a user access to read data from BigQuery tables in a dataset and run jobs"*, *"allow a Cloud Run service account to read a Secret and publish to a Pub/Sub topic"*), this skill designs and validates the **minimal custom role(s)** and **resource-level bindings** required:

1. **Requirement & Persona Decomposition**: Translates natural-language requirements, capability IDs, or candidate predefined roles into atomic GCP permissions for either:
   - **Strict Headless / Service Account (`--persona=headless`)**: Only the core API execution/data-plane permissions.
   - **Interactive Human / Console UI & CLI (`--persona=console` or `both`)**: Adds the minimal read-only metadata/browsing permissions (`*.get`, `*.list`) needed by the Google Cloud Console and `gcloud`/`bq` CLI.
2. **Resource Hierarchy Scope Splitting**: Partitioning permissions into separate custom roles based on the **lowest resource boundary** where Google Cloud evaluates them (`Project` vs. `BigQuery Dataset`, `GCS Bucket`, `Secret Manager Secret`, `Pub/Sub Topic/Subscription`, `Cloud Run Service`, `Artifact Registry Repository`, `KMS CryptoKey`, or `Target Service Account`).
3. **Hybrid Live Validation & Privilege-Escalation Guardrails (`E1`–`E5`)**: Validates candidate permissions against `iam.permissions.queryTestablePermissions` when a `PROJECT_ID` is provided (with automatic offline fallback), strips `NOT_SUPPORTED` and Organization-only permissions (`E5`), and flags privilege-escalation vectors (`E1`–`E4`, such as `iam.serviceAccounts.actAs`, `*.setIamPolicy`, `iam.roles.update`).
4. **Anti-Sprawl & Capability Reuse (`Model A` & `Model B`)**: Scans existing custom roles in the target project and local workspace (`./custom-roles/personas/*.yaml` and `./custom-roles/capabilities/*.yaml`; legacy root `*.yaml` and `disjoint/` are read as a fallback) to recommend exact/superset reuse and generate a disjoint net-new delta capability role (`custom-roles/capabilities/sg_cap_<domain>_<access>[_<qualifier>].yaml`, $R_i \cap R_j = \emptyset$).
5. **Multi-Format IaC, Cloud Run REST & SARIF Deliverables**: Supports both local `gcloud` CLI and GCE Metadata Server REST execution on Cloud Run, automatically reuses cached `scopeguard-output/<project>/audit_bundle_<project>.json` `testablePermissions`, and generates a Markdown design report, persona YAMLs in `custom-roles/personas/` (ID `sg_persona_<workload>`, title `SG Persona · <X>`), any delta capability in `custom-roles/capabilities/`, `provision_roles_and_bindings.sh` (`gcloud`/`bq`), `main.tf` (Terraform HCL), `rollback_runbook.sh`, and **Wiz Shift-Left SARIF v2.1.0 (`role_design.sarif.json`)**.

---

## Dependencies

This skill coordinates with the following installed skills:

- **`gcloud`**: Mandatory for leaf-level command validation (`gcloud help <leaf_command>`), `--project` and `--quiet` flag enforcement, data reduction (`--format`, `--limit`, `--filter`), and strict human-in-the-loop approval before any IAM mutation.
- **`enforcing-resource-attribution`**: Required when executing `gcloud` or `bq` commands directly in the terminal (`CLOUDSDK_METRICS_ENVIRONMENT` and `CLOUDSDK_METRICS_REQUEST_ATTRIBUTION`). Never include tracking prefixes in generated user scripts or Terraform files.
- **`retrieving-developer-knowledge`**: Used to look up official Google Cloud IAM documentation when resolving permissions for newly released services or APIs not yet in the local catalog.
- **`gcp-iam-recommender-audit`**: Shares `./custom-roles/personas/*.yaml` (Model A), `./custom-roles/capabilities/*.yaml` + `bundles.yaml` (Model B) definitions and cached `audit_bundle_<project>.json` testable permissions.
- **`uv`**: Required to execute `./scripts/role_architect_cli.py` via `uv run`.

---

## Quick Start & Mandatory GCS Pre-Check

When `--project` is provided (and `--offline` / `--local-only` are not set), `full-design` automatically executes a `<1s` **GCS Assessment Store Pre-Check**:
- **First Run (`exit code 20`, `BUCKET_CONFIG_REQUIRED`)**: Ask the user to confirm the GCS bucket name (default: `<project_id>_scopeguard_assessments`, or custom bucket) and region (default: `asia-southeast1`, or custom region), then pass `--bucket <BUCKET> --region <REGION> --save-bucket-config` (plus `--ensure-bucket` if creating a new bucket).
- **Subsequent Runs**: Reuses `~/.scopeguard/config.json`, verifies bucket existence/permissions, merges the new role design into a new timestamped GCS run file (`gs://<bucket>/<project_id>/runs/<UTC_timestamp>_role-architect_<id>.json`), updates `<project_id>/latest.json`, and marks carried-forward sibling modules as probably stale.

```bash
python3 plugins/scopeguard/skills/gcp-iam-role-architect/scripts/role_architect_cli.py full-design \
  --requirement="give a user access to read data from bq tables in a dataset and run jobs" \
  --persona=both \
  --project=YOUR_PROJECT_ID \
  --principal="user:analyst@example.com" \
  --dataset-id="analytics_prod" \
  --role-prefix=sg_ \
  --existing-roles-dir=./custom-roles \
  --output-dir=./role-designs/bq-analyst-read
```

*(If designing roles before a GCP project is provisioned, omit `--project` or pass `--offline`. `--role-prefix` is optional — precedence: flag > `$SCOPEGUARD_ROLE_PREFIX` > `sg_`.)*

---

## Utility Scripts

The multi-command CLI script [role_architect_cli.py](./scripts/role_architect_cli.py) supports four subcommands and writes all structured outputs to files.

### 1. `list-capabilities` — Export Built-In Service Capability Matrix
Writes the built-in DevOps capability catalog (services, scopes, headless vs. console permissions, and closest predefined roles) to a JSON file.

```bash
uv run .agents/skills/gcp-iam-role-architect/scripts/role_architect_cli.py list-capabilities \
  --output=./role-designs/capabilities_catalog.json
```

### 2. `design` — Decompose Requirement, Split by Scope & Validate Permissions
Parses `--requirement`, `--capabilities`, `--add-permissions`, and/or `--from-roles`, splits permissions by resource scope (see [resource_hierarchy_matrix.md](./references/resource_hierarchy_matrix.md)), checks `E1`–`E5` escalation rules (see [privilege_escalation_catalog.md](./references/privilege_escalation_catalog.md)), evaluates existing custom roles for reuse, and writes `role_design_spec.json`.

```bash
uv run .agents/skills/gcp-iam-role-architect/scripts/role_architect_cli.py design \
  --requirement="read data from bq tables in a dataset and run jobs" \
  --persona=both \
  --project=YOUR_PROJECT_ID \
  --principal="user:analyst@example.com" \
  --dataset-id="analytics_prod" \
  --role-prefix=sg_ \
  --existing-roles-dir=./custom-roles \
  --output=./role-designs/bq-analyst-read/role_design_spec.json
```

### 3. `generate-artifacts` — Produce Report, Role YAMLs, CLI Script, Terraform & Rollback Runbook
Generates `role_design_report.md`, `custom-roles/personas/*.yaml`, any net-new delta `custom-roles/capabilities/*.yaml`, `provision_roles_and_bindings.sh`, `main.tf`, `rollback_runbook.sh`, and `role_design.sarif.json` following [output_templates.md](./references/output_templates.md).

```bash
uv run .agents/skills/gcp-iam-role-architect/scripts/role_architect_cli.py generate-artifacts \
  --spec=./role-designs/bq-analyst-read/role_design_spec.json \
  --output-dir=./role-designs/bq-analyst-read
```

### 4. `full-design` — Run `design` and `generate-artifacts` Sequentially
Executes `design` $\rightarrow$ `generate-artifacts` in a single command.

---

## Workflow

Whenever a user asks for the least-privilege permissions or custom role design for a GCP access requirement:

1. **Clarify or Infer Target Scope & Persona**:
   - Identify the **actions** needed, the **target resources** (e.g., specific dataset, bucket, secret, topic, or project), and whether the principal is a **Human User** (`console` UI/CLI metadata needed) or a **Service Account / Workload** (`headless` strict API minimum).
   - If the requirement involves a service not covered by `list-capabilities`, use `retrieving-developer-knowledge` or `--from-roles` / `--add-permissions` to supply the candidate permissions.
2. **Present the Mandatory `gcloud` 4-Step Validation Plan**:
   - Present the 4-step validation plan from [output_templates.md](./references/output_templates.md) (`Step 1: Syntax Validation via gcloud help <leaf_command>`, `Step 2: Parameter Verification`, `Step 3: Dry-Run Command Proposal`, `Step 4: Command Proposal & Authorization`).
3. **Execute `role_architect_cli.py full-design`**:
   - Run `uv run .agents/skills/gcp-iam-role-architect/scripts/role_architect_cli.py full-design` with the requirement flags and `--output-dir=./role-designs/<slug>`.
4. **Present the Scoped Architecture & Generated Deliverables**:
   - Link all generated files (`role_design_report.md`, `custom-roles/personas/*.yaml`, `custom-roles/capabilities/*.yaml`, `provision_roles_and_bindings.sh`, `main.tf`, and `rollback_runbook.sh`).
   - Highlight the **Resource Scope Split** (why Project-level permissions and Child-Resource permissions are separated into distinct roles), the **Strict Headless vs. Console UI** comparison, any **Privilege Escalation (`E1`–`E4`)** warnings, and any **Anti-Sprawl Reuse** matches from `./custom-roles/`.
5. **Enforce Strict Human-in-the-Loop Gate Before Provisioning**:
   - **NEVER** execute `gcloud iam roles create`, `gcloud * add-iam-policy-binding`, `bq update`, or `terraform apply` autonomously. Always wait for explicit user approval.

---

## Rate Limiting

`scripts/role_architect_cli.py` enforces cross-process file-lock rate limiting (`/tmp/gcp_iam_audit_ratelimit.lock` + `time.monotonic()`) with exponential backoff (`2**attempt` seconds) on HTTP `429` (`RateLimitError`) and `5xx` responses:
- **IAM API (`iam.googleapis.com`)**: `10` requests/sec (`0.10s` interval)
- **Cloud Resource Manager API (`cloudresourcemanager.googleapis.com`)**: `4` requests/sec (`0.25s` interval)

---

## Common Mistakes

1. **Binding Data-Plane Permissions at the Project Level**:
   - Never combine project-scoped job execution (`bigquery.jobs.create`) and dataset-scoped data reading (`bigquery.tables.getData`) into a single Project-level IAM binding—doing so grants the principal read access to **every** dataset in the project. Always split into a Project-level role and a Dataset/Bucket/Secret-level role.
2. **Granting `iam.serviceAccounts.actAs` at the Project Level**:
   - When a CI/CD pipeline or developer deploys Cloud Run, Cloud Functions, or Compute VMs, bind `iam.serviceAccounts.actAs` **only** on the specific target runtime Service Account resource (`gcloud iam service-accounts add-iam-policy-binding`), never across the entire project.
3. **Including `resourcemanager.projects.list` or `*.serviceAgent` in Project Custom Roles**:
   - Predefined roles like `roles/bigquery.dataViewer` include `resourcemanager.projects.list`, which is only valid in Organization-level custom roles and fails with `400 INVALID_ARGUMENT` in Project custom roles. Always run `role_architect_cli.py` to strip `E5` unsupported/org-only permissions automatically.

---

## Mandatory Post-Execution Output (Option A)

Automatically publish a user-facing Antigravity Artifact (`<artifact_dir>/scopeguard_recommendations_<project_id>.md`) containing the full scoped role design specification, Terraform HCL, and Model B capability reuse mapping, and present a concise resource-split recommendation summary in chat with clickable `file://` links to `main.tf`, `provision_roles_and_bindings.sh`, and the GCS run snapshot.

### Developer `403 PERMISSION_DENIED` Minimal-Fix Debugger (`troubleshoot-403`)

When a developer shares a live GCP `403 PERMISSION_DENIED` error log or stack trace, run `troubleshoot-403` to extract the exact missing permission(s), check existing Model B capability roles for reuse, evaluate `E1`–`E5` escalation risks, and emit the narrowest resource-scoped Terraform fix (`troubleshoot_403_fix.tf`) instead of granting `roles/editor` or `roles/*.admin`:

```bash
python3 plugins/scopeguard/skills/gcp-iam-role-architect/scripts/role_architect_cli.py troubleshoot-403 \
  --project=my-gcp-project \
  --principal="serviceAccount:genai-rag-agent-sa@my-gcp-project.iam.gserviceaccount.com" \
  --error-log="403 PERMISSION_DENIED: Permission 'secretmanager.versions.access' denied on resource 'projects/my-gcp-project/secrets/gemini-rag-config/versions/latest'" \
  --output-dir=./scopeguard-output/my-gcp-project/fix-403
```
