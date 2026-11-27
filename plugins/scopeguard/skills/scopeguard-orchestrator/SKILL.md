---
name: scopeguard-orchestrator
description: >-
  Master end-to-end orchestrator for the ScopeGuard Google Cloud IAM Remediation
  Co-Pilot. Runs all 10 analytical skill modules sequentially on a single GCP
  project (--project) OR recursively sweeps all active projects in a GCP
  Organization (--org-id) or Folder (--folder-id), enforces the GCS Assessment
  Store pre-check, publishes per-project versioned snapshots plus an Org/Folder
  rollup under _scopes/, and complements Google Cloud SCC and Wiz.
---

# ScopeGuard End-to-End IAM Governance Orchestrator Skill

## Overview

Use this skill whenever the user asks for an **end-to-end IAM governance assessment**, **full ScopeGuard scan**, or **multi-skill analysis** of one or more Google Cloud projects.

### Execution Workflow

1. **Step 0 — Mandatory GCS Bucket Pre-Check & First-Run Setup (`<1s`)**:
   - Invokes `scopeguard_pipeline.py`, which checks `~/.scopeguard/config.json` before executing any GCP IAM queries.
   - **First Run (`exit code 20` — `BUCKET_CONFIG_REQUIRED`)**: Stop and ask the user to confirm:
     - **GCS Bucket Name**: Default `<project_id>_scopeguard_assessments`, or a custom bucket name.
     - **GCS Region**: Default `asia-southeast1`, or a custom region.
   - **Missing Bucket (`exit code 21` — `BUCKET_NOT_FOUND`)**: Ask the user to confirm creating `gs://<bucket>` in `<region>` (with uniform bucket-level access and public access prevention enforced), then pass `--bucket <BUCKET> --region <REGION> --ensure-bucket --save-bucket-config`.
   - **Subsequent Runs**: Automatically reuses `~/.scopeguard/config.json` and verifies bucket existence + write permissions prior to scanning.

2. **Step 1–10 — Shared-Telemetry Sequential Execution**:
   - Collects project IAM policy (`etag`), Recommender insights, Service Account keys, testable permissions, ancestry, and Cloud Audit Logs **once**, then executes all 10 governance engines in dependency order:
     1. `gcp-iam-recommender-audit` (`F1`–`F7`, Model A `sg_persona_*` & Model B `sg_cap_*` + `bundles.yaml`, `P0`–`P3`, rollback)
     2. `gcp-iam-role-architect` (Resource-scoped reference & custom role blueprints + Model B capability reuse)
     3. `gcp-iam-breakglass-simulator` (90-day Cloud Audit Log shadow replay proving `0` 403 breakages)
     4. `gcp-iam-federation-architect` (`USER_MANAGED` SA key audit & keyless WIF Terraform)
     5. `gcp-iam-jit-pam-architect` (Standing human privilege -> PAM Entitlements & CEL guards)
     6. `gcp-iam-deny-policy-architect` (IAM v2 preventive Deny Policies `D1`–`D4`)
     7. `gcp-iam-org-hierarchy-auditor` (`Org -> Folder -> Project` ancestry & Org Policy baseline)
     8. `gcp-iam-gitops-pr-guardrail` (Terraform `.tf` / `--plan-json` shift-left drift scan `G1`–`G6` & SARIF; a `SCAN_ERROR` is recorded in `failed_stages` without aborting other stages)
     9. `gcp-iam-compliance-mapper` (CIS GCP v3.0, SOC 2, ISO 27001, and PCI-DSS control matrix)
     10. `gcp-iam-finding-remediator` (SCC/Wiz/derived findings → `finding-remediation/terraform/`, dry-run `remediation_commands.sh`, `ticket_proposed_remediation.md`)

3. **Step 11 — Per-Run Outputs & Versioned GCS Publishing**:
   - Writes to `--output-dir`: `README.md` + `manifest.json` (sha256 per file, grouped Read / Review / Apply / Evidence), `EXECUTIVE_SUMMARY.md`, `REMEDIATION_PLAN.md`, `EVIDENCE.md`, `scopeguard_recommendations_<project_id>.md`, `findings.csv` (CSV-injection safe), `findings.jsonl`, `scc_findings_import.json` (file only — no SCC API write-back), and `scopeguard.sarif.json`. `--bundle-by` adds `bundles/<key>/` subsets; `--redact` adds redacted copies under `shareable/`.
   - Writes a **new immutable timestamped JSON run file** (envelope schema `2.1`) to `gs://<bucket>/<project_id>/runs/<YYYYMMDDTHHMMSSZ>_full-suite_<id>.json`, uploads `latest_recommendations.md`, and updates `gs://<bucket>/<project_id>/latest.json` for instant rendering in the ScopeGuard stateless Web UI. The docs/exports above are also uploaded to `<project_id>/runs/<run_id>/` (immutable) and `<project_id>/latest/`.
   - Finding status (new / persisting / resolved) is stateless — inferred from diffs between runs; no state store is kept.

4. **Step 12 — Mandatory Automatic Post-Run Recommendations (Option A)**:
   - Immediately upon completion (without waiting for the user to ask):
     1. **Create/Overwrite a User-Facing Antigravity Artifact** (`<artifact_dir>/scopeguard_recommendations_<project_id>.md`) populated from `<output_dir>/scopeguard_recommendations_<project_id>.md` so the full multi-skill recommendations and runbook open in the side pane.
     2. **Output a Structured Chat Action Summary** from `recommendation_digest` in `stdout`: Executive KPIs, prioritized **`P0` $\rightarrow$ `P3` recommendations** (naming principals, custom roles, PAM/WIF/Deny/GitOps actions), clickable `file://` links to key `.tf`/`.yaml`/`.sh` files, and the GCS run URI.

## Quick Start

### Single GCP Project
```bash
python3 plugins/scopeguard/skills/scopeguard-orchestrator/scripts/scopeguard_pipeline.py \
  --project=my-gcp-project \
  --stages=all \
  --tf-scan-path=./terraform \
  --output-dir=./scopeguard-output/my-gcp-project
```

### Entire GCP Organization or Folder (Interactive Live-Progress Sweep — Recommended for `agy` CLI & Claude Code)
```bash
# Step 1: Discover active projects + run GCS & upfront API preflight (~2s)
python3 plugins/scopeguard/skills/scopeguard-orchestrator/scripts/scopeguard_pipeline.py \
  --org-id=123456789012 \
  --max-projects=25 \
  --discover-only \
  --output-dir=./scopeguard-output/org-123456789012

# Step 2: Run each project individually (posting a live progress update in chat after each project)
python3 plugins/scopeguard/skills/scopeguard-orchestrator/scripts/scopeguard_pipeline.py \
  --project=<PROJECT_ID> \
  --stages=all \
  --output-dir=./scopeguard-output/org-123456789012/<PROJECT_ID>

# Step 3: Publish the consolidated Org / Folder fleet rollup to GCS (_scopes/org_<ID>/latest.json)
python3 plugins/scopeguard/skills/scopeguard-orchestrator/scripts/scopeguard_pipeline.py \
  --org-id=123456789012 \
  --finalize-rollup \
  --output-dir=./scopeguard-output/org-123456789012
```

*(You can also run a single unattended sweep by omitting `--discover-only` and `--finalize-rollup`, or use `--folder-id=<FOLDER_ID>` instead of `--org-id`. Optional flags: `--exclude-projects=proj-a,proj-b`, `--include-projects=proj-c`, `--host-project=<quota_project>`, `--fetch-live-scc`, `--ensure-apis`, `--skip-api-check`.)*

### Optional Flags

| Flag | Purpose |
| :--- | :--- |
| `--principal=<member>` | Fast single-identity triage (e.g. `serviceAccount:foo@proj.iam.gserviceaccount.com`); filters analysis and remediation focus while preserving policy etag/metadata. |
| `--role-prefix=<p>` | Custom role ID prefix (precedence: flag > `$SCOPEGUARD_ROLE_PREFIX` > `sg_`). |
| `--bundle-by=owner\|folder\|principal` | Also write per-key subsets under `bundles/<key>/`. |
| `--redact` | Also write redacted copies under `shareable/` (salt from `$SCOPEGUARD_REDACT_SALT`). |
| `--plan-json=<plan.json>` | GitOps guardrail scans a `terraform show -json` plan (no regex fallback). |
| `--max-expiry-days=<n>` / `--include-unchanged` | GitOps: flag conditions longer than `n` days (default `90`); include no-op plan resources. |
| `--approver-group=<g1,g2>` / `--notification-email=<e>` | PAM approvers (comma-separated, distinct from requesters) and notification emails (repeatable). |
| `--breakglass-principal=<member>` | Deny-policy exception principal (repeatable). |
| `--ai-agent-principal=<member>` | AI agent / autonomous workload principal for D5 IAM v2 Deny Policy blast-radius guardrails (repeatable). |
| `--authoritative` | Finding remediator emits authoritative Terraform (writes `AUTHORITATIVE_TERRAFORM_WARNING.md`); default is non-authoritative `_member`. |
| `--canary` | Finding remediator emits dual-bind canary cutover scripts/Terraform (recommended when `audit_log_confidence` is `LOW` or `MEDIUM`). |
| `--github-org` / `--github-repo` / `--github-ref` | WIF GitHub Actions attribute condition. |
| `--gitlab-project` / `--gitlab-url` / `--gitlab-ref` | WIF GitLab CI attribute condition (`--gitlab-url` default `https://gitlab.com`). |
| `--project-number` / `--ci-platforms=github,gitlab` | WIF provider project number and CI templates to emit. |
