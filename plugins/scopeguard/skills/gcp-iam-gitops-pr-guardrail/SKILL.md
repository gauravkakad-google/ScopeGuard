---
name: gcp-iam-gitops-pr-guardrail
description: >-
  Scans Terraform HCL files (.tf) and Terraform plan JSON outputs in CI/CD or
  local workspaces to prevent IAM posture drift before merge. Evaluates 6
  Shift-Left gates (Basic Roles Owner/Editor, static SA key resources, E1-E5
  transitive impersonation combinations, un-scoped project-wide data-plane
  grants, stale or long-lived CEL condition windows, and public principals), generates
  PR review Markdown, CI pipeline YAML, and SARIF v2.1.0, and publishes results
  to the ScopeGuard GCS assessment store.
---

# GCP IAM GitOps PR & Terraform Drift Guardrail Skill

## Overview

Once a project is cleaned up to least privilege, unreviewed `terraform apply` changes can re-introduce `roles/editor` or static Service Account keys. This skill provides Shift-Left IaC enforcement:
1. **Mandatory GCS Assessment Store Pre-Check**: Verifies `~/.scopeguard/config.json` (or prompts on first run for `<project_id>_scopeguard_assessments` and region) and checks bucket existence/permissions in `<1s`.
2. **Static HCL & Plan JSON Scanner (`G1`–`G6`)**: Parses `google_project_iam_*`, `google_service_account_iam_*`, `google_service_account_key`, and `google_project_iam_custom_role` blocks across `.tf` files (`--scan-path`) or a `terraform show -json` plan (`--plan-json`; disables the regex fallback, `--include-unchanged` also evaluates no-op resources). Rules:
   - `G1_BASIC_ROLE_BLOCKED`, `G2_STATIC_SA_KEY`, `G3_TRANSITIVE_ESCALATION_EDGE`, `G4_UNSCOPED_PROJECT_DATA_ROLE`
   - `G5_STALE_CONDITION_WINDOW` (MEDIUM — condition expiry already passed), `G5_LONG_LIVED_CONDITION_WINDOW` (LOW — window longer than `--max-expiry-days`, default `90`)
   - `G6_PUBLIC_PRINCIPAL` (CRITICAL — `allUsers` / `allAuthenticatedUsers`)
3. **CI/CD Gate & SARIF Output**: Emits `APPROVE_CLEAN` / `BLOCK_MERGE` (any CRITICAL/HIGH finding) / `SCAN_ERROR` verdicts with a coverage section (input mode, files scanned, resources parsed/skipped), `gitops_guardrail_report.md` (PR review Markdown), `gitops_pr_comment.md` (concise PR-comment-ready Markdown with verdict badge and copy-pasteable HCL snippet; also writable to a custom path via `--pr-comment-md`), `gitops_guardrail_results.json`, the GitHub Actions template `scopeguard-iam-guardrail.yml`, GitHub/Wiz-compatible `gitops_guardrail.sarif.json`, and an auto-fixed `remediated_patch.tf`. Via the orchestrator these live under `gitops-guardrail/`.
   - **Shift-Left CI Exit Gating (`--fail-on`)**: Accepts `NONE` (default — always exits `0` on findings so orchestrator/local runs stay non-fatal), `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `ANY`. When `--fail-on != NONE`, exits `2` if any violation meets or exceeds the threshold (`ANY` with ≥1 violation), `3` on `SCAN_ERROR`, and `0` otherwise. `--verbose` enables debug logging.

## Quick Start

```bash
python3 plugins/scopeguard/skills/gcp-iam-gitops-pr-guardrail/scripts/gitops_guardrail_cli.py \
  --project=my-gcp-project \
  --scan-path=./terraform \
  --output-dir=./scopeguard-output/my-gcp-project/gitops-guardrail

# Or evaluate a Terraform plan with CI exit-code gating + PR comment output
terraform show -json tfplan > plan.json
python3 plugins/scopeguard/skills/gcp-iam-gitops-pr-guardrail/scripts/gitops_guardrail_cli.py \
  --project=my-gcp-project \
  --plan-json=plan.json \
  --max-expiry-days=90 \
  --fail-on=HIGH \
  --pr-comment-md=./pr-comment.md \
  --output-dir=./scopeguard-output/my-gcp-project/gitops-guardrail
```

## Mandatory Post-Execution Output (Option A)

Upon completion, automatically publish `<artifact_dir>/scopeguard_recommendations_<project_id>.md` (`UserFacing: true`) from `<output_dir>/scopeguard_recommendations_<project_id>.md`, and present the PR gate verdict (`APPROVE_CLEAN` / `BLOCK_MERGE` / `SCAN_ERROR`), `G1`–`G6` line-level violations, and clickable `file://` links to `gitops_guardrail_report.md`, `remediated_patch.tf`, `scopeguard-iam-guardrail.yml`, and `gitops_guardrail.sarif.json` in chat.
