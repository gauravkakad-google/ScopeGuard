---
name: gcp-iam-federation-architect
description: >-
  Audits customer-managed Service Account JSON keys (USER_MANAGED keys, key age,
  and external CI/CD automation accounts) and generates keyless Workload Identity
  Federation (WIF) Pool and Provider Terraform configurations (GitHub Actions,
  GitLab CI, AWS/OIDC) with anti-spoofing CEL attribute_condition guards and a
  zero-downtime key-retirement runbook, publishing outputs to the ScopeGuard GCS
  assessment store.
---

# GCP Workload Identity Federation (WIF) & Key Retirement Architect Skill

## Overview

Exported Service Account JSON keys (`USER_MANAGED`) do not expire automatically and are the #1 credential leak vector in cloud environments. This skill:
1. **Mandatory GCS Assessment Store Pre-Check**: Verifies `~/.scopeguard/config.json` (or prompts on first run for `<project_id>_scopeguard_assessments` and region) and checks bucket existence/permissions in `<1s`.
2. **Service Account Key Inventory**: Queries `iam.projects.serviceAccounts.keys.list` (`keyTypes=USER_MANAGED`) across all customer-managed Service Accounts in the project and flags aged keys (`>90 days`) and CI/CD deployer identities.
3. **Existing WIF Pool & Provider Hygiene Audit**: Read-only audit of existing Workload Identity Pools & Providers (`locations/global/workloadIdentityPools` + `/providers`, degrading gracefully on 403/404) flagging `WIF_MISSING_ATTRIBUTE_CONDITION` (CRITICAL), `WIF_BROAD_ORG_TRUST` (HIGH), and `WIF_UNRESTRICTED_ISSUER` (MEDIUM) with concrete Terraform hardening snippets in `federation_audit.json` and `WIF_MIGRATION.md`.
4. **Keyless WIF Blueprint Synthesis**: Generates `google_iam_workload_identity_pool`, `google_iam_workload_identity_pool_provider`, and `principalSet://` bindings in Terraform HCL with strict `attribute_condition` repository/org guards, plus a phased key-disable-then-delete runbook.
5. **CI Templates & Migration Guide**: Flags `--github-org`, `--github-repo`, `--github-ref` (optional ref pin), `--gitlab-project`, `--gitlab-url` (OIDC issuer), `--gitlab-ref`, `--project-number` (provider resource names), and `--ci-platforms` (default `github,gitlab`). Outputs: `federation_audit.json`, `wif_federation.tf`, `ci/github-actions-wif.yml`, `ci/gitlab-ci-wif.yml`, `WIF_MIGRATION.md`, and `retire_sa_keys.sh` (**dry-run by default**; `--apply [--yes]` to execute).

## Quick Start

```bash
python3 plugins/scopeguard/skills/gcp-iam-federation-architect/scripts/federation_architect_cli.py \
  --project=my-gcp-project \
  --github-org="scopeguard-enterprise" \
  --github-repo="scopeguard-enterprise/platform-infra" \
  --github-ref=refs/heads/main \
  --project-number=123456789012 \
  --output-dir=./scopeguard-output/my-gcp-project/federation-wif
```

## Mandatory Post-Execution Output (Option A)

Upon completion, automatically publish `<artifact_dir>/scopeguard_recommendations_<project_id>.md` (`UserFacing: true`) from `<output_dir>/scopeguard_recommendations_<project_id>.md`, and summarize static `USER_MANAGED` SA key findings, WIF OIDC candidate mappings, and clickable `file://` links to `wif_federation.tf`, `ci/github-actions-wif.yml` / `ci/gitlab-ci-wif.yml`, `WIF_MIGRATION.md`, and `retire_sa_keys.sh` in chat.
