---
name: gcp-iam-finding-remediator
description: >-
  Complements Google Cloud Security Command Center (SCC) and Wiz by ingesting
  inbound IAM security findings, alerts, or attack-path JSON exports and
  converting them into replay-verified, zero-breakage Terraform patches,
  least-privilege custom role replacements, atomic etag rollback commands,
  proposed-remediation ticket notes, and post-change verification notes for Jira,
  ServiceNow, SCC, or Wiz.
---

# GCP IAM SCC & Wiz Finding-to-Fix Remediator Skill

## Overview

Cloud Security Posture Management (CSPM / CNAPP) platforms such as **Google Cloud Security Command Center (SCC)** and **Wiz** excel at detecting misconfigurations and prioritizing cross-cloud attack paths. **ScopeGuard does not replace SCC or Wiz**—this skill acts as the **last-mile remediation co-pilot** that helps Cloud Administrators and Developers safely fix IAM findings raised by SCC or Wiz without breaking production workloads.

### Capabilities
1. **Mandatory GCS Assessment Store Pre-Check**: Verifies `~/.scopeguard/config.json` (or prompts on first run for `<project_id>_scopeguard_assessments` and region) in `<1s`.
2. **Multi-Source Inbound Finding & Attack-Path Ingestion**:
   - **Cloud SCC Findings & SCC Premium Attack Paths**: Ingests SCC Finding JSON, `toxicCombination` (`attackExposureScore`), `attackExposure`, and multi-hop `attackPath` (`nodes`/`edges` or `sourceProperties.attackPath`) via `--scc-finding-file` / `--finding-json`, or queries live active IAM findings from `securitycenter.googleapis.com` (`--fetch-live-scc`, with graceful fallback when SCC API is not enabled).
   - **Wiz Issues & Attack Paths**: Ingests Wiz Issue / Graph Attack Path JSON exports (`attackPath`, `graph`/`edges`, `entitySnapshot`, `issueId`/`id`) via `--wiz-issue-file`.
   - **Deterministic Choke-Point Selection**: Identifies the minimum-disruption IAM choke-point edge to sever multi-hop attack paths—preferring (1) severing a non-critical `iam.serviceAccounts.actAs` / `getAccessToken` impersonation edge, or (2) replacing a broad basic/admin role (`roles/owner`, `roles/editor`, `roles/iam.*Admin`) on the entry Service Account with its evidence-backed `sg_persona_*` role—and renders an **Attack-Path Choke-Point** block in `ticket_proposed_remediation.md`.
3. **Replay-Verified Surgical Remediation**:
   - Correlates each SCC/Wiz finding against the project's live IAM policy (`etag`), Active Assist 90-day exercised permissions, and synthesized Model A persona (`sg_persona_*`) / Model B capability (`sg_cap_*`) roles.
   - Uses real simulated-403 numbers from `breakglass_simulation.json` (`--simulation-file`) or a local envelope (`--envelope-file latest.json`) when GCS is not used; verifies **`0` simulated HTTP `403` denials** before recommending cutover.
4. **Dual-Bind Canary Cutover Mode (`--canary`)**:
   - Enabled explicitly via `--canary` or **auto-recommended** whenever simulation data reports `audit_log_confidence == "LOW"`.
   - Emits two safe-by-default (dry-run; `--apply` required) rollout scripts and adds a 2-step Canary Cutover guide to `ticket_proposed_remediation.md` and `terraform/README.md`:
     - `canary_step1_bind_least_privilege.sh` — Creates custom `sg_persona_*` role(s) and binds them **alongside** existing broad roles (zero breakage risk).
     - `canary_step2_remove_broad_role.sh` — Revokes the old broad roles after `--verify` confirms clean usage.
5. **Actionable Fix & Ticket Deliverables** (readiness `READY_FOR_PR_REVIEW`; no SCC/Wiz API write-back):
   - `terraform/` — PR-ready module: `versions.tf`, `variables.tf`, `main.tf` (non-authoritative `google_project_iam_member` by default; `--authoritative` emits `google_project_iam_binding` plus `AUTHORITATIVE_TERRAFORM_WARNING.md`), `old_bindings_import.tf.example`, `README.md`.
   - `remediation_patch.tf` — Single-file Terraform HCL equivalent.
   - `remediation_commands.sh` — **Dry-run by default**; `--apply [--yes]`, `--only <id>`, `--phase add|remove|all`, `etag` preflight (`--skip-etag-check` to override), add → verify → remove ordering, and `--rollback <backup.json> [--force-rollback]`.
   - `ticket_proposed_remediation.md` — Copy-pasteable Jira / ServiceNow / Wiz / SCC comment with before/after permission counts, attack-path choke-point analysis, canary rollout steps (when enabled), and replay evidence (proposed, not closure).
   - `finding_remediations.json` — Machine-readable plans (input to `--verify`).
6. **Closed-Loop Post-Change Verification (`--verify`, strictly read-only, local)**: After the change is applied, re-reads the live policy and `PERMISSION_DENIED` audit logs (`--verify-hours`, default `24`) for the plans in `--output-dir` (or `--plan-file`) and writes `ticket_verification_note.md` / `.json`. Includes inbound SCC/Wiz finding IDs, `audit_log_confidence`, a Terraform PR link placeholder (`<!-- Paste PR URL -->`), and an exact copy-pasteable verification status block so Security Admins can close SCC/Wiz/Jira tickets with audit-ready proof (no SCC/Wiz API write-back). Each check is `PASS` / `FAIL` / `NOT_VERIFIED`; overall `VERIFIED` / `FAILED` / `PARTIALLY_VERIFIED`. Exits `3` if any check fails.

## Quick Start

```bash
python3 plugins/scopeguard/skills/gcp-iam-finding-remediator/scripts/finding_remediator_cli.py \
  --project=my-gcp-project \
  --scc-finding-file=./examples/sample-findings/scc_sample_finding.json \
  --wiz-issue-file=./examples/sample-findings/wiz_sample_attack_path.json \
  --canary \
  --output-dir=./scopeguard-output/my-gcp-project/finding-remediation

# After the reviewed change is applied: verify and produce closed-loop ticket verification evidence
python3 plugins/scopeguard/skills/gcp-iam-finding-remediator/scripts/finding_remediator_cli.py \
  --project=my-gcp-project \
  --verify --verify-hours=24 \
  --output-dir=./scopeguard-output/my-gcp-project/finding-remediation
```

## Mandatory Post-Execution Output (Option A)

Upon completion, automatically publish `<artifact_dir>/scopeguard_recommendations_<project_id>.md` (`UserFacing: true`) from `<output_dir>/scopeguard_recommendations_<project_id>.md`, and present each ingested SCC/Wiz finding's root cause, verified Terraform fix, rollback command, proposed-remediation note, and clickable `file://` links (`terraform/main.tf`, `remediation_commands.sh`, `ticket_proposed_remediation.md`, and `ticket_verification_note.md` after `--verify`) directly in chat.
