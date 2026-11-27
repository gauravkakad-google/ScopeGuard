---
name: gcp-iam-jit-pam-architect
description: >-
  Eliminates standing human administrative privileges by auditing persistent user
  and group IAM bindings (Owner, Editor, Admin, and expired IAM conditions) and
  generating Google Cloud Privileged Access Manager (PAM) entitlement manifests,
  Terraform HCL, dual-persona approval workflows, and time/attribute-scoped IAM
  Conditions (CEL), publishing outputs to the ScopeGuard GCS assessment store.
---

# GCP Just-in-Time (JIT) & Privileged Access Manager (PAM) Architect Skill

## Overview

Even right-sized standing privileges for human operators represent unnecessary persistent exposure. This skill converts standing human/group bindings into **Zero Standing Privilege (ZSP)** architectures:
1. **Mandatory GCS Assessment Store Pre-Check**: Verifies `~/.scopeguard/config.json` (or prompts on first run for `<project_id>_scopeguard_assessments` and region) and checks bucket existence/permissions in `<1s`.
2. **Standing Privilege Discovery**: Scans project IAM bindings for persistent `user:`, `group:`, and `domain:` grants holding Basic or Administrative roles (`roles/owner`, `roles/editor`, `roles/*Admin`, `roles/cloudsql.admin`, etc.), plus `F5` expired conditional bindings.
3. **PAM Entitlement & CEL Generation**: Synthesizes `google_privileged_access_manager_entitlement` Terraform HCL, `gcloud pam entitlements` YAML specs, ticket-justification gates, non-self-approving reviewer pools, and CEL condition templates.
4. **Approver Readiness Checks**: `--approver-group` (comma-separated, must be distinct from requesters) and `--notification-email` (repeatable). Each entitlement carries `readiness: READY` or `NOT READY: approver required` — set when no approver is supplied (placeholder `group:REPLACE-pam-approvers@example.com`) or self-approval is detected (`self_approval_detected`). Outputs: `jit_pam_spec.json`, `pam_entitlements.tf`, and `pam_rollout.md` (rollout guide).

## Quick Start

```bash
python3 plugins/scopeguard/skills/gcp-iam-jit-pam-architect/scripts/jit_pam_architect_cli.py \
  --project=my-gcp-project \
  --approver-group="group:cloud-security-approvers@example.com" \
  --notification-email=secops@example.com \
  --output-dir=./scopeguard-output/my-gcp-project/jit-pam
```

## Mandatory Post-Execution Output (Option A)

Upon completion, automatically publish `<artifact_dir>/scopeguard_recommendations_<project_id>.md` (`UserFacing: true`) from `<output_dir>/scopeguard_recommendations_<project_id>.md`, and present the standing human bindings discovered, proposed PAM Entitlement parameters (duration, approver, CEL guards), any `NOT READY` entitlements, and clickable `file://` links to `pam_entitlements.tf` and `pam_rollout.md` in chat.
