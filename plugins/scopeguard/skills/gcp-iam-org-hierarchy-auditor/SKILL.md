---
name: gcp-iam-org-hierarchy-auditor
description: >-
  Resolves the Google Cloud Organization -> Folder -> Project resource ancestry
  chain, inspects inherited IAM bindings (when Cloud Asset Inventory / ancestor
  read access is available, degrading gracefully on project-scoped credentials),
  and evaluates critical IAM Organization Policy constraints (SA key disablement,
  default SA auto-grants, and domain restriction), publishing outputs to the
  ScopeGuard GCS assessment store.
---

# GCP Organization Hierarchy & Org Policy Drift Auditor Skill

## Overview

Project-level IAM policies tell only part of the governance story—Organization and Folder bindings inherit downward, and missing Organization Policy constraints allow drift to recur. This skill:
1. **Mandatory GCS Assessment Store Pre-Check**: Verifies `~/.scopeguard/config.json` (or prompts on first run for `<project_id>_scopeguard_assessments` and region) and checks bucket existence/permissions in `<1s`.
2. **Resource Ancestry Resolution**: Queries `projects.getAncestry` (`Organization -> Folders -> Project`) and checks ancestor IAM visibility.
3. **Org Policy Baseline Evaluation**: Checks effective status of 4 foundational IAM Org Policies (`iam.disableServiceAccountKeyCreation`, `iam.disableServiceAccountCreation`, `iam.automaticIamGrantsForDefaultServiceAccounts`, `iam.allowedPolicyMemberDomains`) and generates Org Policy v2 Terraform HCL.

## Quick Start

```bash
python3 plugins/scopeguard/skills/gcp-iam-org-hierarchy-auditor/scripts/org_hierarchy_cli.py \
  --project=my-gcp-project \
  --output-dir=./scopeguard-output/my-gcp-project/org-hierarchy
```

## Mandatory Post-Execution Output (Option A)

Upon completion, automatically publish `<artifact_dir>/scopeguard_recommendations_<project_id>.md` (`UserFacing: true`) from `<output_dir>/scopeguard_recommendations_<project_id>.md`, and summarize the resolved `Org -> Folder -> Project` ancestry path, Org Policy enforcement status, and clickable `file://` link to `org_policies.tf` in chat.
