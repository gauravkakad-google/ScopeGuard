---
name: gcp-iam-deny-policy-architect
description: >-
  Synthesizes Google Cloud IAM v2 Deny Policies (iam.googleapis.com/DenyPolicy)
  and Terraform HCL to establish hard preventative guardrails that override any
  accidental Allow bindings—blocking static Service Account key creation, Cloud
  Audit Log sink deletion, unauthorized root IAM policy mutations outside GitOps
  pipelines, and unapproved public storage exposure, with explicit principal and
  resource-tag exemptions, publishing outputs to the ScopeGuard GCS assessment store.
---

# GCP IAM v2 Deny Policy Preventive Guardrail Architect Skill

## Overview

IAM Allow policies alone cannot guarantee that a future administrator won't accidentally grant an overly broad role. **IAM v2 Deny Policies** evaluate *before* Allow policies and act as immutable preventive guardrails across an Organization, Folder, or Project.

This skill:
1. **Mandatory GCS Assessment Store Pre-Check**: Verifies `~/.scopeguard/config.json` (or prompts on first run for `<project_id>_scopeguard_assessments` and region) and checks bucket existence/permissions in `<1s`.
2. **Validated Preventive Guardrail Synthesis (`D1`–`D5`)**: Generates IAM v2 `DenyPolicy` JSON specs and `google_iam_deny_policy` Terraform HCL validated against the official `DENY_SUPPORTED_PERMISSIONS` allowlist (`<service_fqdn>/<resource>.<verb>`), complete with breakglass and CI/CD exemptions so `terraform apply` / `gcloud iam policies create` never fail on unsupported permissions.
3. **AI Agent Blast-Radius Containment (`D5_CONTAIN_AI_AGENT_BLAST_RADIUS`)**: Accepts repeatable `--ai-agent-principal` flags and auto-discovers AI/agent Service Accounts (`F8_ai_agent_blast_radius`, `aiplatform`/`ml`/`discoveryengine` roles, or `*agent*`/`*rag*`/`*llm*`/`*mcp*` SAs) to hard-deny privilege escalation, key/API-key minting, and audit sink deletion. Complements **Agent Gateway** and **Model Armor** (runtime prompt/tool filters) with an unbypassable IAM control-plane ceiling.
4. **Break-Glass Exemptions & Observe-First Rollout**: `--breakglass-principal` (repeatable; `user:` / `group:` / `serviceAccount:` members or IAM v2 `principal://` IDs) is exempted from every rule; a warning is logged if none is supplied. Outputs: `deny_policy_v2.json`, `deny_policy_spec.json`, `deny_policies.tf`, and `deny_rollout.md` — an observe-first rollout guide (IAM deny policies have no dry-run mode).

## Quick Start

```bash
python3 plugins/scopeguard/skills/gcp-iam-deny-policy-architect/scripts/deny_policy_cli.py \
  --project=my-gcp-project \
  --breakglass-principal=group:breakglass-admins@example.com \
  --ai-agent-principal=serviceAccount:rag-agent@my-gcp-project.iam.gserviceaccount.com \
  --output-dir=./scopeguard-output/my-gcp-project/deny-policies
```

## Mandatory Post-Execution Output (Option A)

Upon completion, automatically publish `<artifact_dir>/scopeguard_recommendations_<project_id>.md` (`UserFacing: true`) from `<output_dir>/scopeguard_recommendations_<project_id>.md`, and present the `D1`–`D5` IAM v2 Deny Rules, guarded high-risk permissions, contained AI agent principals, breakglass exemptions, and clickable `file://` links to `deny_policies.tf`, `deny_policy_v2.json`, and `deny_rollout.md` in chat.
