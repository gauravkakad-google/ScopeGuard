# ScopeGuard — Google Cloud IAM Remediation & Least-Privilege Co-Pilot

[![CI](https://github.com/gauravkakad-google/ScopeGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/gauravkakad-google/ScopeGuard/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

**ScopeGuard** is a modular 11-skill AI agent plugin (built for Google Antigravity / `agy` CLI and compatible agent harnesses) and optional stateless Cloud Run review portal that helps **Security Admins and DevOps Engineers** safely eliminate overprivileged Google Cloud IAM bindings — **complementing Google Cloud Security Command Center (SCC) Premium, Wiz, and Agent Gateway / Model Armor**.

> **Complementary to SCC Premium, Wiz & Agent Gateway (Not a Replacement)**: Cloud SCC and Wiz excel at cloud-wide detection, attack-path graphing, and alerting, while Agent Gateway / Model Armor enforce runtime prompt and tool-call guardrails. ScopeGuard bridges the *last mile* of IAM engineering — turning findings and usage telemetry into **replay-verified Terraform HCL patches, attack-path choke-point fixes, least-privilege persona/capability roles, AI-agent IAM v2 Deny ceilings, dual-bind canary cutover scripts, `etag`-pinned rollbacks, and ticket verification evidence** — without ever auto-mutating production IAM.

---

## Key Capabilities (11 Modular Skills)

| Skill | Purpose |
| :--- | :--- |
| **`scopeguard-orchestrator`** | Runs all skills sequentially on a single GCP project (`--project`), fast-path triages a single identity (`--principal`), or sweeps an entire Organization (`--org-id`) / Folder (`--folder-id`) with live progress and GCS rollup publishing. |
| **`gcp-iam-recommender-audit`** | Brownfield IAM posture audit (`F1`–`F8`, including `F8_ai_agent_blast_radius` for AI/agentic SAs), Active Assist 90-day usage correlation, workload-only Model A persona roles (`sg_persona_*`, default) & Model B capability bundles (`sg_cap_*`), human `user:` → Groups + PAM JIT routing, `P0`–`P3` roadmap, and `etag`-pinned rollback runbook (including SA re-enable). |
| **`gcp-iam-finding-remediator`** | **SCC & Wiz Finding-to-Fix Co-Pilot**: Ingests live Cloud SCC findings (`--fetch-live-scc`) or exported SCC Toxic Combination / Attack Path & Wiz Attack Path JSON, selects the minimum-disruption IAM choke-point edge, and emits a reviewable `terraform/` module (non-authoritative `_member` by default), `remediation_patch.tf`, dry-run `remediation_commands.sh`, dual-bind `--canary` cutover scripts (`canary_step1/2_*.sh`), `ticket_proposed_remediation.md`, and (with `--verify`) closed-loop `ticket_verification_note.md`. No SCC/Wiz API write-back. |
| **`gcp-iam-role-architect`** | Shift-left natural-language-to-role designer **plus** Developer `troubleshoot-403` minimal-fix debugger (`E1`–`E5` escalation screening + Model B capability reuse). |
| **`gcp-iam-breakglass-simulator`** | Replays 90 days of Cloud Audit Logs against proposed custom roles, checks `policy.auditConfigs` Data Access log coverage (`audit_log_confidence`: `HIGH` / `MEDIUM` / `LOW`), and recommends `DIRECT` vs. `CANARY_DUAL_BIND` vs. `HOLD` before cutover. |
| **`gcp-iam-jit-pam-architect`** | Converts standing human `roles/owner` / `roles/editor` / admin bindings into time-bound Google Cloud Privileged Access Manager (PAM) entitlements with dual-persona approval, notification routing, and CEL guards. |
| **`gcp-iam-federation-architect`** | Audits `USER_MANAGED` Service Account JSON keys **and existing WIF Pools & Providers** (`WIF_MISSING_ATTRIBUTE_CONDITION`, `WIF_BROAD_ORG_TRUST`, `WIF_UNRESTRICTED_ISSUER`), and generates keyless Workload Identity Federation (WIF) Terraform + GitHub Actions / GitLab CI snippets. |
| **`gcp-iam-deny-policy-architect`** | Generates validated GCP IAM v2 Preventive Deny Policies (`D1`–`D5`) blocking static SA key creation, audit sink tampering, unapproved IAM mutations, storage exposure, and AI-agent blast-radius escalation (`D5_CONTAIN_AI_AGENT_BLAST_RADIUS`, complementing Agent Gateway / Model Armor). |
| **`gcp-iam-gitops-pr-guardrail`** | Shift-left CI gate scanning local Terraform (`.tf`) or `terraform show -json` plans (`--plan-json`) for `G1`–`G6` IAM drift before merge (`APPROVE_CLEAN` / `BLOCK_MERGE` / `SCAN_ERROR`), with `--fail-on` CI exit codes (`2` violation, `3` scan error), PR-ready `gitops_pr_comment.md`, `gitops-guardrail/remediated_patch.tf`, GitHub Actions + SARIF. |
| **`gcp-iam-org-hierarchy-auditor`** | Audits `Org → Folder → Project` ancestry and IAM Org Policy prerequisites (`CIS 1.4`, DRS, default SA grants). |
| **`gcp-iam-compliance-mapper`** | Produces auditor-ready CIS GCP v3.0, SOC 2 Type II, ISO/IEC 27001:2022, and PCI-DSS v4.0 scorecards (Before vs. Projected After). |

---

## Security & Zero-Trust Design

1. **Strictly Read-Only Assessment & IaC-Only Output (Human-in-the-Loop Gate)**: ScopeGuard never calls `set-iam-policy`, deletes Service Account keys, or modifies IAM bindings. Every remediation is emitted as reviewable Terraform HCL, PAM YAML, and `etag`-pinned rollback scripts. Generated shell scripts (`rollback_runbook.sh`, `remediation_commands.sh`, `canary_step1_bind_least_privilege.sh`, `canary_step2_remove_broad_role.sh`, `retire_sa_keys.sh`) are **dry-run by default** and require `--apply`.
2. **Upfront Pre-Req Checks (No Silent Mutations)**:
   - **GCS Assessment Bucket**: Prompts on first run to confirm bucket name and region (`exit code 20` / `21`), then reuses `~/.scopeguard/config.json`.
   - **Required GCP APIs**: Verifies `cloudresourcemanager`, `iam`, `recommender`, `logging`, `orgpolicy` (and `securitycenter` when `--fetch-live-scc` is set) upfront (`exit code 23`) and asks whether to enable missing APIs (`--ensure-apis`) or proceed in degraded mode (`--skip-api-check`).
3. **Bucket-Only Stateless Portal**: The optional Cloud Run portal (`portal/`) runs as a dedicated service account holding **only** `roles/storage.objectViewer` on the GCS assessment bucket — zero IAM, Admin, or Recommender permissions on your GCP projects.

---

## Prerequisites

- Python **3.10+** (zero external third-party Python packages required — standard library only)
- Authenticated Google Cloud CLI (`gcloud auth login` & `gcloud auth application-default login`)
- Read-only IAM permissions on target projects/org (e.g., `roles/viewer`, `roles/recommender.iamViewer`, `roles/logging.viewer`, `roles/orgpolicy.policyViewer`, and `roles/resourcemanager.organizationViewer` / `roles/resourcemanager.folderViewer` for Org/Folder sweeps)

---

## Quick Start

### 1. Install the ScopeGuard Plugin
```bash
git clone https://github.com/gauravkakad-google/ScopeGuard.git
cd ScopeGuard
./install.sh
```
This installs the plugin into `~/.gemini/config/plugins/scopeguard/` so Antigravity IDE and `agy` CLI discover it automatically across any workspace.

### 2. Run on a Single Project, Organization, or Folder

**Via Antigravity / `agy` CLI (natural language):**
- *"Run a full ScopeGuard IAM governance assessment on project `my-gcp-project` and publish the results to GCS."*
- *"Sweep all active GCP projects in organization `123456789012` with ScopeGuard and publish a fleet rollup to GCS."*
- *"My Cloud Run service account hit a 403 PERMISSION_DENIED error for `secretmanager.versions.access` in `my-gcp-project` — calculate the minimal safe IAM fix."*

**Via Direct CLI:**
```bash
# Single GCP project (add --audit-bq-table=<proj>.<dataset>._AllLogs for 100% 90-day Log Analytics coverage)
python3 plugins/scopeguard/skills/scopeguard-orchestrator/scripts/scopeguard_pipeline.py \
  --project=my-gcp-project \
  --stages=all \
  --log-limit=500 \
  --tf-scan-path=./terraform \
  --output-dir=./scopeguard-output/my-gcp-project

# Optional flags: see the full CLI Flag Reference below for defaults and when to use each flag.

# GitOps PR CI gate (exits 2 on HIGH/CRITICAL violation, 3 on SCAN_ERROR; writes PR comment Markdown)
python3 plugins/scopeguard/skills/gcp-iam-gitops-pr-guardrail/scripts/gitops_guardrail_cli.py \
  --project=my-gcp-project \
  --plan-json=./tfplan.json \
  --fail-on=HIGH \
  --pr-comment-md=./gitops_pr_comment.md \
  --output-dir=./scopeguard-output/my-gcp-project/gitops-guardrail

# Entire GCP Organization (interactive live-progress 3-step loop)
python3 plugins/scopeguard/skills/scopeguard-orchestrator/scripts/scopeguard_pipeline.py \
  --org-id=123456789012 \
  --discover-only \
  --output-dir=./scopeguard-output/org-123456789012

# Remediate Cloud SCC & Wiz findings into Terraform + proposed-remediation ticket note
# (add --verify after apply to emit ticket_verification_note.md; exits 3 if any check FAILs)
python3 plugins/scopeguard/skills/gcp-iam-finding-remediator/scripts/finding_remediator_cli.py \
  --project=my-gcp-project \
  --scc-finding-file=./examples/sample-findings/scc_example_finding.json \
  --wiz-issue-file=./examples/sample-findings/wiz_example_attack_path.json \
  --output-dir=./scopeguard-output/my-gcp-project/finding-remediation

# Developer 403 minimal-fix debugger
python3 plugins/scopeguard/skills/gcp-iam-role-architect/scripts/role_architect_cli.py troubleshoot-403 \
  --project=my-gcp-project \
  --principal="serviceAccount:app-runtime-sa@my-gcp-project.iam.gserviceaccount.com" \
  --error-log="403 PERMISSION_DENIED: Permission 'secretmanager.versions.access' denied on resource 'projects/my-gcp-project/secrets/app-config/versions/latest'" \
  --output-dir=./scopeguard-output/my-gcp-project/fix-403
```

### 3. CLI Flag Reference (What They Mean & When to Use Them)

#### Target Scope & Fast-Path Triage (`scopeguard_pipeline.py`)
| Flag | Default | What It Means & When to Use It |
| :--- | :--- | :--- |
| `--project=<id>` | — | Assess a single GCP project. Use for day-to-day project audits or PR validation. |
| `--principal=<member>` | all | Fast-path single-identity filter (e.g., `serviceAccount:sa@proj.iam.gserviceaccount.com`). Use when triaging a single Wiz or SCC alert in seconds instead of running a full project review. |
| `--org-id=<id>` / `--folder-id=<id>` | — | Sweep all active projects in a GCP Organization or Folder. Pair with `--max-projects` (default `25`), `--include-projects`, or `--exclude-projects` to control blast radius and runtime. |
| `--discover-only` / `--finalize-rollup` | off | Splits an Org/Folder sweep into 3 steps (discover → run per project → publish `_scopes/` rollup) so agent harnesses (`agy` / Antigravity) can print live project-by-project progress. |
| `--stages=<list\|all>` | `all` | Comma-separated subset of the 10 engines (e.g., `recommender_audit,breakglass_simulator,finding_remediator`). Use when you only need a targeted re-run; sibling modules are carried forward in GCS and flagged if stale. |
| `--output-dir=<path>` | required | Local directory where all reports, Terraform, YAMLs, and dry-run scripts are written. |

#### Telemetry & Audit-Log Coverage
| Flag | Default | What It Means & When to Use It |
| :--- | :--- | :--- |
| `--freshness-days=<n>` | `90` | Lookback window in days for IAM Recommender and Cloud Audit Logs. |
| `--log-limit=<n>` | `500` | Max paginated Cloud Audit Log entries fetched per principal via the Logging API when `--audit-bq-table` is not set. Increase for busy service accounts, or switch to `--audit-bq-table`. |
| `--audit-bq-table=<proj.ds.tbl>` | — | Queries a BigQuery / Cloud Logging Log Analytics table (e.g., `my-proj.global._Default._AllLogs`) for **100% 90-day coverage** on high-volume production projects where API pagination would truncate logs. |
| `--location=<loc>` | `global` | Recommender API location (rarely needs changing). |

#### Custom Role Naming, Team Bundles & Redacted Sharing
| Flag | Default | What It Means & When to Use It |
| :--- | :--- | :--- |
| `--role-prefix=<prefix>` | `$SCOPEGUARD_ROLE_PREFIX` or `sg_` | Prefix for generated custom role IDs (`<prefix>persona_*`, `<prefix>cap_*`). Use to match your organization's naming standard (e.g., `acme_`). |
| `--bundle-by=owner\|folder\|principal` | off | Splits outputs into per-team/owner, per-folder, or per-principal subsets under `bundles/<key>/` (each with its own `REMEDIATION_PLAN.md`, `findings.csv`, and `manifest.json`). Use when handing remediation tickets out to multiple engineering squads. |
| `--redact` | off | Writes sanitized copies of `.md`/`.json`/`.jsonl`/`.csv` files under `shareable/` with user emails, project numbers, and external IDs replaced by stable salted hashes (set `$SCOPEGUARD_REDACT_SALT` per org). Originals are untouched and `.sh`/`.tf` are never copied. Use before sharing reports with external auditors or vendors. |

#### SCC / Wiz Remediation, Canary Cutover & Post-Change Verification
| Flag | Default | What It Means & When to Use It |
| :--- | :--- | :--- |
| `--scc-finding-file=<json>` / `--wiz-issue-file=<json>` | — | Ingests exported Cloud SCC (incl. Toxic Combination / Attack Path) or Wiz Issue / Attack Path JSON so `finding-remediator` generates surgical choke-point Terraform patches + ticket notes. |
| `--fetch-live-scc` | off | Queries the live Cloud SCC API for active IAM findings (degrades gracefully if the API is disabled or not licensed). |
| `--canary` | off *(auto on `LOW` confidence)* | Emits 2-step dual-bind cutover scripts (`canary_step1_bind_least_privilege.sh` + `canary_step2_remove_broad_role.sh`) that bind the new least-privilege role *alongside* the old role first. Use on production workloads or whenever `audit_log_confidence` is `LOW`/`MEDIUM`. |
| `--authoritative` | off | Switches remediator Terraform from safe non-authoritative `google_project_iam_member` to authoritative `google_project_iam_binding` (writes `AUTHORITATIVE_TERRAFORM_WARNING.md`). Only use if your repo already manages IAM bindings authoritatively. |
| `--verify` / `--verify-hours=<n>` / `--plan-file=<json>` *(standalone `finding_remediator_cli.py`)* | `24`h | Run **after** applying Terraform/scripts to verify the new role is bound, old broad role is gone, and no new 403s appeared; writes `ticket_verification_note.md` for SCC/Wiz/Jira closure and exits `3` if any check fails. |

#### Preventive Guardrails: PAM, Deny (`D1`–`D5`), WIF & GitOps CI
| Flag | Default | What It Means & When to Use It |
| :--- | :--- | :--- |
| `--approver-group=<g1,g2>` / `--notification-email=<e>` | — | Supplies real PAM approver groups (comma-separated, distinct from requesters) and notification emails (repeatable) so `pam_entitlements.tf` is apply-ready with zero placeholder warnings. |
| `--breakglass-principal=<member>` | — | Repeatable emergency exception principal (e.g., `group:gcp-breakglass@example.com`) exempted from `D1`–`D5` IAM v2 Deny Policies so you never lock out incident responders. |
| `--ai-agent-principal=<member>` | auto-discovered | Repeatable AI/agentic SA to include in `D5_CONTAIN_AI_AGENT_BLAST_RADIUS` (in addition to SAs auto-detected from `F8` and Vertex AI / ML roles). Use to pin specific Agent Gateway / MCP backend SAs. |
| `--github-org` / `--github-repo` / `--github-ref` | — | Locks generated GitHub Actions WIF `attribute_condition` to a specific org, repo, and branch/ref (e.g., `refs/heads/main`) to prevent OIDC spoofing from forks. |
| `--gitlab-project` / `--gitlab-url` / `--gitlab-ref` | `https://gitlab.com` | Locks generated GitLab CI WIF `attribute_condition` to a specific project path and ref. |
| `--project-number=<num>` / `--ci-platforms=<list>` | `github,gitlab` | Supplies the numeric project number for WIF principal URIs and chooses which CI workflow snippets (`ci/*.yml`) to emit. |
| `--tf-scan-path=<dir>` / `--plan-json=<plan.json>` | — | Target for GitOps PR Guardrail (`G1`–`G6`). Prefer `--plan-json` (`terraform show -json tfplan`) in CI because it resolves modules, variables, and `for_each` (regex `.tf` scan is a fallback). |
| `--max-expiry-days=<n>` / `--include-unchanged` | `90` / off | Flags temporary IAM conditions longer than `n` days (`G5`); `--include-unchanged` audits existing plan resources in addition to changed ones. |
| `--fail-on=<level>` / `--pr-comment-md=<path>` *(standalone `gitops_guardrail_cli.py`)* | `NONE` | Turns the guardrail into a real CI merge gate (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `ANY`): exits `2` on threshold breach and `3` on `SCAN_ERROR`, and writes a compact PR comment with the copy-pasteable HCL fix. |

#### GCS Assessment Store & API Preflight
| Flag | Default | What It Means & When to Use It |
| :--- | :--- | :--- |
| `--bucket=<name>` / `--region=<reg>` / `--host-project=<pid>` | `~/.scopeguard/config.json` / `asia-southeast1` | Central GCS bucket storing versioned snapshots and portal data. Prompted once on first run (`exit 20`/`21`), then reused automatically. |
| `--save-bucket-config` / `--ensure-bucket` | off | Persists confirmed bucket/region to `~/.scopeguard/config.json` and creates the bucket (with UBLA + Public Access Prevention) after explicit confirmation. |
| `--local-only` | off | Skips GCS preflight and writes all deliverables locally only. Use for offline/sandbox testing. |
| `--ensure-apis` / `--skip-api-check` | off | Handles missing required GCP APIs (`exit 23`): `--ensure-apis` enables them after user confirmation; `--skip-api-check` continues in degraded mode without mutating project APIs. |

---

### 4. Run Outputs

Each project run writes the files below to `--output-dir`. The summary docs, `README.md`/`manifest.json`, and the exports (`findings.*`, `scopeguard.sarif.json`, `scc_findings_import.json`) are also uploaded to GCS under `<pid>/runs/<run_id>/` (immutable) and `<pid>/latest/`.

| Group | Files |
| :--- | :--- |
| **Read** | `README.md` + `manifest.json` (sha256 per file), `EXECUTIVE_SUMMARY.md`, `scopeguard_recommendations_<pid>.md` |
| **Review** | `REMEDIATION_PLAN.md`, `findings.csv` (CSV-injection safe), `findings.jsonl`, `gitops-guardrail/gitops_pr_comment.md` |
| **Apply** | `custom-roles/personas/`, `custom-roles/capabilities/`, `custom-roles/bundles.yaml`, `finding-remediation/terraform/`, `finding-remediation/canary_step*.sh`, PAM/WIF/Deny IaC, dry-run scripts |
| **Evidence** | `EVIDENCE.md`, `scopeguard.sarif.json`, `scc_findings_import.json` (file only — no SCC API write-back), `iam_policy_backup_<pid>.json` |

`--bundle-by` adds per-owner/folder/principal subsets under `bundles/<key>/`; `--redact` adds redacted copies under `shareable/`. Finding status (new / persisting / resolved) is stateless — inferred from diffs between runs.

**Custom role naming & identity hygiene**: Custom roles are generated strictly for **non-human workload Service Accounts** (human `user:` principals route exclusively to Google Groups + PAM JIT). Model A persona roles `sg_persona_<workload>` (title `SG Persona · X`, default) live in `custom-roles/personas/`; Model B capability roles `sg_cap_<domain>_<access>[_<qualifier>]` (title `SG Capability · X`) live in `custom-roles/capabilities/`, combined per principal in `custom-roles/bundles.yaml` as an exact cover (no over/under-grant, zero pairwise overlap). Sensitive permissions are isolated in visibly named roles (e.g. `sg_cap_sa_impersonate`). Prefix precedence: `--role-prefix` > `$SCOPEGUARD_ROLE_PREFIX` > `sg_`. Envelope schema `2.1` (`2.0` still readable); legacy `custom-roles/disjoint/` is read as a fallback only.

### 5. Optional: Deploy the Stateless GCS Review Portal to Cloud Run
```bash
./deploy/deploy_portal.sh \
  --project=my-host-project \
  --bucket=my-scopeguard-assessments \
  --region=us-central1
```
The stateless Cloud Run portal (`v2.1`, protected by Cloud Run IAP with bucket-only `roles/storage.objectViewer`) provides:
- **Global Quick-Jump (`⌘K` / `/`)** across principals, SCC/Wiz finding IDs, and `sg_persona_*` / `sg_cap_*` roles
- **Role View Toggle (`All` | `DevOps` | `SecOps & GRC`)** to focus navigation tabs by operator workflow
- **1-Click Daily Triage Preset Pills** (`All Open`, `New Since Last Run`, `SCC / Wiz Alerts`, `AI / Agent SAs (F8)`, `WIF Misconfigs`, `P0 Quick Wins`)
- **Run Deliverables Download Bar** backed by read-only allowlisted `GET /api/artifact` for `EXECUTIVE_SUMMARY.md`, `REMEDIATION_PLAN.md`, `EVIDENCE.md`, `scopeguard.sarif.json`, `scc_findings_import.json`, `findings.csv`, and `manifest.json`
- **Simulation Confidence (`HIGH` / `MEDIUM` / `LOW`) & Canary Cutover Badges**, **Attack-Path Choke-Point** cards, **Existing WIF Audit**, **Compare Runs** (`/api/diff`), inline **Copy** buttons on all code viewers, and 1-click copyable CLI commands (`--principal --canary` and `--verify`) inside Identity Drawers and Change Plans.

---

## Running Tests

```bash
python3 -m unittest discover -s tests -v
```

## License

Apache License 2.0 — see [LICENSE](LICENSE).
