# Standardized Report, Detailed Recommendations & Emergency Rollback Playbook Template

Every audit run produces `iam_security_posture_report.md`, `detailed_recommendations.md`, `rollback_runbook.sh`, `iam_policy_backup_<project>.json`, `principal_mapping.json`, and `custom-roles/{personas,capabilities}/*.yaml` + `custom-roles/bundles.yaml` inside `--output-dir`. The generated deliverables must include all sections below.

> **Note**: When run via `scopeguard-orchestrator`, the audience-facing `EXECUTIVE_SUMMARY.md` and `REMEDIATION_PLAN.md` (plus `EVIDENCE.md`) supersede `iam_security_posture_report.md` and `detailed_recommendations.md`, which remain as legacy per-module reports.

---

## Detailed Recommendations Document Structure (`detailed_recommendations.md`)

1. **Section 1: Active Assist (`google.iam.policy.Recommender` & `google.iam.serviceAccount.Insight`) Breakdown**:
   - Subsections `1.1` through `1.N` detailing each Active Assist IAM policy recommendation (`rec_id`, `etag`, `priority`, `subtype`, exercised vs. inferred permissions, permissions revoked, target custom role, and exact implementation & rollback commands).
   - Complete table of inactive service accounts (`google.iam.serviceAccount.Insight`) with `21`-digit `uniqueId`, `lastAuthenticatedTime`, active bindings, and disable/undelete commands.
2. **Section 2: Minimal Custom Role Architecture (`x` Roles: `Model A` Personas & `Model B` Capabilities)**:
   - Complete specification of every custom role (`role_id`, `title`, `stage`, YAML paths, assigned principals, source predefined roles consolidated, stripped unsupported permissions, and full permission inventory).
   - Role traceability: for each role, the source predefined roles, members, and evidence source (`recommender_insight` or `role_definition_no_usage_data`).
3. **Section 3: Complete Principal-to-Role Mapping (`100%` Coverage)**:
   - Partition summary table ($y_1 + y_2 + \dots = N$ total principals) plus exhaustive table mapping every principal in the project to its target state and remediation phase.
4. **Section 4: Phased Implementation Runbook (`P0` $\rightarrow$ `P3`) with Service Impact Analysis**:
   - Step-by-step copy-pasteable `gcloud` commands for `P0`, `P1`, `P2`, and `P3` paired with expected service impact and pre-cutover verification checklists.
5. **Section 5: Emergency Rollback & Service Recovery Matrix**:
   - Phase-by-phase and symptom-by-symptom `1`-command rollback matrix plus full atomic policy restore command.

---

## Report Structure (`iam_security_posture_report.md`)

### Section 1: Executive Summary & Baseline IAM Scenario
- Project ID, Project Number, Policy `etag`, Audit Timestamp, and Observation Window (`90` days).
- Total Role Bindings, Total Unique Principals, and Principal Taxonomy Breakdown:
  - Human Users (`user:*`, `group:*`)
  - Default Project Service Accounts
  - Customer-Managed Service Accounts (Active vs. Inactive)
  - Google-Managed Service Agents (Standard vs. Over-Privileged)
- Total Excess Permissions Identified for Revocation.

### Section 2: Detailed Security Findings (`F1`–`F7`)
- Evidence-backed table and subsection for each finding (`F1` through `F7`):
  - **F1**: Primitive/Basic Roles (`roles/owner`, `roles/editor`, `roles/viewer`) & 90-day Recommender usage metrics.
  - **F2**: Over-Privileged Principals (`exercisedPermissions` + `inferredPermissions` vs. total granted).
  - **F3**: Privilege Escalation & Impersonation Risks (`projectIamAdmin`, `serviceAccountAdmin`, `serviceAccountTokenCreator`, `serviceAccountUser`).
  - **F4**: Inactive & Orphaned Service Accounts ($\ge 90$ days inactive, with last authenticated timestamps and 21-digit `uniqueId`s).
  - **F5**: Expired Temporary / Conditional Bindings (`request.time < timestamp(...)`).
  - **F6**: Over-Privileged or Cross-Project Google-Managed Service Agents.
  - **F7**: Role Sprawl & Redundant Predefined Role Bindings.

### Section 3: Minimal Custom Role Architecture (`Model A` Personas & `Model B` Capabilities)
- Side-by-side table of the $x$ synthesized custom roles:
  - **Model A, default (`custom-roles/personas/sg_persona_<workload>.yaml`)**: 1-to-1 self-contained persona roles (title `SG Persona · <Workload>`).
  - **Model B (`custom-roles/capabilities/sg_cap_<domain>_<access>[_<qualifier>].yaml` + `custom-roles/bundles.yaml`)**: Pairwise-disjoint capability roles ($R_i \cap R_j = \emptyset$ for all $i \neq j$) combined per persona as an exact cover; sensitive permissions isolated in visibly named roles (e.g. `sg_cap_sa_impersonate`).
- Flags personas built without usage data (`no_usage_data_personas`).
- Lists any `NOT_SUPPORTED` or organization-level permissions (e.g., `resourcemanager.projects.list`, `gkehub.fleet.get`) automatically stripped during `queryTestablePermissions` validation.

### Section 4: Complete 100% Principal-to-Role Mapping
- Summary Partition Table showing exact principal counts ($y_1 + y_2 + \dots = N$ total principals) across Custom Roles, Recommender Revocations, and Managed Service Agent buckets.
- Link to the full machine-readable `principal_mapping.json`.

### Section 5: Phased Implementation Plan (`P0`, `P1`, `P2`, `P3`) & Service Impact Assessment
- **`P0` (Immediate Zero-Downtime Hygiene — Zero Expected Service Impact)**:
  - Expired conditional bindings removal, zero-usage basic role removal (`cloudservices`, `clouddeploy` `roles/owner`), and disabling orphaned SAs with `0` bindings.
- **`P1` (High-Risk Privilege Escalation & Inactive SA Remediation — Low/Medium Service Impact)**:
  - Additive-first replacement of `roles/owner` on Cloud Build SA with `customCloudBuildRecommenderLP`, stripping `projectIamAdmin`/`serviceAccountAdmin` from Default Compute SA, and revoking/disabling inactive customer SAs holding active bindings.
- **`P2` (Minimal Custom Role Rollout & Role Sprawl Consolidation — Medium Service Impact)**:
  - Creating custom roles (`CustomRole 1..x`), binding them to active workloads and users, verifying health checks after the 60–120s IAM propagation window, and removing legacy predefined roles.
- **`P3` (Breakglass Governance, Bucket-Level Service Agent Scoping & SA Deletion — Architectural Impact)**:
  - Transitioning human `roles/owner` to PAM breakglass + `customProjectAdminRecommenderLP`, scoping AI Platform `storage.admin` to specific GCS buckets, and deleting quarantined SAs after 30 days.

### Section 6: Emergency Rollback & Incident Recovery Section
- **1. Symptom-to-Principal Triage Matrix**:
  - Maps specific failure symptoms (e.g., Cloud Build step `403`, Cloud Run startup/invocation `403`, Vertex AI prediction `403`, Cloud SQL connection failure, Discovery Engine / Agentspace `403`, background batch job authentication failure) to the exact principal and the 1-line rollback command.
- **2. Granular Per-Phase & Per-Principal Rollback Commands**:
  - `rollback_runbook.sh` is **dry-run by default**: run `./rollback_runbook.sh` to print, `--apply [--yes]` to execute, `--principal <member>` to restore one principal. Restores every current binding including IAM conditions.
  - Exact `gcloud projects add-iam-policy-binding`, `gcloud projects remove-iam-policy-binding`, `gcloud iam service-accounts enable`, and `gcloud iam service-accounts undelete <UNIQUE_ID>` commands.
- **3. Full-Project Atomic Policy Restore (Last Resort)**:
  - Restores the entire project IAM policy to the pre-audit snapshot (`iam_policy_backup_<project>.json`, which includes the `etag`) via `gcloud projects set-iam-policy` — `./rollback_runbook.sh --rollback iam_policy_backup_<project>.json [--force-rollback]`.
