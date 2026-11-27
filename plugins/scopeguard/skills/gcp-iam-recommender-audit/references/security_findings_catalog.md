# Security Findings Catalog (`F1`–`F7`) & Service Impact Heuristics

This reference defines the 7 automated security posture detectors implemented by `scripts/iam_audit_cli.py`, their severity scoring rules, recommended remediation phases (`P0`–`P3`), and service blast-radius heuristics.

---

## Finding Taxonomy (`F1`–`F7`)

| Finding ID | Category | Default Severity | Recommended Phase | Detection Logic |
| :--- | :--- | :---: | :---: | :--- |
| **`F1`** | **Primitive / Basic Role Usage** (`roles/owner`, `roles/editor`, `roles/viewer`) | `CRITICAL` (`owner`/`editor`)<br/>`HIGH` (`viewer`) | `P0` (if 0 perms used)<br/>`P1` (on build/workload SAs)<br/>`P3` (on breakglass humans) | Any IAM binding granting `roles/owner`, `roles/editor`, or `roles/viewer`. Cross-referenced with `google.iam.policy.Insight` to report exact `currentTotalPermissionsCount` vs. `exercisedPermissions` + `inferredPermissions`. |
| **`F2`** | **Over-Privileged Principal (Excess Unused Permissions)** | `HIGH` | `P1` / `P2` | Any principal where `google.iam.policy.Insight` or 90-day Cloud Audit Logs show $>80\%$ of granted permissions were unused over the observation window. |
| **`F3`** | **Privilege Escalation & Impersonation Risk** | `CRITICAL` | `P1` | Non-admin or default workload service accounts holding IAM mutation or impersonation permissions: `resourcemanager.projects.setIamPolicy` (`roles/resourcemanager.projectIamAdmin`), `iam.serviceAccounts.setIamPolicy` / `create` (`roles/iam.serviceAccountAdmin`), `iam.serviceAccounts.getAccessToken` / `signBlob` (`roles/iam.serviceAccountTokenCreator`), `iam.serviceAccounts.actAs` (`roles/iam.serviceAccountUser`), or `iam.serviceAccountKeys.create`. |
| **`F4`** | **Inactive / Orphaned Service Accounts ($\ge 90$ Days)** | `HIGH` (with active bindings)<br/>`LOW` (0 bindings) | `P0` (0 bindings: disable)<br/>`P1` (active bindings: revoke & disable) | Service accounts flagged by `google.iam.serviceAccount.Insight` (`SERVICE_ACCOUNT_USAGE`) or having no authentication activity in $\ge 90$ days. Split into `F4a` (holds active IAM bindings) and `F4b` (0 IAM bindings — orphaned SA). |
| **`F5`** | **Expired Conditional IAM Bindings** | `MEDIUM` | `P0` | IAM policy bindings containing a CEL condition matching `request.time < timestamp("YYYY-MM-DDTHH:MM:SS...")` where the timestamp is in the past relative to audit execution time. |
| **`F6`** | **Over-Privileged or External Google-Managed Service Agents** | `HIGH` | `P0` (`roles/owner`)<br/>`P3` (`storage.admin` / `aiplatform.admin` / cross-project) | Google-managed service agents (`service-*@*.iam.gserviceaccount.com`) holding non-service-agent admin roles (`roles/owner`, `roles/editor`, `roles/storage.admin`, `roles/aiplatform.admin`, `roles/secretmanager.admin`) or belonging to a foreign project number (`service-<OTHER_PROJECT_NUMBER>@...`). |
| **`F7`** | **Role Sprawl & Redundant Predefined Bindings** | `MEDIUM` | `P2` | Principals holding $\ge 2$ predefined roles with overlapping permission sets (e.g., `roles/artifactregistry.admin` alongside `reader` and `writer`, or `roles/discoveryengine.admin` alongside `roles/serviceusage.serviceUsageViewer`). |

---

## Service Impact & Blast-Radius Heuristics by Principal Type

When generating the Phased Implementation Plan (`P0`–`P3`), the analyzer attaches specific blast-radius warnings depending on the principal class:

1. **Default Compute Engine Service Account (`<PROJECT_NUMBER>-compute@developer.gserviceaccount.com`)**:
   - **Blast Radius**: By default, GCE VMs, GKE nodes, Cloud Run services/jobs, Cloud Functions (Gen 2), App Engine Flex, and Vertex AI custom training jobs that do not specify a custom service account authenticate as this identity.
   - **Safe Remediation Pattern**:
     - First remove expired conditional bindings (`P0`) and privilege-escalation roles (`roles/resourcemanager.projectIamAdmin`, `roles/iam.serviceAccountAdmin`) in `P1`.
     - Bind the consolidated runtime custom role (`customGenAiWorkloadRuntime`) **before** removing overlapping predefined roles (`P2`).
2. **Legacy Cloud Build Service Account (`<PROJECT_NUMBER>@cloudbuild.gserviceaccount.com`)**:
   - **Blast Radius**: Cloud Build triggers and build steps that do not specify a custom user-managed service account run as this principal.
   - **Safe Remediation Pattern**:
     - Bind `customCloudBuildRecommenderLP` (containing all 90-day exercised + inferred permissions) *prior* to removing `roles/owner` (`P1`).
3. **Google APIs Service Agent (`<PROJECT_NUMBER>@cloudservices.gserviceaccount.com`)**:
   - **Blast Radius**: Historically used by managed instance groups, Dataflow, and internal Google APIs, though modern GCP services use dedicated `service-<PROJECT_NUMBER>@gcp-sa-*.iam.gserviceaccount.com` identities.
   - **Safe Remediation Pattern**:
     - Only remove `roles/editor` in `P0` when `google.iam.policy.Insight` confirms `exercisedPermissions == 0` and `inferredPermissions == 0` over the 90-day observation window.
4. **Inactive Customer-Managed Service Accounts (`*@<PROJECT_ID>.iam.gserviceaccount.com`)**:
   - **Blast Radius**: Zero impact on daily/weekly traffic if inactive for $>90$ days, but could impact quarterly/annual scheduled jobs or disaster-recovery scripts.
   - **Safe Remediation Pattern**:
     - **Stage 1 (`P0`/`P1`)**: Disable the service account (`gcloud iam service-accounts disable`) and optionally migrate its bindings to a least-privilege custom role or remove them while keeping the backup command in `rollback_runbook.sh`.
     - **Stage 2 (`P3`, after 30 days)**: Permanently delete (`gcloud iam service-accounts delete`) once a full monthly/quarterly cycle passes without HTTP `403`/`401` alerts.
