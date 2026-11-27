# GCP Custom Role Privilege Escalation & Unsupported Permission Catalog

Whenever `gcp-iam-role-architect` synthesizes or validates a custom role, it scans all candidate permissions against the following 5 risk categories (`E1`–`E5`). Any permission matching `E1`–`E4` is flagged in the design report with a mandatory **Blast Radius & Mitigation Requirement**. Any permission matching `E5` is stripped or moved to the appropriate resource level before generating the custom role YAML.

---

## `E1` — Service Account Impersonation & Key Generation (`CRITICAL`)

| Permission | Escalation Mechanism | Least-Privilege Mitigation |
| :--- | :--- | :--- |
| `iam.serviceAccounts.actAs` | Allows the principal to attach a service account to a resource (Cloud Run, Compute VM, Dataflow, Cloud Build) and inherit all permissions of that service account. | **Never** bind at the Project level. Bind **only** on the specific target Service Account resource (`gcloud iam service-accounts add-iam-policy-binding TARGET_SA`). |
| `iam.serviceAccounts.getAccessToken` | Mint OAuth2 access tokens directly for a target service account. | Bind **only** on the specific target Service Account resource; require short token lifetime and audit logging. |
| `iam.serviceAccounts.getOpenIdToken` | Mint OIDC ID tokens for a target service account (can invoke authenticated Cloud Run/Functions). | Bind **only** on the specific target Service Account resource. |
| `iam.serviceAccounts.signBlob` / `signJwt` | Sign arbitrary payloads or JWTs as the service account, enabling self-signed token impersonation. | Bind **only** on the specific target Service Account resource. |
| `iam.serviceAccountKeys.create` | Creates a persistent, downloadable JSON private key for a service account, bypassing short-lived credentials. | **Prohibit** in custom roles unless explicitly required by legacy on-prem workloads; prefer Workload Identity Federation. |

---

## `E2` — IAM Policy & Custom Role Self-Escalation (`CRITICAL`)

| Permission | Escalation Mechanism | Least-Privilege Mitigation |
| :--- | :--- | :--- |
| `resourcemanager.projects.setIamPolicy` | Grants the principal arbitrary roles (including `roles/owner`) across the entire project. | Exclude from operational custom roles. If IAM administration is required, restrict via IAM Conditions to specific non-admin roles (`api.getAttribute('iam.googleapis.com/modifiedGrantsByRole', []).hasOnly([...])`). |
| `iam.roles.update` / `iam.roles.create` | Allows a principal who already holds a custom role to add `resourcemanager.projects.setIamPolicy` or `bigquery.tables.getData` to their own custom role. | Never grant `iam.roles.update` to the same principal that uses custom roles in production; restrict to CI/CD Terraform automation with PR approval. |
| `iam.serviceAccounts.setIamPolicy` | Allows the principal to grant themselves `roles/iam.serviceAccountTokenCreator` or `actAs` on any service account. | Bind only on specific managed service accounts or restrict to Terraform CI/CD. |
| `storage.buckets.setIamPolicy` / `bigquery.datasets.update` / `bigquery.tables.setIamPolicy` / `secretmanager.secrets.setIamPolicy` | Allows overriding child resource ACLs to grant external or unauthorized principals data access. | Exclude from data reader/writer custom roles (`bigquery.datasets.get` is safe; `bigquery.datasets.update` modifies dataset ACLs). |

---

## `E3` — Compute & Serverless Code-Execution Takeover (`HIGH`)

| Permission | Escalation Mechanism | Least-Privilege Mitigation |
| :--- | :--- | :--- |
| `compute.instances.setMetadata` / `compute.projects.setCommonInstanceMetadata` | Injects SSH keys or `startup-script` onto existing VMs to execute code as the VM's attached service account. | Exclude from read/monitoring/operator roles; use OS Login (`compute.osLogin`) scoped to specific instances. |
| `cloudfunctions.functions.update` / `cloudfunctions.functions.create` | Replaces source code of an existing function running with a privileged service account. | Scope to specific functions or pair with a dedicated least-privilege runtime service account via resource-level `actAs`. |
| `run.services.update` / `run.services.create` | Deploys a container image running as the Cloud Run service's runtime service account. | Bind on the specific Cloud Run service (`gcloud run services add-iam-policy-binding`) and restrict `actAs` to a dedicated single-service runtime SA. |
| `cloudbuild.builds.create` | Executes arbitrary build steps as the Cloud Build service account. | Always pair with a custom user-managed worker service account rather than the default Cloud Build SA. |
| `deploymentmanager.deployments.create` / `update` | Executes deployments using the legacy `PROJECT_NUMBER@cloudservices.gserviceaccount.com` (`roles/editor`). | Avoid Deployment Manager; use Terraform or Infrastructure Manager with explicit service accounts. |

---

## `E4` — Cross-Service Data Exfiltration & Bypass Primitives (`MEDIUM-HIGH`)

| Permission | Risk Description | Least-Privilege Mitigation |
| :--- | :--- | :--- |
| `bigquery.tables.export` | Exports table data directly to an external Cloud Storage bucket. | Omit from standard query/read roles unless bulk GCS export jobs are explicitly required (`bigquery.tables.getData` suffices for SQL queries). |
| `storage.hmacKeys.create` | Creates S3-compatible HMAC keys for a service account that persist outside standard IAM token flows. | Omit from standard GCS custom roles. |
| `logging.sinks.create` / `logging.sinks.update` | Routes sensitive audit/application log streams to an external destination. | Omit from developer log-viewer roles. |

---

## `E5` — Custom Role Technical Constraints (`NOT_SUPPORTED` & Scope Mismatch)

1. **`customRolesSupportLevel == NOT_SUPPORTED`**:
   - Permissions such as `*.serviceAgent`, `bigquery.RowAccessPolicies.overrideTimeTravelRestrictions`, `gkehub.fleet.get`, or `stackdriver.projects.edit` cannot be included in custom roles and will cause `gcloud iam roles create` to fail with `400 INVALID_ARGUMENT: Permission ... is not valid for custom roles`.
   - **Action**: Automatically filter out via `iam list-testable-permissions` (`customRolesSupportLevel != NOT_SUPPORTED`).
2. **Organization-Only Permissions in Project Custom Roles**:
   - Permissions such as `resourcemanager.projects.list`, `resourcemanager.folders.get`, and `orgpolicy.policy.get` are only valid in Organization-level (`--organization=ORG_ID`) custom roles and fail if included in Project-level (`--project=PROJECT_ID`) custom roles.
   - **Action**: Automatically strip from Project-level custom roles and place into an Organization-level role only if Organization scope is requested.
3. **`stage == TESTING` (`ALPHA` / `BETA`) Permissions**:
   - Allowed in custom roles, but Google Cloud may rename or deprecate them before GA.
   - **Action**: Flag in `role_design_report.md` so the DevOps team is aware of pre-GA stability.
