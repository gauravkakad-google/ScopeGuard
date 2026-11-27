# GCP Resource Hierarchy & IAM Scope Splitting Matrix

A core principle of least privilege on Google Cloud is **Resource Scope Alignment**: permissions must be bound at the **lowest resource level** in the hierarchy where Google Cloud evaluates them, rather than binding everything at the Project level.

---

## 1. Resource Level Evaluation Rules

| Resource Level | Examples of Permissions Evaluated Exclusively Here | Why It Matters |
| :--- | :--- | :--- |
| **Organization / Folder** | `resourcemanager.projects.list`, `orgpolicy.policy.get`, `resourcemanager.folders.get` | Cannot be added to Project-level custom roles (`NOT_SUPPORTED` at project scope) and have no effect if bound on a single project. |
| **Project** | `bigquery.jobs.create`, `compute.instances.list`, `logging.logEntries.create`, `monitoring.timeSeries.create`, `serviceusage.services.use` | Billing, job execution, and project-wide listing APIs are checked against the execution/host project, not child datasets or buckets. |
| **Child Resource (Native Resource IAM)** | `bigquery.tables.getData` (Dataset/Table), `storage.objects.get` (Bucket), `secretmanager.versions.access` (Secret), `pubsub.topics.publish` (Topic), `run.routes.invoke` (Cloud Run Service), `cloudkms.cryptoKeyVersions.useToEncrypt` (CryptoKey), `artifactregistry.repositories.downloadArtifacts` (Repository), `iam.serviceAccounts.actAs` (Service Account) | Binding these at the Project level grants access to **every** dataset, bucket, secret, topic, or service account in the project. Always split these into a child-resource custom role. |
| **Child Resource via IAM Conditions (CEL)** | Compute Engine disks/instances by tag/prefix, GCS object prefixes (`storage.objects.get` on `projects/_/buckets/my-bucket/objects/prefix/*`), Cloud SQL instances | Used when a service evaluates permissions at the project/bucket level without native per-child IAM policies, or when scoping access by prefix/resource tag. |

---

## 2. Service-by-Service Least-Privilege Decomposition Reference

### A. BigQuery (`bigquery.googleapis.com`)
| Capability | Evaluation Scope | Headless / Service Account (Strict API Minimum) | Interactive Human (Console UI & `bq` CLI Additions) | Optional Extras (Storage Read API) |
| :--- | :--- | :--- | :--- | :--- |
| **Run Query Jobs** | **Project** (Billing/Execution Project) | `bigquery.jobs.create` | `bigquery.jobs.get`, `bigquery.jobs.list` (own jobs) | `bigquery.readsessions.create`, `bigquery.readsessions.getData` |
| **Read Table Data** | **Dataset** (or **Table**) | `bigquery.tables.getData` | `bigquery.datasets.get`, `bigquery.tables.get`, `bigquery.tables.list` | — |
| **Write / Load Table Data** | **Dataset** (or **Table**) | `bigquery.tables.updateData`, `bigquery.tables.create` | `bigquery.datasets.get`, `bigquery.tables.get`, `bigquery.tables.list` | — |

### B. Cloud Storage (`storage.googleapis.com`)
| Capability | Evaluation Scope | Headless / Service Account (Strict API Minimum) | Interactive Human (Console UI & `gcloud storage` Additions) | Optional Extras (Object Prefix CEL) |
| :--- | :--- | :--- | :--- | :--- |
| **Read Objects** | **Bucket** | `storage.objects.get` | `storage.objects.list`, `storage.buckets.get` | `resource.name.startsWith("projects/_/buckets/BUCKET/objects/PREFIX/")` |
| **Write / Overwrite Objects** | **Bucket** | `storage.objects.create`, `storage.objects.delete` | `storage.objects.get`, `storage.objects.list`, `storage.buckets.get` | `resource.name.startsWith(...)` |
| **Multipart Uploads** | **Bucket** | `storage.multipartUploads.create`, `storage.multipartUploads.abort`, `storage.multipartUploads.listParts` | — | — |

### C. Secret Manager (`secretmanager.googleapis.com`)
| Capability | Evaluation Scope | Headless / Service Account (Strict API Minimum) | Interactive Human (Console UI & CLI Additions) |
| :--- | :--- | :--- | :--- |
| **Read Secret Payload** | **Secret** (`projects/*/secrets/*`) | `secretmanager.versions.access` | `secretmanager.secrets.get`, `secretmanager.versions.get`, `secretmanager.versions.list` |
| **Rotate / Add Secret Version** | **Secret** (`projects/*/secrets/*`) | `secretmanager.versions.add`, `secretmanager.versions.enable`, `secretmanager.versions.destroy` | `secretmanager.secrets.get`, `secretmanager.versions.list` |

### D. Pub/Sub (`pubsub.googleapis.com`)
| Capability | Evaluation Scope | Headless / Service Account (Strict API Minimum) | Interactive Human (Console UI & CLI Additions) |
| :--- | :--- | :--- | :--- |
| **Publish Messages** | **Topic** (`projects/*/topics/*`) | `pubsub.topics.publish` | `pubsub.topics.get` |
| **Consume Messages** | **Subscription** (`projects/*/subscriptions/*`) | `pubsub.subscriptions.consume` | `pubsub.subscriptions.get`, `pubsub.topics.attachSubscription` (if creating sub) |

### E. Cloud Run (`run.googleapis.com`) & Service Account Attachment
| Capability | Evaluation Scope | Headless / Service Account (Strict API Minimum) | Interactive Human (Console UI & CLI Additions) |
| :--- | :--- | :--- | :--- |
| **Invoke Private Service** | **Cloud Run Service** | `run.routes.invoke` | `run.services.get` |
| **Deploy Cloud Run Revision** | **Cloud Run Service** (or **Project** for initial create) + **Runtime SA** | `run.services.create`, `run.services.update`, `run.services.get`, `run.operations.get` + `iam.serviceAccounts.actAs` *(bound ONLY on the specific runtime Service Account)* | `run.services.list`, `run.revisions.list`, `run.revisions.get`, `run.locations.list` |

### F. Artifact Registry (`artifactregistry.googleapis.com`)
| Capability | Evaluation Scope | Headless / Service Account (Strict API Minimum) | Interactive Human (Console UI & CLI Additions) |
| :--- | :--- | :--- | :--- |
| **Pull Images / Packages** | **Repository** (`projects/*/locations/*/repositories/*`) | `artifactregistry.repositories.downloadArtifacts` | `artifactregistry.repositories.get`, `artifactregistry.packages.list`, `artifactregistry.tags.list`, `artifactregistry.versions.list` |
| **Push Images / Packages** | **Repository** (`projects/*/locations/*/repositories/*`) | `artifactregistry.repositories.uploadArtifacts`, `artifactregistry.repositories.downloadArtifacts` | `artifactregistry.repositories.get`, `artifactregistry.packages.list` |

### G. Cloud KMS (`cloudkms.googleapis.com`)
| Capability | Evaluation Scope | Headless / Service Account (Strict API Minimum) | Interactive Human (Console UI & CLI Additions) |
| :--- | :--- | :--- | :--- |
| **Encrypt / Decrypt (CMEK)** | **CryptoKey** (`projects/*/locations/*/keyRings/*/cryptoKeys/*`) | `cloudkms.cryptoKeyVersions.useToEncrypt`, `cloudkms.cryptoKeyVersions.useToDecrypt` | `cloudkms.cryptoKeys.get`, `cloudkms.keyRings.get` |

### H. Cloud SQL (`sqladmin.googleapis.com`)
| Capability | Evaluation Scope | Headless / Service Account (Strict API Minimum) | Interactive Human (Console UI & CLI Additions) |
| :--- | :--- | :--- | :--- |
| **Connect via Auth Proxy / IAM DB Auth** | **Project** (optionally scoped via IAM Condition to instance name) | `cloudsql.instances.connect`, `cloudsql.instances.get`, `cloudsql.instances.login` (for IAM DB auth) | `cloudsql.instances.list`, `cloudsql.databases.list` |

### I. Google Kubernetes Engine (`container.googleapis.com`)
| Capability | Evaluation Scope | Headless / Service Account (Strict API Minimum) | Interactive Human (Console UI & `kubectl` CLI Additions) |
| :--- | :--- | :--- | :--- |
| **Fetch Cluster Credentials & Read Workloads** | **Project** (or Cluster Condition) + **Kubernetes RBAC** | `container.clusters.get`, `container.pods.get`, `container.pods.list` | `container.clusters.list`, `container.deployments.get`, `container.deployments.list`, `container.services.get`, `container.services.list`, `container.pods.getLogs` |

### J. Vertex AI & Discovery Engine (`aiplatform.googleapis.com`, `discoveryengine.googleapis.com`)
| Capability | Evaluation Scope | Headless / Service Account (Strict API Minimum) | Interactive Human (Console UI & CLI Additions) |
| :--- | :--- | :--- | :--- |
| **Online Prediction / Gemini Inference** | **Project** (or Endpoint) | `aiplatform.endpoints.predict` | `aiplatform.endpoints.get`, `aiplatform.endpoints.list`, `aiplatform.models.get`, `aiplatform.models.list` |
| **Discovery Engine Search / Converse** | **Project** | `discoveryengine.servingConfigs.search`, `discoveryengine.ServingConfigs.answer`, `discoveryengine.conversations.converse` | `discoveryengine.engines.get`, `discoveryengine. engines.list`, `discoveryengine.dataStores.get`, `discoveryengine.dataStores.list` |
