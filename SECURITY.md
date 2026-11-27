# Security Policy

## Security Guarantees

ScopeGuard is built with strict defense-in-depth boundaries for enterprise Google Cloud environments:

1. **Read-Only Assessment Mode**: ScopeGuard skills never call `set-iam-policy`, `add-iam-policy-binding`, `remove-iam-policy-binding`, disable Service Accounts, or delete Service Account keys. All remediation outputs are generated as Terraform HCL, PAM manifests, and `etag`-pinned rollback scripts for human-in-the-loop GitOps review.
2. **Explicit Confirmation Before Infrastructure/API Changes**: ScopeGuard never silently creates a GCS bucket (`exit code 20`/`21`) or enables GCP APIs (`exit code 23`) without explicit user confirmation (`--ensure-bucket` / `--ensure-apis`).
3. **Zero-Trust Stateless Portal**: The Cloud Run review portal (`portal/`) requires only bucket-scoped `roles/storage.objectViewer` on the GCS assessment bucket and is deployed behind Identity-Aware Proxy (`--iap --no-allow-unauthenticated`).
4. **Zero Third-Party Python Dependencies**: All runtime libraries and scripts use Python's standard library only, minimizing supply-chain attack surface.

## Reporting a Vulnerability

If you discover a security vulnerability in ScopeGuard, please **do not** open a public GitHub issue with exploit details or sensitive GCP project data. Instead, report it privately via GitHub Security Advisories on this repository.
