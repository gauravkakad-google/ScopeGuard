#!/usr/bin/env python3
# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0

"""Workload Identity Federation (WIF) & Service Account Key Retirement Architect.

Audits customer-managed Service Accounts for USER_MANAGED static keys and CI/CD
automation patterns, generating keyless OIDC Workload Identity Pool/Provider
Terraform HCL with strict CEL attribute conditions and key-retirement runbooks.

ART-11 additions:
  * Ready-to-paste CI snippets next to the Terraform: a GitHub Actions workflow
    (`google-github-actions/auth@v2`) and a GitLab CI job (`id_tokens` +
    `gcloud iam workload-identity-pools create-cred-config`).
  * Anti-spoofing `attribute_condition` pins BOTH the owner/namespace and the
    exact repository/project (optionally the git ref), documented in
    `WIF_MIGRATION.md`.
  * The key-retirement runbook is DRY-RUN by default.
"""

import argparse
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import re
import sys
from typing import Any, Dict, List, Optional, Tuple
from urllib import parse as urllib_parse

PLUGIN_ROOT = Path(__file__).resolve().parents[3]
if str(PLUGIN_ROOT) not in sys.path:
  sys.path.insert(0, str(PLUGIN_ROOT))

from lib.envelope_schema import SCHEMA_VERSION, utc_now_iso  # pylint: disable=wrong-import-position
from lib.gcp_client import GCPHTTPError, ScopeGuardGCPClient  # pylint: disable=wrong-import-position
from lib.gcs_publisher import (  # pylint: disable=wrong-import-position
    GCSAssessmentStore,
    add_gcs_publish_arguments,
    run_skill_gcs_preflight,
)

logger = logging.getLogger("scopeguard.federation_architect")

AUTOMATION_SA_KEYWORDS = (
    "cicd",
    "deploy",
    "pipeline",
    "github",
    "gitlab",
    "terraform",
    "automation",
    "etl",
    "worker",
)

POOL_ID = "scopeguard-cicd-oidc-pool"
GITHUB_PROVIDER_ID = "github-actions-provider"
GITLAB_PROVIDER_ID = "gitlab-ci-provider"
PLACEHOLDER_PROJECT_NUMBER = "PROJECT_NUMBER"
PLACEHOLDER_GITLAB_PROJECT = "REPLACE-gitlab-group/REPLACE-project"

# Well-known public OIDC issuers that validate Google STS audience by default.
_WELL_KNOWN_OIDC_ISSUER_PREFIXES = (
    "https://token.actions.githubusercontent.com",
    "https://gitlab.com",
    "https://accounts.google.com",
    "https://sts.windows.net/",
    "https://login.microsoftonline.com/",
)
# Regexes for detecting org-wide trust without repo/branch/environment pinning.
_BROAD_ORG_CLAIM_RE = re.compile(
    r"\b(repository_owner|repository_owner_id|namespace_path|namespace_id)\b"
)
_NARROW_PIN_CLAIM_RE = re.compile(
    r"\b(repository|repository_id|project_path|project_id|ref|environment|job_workflow_ref|sub)\b"
)
_BROAD_PRINCIPAL_SET_RE = re.compile(
    r"/attribute\.(repository_owner|namespace_path)/[^/\s]+$"
)


def _compute_key_age_days(valid_after_time: str) -> int:
  """Returns the age in days of a key from its RFC3339 `validAfterTime`."""
  if not valid_after_time:
    return 0
  try:
    cleaned = valid_after_time.replace("Z", "+00:00")
    created = datetime.fromisoformat(cleaned)
    delta = datetime.now(timezone.utc) - created
    return max(0, delta.days)
  except ValueError:
    logger.debug("Unparseable validAfterTime %r", valid_after_time)
    return 0


def _cel_quote(value: str) -> str:
  """Escapes a value for embedding in a single-quoted CEL string literal."""
  return value.replace("\\", "\\\\").replace("'", "\\'")


def build_github_condition(github_org: str, github_repo: str, github_ref: str = "") -> str:
  """Builds the anti-spoofing CEL condition for the GitHub provider.

  Pins the repository owner AND the exact repository (and optionally the ref)
  so that tokens minted by any other GitHub repository are rejected by STS.
  """
  parts = [
      f"assertion.repository_owner == '{_cel_quote(github_org)}'",
      f"assertion.repository == '{_cel_quote(github_repo)}'",
  ]
  if github_ref:
    parts.append(f"assertion.ref == '{_cel_quote(github_ref)}'")
  return " && ".join(parts)


def build_gitlab_condition(gitlab_project: str, gitlab_ref: str = "") -> str:
  """Builds the anti-spoofing CEL condition for the GitLab provider."""
  namespace = gitlab_project.rsplit("/", 1)[0] if "/" in gitlab_project else gitlab_project
  parts = [
      f"assertion.namespace_path == '{_cel_quote(namespace)}'",
      f"assertion.project_path == '{_cel_quote(gitlab_project)}'",
  ]
  if gitlab_ref:
    parts.append(f"assertion.ref == '{_cel_quote(gitlab_ref)}'")
  return " && ".join(parts)


def _hcl_escape(value: str) -> str:
  """Escapes double quotes for an HCL string literal."""
  return value.replace("\\", "\\\\").replace('"', '\\"')


def _provider_resource(project_number: str, provider_id: str) -> str:
  """Returns the full provider resource name used by CI auth tooling."""
  return (
      f"projects/{project_number}/locations/global/workloadIdentityPools/"
      f"{POOL_ID}/providers/{provider_id}"
  )


def render_github_workflow(
    project_id: str, provider_resource: str, service_account: str, github_repo: str
) -> str:
  """Renders a ready-to-paste GitHub Actions workflow using WIF."""
  return "\n".join([
      "# ScopeGuard: keyless GitHub Actions -> Google Cloud (Workload Identity Federation)",
      f"# Place in {github_repo}: .github/workflows/gcp-keyless.yml",
      "# Then delete the GOOGLE_CREDENTIALS / SA key secret from the repository.",
      "name: gcp-keyless-deploy",
      "on:",
      "  push:",
      "    branches: [main]",
      "  workflow_dispatch: {}",
      "",
      "permissions:",
      "  contents: read",
      "  id-token: write   # required to mint the GitHub OIDC token",
      "",
      "jobs:",
      "  deploy:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      "      - uses: actions/checkout@v4",
      "      - id: auth",
      "        uses: google-github-actions/auth@v2",
      "        with:",
      f"          workload_identity_provider: '{provider_resource}'",
      f"          service_account: '{service_account}'",
      "      - uses: google-github-actions/setup-gcloud@v2",
      "      - name: Verify identity",
      f"        run: gcloud auth list && gcloud projects describe {project_id} --format='value(projectId)'",
      "",
  ])


def render_gitlab_ci(
    project_id: str,
    provider_resource: str,
    service_account: str,
    gitlab_project: str,
) -> str:
  """Renders a ready-to-paste GitLab CI job using id_tokens + external_account."""
  return "\n".join([
      "# ScopeGuard: keyless GitLab CI -> Google Cloud (Workload Identity Federation)",
      f"# Add to {gitlab_project}: .gitlab-ci.yml",
      "# Then remove any SA key CI/CD variable (e.g. GOOGLE_CREDENTIALS).",
      "gcp-keyless-deploy:",
      "  image: google/cloud-sdk:slim",
      "  id_tokens:",
      "    GCP_ID_TOKEN:",
      f"      aud: https://iam.googleapis.com/{provider_resource}",
      "  script:",
      '    - echo "${GCP_ID_TOKEN}" > .ci_job_jwt_file',
      "    - >-",
      "      gcloud iam workload-identity-pools create-cred-config",
      f"      {provider_resource}",
      f"      --service-account={service_account}",
      "      --credential-source-file=.ci_job_jwt_file",
      "      --output-file=.gcp_temp_cred.json",
      "    # external_account credential: short-lived, no static key on disk",
      "    - gcloud auth login --cred-file=.gcp_temp_cred.json",
      "    - export GOOGLE_APPLICATION_CREDENTIALS=$CI_PROJECT_DIR/.gcp_temp_cred.json",
      f"    - gcloud projects describe {project_id} --format='value(projectId)'",
      "  after_script:",
      "    - rm -f .ci_job_jwt_file .gcp_temp_cred.json",
      "  rules:",
      "    - if: $CI_COMMIT_REF_PROTECTED == \"true\"",
      "",
  ])


def _render_retirement_runbook(
    project_id: str, audited_accounts: List[Dict[str, Any]], total_user_keys: int
) -> str:
  """Renders a DRY-RUN-by-default key retirement script (disable, never delete)."""
  lines = [
      "#!/usr/bin/env bash",
      "# ScopeGuard Zero-Downtime Service Account Key Retirement Runbook",
      "# Phase 1: Migrate CI to WIF -> disable keys (reversible) -> verify 14d audit logs -> delete",
      "# DRY-RUN by default. Use: ./retire_sa_keys.sh --apply [--yes]",
      "set -euo pipefail",
      f'PROJECT_ID="{project_id}"',
      "DRY_RUN=1; ASSUME_YES=0",
      'for arg in "$@"; do',
      '  case "$arg" in',
      "    --apply) DRY_RUN=0 ;;",
      "    --yes) ASSUME_YES=1 ;;",
      '    *) echo "Unknown argument: $arg" >&2; exit 2 ;;',
      "  esac",
      "done",
      'LOG_FILE="retire_sa_keys_$(date -u +%Y%m%dT%H%M%SZ).log"',
      'run() {',
      '  echo "[$(date -u +%FT%TZ)] ${USER:-unknown}: $*" | tee -a "$LOG_FILE"',
      '  if [[ "$DRY_RUN" == "1" ]]; then echo "  (dry-run, not executed)"; return 0; fi',
      '  "$@"',
      "}",
      'if [[ "$DRY_RUN" == "0" && "$ASSUME_YES" != "1" ]]; then',
      '  read -r -p "Disable static keys in ${PROJECT_ID}? Type yes: " ans',
      '  [[ "$ans" == "yes" ]] || { echo "Aborted."; exit 1; }',
      "fi",
      "",
  ]
  if total_user_keys == 0:
    lines.append(
        "# No active USER_MANAGED keys detected. Enforce Org Policy "
        "`constraints/iam.disableServiceAccountKeyCreation` to lock in keyless posture."
    )
  else:
    for acc in audited_accounts:
      for k in acc["keys"]:
        lines.append(
            f"# Disable static key {k['key_id']} (age: {k['age_days']}d) on {acc['email']}"
        )
        lines.append(
            f'run gcloud iam service-accounts keys disable "{k["key_id"]}" '
            f'--iam-account="{acc["email"]}" --project="${{PROJECT_ID}}" --quiet'
        )
        lines.append(
            f'# Emergency re-enable: gcloud iam service-accounts keys enable "{k["key_id"]}" '
            f'--iam-account="{acc["email"]}" --project="${{PROJECT_ID}}"'
        )
        lines.append("")
  return "\n".join(lines) + "\n"


def _extract_resource_id(resource_name: str, fallback: str = "unknown") -> str:
  """Extracts the trailing segment from a GCP resource name."""
  name = (resource_name or "").strip().rstrip("/")
  return name.rsplit("/", 1)[-1] if "/" in name else (name or fallback)


def _is_well_known_oidc_issuer(issuer_uri: str) -> bool:
  """Returns True when an OIDC issuer URI matches a well-known SaaS/cloud IdP."""
  normalized = issuer_uri.strip().rstrip("/").lower()
  for prefix in _WELL_KNOWN_OIDC_ISSUER_PREFIXES:
    if normalized == prefix.rstrip("/") or normalized.startswith(prefix):
      return True
  return False


def _build_provider_hardening_snippet(
    project_id: str,
    pool_id: str,
    provider_id: str,
    issuer_uri: str,
    rule_id: str,
) -> str:
  """Generates a concrete Terraform hardening snippet for an existing WIF provider."""
  low_issuer = issuer_uri.lower()
  if "githubusercontent.com" in low_issuer:
    cond = (
        "assertion.repository_owner == '<ORG>' && "
        "assertion.repository == '<ORG>/<REPO>' && "
        "assertion.ref == 'refs/heads/main'"
    )
  elif "gitlab" in low_issuer:
    cond = (
        "assertion.namespace_path == '<GROUP>' && "
        "assertion.project_path == '<GROUP>/<PROJECT>' && "
        "assertion.ref == 'main'"
    )
  else:
    cond = "assertion.sub == '<EXPECTED_WORKLOAD_SUBJECT>'"

  safe_tf_name = re.sub(r"[^a-zA-Z0-9_]", "_", f"{pool_id}_{provider_id}")
  if rule_id == "WIF_UNRESTRICTED_ISSUER":
    return "\n".join([
        f'resource "google_iam_workload_identity_pool_provider" "{safe_tf_name}" {{',
        f'  project                            = "{project_id}"',
        f'  workload_identity_pool_id          = "{pool_id}"',
        f'  workload_identity_pool_provider_id = "{provider_id}"',
        "  oidc {",
        f'    issuer_uri        = "{_hcl_escape(issuer_uri)}"',
        "    allowed_audiences = [",
        f'      "https://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/{pool_id}/providers/{provider_id}"',
        "    ]",
        "  }",
        "}",
    ])
  return "\n".join([
      f'resource "google_iam_workload_identity_pool_provider" "{safe_tf_name}" {{',
      f'  project                            = "{project_id}"',
      f'  workload_identity_pool_id          = "{pool_id}"',
      f'  workload_identity_pool_provider_id = "{provider_id}"',
      f'  attribute_condition                = "{_hcl_escape(cond)}"',
      "}",
  ])


def collect_existing_wif_pools(
    project_id: str,
    gcp_client: ScopeGuardGCPClient,
) -> Tuple[List[Dict[str, Any]], str, Optional[str]]:
  """Collects existing Workload Identity Pools and Providers read-only.

  Degrades gracefully on HTTP 403/404 or transport errors without aborting the
  wider federation assessment.

  Args:
    project_id: Target GCP project ID.
    gcp_client: Authenticated `ScopeGuardGCPClient`.

  Returns:
    Tuple of `(pools_with_providers, collection_status, collection_note)`.
  """
  encoded_proj = urllib_parse.quote(project_id, safe="")
  base_pools_url = (
      f"https://iam.googleapis.com/v1/projects/{encoded_proj}"
      "/locations/global/workloadIdentityPools"
  )
  pools: List[Dict[str, Any]] = []
  page_token = ""

  while True:
    url = base_pools_url
    if page_token:
      url = f"{base_pools_url}?pageToken={urllib_parse.quote(page_token, safe='')}"
    try:
      resp = gcp_client.request_json(url=url, method="GET", service_key="iam")
    except GCPHTTPError as exc:
      if exc.status_code == 403:
        note = (
            "Read-only listing of Workload Identity Pools denied (HTTP 403); "
            "grant `roles/iam.workloadIdentityPoolViewer` to audit existing WIF hygiene."
        )
        logger.warning("%s", note)
        return [], "DEGRADED_PERMISSION_DENIED", note
      if exc.status_code == 404:
        note = f"Workload Identity Pools endpoint returned HTTP 404 for {project_id}."
        logger.info("%s", note)
        return [], "DEGRADED_NOT_FOUND", note
      note = f"Failed listing Workload Identity Pools for {project_id}: {exc}"
      logger.warning("%s", note)
      return [], "DEGRADED_ERROR", note
    except RuntimeError as exc:
      note = f"Network/auth error listing Workload Identity Pools: {exc}"
      logger.warning("%s", note)
      return [], "DEGRADED_ERROR", note

    pools.extend(resp.get("workloadIdentityPools", []))
    page_token = resp.get("nextPageToken", "")
    if not page_token:
      break

  enriched_pools: List[Dict[str, Any]] = []
  for pool in pools:
    pool_copy = dict(pool)
    if pool_copy.get("state") == "DELETED":
      pool_copy["providers"] = []
      enriched_pools.append(pool_copy)
      continue
    pool_name = pool_copy.get("name", "")
    if not pool_name:
      pool_copy["providers"] = []
      enriched_pools.append(pool_copy)
      continue

    providers: List[Dict[str, Any]] = []
    prov_base_url = f"https://iam.googleapis.com/v1/{pool_name}/providers"
    prov_token = ""
    while True:
      p_url = prov_base_url
      if prov_token:
        p_url = f"{prov_base_url}?pageToken={urllib_parse.quote(prov_token, safe='')}"
      try:
        p_resp = gcp_client.request_json(url=p_url, method="GET", service_key="iam")
      except (GCPHTTPError, RuntimeError) as exc:
        logger.warning("Unable to list providers for pool %s: %s", pool_name, exc)
        break
      providers.extend(p_resp.get("workloadIdentityPoolProviders", []))
      prov_token = p_resp.get("nextPageToken", "")
      if not prov_token:
        break

    pool_copy["providers"] = providers
    enriched_pools.append(pool_copy)

  return enriched_pools, "OK", None


def audit_existing_wif_pools(
    project_id: str,
    pools: List[Dict[str, Any]],
    collection_status: str = "OK",
    collection_note: Optional[str] = None,
) -> Dict[str, Any]:
  """Audits active existing WIF Pools & Providers for federation hygiene risks.

  Checks each active provider for:
    * `WIF_MISSING_ATTRIBUTE_CONDITION` (CRITICAL): missing/empty `attributeCondition`.
    * `WIF_BROAD_ORG_TRUST` (HIGH): trusts an entire org (`repository_owner` /
      `namespace_path`) without pinning a repo, branch (`ref`), or environment.
    * `WIF_UNRESTRICTED_ISSUER` (MEDIUM): custom OIDC issuer without explicit
      `allowedAudiences`.

  Args:
    project_id: Target GCP project ID.
    pools: List of pool dicts (each containing a `providers` list).
    collection_status: Collection status label (`OK`, `FIXTURE`, `SKIPPED_OFFLINE`,
      `DEGRADED_PERMISSION_DENIED`, `DEGRADED_NOT_FOUND`, `DEGRADED_ERROR`).
    collection_note: Optional diagnostic note when degraded/skipped.

  Returns:
    Structured `existing_wif_audit` dictionary with summary counts, findings,
    and concrete Terraform hardening snippets.
  """
  active_pools = 0
  active_providers = 0
  findings: List[Dict[str, Any]] = []
  by_rule = {
      "WIF_MISSING_ATTRIBUTE_CONDITION": 0,
      "WIF_BROAD_ORG_TRUST": 0,
      "WIF_UNRESTRICTED_ISSUER": 0,
  }

  for pool in pools:
    if pool.get("state") == "DELETED" or pool.get("disabled") is True:
      continue
    active_pools += 1
    pool_name = pool.get("name", "")
    pool_id = pool.get("pool_id") or _extract_resource_id(pool_name, "unknown-pool")
    pool_principal_sets = list(
        pool.get("principalSets") or pool.get("principal_sets") or []
    )

    for prov in pool.get("providers", []):
      if prov.get("state") == "DELETED" or prov.get("disabled") is True:
        continue
      active_providers += 1
      prov_name = prov.get("name", "")
      prov_id = prov.get("provider_id") or _extract_resource_id(
          prov_name, "unknown-provider"
      )
      oidc = prov.get("oidc") or {}
      issuer_uri = str(
          oidc.get("issuerUri") or oidc.get("issuer_uri") or ""
      ).strip()
      allowed_audiences = (
          oidc.get("allowedAudiences") or oidc.get("allowed_audiences") or []
      )
      attr_cond = str(
          prov.get("attributeCondition") or prov.get("attribute_condition") or ""
      ).strip()
      principal_sets = pool_principal_sets + list(
          prov.get("principalSets") or prov.get("principal_sets") or []
      )

      # 1. CRITICAL: Missing/empty attributeCondition
      if not attr_cond:
        by_rule["WIF_MISSING_ATTRIBUTE_CONDITION"] += 1
        findings.append({
            "rule_id": "WIF_MISSING_ATTRIBUTE_CONDITION",
            "severity": "CRITICAL",
            "pool_id": pool_id,
            "provider_id": prov_id,
            "provider_name": prov_name,
            "issuer_uri": issuer_uri,
            "detail": (
                "Provider has no `attributeCondition`; any OIDC token minted by "
                f"`{issuer_uri or 'the issuer'}` can authenticate into pool `{pool_id}`."
            ),
            "terraform_hardening_snippet": _build_provider_hardening_snippet(
                project_id, pool_id, prov_id, issuer_uri,
                "WIF_MISSING_ATTRIBUTE_CONDITION",
            ),
        })

      # 2. HIGH: Broad org-level trust without repo/branch/environment pinning
      broad_reasons: List[str] = []
      if (
          attr_cond
          and _BROAD_ORG_CLAIM_RE.search(attr_cond)
          and not _NARROW_PIN_CLAIM_RE.search(attr_cond)
      ):
        broad_reasons.append(
            f"`attributeCondition` (`{attr_cond}`) trusts an entire org/namespace "
            "without pinning a specific repository, branch (`ref`), or environment."
        )
      broad_psets = [
          ps for ps in principal_sets
          if isinstance(ps, str) and _BROAD_PRINCIPAL_SET_RE.search(ps.strip())
      ]
      if broad_psets:
        broad_reasons.append(
            f"`principalSet` binding(s) ({', '.join(broad_psets)}) grant org-wide "
            "impersonation without repo/project scoping."
        )
      if broad_reasons:
        by_rule["WIF_BROAD_ORG_TRUST"] += 1
        findings.append({
            "rule_id": "WIF_BROAD_ORG_TRUST",
            "severity": "HIGH",
            "pool_id": pool_id,
            "provider_id": prov_id,
            "provider_name": prov_name,
            "issuer_uri": issuer_uri,
            "detail": " ".join(broad_reasons),
            "terraform_hardening_snippet": _build_provider_hardening_snippet(
                project_id, pool_id, prov_id, issuer_uri,
                "WIF_BROAD_ORG_TRUST",
            ),
        })

      # 3. MEDIUM: Custom OIDC issuer without explicit allowedAudiences
      if (
          issuer_uri
          and not _is_well_known_oidc_issuer(issuer_uri)
          and not allowed_audiences
      ):
        by_rule["WIF_UNRESTRICTED_ISSUER"] += 1
        findings.append({
            "rule_id": "WIF_UNRESTRICTED_ISSUER",
            "severity": "MEDIUM",
            "pool_id": pool_id,
            "provider_id": prov_id,
            "provider_name": prov_name,
            "issuer_uri": issuer_uri,
            "detail": (
                f"Custom OIDC issuer `{issuer_uri}` does not declare explicit "
                "`allowedAudiences`, widening token replay surface."
            ),
            "terraform_hardening_snippet": _build_provider_hardening_snippet(
                project_id, pool_id, prov_id, issuer_uri,
                "WIF_UNRESTRICTED_ISSUER",
            ),
        })

  return {
      "collection_status": collection_status,
      "collection_note": collection_note,
      "summary": {
          "pools_scanned": active_pools,
          "providers_scanned": active_providers,
          "total_findings": len(findings),
          "critical_count": sum(1 for f in findings if f["severity"] == "CRITICAL"),
          "high_count": sum(1 for f in findings if f["severity"] == "HIGH"),
          "medium_count": sum(1 for f in findings if f["severity"] == "MEDIUM"),
          "by_rule": by_rule,
      },
      "findings": findings,
  }


def _render_migration_md(
    project_id: str,
    generated_at: str,
    github_condition: str,
    gitlab_condition: str,
    ci_platforms: List[str],
    warnings: List[str],
    service_account: str,
    existing_wif_audit: Optional[Dict[str, Any]] = None,
) -> str:
  """Renders the WIF migration guide including anti-spoofing documentation."""
  lines = [
      f"# ScopeGuard WIF Migration — `{project_id}`",
      "",
      f"_Generated {generated_at} · schema {SCHEMA_VERSION}_",
      "",
  ]
  if warnings:
    lines.append("> [!WARNING]")
    lines.extend(f"> - {w}" for w in warnings)
    lines.append("")
  lines.extend([
      "## Files",
      "",
      "| File | Purpose |",
      "| :--- | :--- |",
      "| `wif_federation.tf` | Pool, provider(s), `roles/iam.workloadIdentityUser` bindings |",
  ])
  if "github" in ci_platforms:
    lines.append("| `ci/github-actions-wif.yml` | GitHub Actions workflow (`google-github-actions/auth@v2`) |")
  if "gitlab" in ci_platforms:
    lines.append("| `ci/gitlab-ci-wif.yml` | GitLab CI job (`id_tokens` + `create-cred-config`) |")
  lines.extend([
      "| `retire_sa_keys.sh` | Dry-run-by-default static key disable runbook |",
      "",
      "## Anti-spoofing `attribute_condition`",
      "",
      "Any identity provider pool without a condition accepts tokens from **every** "
      "repository on the public GitHub/GitLab instance. ScopeGuard pins both the "
      "owner/namespace and the exact repository/project:",
      "",
  ])
  if "github" in ci_platforms:
    lines.extend(["- GitHub: `" + github_condition + "`"])
  if "gitlab" in ci_platforms:
    lines.extend(["- GitLab: `" + gitlab_condition + "`"])
  lines.extend([
      "",
      "Hardening options: pin `assertion.ref` (`--github-ref refs/heads/main`), and "
      "prefer immutable numeric IDs (`assertion.repository_owner_id`, "
      "`assertion.repository_id`) to defeat rename/name-squatting attacks. The SA "
      "binding additionally restricts `principalSet` to the single repository.",
      "",
  ])

  if existing_wif_audit is not None:
    audit_sum = existing_wif_audit.get("summary", {})
    audit_findings = existing_wif_audit.get("findings", [])
    lines.extend([
        "## Existing WIF Pool & Provider Hygiene Audit",
        "",
        f"- Collection status: `{existing_wif_audit.get('collection_status', 'UNKNOWN')}`",
        f"- Active pools scanned: **{audit_sum.get('pools_scanned', 0)}** · "
        f"Active providers scanned: **{audit_sum.get('providers_scanned', 0)}** · "
        f"Findings: **{audit_sum.get('total_findings', 0)}** "
        f"(CRITICAL: {audit_sum.get('critical_count', 0)}, "
        f"HIGH: {audit_sum.get('high_count', 0)}, "
        f"MEDIUM: {audit_sum.get('medium_count', 0)})",
        "",
    ])
    if existing_wif_audit.get("collection_note"):
      lines.extend([f"> [!NOTE]", f"> {existing_wif_audit['collection_note']}", ""])
    if audit_findings:
      lines.extend([
          "| Severity | Rule | Pool / Provider | Finding |",
          "| :--- | :--- | :--- | :--- |",
      ])
      for f in audit_findings:
        lines.append(
            f"| **{f['severity']}** | `{f['rule_id']}` | "
            f"`{f['pool_id']}/{f['provider_id']}` | {f['detail']} |"
        )
      lines.extend(["", "### Terraform Hardening Snippets", ""])
      for f in audit_findings:
        lines.extend([
            f"#### `{f['rule_id']}` — `{f['pool_id']}/{f['provider_id']}`",
            "",
            "```hcl",
            f["terraform_hardening_snippet"],
            "```",
            "",
        ])

  lines.extend([
      "## Rollout",
      "",
      "1. `terraform apply` `wif_federation.tf`; read the `*_workload_identity_provider` "
      f"outputs and replace `{PLACEHOLDER_PROJECT_NUMBER}` in the CI snippets if present.",
      f"2. Paste the CI snippet; run the pipeline and confirm it authenticates as `{service_account}`.",
      "3. Remove the SA key secret from CI, then `./retire_sa_keys.sh` (dry-run) → "
      "`--apply` to disable keys; delete only after 14 days without key usage.",
      "",
  ])
  return "\n".join(lines)


def run_federation_architect(
    project_id: str,
    sa_inventory: Optional[List[Dict[str, Any]]] = None,
    github_org: str = "enterprise-org",
    github_repo: str = "enterprise-org/cloud-workloads",
    gcp_client: Optional[ScopeGuardGCPClient] = None,
    output_dir: Optional[Path] = None,
    github_ref: str = "",
    gitlab_project: str = "",
    gitlab_url: str = "https://gitlab.com",
    gitlab_ref: str = "",
    project_number: str = "",
    ci_platforms: Optional[List[str]] = None,
    existing_wif_pools: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
  """Audits SA keys, existing WIF pools, and generates WIF Terraform & runbooks.

  Args:
    project_id: Target GCP project ID.
    sa_inventory: Pre-fetched SA inventory (fetched read-only if None).
    github_org: GitHub owner pinned in the provider condition.
    github_repo: `owner/repo` allowed to federate.
    gcp_client: Optional injected client.
    output_dir: When set, writes JSON/Terraform/CI/Markdown deliverables.
    github_ref: Optional git ref pin (e.g. `refs/heads/main`).
    gitlab_project: GitLab `group/project` path allowed to federate.
    gitlab_url: GitLab instance URL (OIDC issuer).
    gitlab_ref: Optional GitLab ref pin.
    project_number: Numeric project number for provider resource names.
    ci_platforms: Subset of {"github", "gitlab"}; defaults to both.
    existing_wif_pools: Optional offline fixture list of existing WIF pools
      (with nested `providers`) to audit without live GCP network calls.

  Returns:
    Module entry dict with `summary`, `payload`, and `status`.
  """
  generated_at = utc_now_iso()
  platforms = [p.strip().lower() for p in (ci_platforms or ["github", "gitlab"]) if p.strip()]
  platforms = [p for p in platforms if p in ("github", "gitlab")] or ["github"]
  warnings: List[str] = []

  client = gcp_client
  if sa_inventory is None:
    client = client or ScopeGuardGCPClient(quota_project=project_id)
    accounts = client.fetch_service_accounts_with_keys(project_id)
  else:
    accounts = sa_inventory

  # --- Existing WIF Pool & Provider Hygiene Audit (read-only) ----------------
  if existing_wif_pools is not None:
    existing_wif_audit = audit_existing_wif_pools(
        project_id=project_id,
        pools=existing_wif_pools,
        collection_status="FIXTURE",
    )
  elif client is not None:
    raw_pools, coll_status, coll_note = collect_existing_wif_pools(
        project_id=project_id, gcp_client=client
    )
    existing_wif_audit = audit_existing_wif_pools(
        project_id=project_id,
        pools=raw_pools,
        collection_status=coll_status,
        collection_note=coll_note,
    )
  else:
    existing_wif_audit = audit_existing_wif_pools(
        project_id=project_id,
        pools=[],
        collection_status="SKIPPED_OFFLINE",
        collection_note="Offline mode (sa_inventory provided without gcp_client or existing_wif_pools).",
    )

  audited_accounts: List[Dict[str, Any]] = []
  wif_candidates: List[Dict[str, Any]] = []
  total_user_keys = 0
  aged_keys_over_90d = 0

  for sa in accounts:
    email = sa.get("email", "")
    if not email:
      continue
    disabled = bool(sa.get("disabled", False))
    user_keys = sa.get("user_managed_keys", [])
    key_details: List[Dict[str, Any]] = []
    for k in user_keys:
      k_name = k.get("name", "")
      key_id = k_name.rsplit("/", 1)[-1] if "/" in k_name else k_name
      age_days = _compute_key_age_days(k.get("validAfterTime", ""))
      if age_days > 90:
        aged_keys_over_90d += 1
      key_details.append(
          {
              "key_id": key_id,
              "valid_after": k.get("validAfterTime", ""),
              "age_days": age_days,
              "key_Origin": k.get("keyOrigin", "GOOGLE_PROVIDED"),
              "rotation_violation": age_days > 90,
          }
      )
    total_user_keys += len(key_details)

    low_email = email.lower()
    is_automation_candidate = bool(key_details) or any(
        kw in low_email for kw in AUTOMATION_SA_KEYWORDS
    )
    status_label = (
        "CRITICAL_STATIC_KEY_ACTIVE"
        if key_details
        else (
            "WIF_RECOMMENDED_AUTOMATION_SA"
            if is_automation_candidate and not disabled
            else "CLEAN_KEYLESS"
        )
    )

    rec_item = {
        "email": email,
        "display_name": sa.get("displayName", ""),
        "unique_id": sa.get("uniqueId", ""),
        "disabled": disabled,
        "user_managed_key_count": len(key_details),
        "keys": key_details,
        "posture_status": status_label,
        "recommended_federation": (
            f"GitHub Actions OIDC ({github_repo})"
            if is_automation_candidate
            else "GCP Native Attached Identity (Cloud Run / GKE Workload Identity)"
        ),
    }
    audited_accounts.append(rec_item)
    if is_automation_candidate and not disabled:
      wif_candidates.append(rec_item)

  # --- Input sanity checks (anti-spoofing pins must be coherent) -------------
  if not github_repo.startswith(f"{github_org}/"):
    warnings.append(
        f"--github-repo `{github_repo}` is not owned by --github-org `{github_org}`; "
        "the provider condition will reject every token until fixed."
    )
  gl_project = gitlab_project or PLACEHOLDER_GITLAB_PROJECT
  if "gitlab" in platforms and not gitlab_project:
    warnings.append(
        f"No --gitlab-project supplied; GitLab provider pinned to placeholder "
        f"`{PLACEHOLDER_GITLAB_PROJECT}` (fails closed until replaced)."
    )
  proj_num = project_number or PLACEHOLDER_PROJECT_NUMBER
  if not project_number:
    warnings.append(
        f"No --project-number supplied; CI snippets use `{PLACEHOLDER_PROJECT_NUMBER}`. "
        "Use the Terraform outputs or `gcloud projects describe` to fill it in."
    )
  primary_sa = (
      wif_candidates[0]["email"]
      if wif_candidates
      else f"REPLACE-ci-deployer@{project_id}.iam.gserviceaccount.com"
  )
  if not wif_candidates:
    warnings.append("No WIF candidate SA found; CI snippets use a placeholder SA.")

  github_condition = build_github_condition(github_org, github_repo, github_ref)
  gitlab_condition = build_gitlab_condition(gl_project, gitlab_ref)
  github_provider = _provider_resource(proj_num, GITHUB_PROVIDER_ID)
  gitlab_provider = _provider_resource(proj_num, GITLAB_PROVIDER_ID)

  # --- Keyless Workload Identity Federation Terraform HCL --------------------
  tf_lines = [
      "# ScopeGuard Keyless Workload Identity Federation (WIF) Terraform Blueprint",
      f"# Project: {project_id}",
      f"# Generated: {generated_at} (schema {SCHEMA_VERSION})",
      "# CI snippets: ci/github-actions-wif.yml, ci/gitlab-ci-wif.yml (see WIF_MIGRATION.md)",
      "",
      'resource "google_iam_workload_identity_pool" "scopeguard_cicd_pool" {',
      f'  project                   = "{project_id}"',
      f'  workload_identity_pool_id = "{POOL_ID}"',
      '  display_name              = "ScopeGuard CI/CD Keyless Pool"',
      '  description               = "Replaces static SA JSON keys with short-lived OIDC tokens"',
      "}",
      "",
  ]
  if "github" in platforms:
    tf_lines.extend([
        'resource "google_iam_workload_identity_pool_provider" "github_actions_oidc" {',
        f'  project                            = "{project_id}"',
        "  workload_identity_pool_id          = google_iam_workload_identity_pool.scopeguard_cicd_pool.workload_identity_pool_id",
        f'  workload_identity_pool_provider_id = "{GITHUB_PROVIDER_ID}"',
        '  display_name                       = "GitHub Actions OIDC"',
        "  attribute_mapping = {",
        '    "google.subject"             = "assertion.sub"',
        '    "attribute.actor"            = "assertion.actor"',
        '    "attribute.repository"       = "assertion.repository"',
        '    "attribute.repository_owner" = "assertion.repository_owner"',
        '    "attribute.ref"              = "assertion.ref"',
        "  }",
        "  # Anti-spoofing: pin owner AND exact repository (and ref if set) so tokens",
        "  # from any other GitHub repository are rejected by Google STS.",
        f'  attribute_condition = "{_hcl_escape(github_condition)}"',
        "  oidc {",
        '    issuer_uri = "https://token.actions.githubusercontent.com"',
        "  }",
        "}",
        "",
        'output "github_workload_identity_provider" {',
        "  value = google_iam_workload_identity_pool_provider.github_actions_oidc.name",
        "}",
        "",
    ])
  if "gitlab" in platforms:
    tf_lines.extend([
        'resource "google_iam_workload_identity_pool_provider" "gitlab_ci_oidc" {',
        f'  project                            = "{project_id}"',
        "  workload_identity_pool_id          = google_iam_workload_identity_pool.scopeguard_cicd_pool.workload_identity_pool_id",
        f'  workload_identity_pool_provider_id = "{GITLAB_PROVIDER_ID}"',
        '  display_name                       = "GitLab CI OIDC"',
        "  attribute_mapping = {",
        '    "google.subject"           = "assertion.sub"',
        '    "attribute.namespace_path" = "assertion.namespace_path"',
        '    "attribute.project_path"   = "assertion.project_path"',
        '    "attribute.ref"            = "assertion.ref"',
        "  }",
        "  # Anti-spoofing: pin namespace AND exact project path (and ref if set).",
        f'  attribute_condition = "{_hcl_escape(gitlab_condition)}"',
        "  oidc {",
        f'    issuer_uri = "{gitlab_url.rstrip("/")}"',
        "  }",
        "}",
        "",
        'output "gitlab_workload_identity_provider" {',
        "  value = google_iam_workload_identity_pool_provider.gitlab_ci_oidc.name",
        "}",
        "",
    ])

  for idx, cand in enumerate(wif_candidates[:4], start=1):
    members: List[str] = []
    if "github" in platforms:
      members.append(
          "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.scopeguard_cicd_pool.name}"
          f"/attribute.repository/{github_repo}"
      )
    if "gitlab" in platforms:
      members.append(
          "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.scopeguard_cicd_pool.name}"
          f"/attribute.project_path/{gl_project}"
      )
    for m_idx, member in enumerate(members, start=1):
      res_slug = f"wif_bind_{idx}" if m_idx == 1 else f"wif_bind_{idx}_{m_idx}"
      tf_lines.extend(
          [
              f'resource "google_service_account_iam_member" "{res_slug}" {{',
              f'  service_account_id = "projects/{project_id}/serviceAccounts/{cand["email"]}"',
              '  role               = "roles/iam.workloadIdentityUser"',
              f'  member             = "{member}"',
              "}",
              "",
          ]
      )

  wif_tf = "\n".join(tf_lines)
  retirement_sh = _render_retirement_runbook(project_id, audited_accounts, total_user_keys)

  ci_snippets: Dict[str, str] = {}
  if "github" in platforms:
    ci_snippets["github_actions"] = render_github_workflow(
        project_id, github_provider, primary_sa, github_repo
    )
  if "gitlab" in platforms:
    ci_snippets["gitlab_ci"] = render_gitlab_ci(
        project_id, gitlab_provider, primary_sa, gl_project
    )
  migration_md = _render_migration_md(
      project_id, generated_at, github_condition, gitlab_condition,
      platforms, warnings, primary_sa,
      existing_wif_audit=existing_wif_audit,
  )
  for w in warnings:
    logger.warning("%s", w)

  wif_audit_sum = existing_wif_audit["summary"]
  summary = {
      "service_accounts_scanned": len(audited_accounts),
      "user_managed_keys_found": total_user_keys,
      "keys_exceeding_90d_rotation": aged_keys_over_90d,
      "wif_migration_candidates": len(wif_candidates),
      "ci_platforms": platforms,
      "existing_wif_pools_scanned": wif_audit_sum["pools_scanned"],
      "existing_wif_providers_scanned": wif_audit_sum["providers_scanned"],
      "existing_wif_findings_count": wif_audit_sum["total_findings"],
      "existing_wif_critical_findings": wif_audit_sum["critical_count"],
      "keyless_compliance_status": (
          "COMPLIANT_ZERO_STATIC_KEYS"
          if total_user_keys == 0
          else "ACTION_REQUIRED_RETIRE_KEYS"
      ),
  }
  payload = {
      "schema_version": SCHEMA_VERSION,
      "generated_at": generated_at,
      "warnings": warnings,
      "service_accounts": audited_accounts,
      "wif_candidates": wif_candidates,
      "existing_wif_audit": existing_wif_audit,
      "attribute_conditions": {
          **({"github": github_condition} if "github" in platforms else {}),
          **({"gitlab": gitlab_condition} if "gitlab" in platforms else {}),
      },
      "workload_identity_providers": {
          **({"github": github_provider} if "github" in platforms else {}),
          **({"gitlab": gitlab_provider} if "gitlab" in platforms else {}),
      },
      "wif_terraform_hcl": wif_tf,
      "ci_snippets": ci_snippets,
      "key_retirement_runbook_sh": retirement_sh,
  }

  if output_dir:
    try:
      output_dir.mkdir(parents=True, exist_ok=True)
      (output_dir / "federation_audit.json").write_text(
          json.dumps(
              {
                  "schema_version": SCHEMA_VERSION,
                  "generated_at": generated_at,
                  "project_id": project_id,
                  "summary": summary,
                  "payload": payload,
              },
              indent=2,
          )
          + "\n",
          encoding="utf-8",
      )
      (output_dir / "wif_federation.tf").write_text(wif_tf, encoding="utf-8")
      retire_path = output_dir / "retire_sa_keys.sh"
      retire_path.write_text(retirement_sh, encoding="utf-8")
      retire_path.chmod(0o750)
      ci_dir = output_dir / "ci"
      ci_dir.mkdir(exist_ok=True)
      if "github_actions" in ci_snippets:
        (ci_dir / "github-actions-wif.yml").write_text(
            ci_snippets["github_actions"], encoding="utf-8"
        )
      if "gitlab_ci" in ci_snippets:
        (ci_dir / "gitlab-ci-wif.yml").write_text(
            ci_snippets["gitlab_ci"], encoding="utf-8"
        )
      (output_dir / "WIF_MIGRATION.md").write_text(migration_md, encoding="utf-8")
    except OSError as exc:
      logger.error("Failed writing WIF deliverables to %s: %s", output_dir, exc)
      raise

  return {"summary": summary, "payload": payload, "status": "COMPLETED"}


def main() -> int:
  """CLI entry point."""
  logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
  parser = argparse.ArgumentParser(
      description="Audit Service Account keys and generate keyless WIF Terraform."
  )
  parser.add_argument("--project", required=True, help="Target GCP Project ID.")
  parser.add_argument(
      "--project-number",
      default="",
      help="Numeric project number used in provider resource names for CI snippets.",
  )
  parser.add_argument(
      "--github-org",
      default="scopeguard-enterprise",
      help="GitHub organization owner for OIDC attribute_condition guard.",
  )
  parser.add_argument(
      "--github-repo",
      default="scopeguard-enterprise/platform-infra",
      help="GitHub org/repo allowed to federate into CI/CD Service Accounts.",
  )
  parser.add_argument(
      "--github-ref",
      default="",
      help="Optional git ref pin in the GitHub condition (e.g. refs/heads/main).",
  )
  parser.add_argument(
      "--gitlab-project",
      default="",
      help="GitLab group/project path allowed to federate (pinned in condition).",
  )
  parser.add_argument(
      "--gitlab-url",
      default="https://gitlab.com",
      help="GitLab instance URL used as OIDC issuer.",
  )
  parser.add_argument(
      "--gitlab-ref", default="", help="Optional GitLab ref pin (e.g. main)."
  )
  parser.add_argument(
      "--ci-platforms",
      default="github,gitlab",
      help="Comma-separated CI platforms to generate: github,gitlab.",
  )
  parser.add_argument(
      "--output-dir",
      required=True,
      help="Directory to write WIF Terraform and key retirement scripts.",
  )
  add_gcs_publish_arguments(parser)
  args = parser.parse_args()

  store = GCSAssessmentStore()
  gcs_check = run_skill_gcs_preflight(args, args.project, store=store)

  out_dir = Path(args.output_dir)
  mod_entry = run_federation_architect(
      project_id=args.project,
      github_org=args.github_org,
      github_repo=args.github_repo,
      gcp_client=store.client,
      output_dir=out_dir,
      github_ref=args.github_ref,
      gitlab_project=args.gitlab_project,
      gitlab_url=args.gitlab_url,
      gitlab_ref=args.gitlab_ref,
      project_number=args.project_number,
      ci_platforms=args.ci_platforms.split(","),
  )

  publish_info = None
  if gcs_check:
    live_etag = ""
    try:
      pol = store.client.fetch_project_iam_policy(args.project)
      live_etag = pol.get("etag", "")
    except Exception as exc:  # pylint: disable=broad-except
      logger.warning("Could not fetch live policy etag: %s", exc)
    publish_info = store.publish_assessment_run(
        bucket=gcs_check["bucket"],
        region=gcs_check["region"],
        project_id=args.project,
        trigger_mode="federation-architect",
        updated_modules={"federation_architect": mod_entry},
        live_policy_etag=live_etag,
        local_output_dir=out_dir,
    )

  print(
      json.dumps(
          {
              "federation_summary": mod_entry["summary"],
              "warnings": mod_entry["payload"]["warnings"],
              "gcs_publish": publish_info,
          },
          indent=2,
      )
  )
  return 0


if __name__ == "__main__":
  sys.exit(main())
