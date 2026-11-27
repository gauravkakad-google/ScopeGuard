#!/usr/bin/env python3
# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0

"""Google Cloud IAM v2 Deny Policy Preventive Guardrail Architect.

Generates IAM v2 DenyPolicy JSON manifests and `google_iam_deny_policy` Terraform
HCL rules (D1-D5) with breakglass and GitOps automation exemptions.

Rollout guardrails (ART-11):
  * Break-glass exception principals are supplied via the repeatable
    ``--breakglass-principal`` flag and placed into every rule's
    ``exceptionPrincipals``. A loud warning is emitted when none are given.
  * IAM deny has no dry-run mode, so an "observe first" guide
    (``deny_rollout.md``) explains how to validate impact with audit logs and
    Policy Troubleshooter before enforcing, and how to stage the rollout.
  * Principal and permission identifiers are validated against IAM v2 syntax
    (``principal://`` / ``principalSet://`` and ``service.googleapis.com/res.verb``)
    and against the vetted ``DENY_SUPPORTED_PERMISSIONS`` allowlist so
    ``terraform apply`` / ``gcloud iam policies create`` never fail at apply time.
  * Rule ``D5_CONTAIN_AI_AGENT_BLAST_RADIUS`` enforces an unbypassable IAM
    control-plane ceiling on AI/agent Service Accounts, complementing runtime
    filters such as Agent Gateway and Model Armor.
"""

import argparse
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
from lib.gcp_client import ScopeGuardGCPClient  # pylint: disable=wrong-import-position
from lib.gcs_publisher import (  # pylint: disable=wrong-import-position
    GCSAssessmentStore,
    add_gcs_publish_arguments,
    run_skill_gcs_preflight,
)

logger = logging.getLogger("scopeguard.deny_policy_architect")

POLICY_ID = "scopeguard-core-guardrails"
ALL_PRINCIPALS = "principalSet://goog/public:all"

# IAM v2 deny permission form: `<service>.googleapis.com/<resource>.<verb>`.
_V2_PERMISSION_RE = re.compile(r"^[a-z0-9-]+\.googleapis\.com/[A-Za-z0-9]+\.[A-Za-z0-9]+$")
# IAM v2 principal identifiers accepted in deny rules.
_V2_PRINCIPAL_RE = re.compile(r"^(principal|principalSet)://\S+$")

# Vetted allowlist of official GCP IAM v2 deny-supported permissions.
# Reference: https://cloud.google.com/iam/docs/deny-permissions-support
# Permissions outside this set (e.g., `logging.googleapis.com/buckets.delete`)
# are rejected by the IAM v2 API at `terraform apply` / `gcloud iam policies create` time.
DENY_SUPPORTED_PERMISSIONS = frozenset({
    # IAM & Service Accounts
    "iam.googleapis.com/serviceAccountKeys.create",
    "iam.googleapis.com/serviceAccountKeys.delete",
    "iam.googleapis.com/serviceAccounts.actAs",
    "iam.googleapis.com/serviceAccounts.getAccessToken",
    "iam.googleapis.com/serviceAccounts.signBlob",
    "iam.googleapis.com/serviceAccounts.signJwt",
    "iam.googleapis.com/serviceAccounts.setIamPolicy",
    "iam.googleapis.com/roles.create",
    "iam.googleapis.com/roles.update",
    "iam.googleapis.com/roles.delete",
    # Resource Manager
    "cloudresourcemanager.googleapis.com/projects.setIamPolicy",
    "cloudresourcemanager.googleapis.com/folders.setIamPolicy",
    "cloudresourcemanager.googleapis.com/organizations.setIamPolicy",
    # Cloud Storage
    "storage.googleapis.com/buckets.setIamPolicy",
    "storage.googleapis.com/buckets.update",
    "storage.googleapis.com/buckets.delete",
    "storage.googleapis.com/objects.get",
    "storage.googleapis.com/objects.delete",
    # Cloud Logging (note: `buckets.update` is supported; `buckets.delete` is NOT)
    "logging.googleapis.com/sinks.delete",
    "logging.googleapis.com/sinks.update",
    "logging.googleapis.com/buckets.update",
    "logging.googleapis.com/exclusions.create",
    "logging.googleapis.com/exclusions.update",
    # Secret Manager & API Keys
    "secretmanager.googleapis.com/secrets.setIamPolicy",
    "secretmanager.googleapis.com/versions.access",
    "apikeys.googleapis.com/keys.create",
    "apikeys.googleapis.com/keys.delete",
    # Org Policy, BigQuery, Compute, KMS
    "orgpolicy.googleapis.com/policies.create",
    "orgpolicy.googleapis.com/policies.update",
    "orgpolicy.googleapis.com/policies.delete",
    "bigquery.googleapis.com/datasets.setIamPolicy",
    "bigquery.googleapis.com/tables.setIamPolicy",
    "compute.googleapis.com/instances.setIamPolicy",
    "compute.googleapis.com/firewalls.create",
    "compute.googleapis.com/firewalls.update",
    "compute.googleapis.com/firewalls.delete",
    "kms.googleapis.com/cryptoKeyVersions.useToDecrypt",
    "kms.googleapis.com/cryptoKeys.setIamPolicy",
})

# Signals used to auto-discover AI/agent Service Accounts for D5 containment.
_AI_AGENT_ROLE_RE = re.compile(
    r"(?:^|[/.])(aiplatform|ml|discoveryengine)(?:[./]|$)", re.IGNORECASE
)
_AI_AGENT_NAME_MARKERS = ("agent", "rag", "llm", "mcp")
_D5_DENIED_PERMISSIONS = [
    "cloudresourcemanager.googleapis.com/projects.setIamPolicy",
    "iam.googleapis.com/serviceAccountKeys.create",
    "iam.googleapis.com/roles.update",
    "logging.googleapis.com/sinks.delete",
    "apikeys.googleapis.com/keys.create",
]


def to_v2_principal(member: str) -> str:
  """Converts an IAM v1 member (`user:`, `group:`, ...) to an IAM v2 identifier.

  Args:
    member: IAM v1 member string or an already-v2 identifier.

  Returns:
    The IAM v2 principal identifier.

  Raises:
    ValueError: If the member type cannot be expressed in a deny policy.
  """
  member = (member or "").strip()
  if _V2_PRINCIPAL_RE.match(member):
    return member
  if ":" not in member:
    if "@" not in member:
      raise ValueError(f"Unrecognised principal: {member!r}")
    # Bare SA emails are unambiguous; other bare emails default to users.
    member = (
        f"serviceAccount:{member}"
        if member.endswith(".gserviceaccount.com")
        else f"user:{member}"
    )
  kind, ident = member.split(":", 1)
  if kind == "user":
    return f"principal://goog/subject/{ident}"
  if kind == "group":
    return f"principalSet://goog/group/{ident}"
  if kind == "serviceAccount":
    return f"principal://iam.googleapis.com/projects/-/serviceAccounts/{ident}"
  if kind == "domain":
    # Deny rules need the Cloud Identity customer ID, not the domain name:
    # pass `principalSet://goog/cloudIdentityCustomerId/<ID>` explicitly.
    raise ValueError(
        f"domain:{ident} must be given as principalSet://goog/cloudIdentityCustomerId/<ID>"
    )
  raise ValueError(f"Principal type {kind!r} is not supported in IAM deny rules")


def validate_deny_rules(rules: List[Dict[str, Any]]) -> List[str]:
  """Validates IAM v2 syntax and official deny-permission support of rules.

  Args:
    rules: List of internal deny rule dicts (`rule_id`, `denied_principals`,
      `exception_principals`, `denied_permissions`).

  Returns:
    List of human-readable validation errors (empty when all rules are valid).
  """
  errors: List[str] = []
  for r in rules:
    rid = r.get("rule_id", "?")
    for p in r.get("denied_principals", []) + r.get("exception_principals", []):
      if not _V2_PRINCIPAL_RE.match(p):
        errors.append(f"{rid}: principal {p!r} is not IAM v2 syntax")
    for perm in r.get("denied_permissions", []):
      if not _V2_PERMISSION_RE.match(perm):
        errors.append(
            f"{rid}: permission {perm!r} must use service.googleapis.com/resource.verb"
        )
      elif perm not in DENY_SUPPORTED_PERMISSIONS:
        errors.append(
            f"{rid}: permission {perm!r} is not in DENY_SUPPORTED_PERMISSIONS "
            "(unsupported by GCP IAM v2 Deny)"
        )
  return errors


def _is_ai_agent_sa_name(member: str) -> bool:
  """Returns True when a Service Account email local-part matches AI/agent keywords."""
  raw = member.strip()
  if raw.startswith("serviceAccount:"):
    email = raw.split(":", 1)[1]
  elif raw.startswith("principal://iam.googleapis.com/projects/-/serviceAccounts/"):
    email = raw.rsplit("/", 1)[-1]
  elif "@" in raw and raw.endswith(".gserviceaccount.com"):
    email = raw
  else:
    return False
  local_part = email.split("@", 1)[0].lower()
  return any(marker in local_part for marker in _AI_AGENT_NAME_MARKERS)


def _is_service_account_member(member: str) -> bool:
  """Returns True if the member string represents a GCP Service Account."""
  raw = (member or "").strip()
  return (
      raw.startswith("serviceAccount:")
      or raw.startswith("principal://iam.googleapis.com/projects/-/serviceAccounts/")
      or raw.endswith(".gserviceaccount.com")
  )


def _extract_principals_from_entry(entry: Any) -> List[str]:
  """Extracts principal strings from heterogeneous finding/analysis objects."""
  found: List[str] = []
  if isinstance(entry, str) and entry.strip():
    found.append(entry.strip())
  elif isinstance(entry, list):
    for item in entry:
      found.extend(_extract_principals_from_entry(item))
  elif isinstance(entry, dict):
    for key in ("principal", "member", "email", "service_account", "sa_email"):
      val = entry.get(key)
      if isinstance(val, str) and val.strip():
        found.append(val.strip())
    for list_key in ("principals", "affected_principals", "service_accounts", "members"):
      val = entry.get(list_key)
      if isinstance(val, list):
        found.extend(_extract_principals_from_entry(val))
  return found


def discover_ai_agent_principals(
    policy: Dict[str, Any],
    analysis_data: Optional[Dict[str, Any]] = None,
    explicit_principals: Optional[List[str]] = None,
) -> Tuple[List[str], Dict[str, List[str]], List[str]]:
  """Discovers AI/agent Service Accounts for D5 blast-radius containment.

  Sources (deduplicated, converted to IAM v2 principal identifiers):
    1. Explicit `--ai-agent-principal` CLI flags / kwargs.
    2. `analysis_data` (`F8_ai_agent_blast_radius`, findings, or principal lists
       with AI/ML roles or `*agent*`/`*rag*`/`*llm*`/`*mcp*` SA names).
    3. Live/provided IAM `policy` bindings matching AI/ML roles (`aiplatform`,
       `ml`, `discoveryengine`) or AI/agent SA naming patterns.

  Args:
    policy: Project IAM policy dict (`bindings`).
    analysis_data: Optional ScopeGuard analysis output dict.
    explicit_principals: Optional explicit AI agent principals.

  Returns:
    Tuple of `(v2_principals, sources_by_principal, warnings)`.
  """
  discovered: List[str] = []
  sources: Dict[str, List[str]] = {}
  warnings: List[str] = []

  def _register(raw: str, source: str) -> None:
    try:
      v2 = to_v2_principal(raw)
    except ValueError as exc:
      warnings.append(f"Ignored AI agent principal: {exc}")
      logger.warning("Ignored AI agent principal %r: %s", raw, exc)
      return
    if v2 not in discovered:
      discovered.append(v2)
    sources.setdefault(v2, [])
    if source not in sources[v2]:
      sources[v2].append(source)

  # 1. Explicit caller-supplied AI agent principals.
  for raw in explicit_principals or []:
    _register(raw, "explicit:--ai-agent-principal")

  # 2. Analysis data signals (F8_ai_agent_blast_radius, findings, principal profiles).
  if isinstance(analysis_data, dict):
    search_roots = [analysis_data]
    if isinstance(analysis_data.get("payload"), dict):
      search_roots.append(analysis_data["payload"])
    for root in search_roots:
      if "F8_ai_agent_blast_radius" in root:
        for p in _extract_principals_from_entry(root["F8_ai_agent_blast_radius"]):
          _register(p, "analysis_data:F8_ai_agent_blast_radius")

      for f_key in ("findings", "security_findings", "escalation_findings"):
        findings_list = root.get(f_key, [])
        if not isinstance(findings_list, list):
          continue
        for item in findings_list:
          if not isinstance(item, dict):
            continue
          tag = " ".join(
              str(item.get(k, ""))
              for k in ("id", "finding_id", "rule_id", "code", "category", "type")
          ).lower()
          if "f8_ai_agent" in tag or "ai_agent" in tag:
            for p in _extract_principals_from_entry(item):
              _register(p, "analysis_data:F8_ai_agent_blast_radius")

      for p_key in ("principals", "principal_profiles", "principal_risks"):
        p_list = root.get(p_key, [])
        if isinstance(p_list, dict):
          p_list = [
              {"principal": k, **(v if isinstance(v, dict) else {})}
              for k, v in p_list.items()
          ]
        if not isinstance(p_list, list):
          continue
        for item in p_list:
          if not isinstance(item, dict):
            continue
          cand = (
              item.get("principal")
              or item.get("member")
              or item.get("email")
              or item.get("service_account")
              or ""
          )
          if not _is_service_account_member(str(cand)):
            continue
          roles = item.get("roles") or item.get("assigned_roles") or []
          if isinstance(roles, str):
            roles = [roles]
          if any(_AI_AGENT_ROLE_RE.search(str(r)) for r in roles):
            _register(str(cand), "analysis_data:ai_role")
          elif _is_ai_agent_sa_name(str(cand)):
            _register(str(cand), "analysis_data:sa_name_pattern")

  # 3. IAM policy bindings (AI/ML roles or AI/agent SA naming patterns).
  for binding in policy.get("bindings", []):
    role = str(binding.get("role", ""))
    is_ai_role = bool(_AI_AGENT_ROLE_RE.search(role))
    for member in binding.get("members", []):
      if not _is_service_account_member(member):
        continue
      if is_ai_role:
        _register(member, f"policy_role:{role}")
      elif _is_ai_agent_sa_name(member):
        _register(member, "policy_sa_name_pattern")

  return discovered, sources, warnings


def _v1_permission(v2_perm: str) -> str:
  """Maps a v2 deny permission to the v1 name seen in audit logs.

  Example: `iam.googleapis.com/serviceAccountKeys.create` ->
  `iam.serviceAccountKeys.create`. Resource Manager is the one service whose
  v1 prefix (`resourcemanager`) differs from its API host.
  """
  host, rest = v2_perm.split("/", 1)
  service = host.split(".googleapis.com", 1)[0]
  if service == "cloudresourcemanager":
    service = "resourcemanager"
  return f"{service}.{rest}"


def _render_rollout_md(
    project_id: str,
    generated_at: str,
    rules: List[Dict[str, Any]],
    exceptions: List[str],
    exceptions_source: str,
    warnings: List[str],
    ai_agent_principals: Optional[List[str]] = None,
) -> str:
  """Renders the observe-first rollout guide (`deny_rollout.md`)."""
  v1_perms = sorted({
      _v1_permission(p) for r in rules for p in r["denied_permissions"]
  })
  attach = f"cloudresourcemanager.googleapis.com/projects/{project_id}"
  lines = [
      f"# ScopeGuard Deny Policy Rollout — `{project_id}`",
      "",
      f"_Generated {generated_at} · schema {SCHEMA_VERSION}_",
      "",
  ]
  if warnings:
    lines.append("> [!WARNING]")
    lines.extend(f"> - {w}" for w in warnings)
    lines.append("")
  lines.extend([
      "## Break-glass exception principals",
      "",
      f"Source: **{exceptions_source}**. These identities are listed in every "
      "rule's `exceptionPrincipals` and are NOT blocked:",
      "",
  ])
  lines.extend(f"- `{e}`" for e in exceptions)
  lines.extend([
      "",
      "Keep break-glass accounts few, MFA-protected, alerted-on, and stored "
      "offline. Re-run with `--breakglass-principal` to set them explicitly.",
      "",
      "## Rules",
      "",
      "| Rule | Denied permissions | Condition |",
      "| :--- | :--- | :--- |",
  ])
  for r in rules:
    cond = r["denial_condition"]["expression"] if r["denial_condition"] else "—"
    lines.append(
        f"| `{r['rule_id']}` | {', '.join(f'`{p}`' for p in r['denied_permissions'])} "
        f"| `{cond}` |"
    )
  lines.extend([
      "",
      "## AI Agent Blast-Radius Containment (`D5`) — Complementing Agent Gateway & Model Armor",
      "",
      "Runtime AI security controls such as **Agent Gateway** and **Model Armor** "
      "inspect prompts, model outputs, and tool invocations at the application layer "
      "to mitigate prompt injection and unsafe tool calls. However, runtime filters "
      "operate inside the application path and cannot substitute for infrastructure "
      "privilege boundaries.",
      "",
      "`D5_CONTAIN_AI_AGENT_BLAST_RADIUS` enforces an **unbypassable IAM control-plane "
      "ceiling** evaluated by Google Cloud *before* any Allow policy. Even if an AI "
      "agent or MCP tool runner is compromised via prompt injection, IAM v2 Deny "
      "hard-blocks privilege escalation (`projects.setIamPolicy`, `roles.update`), "
      "long-lived credential minting (`serviceAccountKeys.create`, `keys.create`), "
      "and audit-log tampering (`sinks.delete`).",
      "",
  ])
  if ai_agent_principals:
    lines.append("Contained AI agent principals in `D5`:")
    lines.append("")
    lines.extend(f"- `{p}`" for p in ai_agent_principals)
    lines.append("")
  else:
    lines.append(
        "_No AI agent principals were auto-discovered in this project. Supply "
        "`--ai-agent-principal=serviceAccount:<sa>` to activate `D5`._"
    )
    lines.append("")
  lines.extend([
      "## Observe first (IAM deny has no dry-run mode)",
      "",
      "1. **Find who uses the denied permissions today** (last 30–90 days) in "
      "Admin Activity audit logs. Anyone listed who is not a break-glass or "
      "automation identity will be blocked:",
      "",
      "   ```bash",
      f"   gcloud logging read 'protoPayload.authorizationInfo.permission=(\"{'\" OR \"'.join(v1_perms)}\")' \\",
      f"     --project={project_id} --freshness=90d \\",
      "     --format='table(timestamp, protoPayload.authenticationInfo.principalEmail, protoPayload.methodName)'",
      "   ```",
      "",
      "2. **Simulate access with Policy Troubleshooter** (it evaluates allow + "
      "deny policies) for each legitimate caller found in step 1, after the "
      "policy is attached to a sandbox project:",
      "",
      "   ```bash",
      "   gcloud policy-intelligence troubleshoot-policy iam \\",
      f"     //cloudresourcemanager.googleapis.com/projects/{project_id} \\",
      "     --principal-email=<caller@domain> \\",
      "     --permission=resourcemanager.projects.setIamPolicy",
      "   ```",
      "",
      "3. **Validate rule syntax and supported permissions** against the "
      "[deny-supported permissions list](https://cloud.google.com/iam/docs/deny-permissions-support); "
      "unsupported permissions are rejected at create time.",
      "4. **Replace the placeholder tag** in `D3` (`tagKeys/000000000000`) with "
      "your real break-glass tag, or remove the condition.",
      "",
      "## Staged rollout",
      "",
      "1. Sandbox project → verify break-glass and GitOps identities still work.",
      "2. One non-production project for ≥ 7 days; watch for `PERMISSION_DENIED` "
      "with `denyPolicy` in audit-log `status.details`.",
      "3. Production project(s), then consider folder/org attachment.",
      "",
      "Create (human-run; ScopeGuard never applies it):",
      "",
      "```bash",
      f"gcloud iam policies create {POLICY_ID} \\",
      f"  --attachment-point={attach} \\",
      "  --kind=denypolicies --policy-file=deny_policy_v2.json",
      "```",
      "",
      "Roll back immediately if legitimate access breaks:",
      "",
      "```bash",
      f"gcloud iam policies delete {POLICY_ID} \\",
      f"  --attachment-point={attach} --kind=denypolicies",
      "```",
      "",
  ])
  return "\n".join(lines)


def run_deny_policy_architect(
    project_id: str,
    policy_data: Optional[Dict[str, Any]] = None,
    exempt_principals: Optional[List[str]] = None,
    gcp_client: Optional[ScopeGuardGCPClient] = None,
    output_dir: Optional[Path] = None,
    breakglass_principals: Optional[List[str]] = None,
    analysis_data: Optional[Dict[str, Any]] = None,
    ai_agent_principals: Optional[List[str]] = None,
) -> Dict[str, Any]:
  """Synthesizes D1-D5 IAM v2 Deny Policy rules, Terraform HCL and rollout guide.

  Args:
    project_id: Target GCP project ID.
    policy_data: Pre-fetched IAM policy (fetched read-only if None).
    exempt_principals: Legacy alias for `breakglass_principals`.
    gcp_client: Optional injected client.
    output_dir: When set, writes JSON/Terraform/Markdown deliverables.
    breakglass_principals: Break-glass identities (v1 member or v2 form) to
      add to every rule's `exceptionPrincipals`.
    analysis_data: Optional ScopeGuard analysis output used to auto-discover
      AI/agent Service Accounts (`F8_ai_agent_blast_radius` or AI/ML roles).
    ai_agent_principals: Explicit AI/agent principals (v1 member or v2 form)
      to contain via `D5_CONTAIN_AI_AGENT_BLAST_RADIUS`.

  Returns:
    Module entry dict with `summary`, `payload`, and `status`.
  """
  generated_at = utc_now_iso()
  if policy_data is None:
    client = gcp_client or ScopeGuardGCPClient(quota_project=project_id)
    policy = client.fetch_project_iam_policy(project_id)
  else:
    policy = policy_data

  warnings: List[str] = []
  supplied = list(breakglass_principals or []) + list(exempt_principals or [])
  exceptions: List[str] = []
  for raw in supplied:
    try:
      v2 = to_v2_principal(raw)
    except ValueError as exc:
      warnings.append(f"Ignored break-glass principal: {exc}")
      logger.warning("Ignored break-glass principal %r: %s", raw, exc)
      continue
    if v2 not in exceptions:
      exceptions.append(v2)

  exceptions_source = "--breakglass-principal"
  if not exceptions:
    exceptions_source = "INFERRED (confirm before applying)"
    warnings.append(
        "No --breakglass-principal supplied. A deny policy without a verified "
        "break-glass exception can lock out administrators. Exceptions below "
        "were inferred and MUST be confirmed."
    )
    logger.warning("No break-glass principals supplied; inferring exceptions.")
    # Fallback: first human owner (lock-out protection) + GitOps automation SA.
    for b in policy.get("bindings", []):
      if b.get("role") == "roles/owner" and not b.get("condition"):
        for m in b.get("members", []):
          if m.startswith("user:"):
            exceptions.append(to_v2_principal(m))
            break
    if not exceptions:
      exceptions.append(
          to_v2_principal(
              f"serviceAccount:terraform-gitops@{project_id}.iam.gserviceaccount.com"
          )
      )

  ai_agents, ai_agent_sources, ai_warnings = discover_ai_agent_principals(
      policy=policy,
      analysis_data=analysis_data,
      explicit_principals=ai_agent_principals,
  )
  warnings.extend(ai_warnings)

  deny_rules: List[Dict[str, Any]] = [
      {
          "rule_id": "D1_DENY_STATIC_SA_KEYS",
          "description": "Block creation of user-managed Service Account JSON keys across all principals.",
          "denied_principals": [ALL_PRINCIPALS],
          "exception_principals": list(exceptions),
          "denied_permissions": [
              "iam.googleapis.com/serviceAccountKeys.create",
          ],
          "denial_condition": None,
      },
      {
          "rule_id": "D2_PROTECT_AUDIT_SINKS",
          "description": "Prevent deletion or tampering with Cloud Logging audit sinks and log buckets.",
          "denied_principals": [ALL_PRINCIPALS],
          "exception_principals": list(exceptions),
          # `logging.googleapis.com/buckets.update` is IAM v2 deny-supported;
          # `logging.googleapis.com/buckets.delete` is NOT and would fail apply.
          "denied_permissions": [
              "logging.googleapis.com/sinks.delete",
              "logging.googleapis.com/sinks.update",
              "logging.googleapis.com/buckets.update",
          ],
          "denial_condition": None,
      },
      {
          "rule_id": "D3_ENFORCE_GITOPS_IAM_MUTATIONS",
          "description": "Block ad-hoc interactive IAM policy mutations outside approved GitOps automation & breakglass.",
          "denied_principals": [ALL_PRINCIPALS],
          "exception_principals": list(exceptions),
          "denied_permissions": [
              "cloudresourcemanager.googleapis.com/projects.setIamPolicy",
              "iam.googleapis.com/roles.delete",
          ],
          # Placeholder tag IDs; deny conditions may only reference resource tags.
          "denial_condition": {
              "title": "enforce_outside_breakglass_tag",
              "expression": "!resource.matchTagId('tagKeys/000000000000', 'tagValues/000000000000')",
          },
      },
      {
          "rule_id": "D4_GUARD_STORAGE_POLICY_EXPOSURE",
          "description": "Restrict Cloud Storage bucket IAM policy changes to approved platform identities.",
          "denied_principals": [ALL_PRINCIPALS],
          "exception_principals": list(exceptions),
          "denied_permissions": [
              "storage.googleapis.com/buckets.setIamPolicy",
          ],
          "denial_condition": None,
      },
  ]
  if ai_agents:
    deny_rules.append({
        "rule_id": "D5_CONTAIN_AI_AGENT_BLAST_RADIUS",
        "description": (
            "Enforce an unbypassable IAM control-plane ceiling on AI/agent "
            "Service Accounts, complementing Agent Gateway & Model Armor."
        ),
        "denied_principals": list(ai_agents),
        "exception_principals": list(exceptions),
        "denied_permissions": list(_D5_DENIED_PERMISSIONS),
        "denial_condition": None,
    })
  warnings.append(
      "D3 uses placeholder tag IDs (tagKeys/000000000000); replace with your "
      "break-glass tag or remove the condition."
  )

  syntax_errors = validate_deny_rules(deny_rules)
  for err in syntax_errors:
    logger.error("Deny policy syntax error: %s", err)
  warnings.extend(syntax_errors)

  attachment_point = urllib_parse.quote(
      f"cloudresourcemanager.googleapis.com/projects/{project_id}", safe=""
  )
  rules_v2 = [
      {
          "description": r["description"],
          "denyRule": {
              "deniedPrincipals": r["denied_principals"],
              "exceptionPrincipals": r["exception_principals"],
              "deniedPermissions": r["denied_permissions"],
              **(
                  {"denialCondition": r["denial_condition"]}
                  if r["denial_condition"]
                  else {}
              ),
          },
      }
      for r in deny_rules
  ]
  iam_v2_policy_json = {
      "displayName": f"ScopeGuard Preventive Guardrails ({project_id})",
      "name": f"policies/{attachment_point}/denypolicies/{POLICY_ID}",
      "rules": rules_v2,
  }
  # gcloud `--policy-file` body: only API fields (no name / ScopeGuard metadata),
  # because unknown fields are rejected by the IAM v2 API.
  gcloud_policy_file = {
      "displayName": iam_v2_policy_json["displayName"],
      "rules": rules_v2,
  }

  tf_lines = [
      "# ScopeGuard IAM v2 Preventive Deny Policy Terraform Blueprint",
      f"# Attachment Point: projects/{project_id}",
      f"# Generated: {generated_at} (schema {SCHEMA_VERSION})",
      "# OBSERVE FIRST: read deny_rollout.md before applying (deny has no dry-run).",
      f"# Break-glass exceptions ({exceptions_source}):",
      *[f"#   - {e}" for e in exceptions],
      "",
      'resource "google_iam_deny_policy" "scopeguard_core_guardrails" {',
      # Terraform's URL-encoding function is `urlencode` (provider docs pattern).
      f'  parent       = urlencode("cloudresourcemanager.googleapis.com/projects/{project_id}")',
      f'  name         = "{POLICY_ID}"',
      f'  display_name = "ScopeGuard Preventive Guardrails ({project_id})"',
      "",
  ]
  for r in deny_rules:
    perms_hcl = ",\n        ".join(f'"{p}"' for p in r["denied_permissions"])
    denied_hcl = ", ".join(f'"{p}"' for p in r["denied_principals"])
    exempt_hcl = ", ".join(f'"{p}"' for p in r["exception_principals"])
    tf_lines.extend(
        [
            "  rules {",
            f'    description = "{r["description"]}"',
            "    deny_rule {",
            f"      denied_principals    = [{denied_hcl}]",
            f"      exception_principals = [{exempt_hcl}]",
            "      denied_permissions = [",
            f"        {perms_hcl}",
            "      ]",
        ]
    )
    if r["denial_condition"]:
      tf_lines.extend(
          [
              "      denial_condition {",
              f'        title      = "{r["denial_condition"]["title"]}"',
              f'        expression = "{r["denial_condition"]["expression"]}"',
              "      }",
          ]
      )
    tf_lines.extend(["    }", "  }", ""])
  tf_lines.append("}\n")
  deny_tf = "\n".join(tf_lines)

  rollout_md = _render_rollout_md(
      project_id,
      generated_at,
      deny_rules,
      exceptions,
      exceptions_source,
      warnings,
      ai_agent_principals=ai_agents,
  )

  total_perms_blocked = sum(len(r["denied_permissions"]) for r in deny_rules)
  summary = {
      "deny_rules_count": len(deny_rules),
      "high_risk_permissions_guarded": total_perms_blocked,
      "breakglass_exemptions_count": len(exceptions),
      "breakglass_source": exceptions_source,
      "breakglass_supplied": exceptions_source == "--breakglass-principal",
      "ai_agent_principals_contained": len(ai_agents),
      "d5_ai_agent_containment_active": bool(ai_agents),
      "syntax_errors_count": len(syntax_errors),
      "attachment_scope": f"projects/{project_id}",
  }
  payload = {
      "schema_version": SCHEMA_VERSION,
      "generated_at": generated_at,
      "warnings": warnings,
      "breakglass_exception_principals": exceptions,
      "ai_agent_principals": ai_agents,
      "ai_agent_discovery_sources": ai_agent_sources,
      "rules": deny_rules,
      "iam_v2_policy_json": iam_v2_policy_json,
      "deny_policy_terraform_hcl": deny_tf,
      "observe_first_rollout_md": rollout_md,
  }

  if output_dir:
    try:
      output_dir.mkdir(parents=True, exist_ok=True)
      (output_dir / "deny_policy_v2.json").write_text(
          json.dumps(gcloud_policy_file, indent=2) + "\n", encoding="utf-8"
      )
      (output_dir / "deny_policy_spec.json").write_text(
          json.dumps(
              {
                  "schema_version": SCHEMA_VERSION,
                  "generated_at": generated_at,
                  "project_id": project_id,
                  "summary": summary,
                  "warnings": warnings,
                  "breakglass_exception_principals": exceptions,
                  "rules": deny_rules,
                  "iam_v2_policy_json": iam_v2_policy_json,
              },
              indent=2,
          )
          + "\n",
          encoding="utf-8",
      )
      (output_dir / "deny_policies.tf").write_text(deny_tf, encoding="utf-8")
      (output_dir / "deny_rollout.md").write_text(rollout_md, encoding="utf-8")
    except OSError as exc:
      logger.error("Failed writing deny deliverables to %s: %s", output_dir, exc)
      raise

  return {"summary": summary, "payload": payload, "status": "COMPLETED"}


def main() -> int:
  """CLI entry point."""
  logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
  parser = argparse.ArgumentParser(
      description="Synthesize GCP IAM v2 Deny Policies (D1-D5) and Terraform HCL."
  )
  parser.add_argument("--project", required=True, help="Target GCP Project ID.")
  parser.add_argument(
      "--breakglass-principal",
      action="append",
      default=[],
      help=(
          "Break-glass identity exempt from all deny rules (repeatable). Accepts "
          "user:/group:/serviceAccount: members or IAM v2 principal:// ids."
      ),
  )
  parser.add_argument(
      "--ai-agent-principal",
      action="append",
      default=[],
      help=(
          "AI/agent Service Account principal to contain via D5 blast-radius "
          "rule (repeatable). Accepts serviceAccount: members or IAM v2 "
          "principal:// ids."
      ),
  )
  parser.add_argument(
      "--output-dir",
      required=True,
      help="Directory to write Deny Policy JSON and Terraform HCL.",
  )
  add_gcs_publish_arguments(parser)
  args = parser.parse_args()

  store = GCSAssessmentStore()
  gcs_check = run_skill_gcs_preflight(args, args.project, store=store)

  policy_data = store.client.fetch_project_iam_policy(args.project)
  out_dir = Path(args.output_dir)
  mod_entry = run_deny_policy_architect(
      project_id=args.project,
      policy_data=policy_data,
      gcp_client=store.client,
      output_dir=out_dir,
      breakglass_principals=args.breakglass_principal,
      ai_agent_principals=args.ai_agent_principal,
  )

  publish_info = None
  if gcs_check:
    publish_info = store.publish_assessment_run(
        bucket=gcs_check["bucket"],
        region=gcs_check["region"],
        project_id=args.project,
        trigger_mode="deny-policy-architect",
        updated_modules={"deny_policy_architect": mod_entry},
        live_policy_etag=policy_data.get("etag", ""),
        local_output_dir=out_dir,
    )

  print(
      json.dumps(
          {
              "deny_policy_summary": mod_entry["summary"],
              "warnings": mod_entry["payload"]["warnings"],
              "gcs_publish": publish_info,
          },
          indent=2,
      )
  )
  return 0


if __name__ == "__main__":
  sys.exit(main())
