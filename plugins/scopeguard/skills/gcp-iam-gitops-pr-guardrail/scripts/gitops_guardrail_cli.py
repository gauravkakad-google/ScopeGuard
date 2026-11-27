#!/usr/bin/env python3
# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0

"""Shift-Left GitOps Terraform IAM Scanner & Pull Request Guardrail.

Evaluates Terraform IAM grants against governance rules G1-G6 before changes
reach `terraform apply`. Two input modes are supported:

* **Plan mode (preferred)** — `--plan-json <file>` consumes the output of
  `terraform show -json <planfile>`. Terraform has already resolved modules,
  variables, `for_each`/`count` instances and `dynamic` blocks, so every
  planned IAM grant is visible. `resource_changes[].change.actions` is used so
  deletions are never reported as new grants and in-place updates only report
  the (role, member, condition) tuples they add.
* **Regex/HCL mode (fallback)** — a dependency-free, comment- and brace-aware
  scan of `.tf` files. It understands `member`, `members = [...]` lists,
  folder/organization/service-account IAM resources and
  `data "google_iam_policy"` documents, but it CANNOT resolve module inputs,
  variables, locals or `for_each` expansion. Anything it cannot evaluate is
  listed in the Coverage section instead of being silently ignored.

Rules:
  G1 basic role (owner/editor), G2 static SA key, G3 transitive escalation
  role, G4 data-plane role at project/folder/org scope, G5 expired or
  long-lived IAM condition window (relative to the current UTC time),
  G6 public principal (allUsers / allAuthenticatedUsers).

The tool is read-only: it never calls IAM-mutating APIs.
"""

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import logging
from pathlib import Path
import re
import sys
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

PLUGIN_ROOT = Path(__file__).resolve().parents[3]
if str(PLUGIN_ROOT) not in sys.path:
  sys.path.insert(0, str(PLUGIN_ROOT))

from lib.envelope_schema import SCHEMA_VERSION  # pylint: disable=wrong-import-position
from lib.gcs_publisher import (  # pylint: disable=wrong-import-position
    GCSAssessmentStore,
    add_gcs_publish_arguments,
    run_skill_gcs_preflight,
)

LOGGER = logging.getLogger("scopeguard.gitops_guardrail")

TOOL_NAME = "ScopeGuard GitOps IAM Guardrail"
TOOL_VERSION = "2.1.0"
SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"
DEFAULT_MAX_EXPIRY_DAYS = 90
FAIL_ON_CHOICES = ("NONE", "CRITICAL", "HIGH", "MEDIUM", "LOW", "ANY")
SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

INPUT_MODE_PLAN = "plan_json"
INPUT_MODE_REGEX = "regex_hcl"

REGEX_MODE_WARNING = (
    "Regex/HCL fallback mode cannot resolve module inputs, variables, locals, "
    "for_each/count expansion or dynamic blocks; grants driven by those "
    "constructs may be MISSED. For a complete PR gate, run `terraform plan "
    "-out=tfplan && terraform show -json tfplan > plan.json` and pass "
    "`--plan-json plan.json`."
)

# IAM grant resources: google_<scope>_iam_<member|binding|policy>.
IAM_GRANT_TYPE_RE = re.compile(
    r"^google_(project|folder|organization|service_account)_iam_"
    r"(member|binding|policy)$"
)
# IAM-adjacent resources that do not grant access (reported, not evaluated).
IAM_NON_GRANT_TYPE_RE = re.compile(
    r"^google_(project|folder|organization|service_account)_iam_"
    r"(member_remove|audit_config|custom_role)$"
)
SA_KEY_TYPE = "google_service_account_key"
IAM_POLICY_DATA_TYPE = "google_iam_policy"

SCOPE_BY_PREFIX = {
    "project": "project",
    "folder": "folder",
    "organization": "organization",
    "service_account": "service_account",
}
TARGET_ATTR_BY_SCOPE = {
    "project": "project",
    "folder": "folder",
    "organization": "org_id",
    "service_account": "service_account_id",
}

BASIC_ROLES = {"roles/owner", "roles/editor"}
PUBLIC_PRINCIPALS = {"allUsers", "allAuthenticatedUsers"}

BROAD_DATA_PLANE_ROLES = {
    "roles/storage.admin",
    "roles/storage.objectAdmin",
    "roles/secretmanager.admin",
    "roles/secretmanager.secretAccessor",
    "roles/bigquery.admin",
    "roles/bigquery.dataEditor",
    "roles/aiplatform.admin",
}

TRANSITIVE_ROLES = {
    "roles/iam.serviceAccountUser",
    "roles/iam.serviceAccountTokenCreator",
    "roles/iam.securityAdmin",
    "roles/cloudbuild.builds.editor",
    "roles/run.admin",
}

# Static rule catalog. Drives both finding text and SARIF `tool.driver.rules`.
RULES: Dict[str, Dict[str, str]] = {
    "G1_BASIC_ROLE_BLOCKED": {
        "name": "BasicRoleBlocked",
        "severity": "CRITICAL",
        "short": "Legacy basic role (roles/owner or roles/editor) granted.",
        "full": "Basic roles grant thousands of permissions across every "
                "service in the resource hierarchy below the binding.",
        "help": "Replace with a scoped custom role from gcp-iam-role-architect "
                "(Model A persona role) or Model B capability bundle.",
    },
    "G2_STATIC_SA_KEY": {
        "name": "StaticServiceAccountKey",
        "severity": "CRITICAL",
        "short": "google_service_account_key stores private key material in state.",
        "full": "A user-managed service account key resource writes raw private "
                "key material into Terraform state.",
        "help": "Use a Workload Identity Federation pool/provider from "
                "gcp-iam-federation-architect instead.",
    },
    "G3_TRANSITIVE_ESCALATION_EDGE": {
        "name": "TransitiveEscalationEdge",
        "severity": "HIGH",
        "short": "Role enables service-account impersonation or deploy-time inheritance.",
        "full": "The role allows actAs/getAccessToken or deploying workloads "
                "that run as another identity, creating a privilege-escalation edge.",
        "help": "Bind on a single low-privilege target service account and gate "
                "with PAM approval.",
    },
    "G4_UNSCOPED_PROJECT_DATA_ROLE": {
        "name": "UnscopedDataPlaneRole",
        "severity": "HIGH",
        "short": "Data-plane role bound at project/folder/organization scope.",
        "full": "Data-plane roles should be bound on the specific bucket, "
                "secret or dataset, not on a container resource.",
        "help": "Move the binding to google_storage_bucket_iam_member, "
                "google_secret_manager_secret_iam_member or "
                "google_bigquery_dataset_iam_member.",
    },
    "G5_STALE_CONDITION_WINDOW": {
        "name": "ExpiredConditionWindow",
        "severity": "MEDIUM",
        "short": "IAM condition expiry timestamp is already in the past.",
        "full": "The binding's condition can never evaluate to true again; it "
                "is dead IAM debt kept in Terraform.",
        "help": "Remove the expired conditional binding (P0 hygiene) or move "
                "temporary access to PAM.",
    },
    "G5_LONG_LIVED_CONDITION_WINDOW": {
        "name": "LongLivedConditionWindow",
        "severity": "LOW",
        "short": "IAM condition expiry is further in the future than allowed.",
        "full": "Time-bound access whose expiry exceeds the configured maximum "
                "window behaves like standing access.",
        "help": "Shorten the window to the allowed maximum or use a PAM "
                "entitlement with a bounded request duration.",
    },
    "G6_PUBLIC_PRINCIPAL": {
        "name": "PublicPrincipalGrant",
        "severity": "CRITICAL",
        "short": "Role granted to allUsers or allAuthenticatedUsers.",
        "full": "Public principals expose the resource to the internet or to "
                "any Google account.",
        "help": "Grant the role to a specific group or service account instead.",
    },
}

# --- G5 condition timestamp parsing -----------------------------------------
_TS_LITERAL = r"timestamp\(\s*['\"]([^'\"]+)['\"]\s*\)"
TS_ANY_RE = re.compile(_TS_LITERAL)
TS_FWD_RE = re.compile(r"request\.time\s*(<=|>=|<|>)\s*" + _TS_LITERAL)
TS_REV_RE = re.compile(_TS_LITERAL + r"\s*(<=|>=|<|>)\s*request\.time")

# --- Regex/HCL fallback patterns ----------------------------------------------
RESOURCE_HEADER_RE = re.compile(
    r'(?m)^[ \t]*(resource|data)\s+"([A-Za-z0-9_]+)"\s+"([A-Za-z0-9_-]+)"\s*\{'
)
MODULE_HEADER_RE = re.compile(r'(?m)^[ \t]*module\s+"([A-Za-z0-9_-]+)"\s*\{')
BINDING_BLOCK_RE = re.compile(r"(?m)^[ \t]*binding\s*\{")
CONDITION_BLOCK_RE = re.compile(r"(?m)^[ \t]*condition\s*\{")
STRING_LITERAL_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')
POLICY_DATA_REF_RE = re.compile(
    r"data\.google_iam_policy\.([A-Za-z0-9_-]+)\.policy_data"
)
EXPANSION_RE = re.compile(r"(?m)^[ \t]*(for_each|count)\s*=|^[ \t]*dynamic\s+\"")


def _utc_iso(ts: datetime) -> str:
  """Formats a datetime as ISO-8601 UTC with a trailing `Z`."""
  return ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _line_number_at(content: str, offset: int) -> int:
  """Returns the 1-based line number of a character offset."""
  return content.count("\n", 0, max(0, offset)) + 1


def _parse_timestamp(value: str) -> Optional[datetime]:
  """Parses a CEL/RFC3339 timestamp literal into an aware UTC datetime."""
  raw = value.strip()
  if raw.endswith(("Z", "z")):
    raw = raw[:-1] + "+00:00"
  try:
    parsed = datetime.fromisoformat(raw)
  except ValueError:
    return None
  if parsed.tzinfo is None:
    parsed = parsed.replace(tzinfo=timezone.utc)
  return parsed.astimezone(timezone.utc)


def analyze_condition_timestamps(
    expression: str,
) -> List[Tuple[str, Optional[datetime], str]]:
  """Extracts `timestamp("...")` literals and their bound direction.

  Args:
    expression: CEL condition expression.

  Returns:
    List of (literal, parsed_utc_or_None, bound) where bound is `upper`
    (request.time must be before it — an expiry), `lower` (a start time) or
    `unknown` (not directly compared with request.time).
  """
  bounds: Dict[int, str] = {}
  for m in TS_FWD_RE.finditer(expression):
    # request.time < ts  => ts is an expiry (upper bound).
    bounds[m.start(2)] = "upper" if m.group(1).startswith("<") else "lower"
  for m in TS_REV_RE.finditer(expression):
    # ts > request.time  => request.time < ts => upper bound.
    bounds[m.start(1)] = "upper" if m.group(2).startswith(">") else "lower"
  out: List[Tuple[str, Optional[datetime], str]] = []
  for m in TS_ANY_RE.finditer(expression):
    out.append(
        (m.group(1), _parse_timestamp(m.group(1)), bounds.get(m.start(1), "unknown"))
    )
  return out


# =============================================================================
# Grant model + rule evaluation
# =============================================================================


def _make_grant(
    *,
    address: str,
    res_type: str,
    role: str,
    members: List[str],
    condition_expr: str,
    file: str,
    line: int,
    change_action: str,
    source: str,
    scope: str,
    target: str = "",
) -> Dict[str, Any]:
  """Builds the normalized grant record evaluated by `evaluate_grant`."""
  return {
      "address": address,
      "res_type": res_type,
      "role": role,
      "members": members,
      "condition_expr": condition_expr or "",
      "file": file,
      "line": max(1, int(line or 1)),
      "change_action": change_action,
      "source": source,
      "scope": scope,
      "target": target or "",
  }


def _finding(rule_id: str, grant: Dict[str, Any], principal: str, message: str,
             remediation: Optional[str] = None) -> Dict[str, Any]:
  """Creates a violation dict (field names preserved for downstream consumers)."""
  rule = RULES[rule_id]
  return {
      "rule_id": rule_id,
      "severity": rule["severity"],
      "file": grant["file"],
      "line": grant["line"],
      "resource": grant["address"],
      "role": grant["role"] or "N/A",
      "principal": principal,
      "message": message,
      "remediation": remediation or rule["help"],
      "scope": grant["scope"],
      "target": grant["target"],
      "change_action": grant["change_action"],
      "input_source": grant["source"],
  }


def evaluate_grant(
    grant: Dict[str, Any], now: datetime, max_expiry_days: int
) -> List[Dict[str, Any]]:
  """Evaluates rules G1, G3-G6 against one normalized grant (all members).

  Args:
    grant: Normalized grant from `_make_grant`.
    now: Current UTC time used for relative G5 checks.
    max_expiry_days: Expiries beyond now + this many days raise G5 long-lived.

  Returns:
    List of violation dicts (one per rule per member).
  """
  findings: List[Dict[str, Any]] = []
  role = grant["role"]
  scope = grant["scope"]
  members = grant["members"] or [""]

  for member in members:
    if role in BASIC_ROLES:
      findings.append(_finding(
          "G1_BASIC_ROLE_BLOCKED", grant, member,
          f"Legacy basic role `{role}` grants thousands of {scope}-wide "
          "permissions across all services."))
    if role in TRANSITIVE_ROLES:
      findings.append(_finding(
          "G3_TRANSITIVE_ESCALATION_EDGE", grant, member,
          f"Role `{role}` introduces service account impersonation "
          "(`actAs`/`getAccessToken`) or runtime deployment inheritance."))
    if scope in ("project", "folder", "organization") and role in BROAD_DATA_PLANE_ROLES:
      findings.append(_finding(
          "G4_UNSCOPED_PROJECT_DATA_ROLE", grant, member,
          f"Data-plane role `{role}` is bound at {scope.capitalize()} scope "
          "instead of child resource scope (Bucket, Secret, or Dataset)."))
    if member in PUBLIC_PRINCIPALS:
      findings.append(_finding(
          "G6_PUBLIC_PRINCIPAL", grant, member,
          f"Role `{role}` is granted to public principal `{member}`."))

    expr = grant["condition_expr"]
    if not expr:
      continue
    horizon = now + timedelta(days=max_expiry_days)
    for literal, parsed, bound in analyze_condition_timestamps(expr):
      if parsed is None:
        continue
      if bound in ("upper", "unknown") and parsed < now:
        findings.append(_finding(
            "G5_STALE_CONDITION_WINDOW", grant, member,
            f"Conditional binding expires at `{literal}`, which is before the "
            f"scan time {_utc_iso(now)}; the grant is dead IAM debt."))
      elif bound == "upper" and parsed > horizon:
        days = (parsed - now).days
        findings.append(_finding(
            "G5_LONG_LIVED_CONDITION_WINDOW", grant, member,
            f"Conditional binding expires at `{literal}` ({days} days from now), "
            f"exceeding the allowed maximum of {max_expiry_days} days."))
  return findings


def _sa_key_finding(address: str, file: str, line: int, change_action: str,
                    source: str, target: str = "") -> Dict[str, Any]:
  """Builds the G2 static-key violation for a google_service_account_key."""
  grant = _make_grant(
      address=address, res_type=SA_KEY_TYPE, role="", members=[],
      condition_expr="", file=file, line=line, change_action=change_action,
      source=source, scope="service_account", target=target)
  return _finding(
      "G2_STATIC_SA_KEY", grant, target or "service_account_key",
      "Static SA key resource (`google_service_account_key`) stores raw private "
      "key material in Terraform state. Replace with Workload Identity Federation.",
      "Use `gcp-iam-federation-architect` WIF pool/provider instead of "
      "`google_service_account_key`.")


class Coverage:
  """Accumulates the Coverage section (what was and was not evaluated)."""

  def __init__(self, input_mode: str):
    self.input_mode = input_mode
    self.files: List[str] = []
    self.resources_seen = 0
    self.resources_parsed = 0
    self.resources_non_iam = 0
    self.grants_evaluated = 0
    self.resources_unchanged = 0
    self.skipped: List[Dict[str, str]] = []
    self.partial: List[Dict[str, str]] = []
    self.warnings: List[str] = []
    self.errors: List[str] = []

  def skip(self, resource: str, file: str, reason: str) -> None:
    """Records a resource that could not be evaluated."""
    LOGGER.debug("Skipped %s (%s): %s", resource, file, reason)
    self.skipped.append({"resource": resource, "file": file, "reason": reason})

  def partially(self, resource: str, file: str, reason: str) -> None:
    """Records a resource that was evaluated only for its literal values."""
    self.partial.append({"resource": resource, "file": file, "reason": reason})

  def to_dict(self) -> Dict[str, Any]:
    """Serializes the coverage record for JSON/Markdown/SARIF."""
    reasons: Dict[str, int] = {}
    for s in self.skipped:
      reasons[s["reason"]] = reasons.get(s["reason"], 0) + 1
    warnings = list(self.warnings)
    if self.input_mode == INPUT_MODE_REGEX and REGEX_MODE_WARNING not in warnings:
      warnings.insert(0, REGEX_MODE_WARNING)
    return {
        "input_mode": self.input_mode,
        "files_scanned": len(self.files),
        "files": self.files,
        "resources_seen": self.resources_seen,
        "resources_parsed": self.resources_parsed,
        "resources_non_iam_ignored": self.resources_non_iam,
        "resources_unchanged_not_evaluated": self.resources_unchanged,
        "grants_evaluated": self.grants_evaluated,
        "resources_skipped_count": len(self.skipped),
        "resources_skipped": self.skipped,
        "skip_reasons": reasons,
        "resources_partially_evaluated": self.partial,
        "warnings": warnings,
        "errors": self.errors,
    }


# =============================================================================
# Plan JSON mode
# =============================================================================


def _condition_expression(attrs: Dict[str, Any]) -> str:
  """Returns the condition expression from plan attrs (blocks are lists)."""
  cond = attrs.get("condition")
  if isinstance(cond, list) and cond:
    cond = cond[0]
  if isinstance(cond, dict):
    return str(cond.get("expression") or "")
  return ""


def _is_unknown(unknown: Any, key: str) -> bool:
  """True when `after_unknown` marks the attribute (or any element) computed."""
  if not isinstance(unknown, dict):
    return False
  val = unknown.get(key)
  if val is True:
    return True
  if isinstance(val, list):
    return any(v is True for v in val)
  return False


def grant_tuples_from_attrs(
    res_type: str, attrs: Optional[Dict[str, Any]], unknown: Any = None
) -> Tuple[Set[Tuple[str, str, str]], List[str]]:
  """Expands one IAM resource's attributes into (role, member, condition) tuples.

  Args:
    res_type: Terraform resource type (google_*_iam_member/binding/policy).
    attrs: `change.after` / `change.before` / planned `values` dict.
    unknown: `change.after_unknown` dict, if any.

  Returns:
    (tuples, issues) where issues explains values that could not be resolved.
  """
  tuples: Set[Tuple[str, str, str]] = set()
  issues: List[str] = []
  if not isinstance(attrs, dict):
    return tuples, issues
  kind = IAM_GRANT_TYPE_RE.match(res_type).group(2)

  if kind in ("member", "binding"):
    role = attrs.get("role")
    if not role:
      issues.append("role is computed/unknown until apply" if _is_unknown(unknown, "role")
                    else "role attribute missing")
      return tuples, issues
    expr = _condition_expression(attrs)
    if kind == "member":
      member = attrs.get("member")
      if not member:
        issues.append("member is computed/unknown until apply"
                      if _is_unknown(unknown, "member") else "member attribute missing")
      else:
        tuples.add((str(role), str(member), expr))
    else:
      members = attrs.get("members")
      if _is_unknown(unknown, "members"):
        issues.append("one or more members are computed/unknown until apply")
      for member in members or []:
        if isinstance(member, str) and member:
          tuples.add((str(role), member, expr))
      if not members and not issues:
        issues.append("members list empty or missing")
    return tuples, issues

  # kind == "policy": authoritative policy document in policy_data (JSON string).
  raw = attrs.get("policy_data")
  if not raw:
    issues.append("policy_data is computed/unknown until apply"
                  if _is_unknown(unknown, "policy_data") else "policy_data missing")
    return tuples, issues
  try:
    doc = json.loads(raw) if isinstance(raw, str) else raw
  except json.JSONDecodeError as exc:
    issues.append(f"policy_data is not valid JSON ({exc.msg})")
    return tuples, issues
  for binding in (doc or {}).get("bindings") or []:
    role = binding.get("role")
    cond = binding.get("condition") or {}
    expr = str(cond.get("expression") or "") if isinstance(cond, dict) else ""
    for member in binding.get("members") or []:
      if role and member:
        tuples.add((str(role), str(member), expr))
  return tuples, issues


def _iter_planned_resources(module: Dict[str, Any]) -> Iterable[Dict[str, Any]]:
  """Recursively yields resources from a planned_values/values module tree."""
  for res in module.get("resources") or []:
    yield res
  for child in module.get("child_modules") or []:
    yield from _iter_planned_resources(child)


def _plan_line_index(raw_text: str) -> Dict[str, int]:
  """Maps resource addresses to the line where they first appear in the plan."""
  index: Dict[str, int] = {}
  for m in re.finditer(r'"address"\s*:\s*"((?:[^"\\]|\\.)*)"', raw_text):
    addr = m.group(1).replace('\\"', '"')
    index.setdefault(addr, _line_number_at(raw_text, m.start()))
  return index


def _normalize_action(actions: List[str]) -> str:
  """Collapses Terraform change actions into create/update/replace/delete/no-op/read."""
  acts = [str(a) for a in actions or []]
  if "create" in acts and "delete" in acts:
    return "replace"
  if acts == ["delete"]:
    return "delete"
  if acts == ["create"]:
    return "create"
  if acts == ["update"]:
    return "update"
  if acts in (["no-op"], ["read"]):
    return acts[0]
  return "+".join(acts) or "unknown"


def scan_plan_json(
    plan_path: Path,
    now: datetime,
    max_expiry_days: int,
    include_unchanged: bool,
    coverage: Coverage,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
  """Evaluates IAM grants in a `terraform show -json` document.

  Args:
    plan_path: Path to the JSON file.
    now: Scan time (UTC).
    max_expiry_days: G5 long-lived threshold.
    include_unchanged: Also evaluate `no-op` (already-applied) grants.
    coverage: Coverage accumulator.

  Returns:
    (violations, removed_grants) — removed grants are informational only.

  Raises:
    ValueError: If the file is not a Terraform JSON plan/state document.
  """
  raw_text = plan_path.read_text(encoding="utf-8", errors="replace")
  try:
    doc = json.loads(raw_text)
  except json.JSONDecodeError as exc:
    raise ValueError(
        f"{plan_path} is not JSON ({exc.msg} at line {exc.lineno}). Pass the "
        "output of `terraform show -json <planfile>`, not the binary planfile."
    ) from exc
  if not isinstance(doc, dict):
    raise ValueError(f"{plan_path} does not contain a Terraform JSON object.")

  file_label = plan_path.name
  coverage.files.append(file_label)
  line_index = _plan_line_index(raw_text)
  findings: List[Dict[str, Any]] = []
  removed: List[Dict[str, Any]] = []

  # Build a uniform list of (address, type, mode, action, before, after, unknown).
  entries: List[Tuple[str, str, str, str, Any, Any, Any]] = []
  if isinstance(doc.get("resource_changes"), list):
    for rc in doc["resource_changes"]:
      change = rc.get("change") or {}
      entries.append((
          str(rc.get("address", "")), str(rc.get("type", "")),
          str(rc.get("mode", "managed")), _normalize_action(change.get("actions")),
          change.get("before"), change.get("after"), change.get("after_unknown"),
      ))
  else:
    # No change set (e.g. `terraform show -json` of state): walk the module tree.
    root = ((doc.get("planned_values") or {}).get("root_module")
            or (doc.get("values") or {}).get("root_module"))
    if root is None:
      raise ValueError(
          f"{plan_path} has neither resource_changes nor planned_values/values; "
          "it does not look like `terraform show -json` output.")
    coverage.warnings.append(
        "Plan JSON has no resource_changes; evaluated planned/state values as "
        "if every grant were new (change actions unavailable).")
    for res in _iter_planned_resources(root):
      entries.append((
          str(res.get("address", "")), str(res.get("type", "")),
          str(res.get("mode", "managed")), "unknown", None, res.get("values"), None,
      ))

  for address, res_type, mode, action, before, after, unknown in entries:
    coverage.resources_seen += 1
    line = line_index.get(address, 1)
    if mode != "managed":
      coverage.resources_non_iam += 1  # data sources are resolved into consumers
      continue

    if res_type == SA_KEY_TYPE:
      coverage.resources_parsed += 1
      if action in ("create", "replace", "unknown") or (
          include_unchanged and action == "no-op"):
        target = str((after or {}).get("service_account_id") or "")
        findings.append(_sa_key_finding(address, file_label, line, action,
                                        INPUT_MODE_PLAN, target))
      elif action == "no-op":
        coverage.resources_unchanged += 1
      continue

    if IAM_NON_GRANT_TYPE_RE.match(res_type):
      coverage.resources_non_iam += 1
      continue
    gm = IAM_GRANT_TYPE_RE.match(res_type)
    if not gm:
      coverage.resources_non_iam += 1
      continue

    scope = SCOPE_BY_PREFIX[gm.group(1)]
    target_attr = TARGET_ATTR_BY_SCOPE[scope]

    if action == "delete":
      old, _ = grant_tuples_from_attrs(res_type, before)
      for role, member, _expr in sorted(old):
        removed.append({"resource": address, "role": role, "principal": member})
      coverage.skip(address, file_label, "deleted in plan (not a new grant)")
      continue
    if action == "no-op" and not include_unchanged:
      coverage.resources_unchanged += 1
      continue
    if action == "read":
      coverage.resources_non_iam += 1
      continue

    new, issues = grant_tuples_from_attrs(res_type, after, unknown)
    if action == "update":
      old, _ = grant_tuples_from_attrs(res_type, before)
      for role, member, _expr in sorted(old - new):
        removed.append({"resource": address, "role": role, "principal": member})
      new = new - old  # only additions are new grants
    if issues and not new:
      coverage.skip(address, file_label, "; ".join(issues))
      continue
    if issues:
      coverage.partially(address, file_label, "; ".join(issues))

    coverage.resources_parsed += 1
    target = str((after or {}).get(target_attr) or "")
    # Group by (role, condition) so each finding carries the right expression.
    grouped: Dict[Tuple[str, str], List[str]] = {}
    for role, member, expr in sorted(new):
      grouped.setdefault((role, expr), []).append(member)
    for (role, expr), members in grouped.items():
      coverage.grants_evaluated += len(members)
      grant = _make_grant(
          address=address, res_type=res_type, role=role, members=members,
          condition_expr=expr, file=file_label, line=line,
          change_action=action, source=INPUT_MODE_PLAN, scope=scope,
          target=target)
      findings.extend(evaluate_grant(grant, now, max_expiry_days))
  return findings, removed


# =============================================================================
# Regex / HCL fallback mode
# =============================================================================


def _strip_comments(text: str) -> str:
  """Blanks out HCL comments and heredoc bodies, preserving offsets/newlines.

  String literals are kept intact so attribute values remain extractable.
  """
  out = list(text)
  i, n = 0, len(text)

  def blank(a: int, b: int) -> None:
    for k in range(a, min(b, n)):
      if out[k] != "\n":
        out[k] = " "

  while i < n:
    ch = text[i]
    if ch == '"':
      j = i + 1
      while j < n and text[j] != '"':
        j += 2 if text[j] == "\\" else 1
      i = j + 1
    elif ch == "#" or text.startswith("//", i):
      j = text.find("\n", i)
      j = n if j < 0 else j
      blank(i, j)
      i = j
    elif text.startswith("/*", i):
      j = text.find("*/", i + 2)
      j = n if j < 0 else j + 2
      blank(i, j)
      i = j
    elif text.startswith("<<", i):
      m = re.match(r"<<-?([A-Za-z_][A-Za-z0-9_]*)[^\n]*\n", text[i:])
      if not m:
        i += 2
        continue
      ident = m.group(1)
      body_start = i + m.end()
      end_m = re.compile(r"(?m)^[ \t]*" + re.escape(ident) + r"[ \t]*$").search(
          text, body_start)
      j = end_m.end() if end_m else n
      # Keep a placeholder so attributes still "exist" but carry no literal.
      blank(body_start, j)
      i = j
    else:
      i += 1
  return "".join(out)


def _match_brace(text: str, open_idx: int, open_ch: str = "{",
                 close_ch: str = "}") -> int:
  """Returns the index of the bracket closing `text[open_idx]`, or -1."""
  depth, i, n = 0, open_idx, len(text)
  while i < n:
    ch = text[i]
    if ch == '"':
      j = i + 1
      while j < n and text[j] != '"':
        j += 2 if text[j] == "\\" else 1
      i = j + 1
      continue
    if ch == open_ch:
      depth += 1
    elif ch == close_ch:
      depth -= 1
      if depth == 0:
        return i
    i += 1
  return -1


def _unescape_hcl(value: str) -> str:
  """Unescapes the common HCL string escapes (\\" and \\\\)."""
  return value.replace('\\"', '"').replace("\\\\", "\\")


def _top_level_attr(body: str, name: str) -> Optional[str]:
  """Returns the raw right-hand side of `name = ...` at body nesting depth 0."""
  depth = 0
  i, n = 0, len(body)
  pattern = re.compile(r"[ \t]*" + re.escape(name) + r"\s*=\s*")
  at_line_start = True
  while i < n:
    ch = body[i]
    if at_line_start and depth == 0:
      m = pattern.match(body, i)
      if m:
        start = m.end()
        if start < n and body[start] == "[":
          end = _match_brace(body, start, "[", "]")
          return body[start:end + 1] if end >= 0 else body[start:]
        end = body.find("\n", start)
        return body[start:end if end >= 0 else n].strip()
    at_line_start = ch == "\n"
    if ch == '"':
      j = i + 1
      while j < n and body[j] != '"':
        j += 2 if body[j] == "\\" else 1
      i = j + 1
      at_line_start = False
      continue
    if ch in "{[(":
      depth += 1
    elif ch in "}])":
      depth -= 1
    i += 1
  return None


def _literal_string(raw: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
  """Parses a raw RHS as a pure string literal.

  Returns:
    (value, problem) — exactly one is non-None when raw is present.
  """
  if raw is None:
    return None, "attribute missing"
  m = STRING_LITERAL_RE.fullmatch(raw.strip())
  if not m:
    return None, f"value is an expression (`{raw.strip()[:60]}`)"
  value = _unescape_hcl(m.group(1))
  if "${" in value:
    return None, f"value uses interpolation (`{value[:60]}`)"
  return value, None


def _literal_list(raw: Optional[str]) -> Tuple[List[str], List[str]]:
  """Parses `[ "a", "b", var.c ]` into literal members plus unresolved items."""
  if raw is None:
    return [], ["attribute missing"]
  raw = raw.strip()
  if not raw.startswith("["):
    return [], [f"list is an expression (`{raw[:60]}`)"]
  inner = raw[1:-1] if raw.endswith("]") else raw[1:]
  values: List[str] = []
  problems: List[str] = []
  for m in STRING_LITERAL_RE.finditer(inner):
    value = _unescape_hcl(m.group(1))
    if "${" in value:
      problems.append(f"interpolated member `{value[:60]}`")
    else:
      values.append(value)
  leftovers = [t.strip() for t in STRING_LITERAL_RE.sub("", inner).split(",")]
  for token in leftovers:
    if token:
      problems.append(f"non-literal member `{token[:60]}`")
  return values, problems


def _condition_expr_from_body(clean_body: str) -> str:
  """Returns the literal `expression` inside the first `condition { }` block."""
  m = CONDITION_BLOCK_RE.search(clean_body)
  if not m:
    return ""
  end = _match_brace(clean_body, m.end() - 1)
  block = clean_body[m.end():end if end >= 0 else len(clean_body)]
  value, _ = _literal_string(_top_level_attr(block, "expression"))
  return value or ""


def _iter_blocks(clean: str, header_re: "re.Pattern[str]", start: int = 0,
                 end: Optional[int] = None):
  """Yields (match, body_start, body_end) for brace-delimited blocks."""
  end = len(clean) if end is None else end
  for m in header_re.finditer(clean, start, end):
    close = _match_brace(clean, m.end() - 1)
    yield m, m.end(), (close if close >= 0 else -1)


def scan_terraform_file(
    tf_file: Path,
    base_dir: Path,
    now: Optional[datetime] = None,
    max_expiry_days: int = DEFAULT_MAX_EXPIRY_DAYS,
    coverage: Optional[Coverage] = None,
    policy_doc_scopes: Optional[Dict[str, str]] = None,
) -> List[Dict[str, Any]]:
  """Scans a single `.tf` file (regex/HCL fallback) for G1-G6 violations.

  Args:
    tf_file: File to scan.
    base_dir: Base directory used for relative paths in findings.
    now: Scan time (UTC); defaults to the current time.
    max_expiry_days: G5 long-lived threshold.
    coverage: Coverage accumulator (a throwaway one is used if omitted).
    policy_doc_scopes: {data.google_iam_policy name: scope} gathered across
      files so policy documents inherit the scope of their consumer.

  Returns:
    List of violation dicts.
  """
  now = now or datetime.now(timezone.utc)
  coverage = coverage or Coverage(INPUT_MODE_REGEX)
  policy_doc_scopes = policy_doc_scopes or {}
  rel_path = (
      str(tf_file.relative_to(base_dir))
      if tf_file.is_relative_to(base_dir)
      else tf_file.name
  )
  try:
    text = tf_file.read_text(encoding="utf-8", errors="replace")
  except OSError as exc:
    LOGGER.error("Cannot read %s: %s", tf_file, exc)
    coverage.errors.append(f"{rel_path}: unreadable ({exc})")
    return []
  clean = _strip_comments(text)
  coverage.files.append(rel_path)
  findings: List[Dict[str, Any]] = []

  # Module calls cannot be expanded without Terraform; record them explicitly.
  for m in MODULE_HEADER_RE.finditer(clean):
    coverage.skip(f"module.{m.group(1)}", rel_path,
                  "module call not expanded in regex mode (use --plan-json)")

  for m, body_start, body_end in _iter_blocks(clean, RESOURCE_HEADER_RE):
    block_kind, res_type, res_name = m.group(1), m.group(2), m.group(3)
    address = (f"{res_type}.{res_name}" if block_kind == "resource"
               else f"data.{res_type}.{res_name}")
    line_no = _line_number_at(text, m.start())
    coverage.resources_seen += 1
    if body_end < 0:
      coverage.skip(address, rel_path, "unbalanced braces; block not parsed")
      continue
    body = clean[body_start:body_end]
    expanded = bool(EXPANSION_RE.search(body))

    if block_kind == "data":
      if res_type != IAM_POLICY_DATA_TYPE:
        coverage.resources_non_iam += 1
        continue
      scope = policy_doc_scopes.get(res_name, "policy_document")
      coverage.resources_parsed += 1
      for bm, b_start, b_end in _iter_blocks(body, BINDING_BLOCK_RE):
        if b_end < 0:
          coverage.skip(address, rel_path, "unbalanced binding block")
          continue
        bbody = body[b_start:b_end]
        b_line = _line_number_at(text, body_start + bm.start())
        role, role_problem = _literal_string(_top_level_attr(bbody, "role"))
        members, member_problems = _literal_list(_top_level_attr(bbody, "members"))
        if role_problem or not members:
          coverage.skip(f"{address} (binding @L{b_line})", rel_path,
                        f"role: {role_problem}" if role_problem
                        else "members: " + "; ".join(member_problems or ["empty"]))
          continue
        if member_problems:
          coverage.partially(address, rel_path, "; ".join(member_problems))
        coverage.grants_evaluated += len(members)
        grant = _make_grant(
            address=address, res_type=res_type, role=role, members=members,
            condition_expr=_condition_expr_from_body(bbody), file=rel_path,
            line=b_line, change_action="unknown", source=INPUT_MODE_REGEX,
            scope=scope)
        findings.extend(evaluate_grant(grant, now, max_expiry_days))
      continue

    if res_type == SA_KEY_TYPE:
      coverage.resources_parsed += 1
      target, _ = _literal_string(_top_level_attr(body, "service_account_id"))
      findings.append(_sa_key_finding(address, rel_path, line_no, "unknown",
                                      INPUT_MODE_REGEX, target or ""))
      continue

    if IAM_NON_GRANT_TYPE_RE.match(res_type):
      coverage.resources_non_iam += 1
      continue
    gm = IAM_GRANT_TYPE_RE.match(res_type)
    if not gm:
      coverage.resources_non_iam += 1
      continue
    scope = SCOPE_BY_PREFIX[gm.group(1)]
    kind = gm.group(2)
    target, _ = _literal_string(_top_level_attr(body, TARGET_ATTR_BY_SCOPE[scope]))

    if kind == "policy":
      ref = POLICY_DATA_REF_RE.search(_top_level_attr(body, "policy_data") or "")
      if ref:
        # Evaluated via the referenced data "google_iam_policy" block.
        coverage.resources_parsed += 1
      else:
        coverage.skip(address, rel_path,
                      "policy_data is not a data.google_iam_policy reference "
                      "(use --plan-json)")
      continue

    role, role_problem = _literal_string(_top_level_attr(body, "role"))
    if kind == "member":
      member, member_problem = _literal_string(_top_level_attr(body, "member"))
      members = [member] if member else []
      member_problems = [member_problem] if member_problem else []
    else:
      members, member_problems = _literal_list(_top_level_attr(body, "members"))

    if role_problem or not members:
      reason = (f"role {role_problem}" if role_problem
                else "member(s) " + "; ".join(member_problems or ["empty"]))
      if expanded:
        reason += " [for_each/count/dynamic not expanded in regex mode]"
      coverage.skip(address, rel_path, reason)
      continue
    if member_problems:
      coverage.partially(address, rel_path, "; ".join(member_problems))
    if expanded:
      coverage.partially(address, rel_path,
                         "for_each/count/dynamic present; evaluated literal "
                         "values only (instances not expanded)")

    coverage.resources_parsed += 1
    coverage.grants_evaluated += len(members)
    grant = _make_grant(
        address=address, res_type=res_type, role=role, members=members,
        condition_expr=_condition_expr_from_body(body), file=rel_path,
        line=line_no, change_action="unknown", source=INPUT_MODE_REGEX,
        scope=scope, target=target or "")
    findings.extend(evaluate_grant(grant, now, max_expiry_days))

  return findings


def _collect_policy_doc_scopes(tf_files: List[Path]) -> Dict[str, str]:
  """Maps data.google_iam_policy names to the scope of the resource using them."""
  scopes: Dict[str, str] = {}
  for tf_file in tf_files:
    try:
      clean = _strip_comments(tf_file.read_text(encoding="utf-8", errors="replace"))
    except OSError:
      continue
    for m, b_start, b_end in _iter_blocks(clean, RESOURCE_HEADER_RE):
      gm = IAM_GRANT_TYPE_RE.match(m.group(2))
      if m.group(1) != "resource" or not gm or gm.group(2) != "policy" or b_end < 0:
        continue
      for ref in POLICY_DATA_REF_RE.finditer(clean[b_start:b_end]):
        scopes[ref.group(1)] = SCOPE_BY_PREFIX[gm.group(1)]
  return scopes


# =============================================================================
# Report builders
# =============================================================================


def _sarif_level(severity: str) -> str:
  """Maps ScopeGuard severity to SARIF result level."""
  if severity in ("CRITICAL", "HIGH"):
    return "error"
  if severity == "MEDIUM":
    return "warning"
  return "note"


_SECURITY_SEVERITY = {"CRITICAL": "9.5", "HIGH": "8.0", "MEDIUM": "5.5", "LOW": "3.0"}


def build_sarif(findings: List[Dict[str, Any]], coverage: Dict[str, Any],
                started: datetime, finished: datetime) -> Dict[str, Any]:
  """Builds a SARIF 2.1.0 document with rule metadata and coverage properties."""
  rule_ids = list(RULES)
  rules = [
      {
          "id": rid,
          "name": meta["name"],
          "shortDescription": {"text": meta["short"]},
          "fullDescription": {"text": meta["full"]},
          "help": {"text": meta["help"]},
          "defaultConfiguration": {"level": _sarif_level(meta["severity"])},
          "properties": {
              "tags": ["security", "iam", "terraform"],
              "severity": meta["severity"],
              "security-severity": _SECURITY_SEVERITY[meta["severity"]],
          },
      }
      for rid, meta in RULES.items()
  ]
  results = []
  for f in findings:
    fingerprint = hashlib.sha256(
        "|".join([f["rule_id"], f["resource"], f["role"], f["principal"]]).encode()
    ).hexdigest()
    results.append({
        "ruleId": f["rule_id"],
        "ruleIndex": rule_ids.index(f["rule_id"]),
        "level": _sarif_level(f["severity"]),
        "message": {"text": f["message"]},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": f["file"]},
                "region": {"startLine": max(1, int(f["line"]))},
            },
            "logicalLocations": [
                {"fullyQualifiedName": f["resource"], "kind": "resource"}
            ],
        }],
        "partialFingerprints": {"scopeguardFinding/v1": fingerprint},
        "properties": {
            "severity": f["severity"],
            "principal": f["principal"],
            "role": f["role"],
            "scope": f.get("scope", ""),
            "change_action": f.get("change_action", ""),
            "input_source": f.get("input_source", ""),
            "remediation": f["remediation"],
        },
    })
  return {
      "$schema": SARIF_SCHEMA_URI,
      "version": "2.1.0",
      "runs": [{
          "tool": {
              "driver": {
                  "name": TOOL_NAME,
                  "version": TOOL_VERSION,
                  "informationUri": "https://cloud.google.com/iam/docs/using-iam-securely",
                  "rules": rules,
              }
          },
          "invocations": [{
              "executionSuccessful": not coverage.get("errors"),
              "startTimeUtc": _utc_iso(started),
              "endTimeUtc": _utc_iso(finished),
          }],
          "results": results,
          "properties": {
              "schema_version": SCHEMA_VERSION,
              "coverage": coverage,
          },
      }],
  }


def _md_escape(value: Any) -> str:
  """Escapes pipe characters for Markdown table cells."""
  return str(value).replace("|", "\\|").replace("\n", " ")


def build_markdown_report(project_id: str, summary: Dict[str, Any],
                          findings: List[Dict[str, Any]],
                          coverage: Dict[str, Any],
                          removed: List[Dict[str, Any]]) -> str:
  """Renders the human-readable PR gate report including the Coverage section."""
  lines = [
      f"# ScopeGuard GitOps IAM Guardrail — `{project_id}`",
      "",
      f"- **Verdict:** `{summary['pr_gate_verdict']}`",
      f"- **Generated:** {summary['generated_at']}",
      f"- **Input mode:** `{coverage['input_mode']}`",
      f"- **Violations:** {summary['total_violations']} "
      f"({summary['critical_count']} CRITICAL, {summary['high_count']} HIGH, "
      f"{summary['medium_count']} MEDIUM, {summary['low_count']} LOW)",
      "",
      "## Violations",
      "",
  ]
  if findings:
    lines += ["| Rule | Severity | Location | Resource | Role → Principal | Action | Remediation |",
              "| :--- | :---: | :--- | :--- | :--- | :---: | :--- |"]
    for f in findings:
      lines.append(
          f"| `{f['rule_id']}` | **{f['severity']}** | `{_md_escape(f['file'])}:{f['line']}` "
          f"| `{_md_escape(f['resource'])}` | `{_md_escape(f['role'])}` → "
          f"`{_md_escape(f['principal'])}` | {f.get('change_action', '')} "
          f"| {_md_escape(f['remediation'])} |")
  else:
    lines.append("_No violations among the evaluated grants._")
  if removed:
    lines += ["", "## Grants removed by this change (informational)", "",
              "| Resource | Role | Principal |", "| :--- | :--- | :--- |"]
    for r in removed:
      lines.append(f"| `{_md_escape(r['resource'])}` | `{_md_escape(r['role'])}` "
                   f"| `{_md_escape(r['principal'])}` |")

  lines += [
      "", "## Coverage", "",
      f"- **Input mode:** `{coverage['input_mode']}`",
      f"- **Files scanned:** {coverage['files_scanned']}",
      f"- **Resources seen:** {coverage['resources_seen']}",
      f"- **IAM resources parsed:** {coverage['resources_parsed']}",
      f"- **Grants (role × member) evaluated:** {coverage['grants_evaluated']}",
      f"- **Non-IAM resources ignored:** {coverage['resources_non_iam_ignored']}",
      f"- **Unchanged grants not evaluated:** "
      f"{coverage['resources_unchanged_not_evaluated']}",
      f"- **Resources skipped:** {coverage['resources_skipped_count']}",
  ]
  for warning in coverage["warnings"]:
    lines += ["", f"> [!WARNING]\n> {warning}"]
  if coverage["resources_skipped"]:
    lines += ["", "### Skipped resources", "", "| Resource | File | Reason |",
              "| :--- | :--- | :--- |"]
    for s in coverage["resources_skipped"]:
      lines.append(f"| `{_md_escape(s['resource'])}` | `{_md_escape(s['file'])}` "
                   f"| {_md_escape(s['reason'])} |")
  if coverage["resources_partially_evaluated"]:
    lines += ["", "### Partially evaluated resources", "",
              "| Resource | File | Reason |", "| :--- | :--- | :--- |"]
    for s in coverage["resources_partially_evaluated"]:
      lines.append(f"| `{_md_escape(s['resource'])}` | `{_md_escape(s['file'])}` "
                   f"| {_md_escape(s['reason'])} |")
  if coverage["errors"]:
    lines += ["", "### Errors", ""] + [f"- {e}" for e in coverage["errors"]]
  return "\n".join(lines) + "\n"


def _patch_block(idx: int, f: Dict[str, Any], project_id: str) -> str:
  """Renders one scope-aware least-privilege replacement HCL block."""
  rid = f["rule_id"]
  member = f.get("principal") or "serviceAccount:WORKLOAD_SA"
  loc = f"{f['file']}:{f['line']} ({f['resource']})"
  scope = f.get("scope", "project")
  if rid == "G1_BASIC_ROLE_BLOCKED":
    if scope == "folder":
      head = (f'resource "google_folder_iam_member" "scopeguard_lp_fix_{idx}" {{\n'
              f'  folder = "{f.get("target") or "folders/FOLDER_ID"}"\n'
              '  role   = "organizations/ORG_ID/roles/customLeastPrivilegeRole"\n'
              f'  member = "{member}"\n')
    elif scope == "organization":
      head = (f'resource "google_organization_iam_member" "scopeguard_lp_fix_{idx}" {{\n'
              f'  org_id = "{f.get("target") or "ORG_ID"}"\n'
              '  role   = "organizations/ORG_ID/roles/customLeastPrivilegeRole"\n'
              f'  member = "{member}"\n')
    else:
      head = (f'resource "google_project_iam_member" "scopeguard_lp_fix_{idx}" {{\n'
              f'  project = "{project_id}"\n'
              f'  role    = "projects/{project_id}/roles/customLeastPrivilegeRole"\n'
              f'  member  = "{member}"\n')
    return f"# Fix #{idx} ({loc}) — Replaces basic role `{f['role']}`\n{head}}}\n"
  if rid == "G3_TRANSITIVE_ESCALATION_EDGE":
    return (
        f"# Fix #{idx} ({loc}) — Scopes `{f['role']}` to target runtime SA (never {scope}-wide)\n"
        f'resource "google_service_account_iam_member" "scopeguard_sa_scoped_{idx}" {{\n'
        f'  service_account_id = "projects/{project_id}/serviceAccounts/TARGET_RUNTIME_SA@{project_id}.iam.gserviceaccount.com"\n'
        f'  role               = "{f["role"]}"\n'
        f'  member             = "{member}"\n'
        "}\n")
  if rid == "G4_UNSCOPED_PROJECT_DATA_ROLE":
    return (
        f"# Fix #{idx} ({loc}) — Moves `{f['role']}` from {scope.capitalize()} scope to a specific Secret resource\n"
        f'resource "google_secret_manager_secret_iam_member" "scopeguard_secret_scoped_{idx}" {{\n'
        f'  project   = "{project_id}"\n'
        '  secret_id = "TARGET_SECRET_ID"\n'
        '  role      = "roles/secretmanager.secretAccessor"\n'
        f'  member    = "{member}"\n'
        "}\n")
  return f"# Fix #{idx} ({loc}): {f['remediation']}\n"


def build_pr_comment_markdown(
    project_id: str,
    summary: Dict[str, Any],
    findings: List[Dict[str, Any]],
    coverage: Dict[str, Any],
    error: str = "",
) -> str:
  """Renders a concise, PR-comment-ready Markdown summary with HCL snippets.

  Args:
    project_id: Target GCP project ID.
    summary: Guardrail summary dict containing `pr_gate_verdict` and counts.
    findings: Sorted list of violation dicts.
    coverage: Coverage dict from `Coverage.to_dict()`.
    error: Optional scan error message when verdict is `SCAN_ERROR`.

  Returns:
    Compact Markdown suitable for posting directly as a GitHub/GitLab PR comment.
  """
  verdict = str(summary.get("pr_gate_verdict", "APPROVE_CLEAN"))
  badges = {
      "BLOCK_MERGE": "🔴 **BLOCK_MERGE**",
      "APPROVE_CLEAN": "🟢 **APPROVE_CLEAN**",
      "SCAN_ERROR": "🟠 **SCAN_ERROR**",
  }
  badge = badges.get(verdict, f"`{verdict}`")
  lines = [
      f"## ScopeGuard IAM PR Guardrail — {badge}",
      "",
      f"**Project:** `{project_id}` · **Input:** `{coverage.get('input_mode', 'unknown')}` · "
      f"**Violations:** `{summary.get('total_violations', 0)}` "
      f"(`{summary.get('critical_count', 0)}` CRITICAL, `{summary.get('high_count', 0)}` HIGH, "
      f"`{summary.get('medium_count', 0)}` MEDIUM, `{summary.get('low_count', 0)}` LOW)",
      "",
  ]
  if verdict == "SCAN_ERROR":
    lines.extend([
        "> [!CAUTION]",
        f"> **Scan Error:** {error or 'Unable to evaluate Terraform input.'}",
        "> Pass valid `terraform show -json <planfile>` output to `--plan-json` and re-run.",
        "",
    ])
  elif findings:
    lines.extend([
        "| Rule | Severity | Location | Terraform Resource | Risk |",
        "| :--- | :---: | :--- | :--- | :--- |",
    ])
    for f in findings:
      lines.append(
          f"| `{f['rule_id']}` | **{f['severity']}** | `{_md_escape(f['file'])}:{f['line']}` "
          f"| `{_md_escape(f['resource'])}` | {_md_escape(f['message'])} |"
      )
    hcl_blocks = "\n".join(
        _patch_block(i, f, project_id).rstrip() for i, f in enumerate(findings, start=1)
    )
    lines.extend(["", "### Copy-Pasteable Least-Privilege HCL Fix", ""])
    if len(findings) > 10:
      lines.extend([
          f"<details><summary>Show least-privilege HCL patches ({len(findings)} findings)</summary>",
          "",
          "```hcl",
          hcl_blocks,
          "```",
          "",
          "</details>",
          "",
      ])
    else:
      lines.extend(["```hcl", hcl_blocks, "```", ""])
  else:
    lines.extend([
        "_No IAM governance violations detected across the evaluated Terraform grants._",
        "",
    ])

  skipped = int(coverage.get("resources_skipped_count") or 0)
  lines.append(
      f"_Coverage: {coverage.get('files_scanned', 0)} file(s), "
      f"{coverage.get('resources_parsed', 0)} IAM resource(s) parsed, "
      f"{skipped} skipped._"
  )
  return "\n".join(lines) + "\n"


def compute_ci_exit_code(mod_entry: Dict[str, Any], fail_on: str = "NONE") -> int:
  """Computes the CLI exit code for Shift-Left CI gating.

  When `fail_on` is `NONE` (default), violations return `0` so existing
  orchestrator/test callers remain non-fatal; unreadable plans still return `2`.
  When `fail_on` is set to a threshold (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`,
  or `ANY`):
    * `3` — verdict is `SCAN_ERROR` (or module status is `FAILED`).
    * `2` — at least one violation meets or exceeds the `fail_on` severity
            threshold (or `ANY` with >= 1 violation).
    * `0` — clean / below threshold.

  Args:
    mod_entry: Return value of `run_gitops_guardrail`.
    fail_on: Threshold string from `FAIL_ON_CHOICES`.

  Returns:
    Process exit code (`0`, `2`, or `3`).
  """
  threshold = (fail_on or "NONE").strip().upper()
  verdict = str((mod_entry.get("summary") or {}).get("pr_gate_verdict", "")).upper()
  is_scan_error = (
      str(mod_entry.get("status", "")).upper() == "FAILED"
      or verdict == "SCAN_ERROR"
  )
  if threshold == "NONE":
    return 2 if is_scan_error else 0
  if is_scan_error:
    return 3
  violations = (mod_entry.get("payload") or {}).get("violations") or []
  if threshold == "ANY":
    return 2 if violations else 0
  min_rank = SEVERITY_RANK.get(threshold, 99)
  for v in violations:
    if SEVERITY_RANK.get(str(v.get("severity", "")).upper(), 0) >= min_rank:
      return 2
  return 0


def _ci_workflow(project_id: str) -> str:
  """Renders the GitHub Actions workflow (plan mode with regex fallback)."""
  script = "plugins/scopeguard/skills/gcp-iam-gitops-pr-guardrail/scripts/gitops_guardrail_cli.py"
  return "\n".join([
      "# .github/workflows/scopeguard-iam-guardrail.yml",
      "# Plan mode resolves modules/variables/for_each; it needs terraform init",
      "# credentials. Without them the step falls back to the regex HCL scan.",
      "name: ScopeGuard Shift-Left IAM PR Guardrail",
      "on:",
      "  pull_request:",
      "    paths:",
      '      - "**/*.tf"',
      '      - "**/*.tfvars"',
      "jobs:",
      "  iam-guardrail:",
      "    runs-on: ubuntu-latest",
      "    permissions:",
      "      contents: read",
      "      security-events: write",
      "    steps:",
      "      - uses: actions/checkout@v4",
      "      - uses: hashicorp/setup-terraform@v3",
      "      - name: Terraform plan to JSON (best effort)",
      "        id: plan",
      "        continue-on-error: true",
      "        run: |",
      "          terraform init -input=false",
      "          terraform plan -input=false -lock=false -out=tfplan",
      "          terraform show -json tfplan > plan.json",
      "      - name: Run ScopeGuard GitOps PR Guardrail",
      "        run: |",
      "          PLAN_ARG=\"\"",
      "          if [ -s plan.json ]; then PLAN_ARG=\"--plan-json=plan.json\"; fi",
      f"          python3 {script} \\",
      f"            --project={project_id} --scan-path=. $PLAN_ARG --local-only \\",
      "            --fail-on=HIGH \\",
      "            --pr-comment-md=./guardrail-out/gitops_pr_comment.md \\",
      "            --output-dir=./guardrail-out",
      "      - name: Upload SARIF",
      "        if: always()",
      "        uses: github/codeql-action/upload-sarif@v3",
      "        with:",
      "          sarif_file: guardrail-out/gitops_guardrail.sarif.json",
  ]) + "\n"


# =============================================================================
# Entry points
# =============================================================================


def run_gitops_guardrail(
    project_id: str,
    scan_path: Path,
    output_dir: Optional[Path] = None,
    plan_json: Optional[Path] = None,
    max_expiry_days: int = DEFAULT_MAX_EXPIRY_DAYS,
    include_unchanged: bool = False,
    now: Optional[datetime] = None,
    pr_comment_md: Optional[Path] = None,
) -> Dict[str, Any]:
  """Scans Terraform (plan JSON preferred, HCL fallback) and writes PR artifacts.

  Args:
    project_id: Target GCP project (used in patches/workflow text).
    scan_path: Directory or `.tf` file for the regex fallback.
    output_dir: Where to write artifacts; nothing is written when None.
    plan_json: Optional `terraform show -json` output; enables plan mode.
    max_expiry_days: G5 long-lived condition threshold in days.
    include_unchanged: In plan mode, also evaluate `no-op` grants.
    now: Override for the scan time (tests); defaults to current UTC time.
    pr_comment_md: Optional extra path to write the concise PR-comment Markdown
      (always written to `gitops_pr_comment.md` inside `output_dir` when set).

  Returns:
    Module entry `{summary, payload, status}`. Status is `FAILED` (with the
    error in `payload.error`) when the plan file cannot be used.
  """
  started = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
  if max_expiry_days < 1:
    raise ValueError("max_expiry_days must be >= 1")

  findings: List[Dict[str, Any]] = []
  removed: List[Dict[str, Any]] = []
  status = "COMPLETED"
  error = ""

  if plan_json:
    coverage = Coverage(INPUT_MODE_PLAN)
    try:
      findings, removed = scan_plan_json(
          Path(plan_json), started, max_expiry_days, include_unchanged, coverage)
    except (OSError, ValueError) as exc:
      LOGGER.error("Plan JSON scan failed: %s", exc)
      coverage.errors.append(str(exc))
      status, error = "FAILED", str(exc)
  else:
    coverage = Coverage(INPUT_MODE_REGEX)
    tf_files: List[Path] = []
    if scan_path.is_file() and scan_path.suffix == ".tf":
      tf_files, base_dir = [scan_path], scan_path.parent
    elif scan_path.is_dir():
      base_dir = scan_path
      tf_files = sorted(
          p for p in scan_path.rglob("*.tf")
          if ".terraform" not in p.parts and "scopeguard-output" not in p.parts
      )
    else:
      base_dir = Path.cwd()
      coverage.errors.append(f"scan path not found or not a .tf file: {scan_path}")
      LOGGER.warning("Scan path %s not found; nothing scanned.", scan_path)
    doc_scopes = _collect_policy_doc_scopes(tf_files)
    for tf_file in tf_files:
      findings.extend(scan_terraform_file(
          tf_file, base_dir, started, max_expiry_days, coverage, doc_scopes))

  # Deterministic order: severity, then file/line.
  rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
  findings.sort(key=lambda f: (rank.get(f["severity"], 9), f["file"], f["line"],
                               f["rule_id"], f["principal"]))
  cov = coverage.to_dict()
  finished = datetime.now(timezone.utc) if now is None else started

  counts = {s: sum(1 for f in findings if f["severity"] == s) for s in rank}
  if status == "FAILED":
    verdict = "SCAN_ERROR"
  elif counts["CRITICAL"] or counts["HIGH"]:
    verdict = "BLOCK_MERGE"
  else:
    verdict = "APPROVE_CLEAN"

  remediated_hcl = "\n".join(
      [f"# ScopeGuard Auto-Generated Shift-Left Terraform Remediation Patch — {project_id}",
       "# Replace the blocked HCL blocks in your PR with these least-privilege equivalents:\n"]
      + [_patch_block(i, f, project_id) for i, f in enumerate(findings, start=1)])
  ci_workflow_yaml = _ci_workflow(project_id)
  sarif_doc = build_sarif(findings, cov, started, finished)

  summary = {
      "schema_version": SCHEMA_VERSION,
      "generated_at": _utc_iso(started),
      "input_mode": cov["input_mode"],
      "files_scanned": cov["files_scanned"],
      "resources_parsed": cov["resources_parsed"],
      "resources_skipped": cov["resources_skipped_count"],
      "total_violations": len(findings),
      "critical_count": counts["CRITICAL"],
      "high_count": counts["HIGH"],
      "medium_count": counts["MEDIUM"],
      "low_count": counts["LOW"],
      "pr_gate_verdict": verdict,
      "auto_patch_blocks_generated": len(findings),
      "max_expiry_days": max_expiry_days,
  }
  payload: Dict[str, Any] = {
      "schema_version": SCHEMA_VERSION,
      "generated_at": _utc_iso(started),
      "pr_gate_verdict": verdict,
      "scanned_files": cov["files"],
      "violations": findings,
      "removed_grants": removed,
      "coverage": cov,
      "remediated_hcl": remediated_hcl,
      "ci_workflow_yaml": ci_workflow_yaml,
      "sarif": sarif_doc,
  }
  if error:
    payload["error"] = error

  pr_comment_text = build_pr_comment_markdown(
      project_id, summary, findings, cov, error=error
  )
  payload["pr_comment_md"] = pr_comment_text

  if output_dir:
    try:
      output_dir.mkdir(parents=True, exist_ok=True)
      artifacts = {
          "results_json": "gitops_guardrail_results.json",
          "report_md": "gitops_guardrail_report.md",
          "pr_comment_md": "gitops_pr_comment.md",
          "sarif": "gitops_guardrail.sarif.json",
          "ci_workflow": "scopeguard-iam-guardrail.yml",
          "remediated_patch": "remediated_patch.tf",
      }
      payload["artifacts"] = artifacts
      (output_dir / artifacts["results_json"]).write_text(
          json.dumps({"schema_version": SCHEMA_VERSION, "generated_at": _utc_iso(started),
                      "summary": summary, "payload": payload}, indent=2) + "\n",
          encoding="utf-8")
      (output_dir / artifacts["report_md"]).write_text(
          build_markdown_report(project_id, summary, findings, cov, removed),
          encoding="utf-8")
      (output_dir / artifacts["pr_comment_md"]).write_text(
          pr_comment_text, encoding="utf-8")
      (output_dir / artifacts["sarif"]).write_text(
          json.dumps(sarif_doc, indent=2) + "\n", encoding="utf-8")
      (output_dir / artifacts["ci_workflow"]).write_text(ci_workflow_yaml, encoding="utf-8")
      (output_dir / artifacts["remediated_patch"]).write_text(
          remediated_hcl + "\n", encoding="utf-8")
    except OSError as exc:
      LOGGER.error("Failed writing guardrail artifacts to %s: %s", output_dir, exc)
      raise

  if pr_comment_md:
    try:
      pr_path = Path(pr_comment_md)
      pr_path.parent.mkdir(parents=True, exist_ok=True)
      pr_path.write_text(pr_comment_text, encoding="utf-8")
    except OSError as exc:
      LOGGER.error("Failed writing PR comment Markdown to %s: %s", pr_comment_md, exc)
      raise

  return {"summary": summary, "payload": payload, "status": status}


def main(argv: Optional[List[str]] = None) -> int:
  """CLI entry point with optional Shift-Left CI exit gating (`--fail-on`)."""
  parser = argparse.ArgumentParser(
      description="Scan Terraform plan JSON (preferred) or HCL files for IAM "
                  "governance violations (G1-G6)."
  )
  parser.add_argument("--project", required=True, help="Target GCP Project ID.")
  parser.add_argument(
      "--scan-path", default=".",
      help="Directory or .tf file for the regex HCL fallback (default: .).")
  parser.add_argument(
      "--plan-json", default=None,
      help="Output of `terraform show -json <planfile>`. Resolves modules, "
           "variables and for_each; disables the regex fallback.")
  parser.add_argument(
      "--max-expiry-days", type=int, default=DEFAULT_MAX_EXPIRY_DAYS,
      help="Flag IAM condition expiries further than N days in the future "
           f"(G5, default {DEFAULT_MAX_EXPIRY_DAYS}).")
  parser.add_argument(
      "--include-unchanged", action="store_true",
      help="Plan mode: also evaluate grants whose action is no-op.")
  parser.add_argument(
      "--fail-on",
      type=str.upper,
      choices=FAIL_ON_CHOICES,
      default="NONE",
      help=(
          "CI exit-code gate threshold: NONE (default, always exit 0 on findings), "
          "CRITICAL, HIGH, MEDIUM, LOW, or ANY. Exits 2 when a violation meets/exceeds "
          "the threshold, 3 on SCAN_ERROR, and 0 otherwise."
      ),
  )
  parser.add_argument(
      "--pr-comment-md",
      default=None,
      help=(
          "Optional output path for a concise PR-comment-ready Markdown summary "
          "(also written as gitops_pr_comment.md inside --output-dir)."
      ),
  )
  parser.add_argument(
      "--output-dir", required=True,
      help="Directory to write PR guardrail findings and SARIF.")
  parser.add_argument("--verbose", action="store_true", help="Debug logging.")
  add_gcs_publish_arguments(parser)
  args = parser.parse_args(argv)
  logging.basicConfig(
      level=logging.DEBUG if args.verbose else logging.INFO,
      format="%(levelname)s %(name)s: %(message)s", stream=sys.stderr)

  if args.max_expiry_days < 1:
    parser.error("--max-expiry-days must be >= 1")
  plan_path = Path(args.plan_json).resolve() if args.plan_json else None
  if plan_path and not plan_path.is_file():
    parser.error(f"--plan-json file not found: {plan_path}")

  store = GCSAssessmentStore()
  gcs_check = run_skill_gcs_preflight(args, args.project, store=store)

  out_dir = Path(args.output_dir)
  pr_comment_path = Path(args.pr_comment_md).resolve() if args.pr_comment_md else None
  mod_entry = run_gitops_guardrail(
      project_id=args.project,
      scan_path=Path(args.scan_path).resolve(),
      output_dir=out_dir,
      plan_json=plan_path,
      max_expiry_days=args.max_expiry_days,
      include_unchanged=args.include_unchanged,
      pr_comment_md=pr_comment_path,
  )
  exit_code = compute_ci_exit_code(mod_entry, args.fail_on)
  if mod_entry["status"] == "FAILED":
    print(json.dumps({"gitops_summary": mod_entry["summary"],
                      "fail_on": args.fail_on,
                      "exit_code": exit_code,
                      "error": mod_entry["payload"].get("error")}, indent=2))
    return exit_code

  publish_info = None
  if gcs_check:
    live_etag = ""
    try:
      pol = store.client.fetch_project_iam_policy(args.project)
      live_etag = pol.get("etag", "")
    except Exception as exc:  # pylint: disable=broad-except
      LOGGER.warning("Could not read live IAM policy etag: %s", exc)
    publish_info = store.publish_assessment_run(
        bucket=gcs_check["bucket"],
        region=gcs_check["region"],
        project_id=args.project,
        trigger_mode="gitops-pr-guardrail",
        updated_modules={"gitops_pr_guardrail": mod_entry},
        live_policy_etag=live_etag,
        local_output_dir=out_dir,
    )

  print(json.dumps(
      {"gitops_summary": mod_entry["summary"],
       "fail_on": args.fail_on,
       "exit_code": exit_code,
       "coverage": {k: mod_entry["payload"]["coverage"][k] for k in (
           "input_mode", "files_scanned", "resources_parsed",
           "resources_skipped_count", "warnings")},
       "gcs_publish": publish_info},
      indent=2))
  return exit_code


if __name__ == "__main__":
  sys.exit(main())
