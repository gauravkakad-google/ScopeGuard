# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0

"""Terraform rendering for the ScopeGuard finding remediator (ART-1).

Produces a self-contained, `terraform plan`-able module directory:

* `versions.tf`  - Terraform / google provider pins and provider block.
* `variables.tf` - `project_id` input (defaults to the assessed project).
* `main.tf`      - `google_project_iam_custom_role` for every replacement role
  plus NON-authoritative `google_project_iam_member` grants (with `condition {}`
  blocks where applicable) that `depends_on` the custom role.
* `old_bindings_import.tf.example` - optional `import {}` blocks that let teams
  who do NOT manage the old broad bindings in Terraform adopt and then revoke
  them through Terraform (disabled by default via the `.example` suffix).
* `README.md`    - how to plan/apply, and how to revoke old bindings
  (`removed {}` / `terraform state rm` / `import`).

Authoritative resources (`google_project_iam_binding`) are only emitted when the
caller explicitly opts in; `google_project_iam_policy` is never emitted because
it replaces the entire project policy and is the most common cause of
Terraform-driven IAM outages.

Only the Python standard library is used.
"""

import json
import re
from typing import Any, Dict, List, Mapping, Optional, Sequence

# Terraform >= 1.7 is required for `removed {}` blocks referenced in README and
# >= 1.5 for `import {}` blocks; pin the provider to a tested major range.
TF_REQUIRED_VERSION = ">= 1.7.0"
GOOGLE_PROVIDER_CONSTRAINT = ">= 5.0, < 7.0"

AUTHORITATIVE_WARNING = (
    "WARNING: --authoritative was set. The generated Terraform uses "
    "google_project_iam_binding, which is AUTHORITATIVE for each listed role: "
    "on apply it REMOVES every member of that role that is not listed here, "
    "including bindings created outside Terraform. Review `terraform plan` "
    "output line by line before applying."
)

_TF_NAME_SAFE = re.compile(r"[^a-zA-Z0-9_]")


def tf_name(value: str, fallback: str = "sg_resource") -> str:
  """Builds a valid, readable Terraform resource name.

  Args:
    value: Arbitrary text (principal, role id, finding id).
    fallback: Name used when `value` sanitises to an empty string.

  Returns:
    A lowercase identifier that starts with a letter or underscore.
  """
  name = _TF_NAME_SAFE.sub("_", value or "").strip("_").lower()
  name = re.sub(r"_+", "_", name)[:60] or fallback
  if not re.match(r"^[a-z_]", name):
    name = f"r_{name}"
  return name


def hcl_str(value: Any) -> str:
  """Returns a safely escaped HCL double-quoted string literal.

  Escapes backslashes, quotes and newlines, and neutralises Terraform template
  sequences (`${` and `%{`) so untrusted finding data can never be evaluated
  as an interpolation or directive.
  """
  text = str(value if value is not None else "")
  text = (
      text.replace("\\", "\\\\")
      .replace('"', '\\"')
      .replace("\r", "")
      .replace("\n", "\\n")
      .replace("${", "$${")
      .replace("%{", "%%{")
  )
  return f'"{text}"'


def _hcl_list(values: Sequence[str], indent: str = "    ") -> str:
  """Renders a multi-line HCL list of strings."""
  if not values:
    return "[]"
  body = ",\n".join(f"{indent}{hcl_str(v)}" for v in values)
  return "[\n" + body + ",\n" + indent[:-2] + "]"


def _condition_block(condition: Optional[Mapping[str, Any]], indent: str = "  ") -> List[str]:
  """Renders a `condition {}` block, or nothing for unconditional bindings."""
  if not condition or not condition.get("expression"):
    return []
  lines = [
      f"{indent}condition {{",
      f"{indent}  title       = {hcl_str(condition.get('title') or 'scopeguard_condition')}",
      f"{indent}  expression  = {hcl_str(condition['expression'])}",
  ]
  if condition.get("description"):
    lines.append(f"{indent}  description = {hcl_str(condition['description'])}")
  lines.append(f"{indent}}}")
  return lines


def _versions_tf() -> str:
  """Renders versions.tf (Terraform + provider pins and provider block)."""
  return "\n".join([
      "# Managed by ScopeGuard. Provider pins for the remediation module.",
      "terraform {",
      f"  required_version = {hcl_str(TF_REQUIRED_VERSION)}",
      "  required_providers {",
      "    google = {",
      '      source  = "hashicorp/google"',
      f"      version = {hcl_str(GOOGLE_PROVIDER_CONSTRAINT)}",
      "    }",
      "  }",
      "}",
      "",
      'provider "google" {',
      "  project = var.project_id",
      "}",
      "",
  ])


def _variables_tf(project_id: str) -> str:
  """Renders variables.tf with a validated `project_id` input."""
  return "\n".join([
      'variable "project_id" {',
      '  description = "GCP project that receives the least-privilege remediation."',
      "  type        = string",
      f"  default     = {hcl_str(project_id)}",
      "",
      "  validation {",
      '    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project_id))',
      '    error_message = "project_id must be a valid GCP project ID."',
      "  }",
      "}",
      "",
  ])


def _custom_role_blocks(roles: Mapping[str, Mapping[str, Any]]) -> Dict[str, List[str]]:
  """Renders one `google_project_iam_custom_role` per replacement role.

  Returns:
    role_id -> HCL lines.
  """
  out: Dict[str, List[str]] = {}
  for role_id in sorted(roles):
    spec = roles[role_id]
    res = tf_name(role_id, "sg_role")
    out[role_id] = [
        f"# Custom role {role_id} ({len(spec.get('permissions') or [])} permissions; "
        f"source: {spec.get('source', 'scopeguard')}).",
        f'resource "google_project_iam_custom_role" "{res}" {{',
        "  project     = var.project_id",
        f"  role_id     = {hcl_str(role_id)}",
        f"  title       = {hcl_str(spec.get('title') or role_id)}",
        f"  description = {hcl_str(spec.get('description') or 'Generated by ScopeGuard.')}",
        f"  stage       = {hcl_str(spec.get('stage') or 'GA')}",
        f"  permissions = {_hcl_list(sorted(set(spec.get('permissions') or [])))}",
        "}",
        "",
    ]
  return out


def _role_ref(role: str, roles: Mapping[str, Any]) -> Dict[str, str]:
  """Resolves a binding role to an HCL expression and optional dependency.

  Custom roles generated in this module are referenced via the resource's
  `name` attribute so Terraform orders creation correctly.
  """
  match = re.match(r"^projects/[^/]+/roles/(.+)$", role or "")
  if match and match.group(1) in roles:
    res = tf_name(match.group(1), "sg_role")
    return {
        "expr": f"google_project_iam_custom_role.{res}.name",
        "depends": f"google_project_iam_custom_role.{res}",
    }
  return {"expr": hcl_str(role), "depends": ""}


def _member_blocks(
    plans: Sequence[Mapping[str, Any]], roles: Mapping[str, Any]
) -> List[str]:
  """Renders NON-authoritative `google_project_iam_member` grants."""
  lines: List[str] = []
  used: Dict[str, int] = {}
  for plan in plans:
    for idx, binding in enumerate(plan.get("add_bindings") or [], start=1):
      base = tf_name(f"{plan['change_id']}_grant_{idx}", "sg_grant")
      used[base] = used.get(base, 0) + 1
      res = base if used[base] == 1 else f"{base}_{used[base]}"
      ref = _role_ref(binding["role"], roles)
      lines += [
          f"# Finding {plan['finding_id']} ({plan.get('source_platform', '')}, "
          f"{plan.get('severity', '')}): grant least-privilege replacement.",
          f"# Old bindings to revoke AFTER verification: "
          f"{', '.join(b['role'] for b in plan.get('remove_bindings') or []) or 'none'}",
          f'resource "google_project_iam_member" "{res}" {{',
          "  project = var.project_id",
          f"  role    = {ref['expr']}",
          f"  member  = {hcl_str(plan['principal'])}",
      ]
      lines += _condition_block(binding.get("condition"))
      if ref["depends"]:
        lines.append(f"  depends_on = [{ref['depends']}]")
      lines += ["}", ""]
  return lines


def _authoritative_blocks(
    plans: Sequence[Mapping[str, Any]], roles: Mapping[str, Any]
) -> List[str]:
  """Renders opt-in AUTHORITATIVE `google_project_iam_binding` resources.

  One binding per (role, condition) pair; members are aggregated across plans.
  """
  grouped: Dict[str, Dict[str, Any]] = {}
  for plan in plans:
    for binding in plan.get("add_bindings") or []:
      cond = binding.get("condition") or None
      key = json.dumps([binding["role"], cond], sort_keys=True)
      entry = grouped.setdefault(key, {"role": binding["role"], "condition": cond, "members": []})
      if plan["principal"] not in entry["members"]:
        entry["members"].append(plan["principal"])
  lines = [f"# {AUTHORITATIVE_WARNING}", ""]
  for idx, key in enumerate(sorted(grouped), start=1):
    entry = grouped[key]
    ref = _role_ref(entry["role"], roles)
    res = tf_name(f"authoritative_{entry['role'].rsplit('/', 1)[-1]}_{idx}", "sg_binding")
    lines += [
        f'resource "google_project_iam_binding" "{res}" {{',
        "  project = var.project_id",
        f"  role    = {ref['expr']}",
        f"  members = {_hcl_list(sorted(entry['members']))}",
    ]
    lines += _condition_block(entry["condition"])
    if ref["depends"]:
      lines.append(f"  depends_on = [{ref['depends']}]")
    lines += ["}", ""]
  return lines


def _import_id(project_id: str, member: str, binding: Mapping[str, Any]) -> str:
  """Builds the provider import ID for an existing google_project_iam_member."""
  parts = [project_id, binding["role"], member]
  cond = binding.get("condition") or {}
  if cond.get("title"):
    parts.append(str(cond["title"]))
  return " ".join(parts)


def _old_bindings_import(project_id: str, plans: Sequence[Mapping[str, Any]]) -> str:
  """Renders an opt-in file that adopts old bindings so Terraform can revoke them."""
  lines = [
      "# OPTIONAL - only for teams that do NOT already manage these bindings in Terraform.",
      "# Step 1: rename this file to old_bindings_import.tf and run `terraform plan`:",
      "#         the import blocks adopt the existing broad bindings (plan shows imports, no changes).",
      "# Step 2: after the new least-privilege grants are applied and verified, delete the",
      "#         resource blocks below (keep nothing) and run `terraform plan` again: Terraform",
      "#         will plan to DESTROY (revoke) exactly these old bindings and nothing else.",
      "# Import blocks require Terraform >= 1.5; the module already pins >= 1.7.",
      "",
  ]
  used: Dict[str, int] = {}
  for plan in plans:
    for idx, binding in enumerate(plan.get("remove_bindings") or [], start=1):
      base = tf_name(f"old_{plan['change_id']}_{idx}", "sg_old")
      used[base] = used.get(base, 0) + 1
      res = base if used[base] == 1 else f"{base}_{used[base]}"
      lines += [
          f"# Finding {plan['finding_id']}: old binding {binding['role']} for {plan['principal']}",
          "import {",
          f"  to = google_project_iam_member.{res}",
          f"  id = {hcl_str(_import_id(project_id, plan['principal'], binding))}",
          "}",
          f'resource "google_project_iam_member" "{res}" {{',
          "  project = var.project_id",
          f"  role    = {hcl_str(binding['role'])}",
          f"  member  = {hcl_str(plan['principal'])}",
      ]
      lines += _condition_block(binding.get("condition"))
      lines += ["}", ""]
  if not used:
    lines.append("# No old bindings to revoke.")
  return "\n".join(lines) + "\n"


def _readme(
    project_id: str,
    plans: Sequence[Mapping[str, Any]],
    blocked: Sequence[Mapping[str, Any]],
    roles: Mapping[str, Any],
    authoritative: bool,
    canary: bool = False,
    canary_reason: str = "",
) -> str:
  """Renders README.md for the Terraform module."""
  lines = [
      f"# ScopeGuard remediation module - `{project_id}`",
      "",
      "This directory is a complete Terraform module. It **adds** least-privilege access;",
      "revoking the old broad bindings is a separate, explicit step (see below) so a",
      "`terraform apply` can never silently remove access you did not review.",
      "",
  ]
  if authoritative:
    lines += [f"> [!CAUTION]\n> {AUTHORITATIVE_WARNING}", ""]
  if canary:
    reason_note = (
        " (`audit_log_confidence == LOW` — auto-recommended)"
        if "low" in canary_reason
        else " (`--canary` enabled)"
    )
    lines += [
        "## Dual-Bind Canary Cutover (2-Step Zero-Breakage Rollout)",
        "",
        f"> [!IMPORTANT]",
        f"> Canary dual-bind cutover is active{reason_note}. Bind the new least-privilege",
        "> custom role(s) alongside the existing broad role(s) first, observe workloads,",
        "> and only revoke the broad role(s) after `--verify` confirms clean usage.",
        "",
        "1. **Step 1 — Bind least-privilege alongside existing roles (zero breakage risk)**:",
        "   Apply this Terraform module (`terraform apply scopeguard.tfplan`) OR run",
        "   `../canary_step1_bind_least_privilege.sh` (dry-run by default; pass `--apply` to execute).",
        "2. **Step 2 — Verify & remove broad roles**:",
        "   Observe workloads (24–72h) and run `finding_remediator_cli.py --project "
        f"{project_id} --output-dir .. --verify --verify-hours 24` to confirm zero",
        "   `PERMISSION_DENIED` entries. Then revoke the old broad roles via",
        "   `../canary_step2_remove_broad_role.sh` (dry-run by default; pass `--apply` to execute)",
        "   or via Terraform (`removed {}` / `old_bindings_import.tf.example`).",
        "",
    ]
  lines += [
      "## Contents",
      "",
      "| File | Purpose |",
      "| :--- | :--- |",
      "| `versions.tf` | Terraform and `hashicorp/google` provider pins, provider block. |",
      "| `variables.tf` | `project_id` input (default: assessed project). |",
      f"| `main.tf` | {len(roles)} custom role(s) and "
      f"{sum(len(p.get('add_bindings') or []) for p in plans)} "
      f"{'AUTHORITATIVE `google_project_iam_binding`' if authoritative else 'non-authoritative `google_project_iam_member`'} grant(s). |",
      "| `old_bindings_import.tf.example` | Optional: adopt old bindings into state so Terraform can revoke them. |",
      "",
      "## Plan and apply the new access",
      "",
      "```bash",
      "terraform init",
      f"terraform plan -var=project_id={project_id} -out=scopeguard.tfplan",
      "# Review: expect only CREATE actions for custom roles and IAM members.",
      "terraform apply scopeguard.tfplan",
      "```",
      "",
      "If a custom role already exists (for example, created by an earlier run or by",
      "`remediation_commands.sh`), import it instead of recreating it:",
      "",
      "```bash",
  ]
  for role_id in sorted(roles):
    lines.append(
        f"terraform import google_project_iam_custom_role.{tf_name(role_id, 'sg_role')} "
        f"projects/{project_id}/roles/{role_id}"
    )
  if not roles:
    lines.append("# (no custom roles in this module)")
  lines += [
      "```",
      "",
      "> [!NOTE]",
      "> Deleted custom roles keep their ID reserved for up to 37 days; if create fails",
      "> with `already exists`, undelete it (`gcloud iam roles undelete`) and import it.",
      "",
      "## Revoke the old broad bindings (after verification)",
      "",
      "Choose the option that matches how the old bindings are managed today:",
      "",
      "1. **Managed in your Terraform as `google_project_iam_member`**: delete those",
      "   resource blocks from your configuration and run `terraform plan` - it will",
      "   show a destroy for each old binding. When moving code between modules, a",
      "   `removed {}` block (Terraform >= 1.7) makes the intent explicit:",
      "",
      "   ```hcl",
      "   removed {",
      "     from = google_project_iam_member.<old_binding_address>",
      "     lifecycle {",
      "       destroy = true   # revoke the binding in GCP",
      "     }",
      "   }",
      "   ```",
      "",
      "   Use `destroy = false` (or `terraform state rm <address>`) only to stop",
      "   managing a binding WITHOUT revoking it.",
      "2. **Not managed in Terraform**: either run",
      "   `../remediation_commands.sh --phase remove` (dry-run by default), or rename",
      "   `old_bindings_import.tf.example` to `.tf`, import, then delete the imported",
      "   resource blocks and apply to revoke them.",
      "3. **Managed with authoritative `google_project_iam_binding`/`_policy`**: edit",
      "   the members list of that resource instead; never mix it with `_member`",
      "   resources for the same role.",
      "",
      "| Finding | Principal | Grant | Revoke after verification |",
      "| :--- | :--- | :--- | :--- |",
  ]
  def _roles_md(bindings: Sequence[Mapping[str, Any]]) -> str:
    """Formats binding roles as inline code for Markdown tables."""
    return ", ".join("`" + str(b["role"]) + "`" for b in bindings) or "-"

  for plan in plans:
    lines.append(
        f"| `{plan['finding_id']}` | `{plan['principal']}` | "
        f"{_roles_md(plan.get('add_bindings') or [])} | "
        f"{_roles_md(plan.get('remove_bindings') or [])} |"
    )
  if blocked:
    lines += ["", "## Findings NOT included (action required)", ""]
    for plan in blocked:
      lines.append(f"- `{plan['finding_id']}` (`{plan.get('principal', '')}`): {plan.get('status')} - {plan.get('status_reason', '')}")
  lines.append("")
  return "\n".join(lines)


def render_terraform_module(
    project_id: str,
    plans: Sequence[Mapping[str, Any]],
    roles: Mapping[str, Mapping[str, Any]],
    blocked: Sequence[Mapping[str, Any]] = (),
    authoritative: bool = False,
    canary: bool = False,
    canary_reason: str = "",
) -> Dict[str, str]:
  """Renders the Terraform module files and the single-file patch.

  Args:
    project_id: Target project.
    plans: Actionable plans with `change_id`, `finding_id`, `principal`,
      `add_bindings`, `remove_bindings` (bindings are `{role, condition?}`).
    roles: role_id -> {title, description, stage, permissions, source} for
      custom roles that must exist before the grants.
    blocked: Plans excluded from the module (listed in README).
    authoritative: Emit opt-in authoritative `google_project_iam_binding`.
    canary: When True, include the 2-step Dual-Bind Canary Cutover section in
      `terraform/README.md`.
    canary_reason: Reason canary mode was activated (e.g. explicit flag or low
      audit log confidence).

  Returns:
    Mapping of relative file path -> content. Keys: `terraform/versions.tf`,
    `terraform/variables.tf`, `terraform/main.tf`,
    `terraform/old_bindings_import.tf.example`, `terraform/README.md`,
    `remediation_patch.tf`.
  """
  role_blocks = _custom_role_blocks(roles)
  header = [
      f"# ScopeGuard least-privilege remediation for project {project_id}.",
      "# Review with `terraform plan` before applying. ScopeGuard never mutates IAM itself.",
      "# Old broad bindings are NOT revoked by this file - see README.md.",
      "",
  ]
  grants = (
      _authoritative_blocks(plans, roles) if authoritative else _member_blocks(plans, roles)
  )
  body: List[str] = []
  for role_id in sorted(role_blocks):
    body += role_blocks[role_id]
  body += grants
  if not plans:
    body.append("# No actionable findings: nothing to grant.")
  main_tf = "\n".join(header + body) + "\n"
  versions_tf = _versions_tf()
  variables_tf = _variables_tf(project_id)
  single = "\n".join([
      "# Single-file variant of the terraform/ module (do NOT copy it into the same",
      "# directory as terraform/*.tf - the blocks would be declared twice).",
      "",
      versions_tf,
      variables_tf,
      main_tf,
  ])
  return {
      "terraform/versions.tf": versions_tf,
      "terraform/variables.tf": variables_tf,
      "terraform/main.tf": main_tf,
      "terraform/old_bindings_import.tf.example": _old_bindings_import(project_id, plans),
      "terraform/README.md": _readme(
          project_id,
          plans,
          blocked,
          roles,
          authoritative,
          canary=canary,
          canary_reason=canary_reason,
      ),
      "remediation_patch.tf": single,
  }
