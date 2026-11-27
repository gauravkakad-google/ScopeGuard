# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0

"""Renders safe-by-default Bash runbooks for IAM changes and rollbacks.

Every generated script shares the same safety contract (ART-2 / ART-3):

* DRY-RUN by default: commands are printed, nothing is changed. `--apply` is
  required to execute, plus an interactive "type the project ID" confirmation
  (skippable with `--yes` for CI).
* Preflight: gcloud present, caller identity resolved, live policy etag
  compared with the etag captured at assessment time (abort on drift unless
  `--skip-etag-check`), custom roles checked or created before use.
* Ordering: create roles -> add new bindings -> verification pause -> remove
  old bindings. Removals never run if any add failed.
* Atomic rollback: a full `get-iam-policy` backup is written before the first
  change; `--rollback <file>` restores it via etag-pinned `set-iam-policy`
  (restores conditional bindings exactly).
* Per-change functions + `--only <id>` so operators can apply one finding at a
  time; every action is logged with UTC timestamp and caller identity.

Conditions are always passed with `--condition-from-file` (JSON written via a
quoted heredoc), which avoids gcloud's comma-delimited KEY=VALUE parsing issues
with CEL expressions. Unconditional bindings use `--condition=None`.

All dynamic values are shell-quoted with `shlex.quote`; generated scripts never
interpolate untrusted input into executable positions.
"""

import json
import re
import shlex
from typing import Any, Dict, List, Mapping, Optional, Sequence

_FUNC_SAFE = re.compile(r"[^A-Za-z0-9_]")

_COMMON_PRELUDE = r'''set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN_TS="$(date -u +%Y%m%dT%H%M%SZ)"
LOG_FILE="${SCRIPT_DIR}/scopeguard_${SCRIPT_KIND}_${RUN_TS}.log"
APPLY=0
ASSUME_YES=0
SKIP_ETAG=0
FORCE_ROLLBACK=0
ONLY=""
PHASE="all"
ROLLBACK_FILE=""
ACTOR="unknown"
COND_N=0
# Private scratch dir created in the parent shell, so cleanup always sees it
# (files created inside $(...) subshells could not be tracked otherwise).
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/scopeguard.XXXXXX")" || { echo "mktemp failed" >&2; exit 1; }
chmod 700 "${WORK_DIR}"

cleanup() { [[ -n "${WORK_DIR:-}" && -d "${WORK_DIR}" ]] && rm -rf "${WORK_DIR}"; }
trap cleanup EXIT

log() {
  printf '%s [%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${ACTOR}" "$*" | tee -a "${LOG_FILE}" >&2
}

die() { log "ERROR: $*"; exit 1; }

# Executes (apply mode) or prints (dry-run) a command given as separate args.
run() {
  if [[ "${APPLY}" -eq 1 ]]; then
    log "EXEC: $(printf '%q ' "$@")"
    if ! "$@"; then
      log "FAILED: $(printf '%q ' "$@")"
      on_failure
      exit 1
    fi
  else
    printf '[dry-run] %s\n' "$(printf '%q ' "$@")"
  fi
}

# Returns a fresh path inside WORK_DIR. Must be called WITHOUT $(...) so the
# counter increments in the parent shell; result is placed in NEXT_FILE.
next_file() {
  COND_N=$((COND_N + 1))
  NEXT_FILE="${WORK_DIR}/f${COND_N}.json"
}

confirm() {
  local prompt="$1"
  if [[ "${ASSUME_YES}" -eq 1 ]]; then return 0; fi
  if [[ ! -t 0 ]]; then die "Non-interactive shell: re-run with --yes to confirm."; fi
  local answer
  read -r -p "${prompt} Type the project ID (${PROJECT_ID}) to confirm: " answer
  [[ "${answer}" == "${PROJECT_ID}" ]] || die "Confirmation did not match; aborting."
}

preflight_identity() {
  command -v gcloud >/dev/null 2>&1 || die "gcloud CLI not found on PATH."
  ACTOR="$(gcloud config get-value account 2>/dev/null || true)"
  [[ -n "${ACTOR}" ]] || ACTOR="unknown"
  log "Caller identity: ${ACTOR} | project: ${PROJECT_ID} | mode: $([[ ${APPLY} -eq 1 ]] && echo APPLY || echo DRY-RUN)"
}

preflight_etag() {
  local current
  current="$(gcloud projects get-iam-policy "${PROJECT_ID}" --format='value(etag)' 2>/dev/null)" \
    || die "Cannot read IAM policy for ${PROJECT_ID} (need resourcemanager.projects.getIamPolicy)."
  if [[ -z "${EXPECTED_ETAG}" ]]; then
    log "No assessment-time etag recorded; skipping drift check (current etag ${current})."
  elif [[ "${current}" != "${EXPECTED_ETAG}" ]]; then
    if [[ "${SKIP_ETAG}" -eq 1 ]]; then
      log "WARNING: policy drift (expected ${EXPECTED_ETAG}, live ${current}); continuing due to --skip-etag-check."
    elif [[ "${APPLY}" -eq 1 ]]; then
      die "IAM policy changed since assessment (expected etag ${EXPECTED_ETAG}, live ${current}). Re-run the assessment or pass --skip-etag-check after review."
    else
      log "WARNING: policy drift detected (expected ${EXPECTED_ETAG}, live ${current}); --apply would abort."
    fi
  else
    log "Policy etag matches assessment (${current})."
  fi
}

backup_policy() {
  [[ "${APPLY}" -eq 1 ]] || { log "Dry-run: a full policy backup is written before any --apply change."; return 0; }
  BACKUP_FILE="${SCRIPT_DIR}/iam_policy_backup_${PROJECT_ID}_${RUN_TS}.json"
  gcloud projects get-iam-policy "${PROJECT_ID}" --format=json > "${BACKUP_FILE}" \
    || die "Failed to back up IAM policy; refusing to change anything."
  log "Full IAM policy backup written: ${BACKUP_FILE}"
}

on_failure() {
  log "Stopped after a failed command. No further changes were made."
  if [[ -n "${BACKUP_FILE:-}" ]]; then
    log "To restore the exact pre-change policy run: $0 --rollback ${BACKUP_FILE}"
  fi
}

restore_from_file() {
  local file="$1"
  [[ -f "${file}" ]] || die "Backup file not found: ${file}"
  confirm "Restore the ENTIRE IAM policy of ${PROJECT_ID} from ${file}?"
  local src="${file}"
  if [[ "${FORCE_ROLLBACK}" -eq 1 ]]; then
    # Strip the etag so set-iam-policy overwrites newer changes (last resort).
    next_file
    src="${NEXT_FILE}"
    grep -v '"etag"' "${file}" > "${src}" || die "Could not prepare etag-less copy of ${file}"
    log "WARNING: --force-rollback strips the etag and overwrites any changes made after the backup."
  fi
  log "Restoring policy from ${file}"
  if ! gcloud projects set-iam-policy "${PROJECT_ID}" "${src}" --format=none; then
    die "Restore failed. If the error mentions an etag/concurrency conflict the policy changed after the backup; review, then re-run with --force-rollback."
  fi
  log "Restore complete."
}
'''

_USAGE_TEMPLATE = '''usage() {{
  cat <<'USAGE'
{title}

Usage: {script} [--apply] [--yes] [--only <id>] [--phase add|remove|all]
                [--skip-etag-check] [--rollback <backup.json> [--force-rollback]]

  (default)           DRY-RUN: print every command, change nothing.
  --apply             Execute changes (asks you to type the project ID).
  --yes               Skip the interactive confirmation (CI use).
  --only <id>         Apply a single change (see the list below).
  --phase <p>         add = only add new bindings; remove = only remove old ones.
  --skip-etag-check   Continue even if the IAM policy changed since assessment.
  --rollback <file>   Restore a full policy backup via set-iam-policy.
  --force-rollback    With --rollback: overwrite even if the policy changed since.

Changes:
{change_list}
USAGE
}}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --apply) APPLY=1 ;;
    --yes|-y) ASSUME_YES=1 ;;
    --only) ONLY="${{2:-}}"; shift ;;
    --phase) PHASE="${{2:-all}}"; shift ;;
    --skip-etag-check) SKIP_ETAG=1 ;;
    --rollback) ROLLBACK_FILE="${{2:-}}"; APPLY=1; shift ;;
    --force-rollback) FORCE_ROLLBACK=1 ;;
    --principal) ONLY="${{2:-}}"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 2 ;;
  esac
  shift
done
case "${{PHASE}}" in add|remove|all) ;; *) die "--phase must be add, remove or all" ;; esac
'''


def _q(value: Any) -> str:
  """Shell-quotes any value for safe embedding in generated Bash."""
  return shlex.quote(str(value if value is not None else ""))


_CTRL = re.compile(r"[\x00-\x1f\x7f]+")


def _one_line(value: Any) -> str:
  """Collapses control characters/newlines so text cannot escape a comment line
  or a quoted heredoc (e.g. a title containing "\nrm -rf /" or "USAGE")."""
  return _CTRL.sub(" ", str(value if value is not None else "")).strip()


def _log(text: Any, indent: str = "  ") -> str:
  """Renders a `log` call whose message is single-quoted (no expansion), so
  untrusted titles/members can never trigger command substitution."""
  return f"{indent}log {_q(_one_line(text))}"


def _func_name(prefix: str, change_id: str) -> str:
  """Builds a Bash-safe function name for a change."""
  return f"{prefix}_{_FUNC_SAFE.sub('_', change_id)}"


def _condition_payload(condition: Optional[Mapping[str, Any]]) -> Optional[str]:
  """Returns a JSON condition document or None for unconditional bindings."""
  if not condition or not condition.get("expression"):
    return None
  doc = {
      "title": condition.get("title") or "scopeguard_condition",
      "expression": condition["expression"],
  }
  if condition.get("description"):
    doc["description"] = condition["description"]
  return json.dumps(doc, sort_keys=True)


def _binding_cmd(verb: str, project_id: str, member: str, binding: Mapping[str, Any]) -> List[str]:
  """Renders Bash lines for one add/remove binding call (condition-aware)."""
  role = binding["role"]
  payload = _condition_payload(binding.get("condition"))
  base = (
      f"run gcloud projects {verb}-iam-policy-binding \"${{PROJECT_ID}}\" "
      f"--member={_q(member)} --role={_q(role)}"
  )
  if payload is None:
    return [f"  {base} --condition=None --format=none --quiet"]
  # Quoted heredoc ('JSON') disables all shell expansion inside the condition.
  return [
      "  next_file",
      "  cat > \"${NEXT_FILE}\" <<'SG_COND_JSON'",
      payload,
      "SG_COND_JSON",
      f"  {base} --condition-from-file=\"${{NEXT_FILE}}\" --format=none --quiet",
  ]


def _header(title: str, project_id: str, run_id: str, kind: str, expected_etag: str) -> List[str]:
  """Common script header with metadata and variables."""
  return [
      "#!/usr/bin/env bash",
      "# Copyright 2026 Google LLC",
      "# SPDX-License-Identifier: Apache-2.0",
      "#",
      f"# {_one_line(title)}",
      f"# Generated by ScopeGuard for project {_one_line(project_id)} (run {_one_line(run_id)}).",
      "# SAFE BY DEFAULT: runs in DRY-RUN mode unless --apply is passed.",
      "# Review every command before applying. Run with --help for options.",
      "",
      f"PROJECT_ID={_q(project_id)}",
      f"EXPECTED_ETAG={_q(expected_etag or '')}",
      f"SCRIPT_KIND={_q(kind)}",
      "BACKUP_FILE=\"\"",
  ]


def render_change_runbook(
    project_id: str,
    run_id: str,
    title: str,
    changes: Sequence[Mapping[str, Any]],
    expected_etag: str = "",
    roles_to_create: Sequence[Mapping[str, str]] = (),
    script_name: str = "remediation_commands.sh",
) -> str:
  """Renders a safe, ordered, per-change IAM remediation runbook.

  Args:
    project_id: Target project.
    run_id: Assessment run identifier for provenance.
    title: Human title printed in the header and usage.
    changes: Items with keys `id`, `title`, `principal`, `add` (list of
      bindings), `remove` (list of bindings), optional `verify` (text). A
      binding is `{"role": str, "condition": {title, expression, description}?}`.
    expected_etag: Live policy etag captured at assessment time.
    roles_to_create: Items `{"role_id", "yaml_path"}` (yaml path relative to the
      script directory) that must exist before any binding is added.
    script_name: File name used in usage text.

  Returns:
    The complete Bash script as a string.
  """
  lines = _header(title, project_id, run_id, "apply", expected_etag)
  lines.append(_COMMON_PRELUDE)
  change_list = "\n".join(
      _one_line(f"  {c['id']:<16} {c.get('title', '')}") for c in changes
  ) or "  (none)"
  lines.append(_USAGE_TEMPLATE.format(title=_one_line(title), script=_one_line(script_name), change_list=change_list))

  # Role creation (idempotent: describe first, create only when missing).
  lines.append("ensure_roles() {")
  if not roles_to_create:
    lines.append("  :  # No custom roles required.")
  for role in roles_to_create:
    rid, ypath = role["role_id"], role["yaml_path"]
    lines += [
        f"  if gcloud iam roles describe {_q(rid)} --project=\"${{PROJECT_ID}}\" --format='value(name)' >/dev/null 2>&1; then",
        _log(f"Custom role {rid} already exists.", "    "),
        "  else",
        f"    [[ -f \"${{SCRIPT_DIR}}/\"{_q(ypath)} ]] || die \"Role definition missing: {ypath}\"",
        f"    run gcloud iam roles create {_q(rid)} --project=\"${{PROJECT_ID}}\" --file=\"${{SCRIPT_DIR}}/\"{_q(ypath)} --format=none --quiet",
        "  fi",
    ]
  lines.append("}")
  lines.append("")

  for change in changes:
    cid, member = change["id"], change["principal"]
    lines.append(_one_line(f"# --- {cid}: {change.get('title', '')} ({member})"))
    if change.get("verify"):
      for vline in str(change["verify"]).splitlines():
        lines.append(f"#     verify: {_one_line(vline)}")
    lines.append(f"{_func_name('add', cid)}() {{")
    lines.append(_log(f"[{cid}] adding new bindings for {member}"))
    adds = change.get("add") or []
    if not adds:
      lines.append("  :")
    for b in adds:
      lines += _binding_cmd("add", project_id, member, b)
    lines.append("}")
    lines.append(f"{_func_name('remove', cid)}() {{")
    lines.append(_log(f"[{cid}] removing old bindings for {member}"))
    removes = change.get("remove") or []
    if not removes:
      lines.append("  :")
    for b in removes:
      lines += _binding_cmd("remove", project_id, member, b)
    lines.append("}")
    lines.append("")

  ids = " ".join(_q(c["id"]) for c in changes)
  lines += [
      "main() {",
      "  preflight_identity",
      "  if [[ -n \"${ROLLBACK_FILE}\" ]]; then restore_from_file \"${ROLLBACK_FILE}\"; return; fi",
      "  preflight_etag",
      f"  local all_ids=({ids})",
      "  local selected=()",
      "  for id in \"${all_ids[@]:-}\"; do",
      "    [[ -z \"$id\" ]] && continue",
      "    if [[ -z \"${ONLY}\" || \"${ONLY}\" == \"$id\" ]]; then selected+=(\"$id\"); fi",
      "  done",
      "  [[ ${#selected[@]} -gt 0 ]] || die \"No change matches --only ${ONLY}.\"",
      "  if [[ \"${APPLY}\" -eq 1 ]]; then confirm \"Apply ${#selected[@]} change(s) to ${PROJECT_ID}?\"; fi",
      "  backup_policy",
      "  if [[ \"${PHASE}\" != \"remove\" ]]; then",
      "    ensure_roles",
      "    for id in \"${selected[@]}\"; do \"add_${id//[^A-Za-z0-9_]/_}\"; done",
      "  fi",
      "  if [[ \"${PHASE}\" == \"all\" && \"${APPLY}\" -eq 1 && \"${ASSUME_YES}\" -eq 0 ]]; then",
      "    log \"New bindings added. Verify workloads (see 'verify:' notes in this script) before removing old access.\"",
      "    confirm \"Continue with REMOVAL of old bindings?\"",
      "  fi",
      "  if [[ \"${PHASE}\" != \"add\" ]]; then",
      "    for id in \"${selected[@]}\"; do \"remove_${id//[^A-Za-z0-9_]/_}\"; done",
      "  fi",
      "  log \"Done. $([[ ${APPLY} -eq 1 ]] && echo \"Backup: ${BACKUP_FILE}\" || echo 'Dry-run only; re-run with --apply to execute.')\"",
      "}",
      "",
      "main",
      "",
  ]
  return "\n".join(lines)


def render_restore_runbook(
    project_id: str,
    run_id: str,
    principals: Mapping[str, Sequence[Mapping[str, Any]]],
    backup_file: str = "",
    triage: Optional[Mapping[str, str]] = None,
    script_name: str = "rollback_runbook.sh",
    disabled_service_accounts: Optional[Sequence[str]] = None,
) -> str:
  """Renders a per-principal, condition-aware restore runbook (ART-3).

  Args:
    project_id: Target project.
    run_id: Assessment run identifier.
    principals: member -> ALL original bindings (role + optional condition)
      that the remediation may remove; every one is restored.
    backup_file: Assessment-time policy backup (relative path) offered as a
      full-restore option.
    triage: Optional member -> symptom text shown in usage and comments.
    script_name: File name used in usage text.
    disabled_service_accounts: Optional list of quarantined/disabled Service
      Account emails (e.g. F4 inactive SAs) to re-enable during rollback so
      P0/P1 quarantine is 1-command reversible.

  Returns:
    The complete Bash script as a string.
  """
  title = f"ScopeGuard emergency rollback runbook for {project_id}"
  lines = _header(title, project_id, run_id, "rollback", "")
  lines.append(f"ASSESSMENT_BACKUP={_q(backup_file)}")
  lines.append(_COMMON_PRELUDE)
  # Normalize disabled SA emails (strip optional serviceAccount: prefix).
  disabled_sas = sorted({
      str(sa).split(":", 1)[-1].strip()
      for sa in (disabled_service_accounts or [])
      if str(sa or "").strip()
  })
  disabled_sa_set = set(disabled_sas)
  # Short, Bash-safe IDs per principal; de-duplicated when two members share a
  # local part (e.g. user:ops@a.com and serviceAccount:ops@b.iam...).
  ids: Dict[str, str] = {}
  used: Dict[str, int] = {}
  for m in sorted(principals):
    base_id = _FUNC_SAFE.sub("_", m.split(":", 1)[-1].split("@", 1)[0]) or "principal"
    used[base_id] = used.get(base_id, 0) + 1
    ids[m] = base_id if used[base_id] == 1 else f"{base_id}_{used[base_id]}"
  change_list_rows = [
      "  " + _one_line(f"{ids[m]:<28} {m}" + (f"  | symptom: {triage[m]}" if triage and triage.get(m) else ""))
      for m in sorted(principals)
  ]
  if disabled_sas:
    change_list_rows.append(
        "  " + _one_line(f"{'(quarantined SAs)':<28} Re-enable {len(disabled_sas)} disabled service account(s)")
    )
  change_list = "\n".join(change_list_rows) or "  (none)"
  usage = _USAGE_TEMPLATE.format(title=title + " (use --principal <id>)", script=script_name, change_list=change_list)
  lines.append(usage)

  if disabled_sas:
    lines.append("# --- Re-enable quarantined/disabled Service Accounts (P0/P1 quarantine rollback)")
    lines.append("re_enable_disabled_service_accounts() {")
    lines.append(_log(f"Re-enabling {len(disabled_sas)} quarantined service account(s)"))
    for sa_email in disabled_sas:
      lines.append(
          f"  run gcloud iam service-accounts enable {_q(sa_email)} "
          f"--project=\"${{PROJECT_ID}}\" --quiet"
      )
    lines.append("}")
    lines.append("")

  for member in sorted(principals):
    fid = ids[member]
    sa_email = member.split(":", 1)[-1] if member.startswith("serviceAccount:") else ""
    lines.append(_one_line(f"# --- Restore ALL original bindings for {member}"))
    lines.append(f"{_func_name('restore', fid)}() {{")
    if sa_email and sa_email in disabled_sa_set:
      # When scoped to --principal <id>, also re-enable this SA before binding restore.
      lines.append("  if [[ -n \"${ONLY}\" ]]; then")
      lines.append(_log(f"Re-enabling quarantined service account {sa_email}", "    "))
      lines.append(
          f"    run gcloud iam service-accounts enable {_q(sa_email)} "
          f"--project=\"${{PROJECT_ID}}\" --quiet"
      )
      lines.append("  fi")
    lines.append(_log(f"Restoring {len(principals[member])} binding(s) for {member}"))
    for b in principals[member]:
      lines += _binding_cmd("add", project_id, member, b)
    if not principals[member]:
      lines.append("  :")
    lines.append("}")
    lines.append("")

  all_ids = " ".join(_q(ids[m]) for m in sorted(principals))
  has_disabled = "1" if disabled_sas else "0"
  lines += [
      "main() {",
      "  preflight_identity",
      "  if [[ -n \"${ROLLBACK_FILE}\" ]]; then",
      "    restore_from_file \"${ROLLBACK_FILE}\"",
      f"    if [[ \"{has_disabled}\" -eq 1 ]]; then re_enable_disabled_service_accounts; fi",
      "    return",
      "  fi",
      f"  local all_ids=({all_ids})",
      "  local selected=()",
      "  for id in \"${all_ids[@]:-}\"; do",
      "    [[ -z \"$id\" ]] && continue",
      "    if [[ -z \"${ONLY}\" || \"${ONLY}\" == \"$id\" ]]; then selected+=(\"$id\"); fi",
      "  done",
      f"  if [[ ${{#{ 'selected[@]' }}} -eq 0 && ( -n \"${{ONLY}}\" || \"{has_disabled}\" -eq 0 ) ]]; then",
      "    die \"No principal matches --principal ${ONLY}.\"",
      "  fi",
      "  if [[ \"${APPLY}\" -eq 1 ]]; then confirm \"Restore bindings and re-enable quarantined SAs in ${PROJECT_ID}?\"; fi",
      f"  if [[ -z \"${{ONLY}}\" && \"{has_disabled}\" -eq 1 ]]; then re_enable_disabled_service_accounts; fi",
      "  for id in \"${selected[@]:-}\"; do [[ -n \"$id\" ]] && \"restore_${id}\"; done",
      "  if [[ -n \"${ASSESSMENT_BACKUP}\" ]]; then",
      "    log \"Full restore option: $0 --rollback \\\"${SCRIPT_DIR}/${ASSESSMENT_BACKUP}\\\" (restores the assessment-time policy exactly).\"",
      "  fi",
      "}",
      "",
      "main",
      "",
  ]
  return "\n".join(lines)
