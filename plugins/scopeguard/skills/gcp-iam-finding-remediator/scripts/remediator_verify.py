# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0

"""Post-change verification for the ScopeGuard finding remediator (ART-8).

`--verify` re-reads the live project IAM policy and Cloud Logging (both
read-only) after an operator has applied the proposed remediation, and proves
for every finding that:

1. none of the old broad roles is still bound to the principal,
2. the least-privilege replacement binding is present,
3. the policy etag changed since the assessment (a change really happened),
4. the principal has produced no PERMISSION_DENIED audit entries in the last
   N hours (no breakage caused by the change).

Each check reports PASS / FAIL / NOT_VERIFIED (with the reason). Missing
permissions or disabled APIs never crash the run; they downgrade the affected
checks to NOT_VERIFIED so the ticket note stays truthful.

Only the Python standard library is used.
"""

import datetime
import logging
import re
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence

LOGGER = logging.getLogger("scopeguard.finding_remediator.verify")

PASS = "PASS"
FAIL = "FAIL"
NOT_VERIFIED = "NOT_VERIFIED"

# Principal types whose audit-log identity is an email we can filter on.
_EMAIL_MEMBER = re.compile(r"^(user|serviceAccount):([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+)$")


def _utc_iso(dt: datetime.datetime) -> str:
  """Formats a datetime as ISO-8601 UTC with a trailing Z."""
  return dt.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _check(status: str, detail: str, **extra: Any) -> Dict[str, Any]:
  """Builds one check result record."""
  out: Dict[str, Any] = {"status": status, "detail": detail}
  out.update(extra)
  return out


def _member_roles(policy: Mapping[str, Any], member: str) -> List[Dict[str, Any]]:
  """Lists every binding (role + condition) that includes `member`."""
  found: List[Dict[str, Any]] = []
  for binding in policy.get("bindings") or []:
    if member in (binding.get("members") or []):
      entry: Dict[str, Any] = {"role": binding.get("role", "")}
      if binding.get("condition"):
        entry["condition"] = binding["condition"]
      found.append(entry)
  return found


def evaluate_policy_for_plan(
    plan: Mapping[str, Any],
    policy: Optional[Mapping[str, Any]],
    policy_error: str = "",
) -> Dict[str, Dict[str, Any]]:
  """Checks old-roles-absent and new-binding-present for one plan.

  Args:
    plan: Remediation plan (needs `principal`, `remove_bindings`,
      `add_bindings`).
    policy: Live IAM policy, or None when it could not be read.
    policy_error: Reason the policy could not be read.

  Returns:
    {"old_roles_absent": check, "new_bindings_present": check}.
  """
  if policy is None:
    reason = f"not verified: live IAM policy unavailable ({policy_error or 'unknown error'})"
    return {
        "old_roles_absent": _check(NOT_VERIFIED, reason),
        "new_bindings_present": _check(NOT_VERIFIED, reason),
    }
  member = plan.get("principal", "")
  current = _member_roles(policy, member)
  current_roles = {b["role"] for b in current}

  old_roles = sorted({b["role"] for b in plan.get("remove_bindings") or []})
  still_bound = [r for r in old_roles if r in current_roles]
  if not old_roles:
    old_check = _check(PASS, "No old bindings were scheduled for removal.", still_bound=[])
  elif still_bound:
    old_check = _check(
        FAIL,
        f"{len(still_bound)} old role(s) still bound to {member}: {', '.join(still_bound)}",
        still_bound=still_bound,
    )
  else:
    old_check = _check(
        PASS, f"All {len(old_roles)} old role(s) are absent for {member}.", still_bound=[]
    )

  new_roles = sorted({b["role"] for b in plan.get("add_bindings") or []})
  missing = [r for r in new_roles if r not in current_roles]
  if not new_roles:
    new_check = _check(NOT_VERIFIED, "not verified: plan has no replacement binding.", missing=[])
  elif missing:
    new_check = _check(
        FAIL, f"Replacement binding(s) missing for {member}: {', '.join(missing)}", missing=missing
    )
  else:
    new_check = _check(
        PASS, f"Replacement binding(s) present for {member}: {', '.join(new_roles)}", missing=[]
    )
  return {"old_roles_absent": old_check, "new_bindings_present": new_check}


def evaluate_etag(assessment_etag: str, policy: Optional[Mapping[str, Any]], policy_error: str = "") -> Dict[str, Any]:
  """Compares the live etag with the etag captured at assessment time."""
  if policy is None:
    return _check(NOT_VERIFIED, f"not verified: live IAM policy unavailable ({policy_error or 'unknown error'})")
  live = str(policy.get("etag") or "")
  if not assessment_etag:
    return _check(NOT_VERIFIED, "not verified: no assessment-time etag was recorded.", live_etag=live)
  if not live:
    return _check(NOT_VERIFIED, "not verified: live policy returned no etag.", assessment_etag=assessment_etag)
  if live == assessment_etag:
    return _check(
        FAIL,
        "Policy etag is unchanged since the assessment: the remediation has not been applied.",
        assessment_etag=assessment_etag, live_etag=live,
    )
  return _check(PASS, "Policy etag changed since the assessment.", assessment_etag=assessment_etag, live_etag=live)


def build_permission_denied_filter(email: str, since_iso: str) -> str:
  """Builds the Cloud Logging filter for PERMISSION_DENIED entries of one principal.

  `protoPayload.status.code=7` is the gRPC PERMISSION_DENIED code recorded in
  Cloud Audit Logs for denied API calls.
  """
  return " AND ".join([
      'logName:"cloudaudit.googleapis.com"',
      "protoPayload.status.code=7",
      f'protoPayload.authenticationInfo.principalEmail="{email}"',
      f'timestamp>="{since_iso}"',
  ])


def query_permission_denied(
    gcp_client: Any,
    project_id: str,
    member: str,
    hours: int,
    now: Optional[datetime.datetime] = None,
    max_entries: int = 50,
) -> Dict[str, Any]:
  """Counts PERMISSION_DENIED audit entries for a principal (read-only).

  Args:
    gcp_client: ScopeGuardGCPClient (or a test double exposing `request_json`).
    project_id: Project whose logs are queried.
    member: IAM member (`user:` / `serviceAccount:` are supported).
    hours: Lookback window in hours.
    now: Override for the current time (tests).
    max_entries: Upper bound on entries fetched (count is "at least" beyond it).

  Returns:
    A check record; `count` and `sample_methods` are set when verified.
  """
  match = _EMAIL_MEMBER.match(member or "")
  if not match:
    return _check(
        NOT_VERIFIED,
        f"not verified: audit logs cannot be filtered for member type of {member!r} "
        "(only user: and serviceAccount: identities appear as principalEmail).",
    )
  email = match.group(2)
  since = _utc_iso((now or datetime.datetime.now(datetime.timezone.utc)) - datetime.timedelta(hours=max(1, int(hours))))
  body = {
      "resourceNames": [f"projects/{project_id}"],
      "filter": build_permission_denied_filter(email, since),
      "orderBy": "timestamp desc",
      "pageSize": max(1, min(int(max_entries), 1000)),
  }
  try:
    resp = gcp_client.request_json(
        url="https://logging.googleapis.com/v2/entries:list",
        method="POST",
        body=body,
        service_key="logging",
        include_quota_project=True,
    )
  except Exception as exc:  # pylint: disable=broad-except
    # Any failure (403 missing logging.logEntries.list, API disabled, network)
    # is reported, never raised: verification must degrade, not crash.
    status_code = getattr(exc, "status_code", "")
    LOGGER.warning("PERMISSION_DENIED log query failed for %s: %s", member, exc)
    return _check(
        NOT_VERIFIED,
        f"not verified: Cloud Logging query failed ({status_code or type(exc).__name__}: "
        f"{str(exc)[:200]}). Requires roles/logging.viewer (logging.logEntries.list).",
        window_start=since,
    )
  entries = (resp or {}).get("entries") or []
  methods = sorted({
      str((e.get("protoPayload") or {}).get("methodName", "")) for e in entries
  } - {""})
  count = len(entries)
  more = bool((resp or {}).get("nextPageToken"))
  if count == 0:
    return _check(PASS, f"No PERMISSION_DENIED entries for {email} in the last {hours}h.", count=0, sample_methods=[], window_start=since)
  return _check(
      FAIL,
      f"{count}{'+' if more else ''} PERMISSION_DENIED entr{'y' if count == 1 else 'ies'} for "
      f"{email} in the last {hours}h (methods: {', '.join(methods[:5]) or 'unknown'}).",
      count=count, truncated=more, sample_methods=methods[:10], window_start=since,
  )


def _overall(checks: Mapping[str, Mapping[str, Any]]) -> str:
  """Rolls individual checks up to VERIFIED / FAILED / PARTIALLY_VERIFIED."""
  statuses = [c.get("status") for c in checks.values()]
  if any(s == FAIL for s in statuses):
    return "FAILED"
  if statuses and all(s == PASS for s in statuses):
    return "VERIFIED"
  return "PARTIALLY_VERIFIED"


def run_verification(
    project_id: str,
    plans: Sequence[Mapping[str, Any]],
    assessment_etag: str,
    fetch_policy: Callable[[], Mapping[str, Any]],
    gcp_client: Any,
    hours: int = 24,
    now: Optional[datetime.datetime] = None,
    audit_log_confidence: Optional[str] = None,
) -> Dict[str, Any]:
  """Verifies every actionable plan against live (read-only) state.

  Args:
    project_id: Target project.
    plans: Plans from finding_remediations.json (blocked ones are skipped).
    assessment_etag: Etag captured when the remediation was generated.
    fetch_policy: Zero-arg callable returning the live IAM policy.
    gcp_client: Client used for the Cloud Logging query.
    hours: PERMISSION_DENIED lookback window.
    now: Override for the current time (tests).
    audit_log_confidence: Audit log confidence level from simulation data
      (e.g. HIGH / MEDIUM / LOW), if available.

  Returns:
    Verification report dict (without schema_version; caller adds envelope).
  """
  policy: Optional[Mapping[str, Any]] = None
  policy_error = ""
  try:
    policy = fetch_policy()
    if not isinstance(policy, Mapping):
      policy_error, policy = "unexpected policy response", None
  except Exception as exc:  # pylint: disable=broad-except
    status_code = getattr(exc, "status_code", "")
    policy_error = f"{status_code or type(exc).__name__}: {str(exc)[:200]}"
    LOGGER.warning("Live IAM policy read failed during --verify: %s", policy_error)

  etag_check = evaluate_etag(assessment_etag, policy, policy_error)
  results: List[Dict[str, Any]] = []
  inbound_finding_ids: List[Dict[str, str]] = []
  for plan in plans:
    fid = str(plan.get("finding_id") or "")
    src = str(plan.get("source_platform") or "External")
    if fid:
      inbound_finding_ids.append({"finding_id": fid, "source_platform": src})
    if plan.get("status") not in ("READY", "HOLD_SIMULATED_403"):
      results.append({
          "finding_id": plan.get("finding_id"),
          "source_platform": plan.get("source_platform"),
          "principal": plan.get("principal"),
          "overall": "SKIPPED",
          "reason": f"Plan was not actionable ({plan.get('status')}).",
          "checks": {},
      })
      continue
    checks = evaluate_policy_for_plan(plan, policy, policy_error)
    checks["etag_changed"] = etag_check
    checks["no_recent_permission_denied"] = query_permission_denied(
        gcp_client, project_id, plan.get("principal", ""), hours, now=now
    )
    results.append({
        "finding_id": plan.get("finding_id"),
        "source_platform": plan.get("source_platform"),
        "principal": plan.get("principal"),
        "overall": _overall(checks),
        "checks": checks,
    })
  verified = [r for r in results if r["overall"] != "SKIPPED"]
  verified_count = sum(1 for r in verified if r["overall"] == "VERIFIED")
  failed_count = sum(1 for r in verified if r["overall"] == "FAILED")
  partial_count = sum(1 for r in verified if r["overall"] == "PARTIALLY_VERIFIED")
  if not verified:
    overall_status = "NO_FINDINGS"
  elif failed_count > 0:
    overall_status = "FAILED"
  elif verified_count == len(verified):
    overall_status = "VERIFIED"
  else:
    overall_status = "PARTIALLY_VERIFIED"
  return {
      "project_id": project_id,
      "verify_hours": hours,
      "assessment_etag": assessment_etag,
      "live_etag": (policy or {}).get("etag", "") if policy is not None else "",
      "policy_read_error": policy_error,
      "audit_log_confidence": audit_log_confidence,
      "inbound_finding_ids": inbound_finding_ids,
      "overall_status": overall_status,
      "results": results,
      "summary": {
          "findings_checked": len(verified),
          "verified": verified_count,
          "failed": failed_count,
          "partially_verified": partial_count,
          "skipped": len(results) - len(verified),
          "overall_status": overall_status,
          "audit_log_confidence": audit_log_confidence,
      },
  }


_CHECK_LABELS = {
    "old_roles_absent": "Old broad role(s) absent",
    "new_bindings_present": "Least-privilege binding present",
    "etag_changed": "Policy etag changed since assessment",
    "no_recent_permission_denied": "No PERMISSION_DENIED for principal",
}


def render_verification_note(report: Mapping[str, Any], generated_at: str) -> str:
  """Renders ticket_verification_note.md from a verification report.

  Produces closed-loop, audit-ready evidence (strictly read-only, no SCC/Wiz
  API write-back) including inbound SCC/Wiz finding IDs, audit_log_confidence,
  a Terraform PR link placeholder, and copy-pasteable verification status.
  """
  s = report.get("summary", {})
  conf = report.get("audit_log_confidence") or "n/a (not recorded in simulation data)"
  overall_status = report.get("overall_status") or s.get("overall_status") or "UNKNOWN"
  inbound_entries = report.get("inbound_finding_ids") or [
      {"finding_id": str(r.get("finding_id") or ""), "source_platform": str(r.get("source_platform") or "External")}
      for r in report.get("results", [])
      if r.get("finding_id")
  ]
  inbound_str = (
      ", ".join(f"`{e['finding_id']}` ({e['source_platform']})" for e in inbound_entries)
      or "none"
  )
  lines = [
      f"# Verification note - `{report.get('project_id')}`",
      "",
      f"- **Generated (UTC)**: {generated_at}",
      f"- **Overall Verification Status**: `{overall_status}`",
      f"- **Inbound SCC/Wiz Finding IDs**: {inbound_str}",
      f"- **Audit Log Confidence**: `{conf}`",
      "- **Terraform PR**: <!-- Paste PR URL -->",
      f"- **Assessment etag**: `{report.get('assessment_etag') or 'n/a'}` -> **live etag**: `{report.get('live_etag') or 'n/a'}`",
      f"- **PERMISSION_DENIED lookback**: last {report.get('verify_hours')}h",
      f"- **Result**: {s.get('verified', 0)} verified, {s.get('failed', 0)} failed, "
      f"{s.get('partially_verified', 0)} partially verified, {s.get('skipped', 0)} skipped",
      "",
      "Close an external finding ONLY when its result below is `VERIFIED` "
      "(ScopeGuard is strictly read-only and never writes back to SCC/Wiz APIs).",
      "",
  ]
  if report.get("policy_read_error"):
    lines += [f"> [!WARNING]\n> Live IAM policy could not be read: {report['policy_read_error']}", ""]
  for res in report.get("results", []):
    finding_id = res.get("finding_id")
    src = res.get("source_platform")
    principal = res.get("principal")
    overall = res.get("overall")
    checks = res.get("checks") or {}
    denied_status = (checks.get("no_recent_permission_denied") or {}).get("status", "N/A")
    lines += [
        f"## [{src}] `{finding_id}` - **{overall}**",
        "",
        f"- **External finding ID**: `{finding_id}` ({src})",
        f"- **Principal**: `{principal}`",
        f"- **Audit Log Confidence**: `{conf}`",
        "- **Terraform PR**: <!-- Paste PR URL -->",
    ]
    if res.get("reason"):
      lines.append(f"- **Reason**: {res['reason']}")
    if checks:
      lines += ["", "| Check | Status | Detail |", "| :--- | :--- | :--- |"]
      for key, chk in checks.items():
        detail = str(chk.get("detail", "")).replace("|", "\\|")
        lines.append(f"| {_CHECK_LABELS.get(key, key)} | `{chk.get('status')}` | {detail} |")
    lines += [
        "",
        "**Copy-Pasteable Ticket Verification Status**",
        "```text",
        f"Verification Status: {overall} | Finding: {finding_id} ({src}) | "
        f"Principal: {principal} | Policy Etag: {report.get('assessment_etag') or 'n/a'} -> "
        f"{report.get('live_etag') or 'n/a'} | Audit Log Confidence: {conf} | "
        f"PERMISSION_DENIED ({report.get('verify_hours')}h): {denied_status} | "
        "Terraform PR: <!-- Paste PR URL -->",
        "```",
        "",
        "- **Verified by**: `<name / team>`  **Ticket**: `<JIRA/SNOW-ID>`",
        "",
    ]
  return "\n".join(lines)
