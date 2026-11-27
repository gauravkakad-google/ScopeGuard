# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0

"""Run-level machine-readable exports, owner bundles and redacted copies.

Implements Part B of the artifact contract for the orchestrator:

* ART-7  `findings.csv`, `findings.jsonl`, `scc_findings_import.json` and the
  unified `scopeguard.sarif.json` built from `lib.findings_engine`.
* ART-9  `bundles/<key>/` subsets grouped by owner, folder or principal.
* ART-14 `shareable/` copies with emails, project numbers and external IDs
  replaced by stable short SHA-256 tokens (originals are never modified).

Design notes:
  * Pure standard library and file-only: nothing here calls a Google API. In
    particular `scc_findings_import.json` is an import *file*; ScopeGuard never
    writes back to Security Command Center.
  * CSV cells are neutralised against spreadsheet formula injection (CWE-1236)
    because finding text contains attacker-influenced values (principal
    names, inbound SCC/Wiz titles).
"""

import csv
import datetime as _dt
import hashlib
import json
import logging
import os
from pathlib import Path
import re
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence

from .envelope_schema import SCHEMA_VERSION
from .findings_engine import SEVERITY_RANK, normalize_findings, sort_findings
from .naming import short_principal

logger = logging.getLogger(__name__)

# Standard export file names (ART-12: one name per artifact, everywhere).
FINDINGS_CSV = "findings.csv"
FINDINGS_JSONL = "findings.jsonl"
SCC_IMPORT_JSON = "scc_findings_import.json"
SARIF_JSON = "scopeguard.sarif.json"

CSV_COLUMNS = (
    "id", "project_id", "severity", "priority", "category", "category_label",
    "principal", "principal_type", "title", "detail", "resource",
    "recommended_action", "deliverable", "confidence", "source_skill",
    "module_key", "run_id",
)

# Leading characters that make Excel / Sheets / LibreOffice evaluate a cell.
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")

# Finding categories whose fix lands in Terraform / IAM policy-as-code and
# therefore belong in the SARIF code-scanning report.
IAC_RELEVANT_CATEGORIES = frozenset({
    "basic_role", "overprivileged", "escalation_risk", "escalation_path",
    "expired_condition", "service_agent_excess", "role_sprawl", "iac_violation",
    "standing_admin", "pam_not_ready", "sa_key", "wif_candidate",
    "external_finding", "org_policy_gap",
})

_SARIF_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}
# GitHub code scanning maps `security-severity` (0-10) to its severity badge.
_SECURITY_SEVERITY = {"CRITICAL": "9.5", "HIGH": "8.0", "MEDIUM": "5.5", "LOW": "3.0"}
_SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def utc_now_iso() -> str:
  """Returns the current UTC time as ISO-8601 with a `Z` suffix (ART-12)."""
  return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _write_text(path: Path, text: str) -> Path:
  """Writes UTF-8 text (LF endings), creating parent folders."""
  path.parent.mkdir(parents=True, exist_ok=True)
  path.write_text(text, encoding="utf-8", newline="\n")
  return path


def _write_json(path: Path, doc: Any) -> Path:
  """Writes pretty JSON with a trailing newline."""
  return _write_text(path, json.dumps(doc, indent=2, ensure_ascii=False) + "\n")


# -----------------------------------------------------------------------------
# Findings
# -----------------------------------------------------------------------------
def build_findings(envelope: Dict[str, Any]) -> List[Dict[str, Any]]:
  """Builds unified findings for an envelope, never raising.

  Args:
    envelope: ScopeGuard v2.x assessment envelope (2.0 and 2.1 accepted).

  Returns:
    Findings sorted by priority then severity; empty on failure.
  """
  try:
    return sort_findings(normalize_findings(envelope or {}))
  except Exception:  # pylint: disable=broad-except
    # A malformed module must not stop the other exports from being written.
    logger.exception("Failed to normalize findings; exporting an empty list.")
    return []


def csv_safe(value: Any) -> str:
  """Neutralises spreadsheet formula injection for one CSV cell.

  Cells beginning with `= + - @ TAB CR` are prefixed with a single quote
  so spreadsheet tools treat them as text (OWASP CSV-injection guidance).

  Args:
    value: Any cell value; dicts/lists are JSON-encoded first.

  Returns:
    Safe string value.
  """
  if value is None:
    return ""
  if isinstance(value, (dict, list)):
    text = json.dumps(value, sort_keys=True, ensure_ascii=False)
  else:
    text = str(value)
  if text.startswith(_FORMULA_PREFIXES):
    return "'" + text
  return text


def write_findings_csv(
    findings: Sequence[Dict[str, Any]], path: Path, run_id: str = ""
) -> Path:
  """Writes `findings.csv` with formula-injection-safe cells.

  Args:
    findings: Unified findings.
    path: Destination file.
    run_id: Run identifier stamped on each row.

  Returns:
    The written path.
  """
  path.parent.mkdir(parents=True, exist_ok=True)
  with path.open("w", encoding="utf-8", newline="") as fh:
    # QUOTE_ALL also protects embedded commas/newlines in free-text fields.
    writer = csv.writer(fh, quoting=csv.QUOTE_ALL, lineterminator="\n")
    writer.writerow(CSV_COLUMNS)
    for f in findings:
      row = dict(f, run_id=run_id or f.get("run_id", ""))
      writer.writerow([csv_safe(row.get(col, "")) for col in CSV_COLUMNS])
  return path


def write_findings_jsonl(
    findings: Sequence[Dict[str, Any]],
    path: Path,
    run_id: str = "",
    generated_at: str = "",
) -> Path:
  """Writes `findings.jsonl` (one JSON object per finding, SIEM-friendly).

  Args:
    findings: Unified findings.
    path: Destination file.
    run_id: Run identifier stamped on each record.
    generated_at: ISO-8601 UTC timestamp stamped on each record.

  Returns:
    The written path.
  """
  generated_at = generated_at or utc_now_iso()
  lines = []
  for f in findings:
    rec = {"schema_version": SCHEMA_VERSION, "run_id": run_id, "generated_at": generated_at}
    rec.update(f)
    lines.append(json.dumps(rec, sort_keys=True, ensure_ascii=False))
  return _write_text(path, "\n".join(lines) + ("\n" if lines else ""))


# -----------------------------------------------------------------------------
# SCC import file (format only - no API write-back)
# -----------------------------------------------------------------------------
def _project_resource_name(envelope: Dict[str, Any]) -> str:
  """Full resource name of the project, preferring the project number."""
  number = (
      envelope.get("project_number")
      or ((envelope.get("metadata") or {}).get("project_number"))
      or ((((envelope.get("modules") or {}).get("recommender_audit") or {})
           .get("payload") or {}).get("analysis") or {}).get("metadata", {}).get("project_number")
  )
  return f"//cloudresourcemanager.googleapis.com/projects/{number or envelope.get('project_id', '')}"


def _scc_finding_id(fid: str) -> str:
  """SCC finding IDs must be 1-32 alphanumerics; derive one from our ID."""
  clean = re.sub(r"[^A-Za-z0-9]", "", fid or "")
  return (clean or hashlib.sha256((fid or "x").encode()).hexdigest())[:32]


def build_scc_import(
    envelope: Dict[str, Any], findings: Sequence[Dict[str, Any]]
) -> Dict[str, Any]:
  """Builds an SCC custom-source finding import document.

  Each entry mirrors the `Finding` resource accepted by
  `organizations.sources.findings.create` (category, state, severity,
  eventTime, resourceName, sourceProperties). The `parent` is a placeholder
  that the operator fills in; ScopeGuard never calls the SCC API.

  Args:
    envelope: Assessment envelope.
    findings: Unified findings.

  Returns:
    JSON-serialisable import document.
  """
  event_time = envelope.get("timestamp_utc") or utc_now_iso()
  resource_name = _project_resource_name(envelope)
  parent = "organizations/ORGANIZATION_ID/sources/SOURCE_ID"
  entries = []
  for f in findings:
    fid = _scc_finding_id(f.get("id", ""))
    entries.append({
        "findingId": fid,
        "finding": {
            "name": f"{parent}/findings/{fid}",
            "parent": parent,
            "resourceName": resource_name,
            "state": "ACTIVE",
            "category": str(f.get("category", "SCOPEGUARD_FINDING")).upper(),
            "severity": f.get("severity", "MEDIUM"),
            "findingClass": "MISCONFIGURATION",
            "eventTime": event_time,
            "description": f"{f.get('title', '')}. {f.get('detail', '')}".strip(),
            "sourceProperties": {
                "scopeguard_finding_id": f.get("id", ""),
                "priority": f.get("priority", ""),
                "principal": f.get("principal", ""),
                "principal_type": f.get("principal_type", ""),
                "resource": f.get("resource", ""),
                "recommended_action": f.get("recommended_action", ""),
                "deliverable": f.get("deliverable", ""),
                "source_skill": f.get("source_skill", ""),
                "confidence": f.get("confidence", ""),
                "run_id": envelope.get("run_id", ""),
            },
        },
    })
  return {
      "schema_version": SCHEMA_VERSION,
      "generated_at": utc_now_iso(),
      "run_id": envelope.get("run_id", ""),
      "project_id": envelope.get("project_id", ""),
      "import_note": (
          "File-only export. Replace ORGANIZATION_ID/SOURCE_ID with your SCC custom "
          "source and import with your own tooling; ScopeGuard does not write to SCC."
      ),
      "source": {"displayName": "ScopeGuard IAM Governance", "parent": parent},
      "findings": entries,
  }


# -----------------------------------------------------------------------------
# Unified SARIF
# -----------------------------------------------------------------------------
def _sarif_location(f: Dict[str, Any], project_id: str) -> Dict[str, Any]:
  """Best physical location for a finding (file:line for IaC, else deliverable)."""
  ev = f.get("evidence") or {}
  uri = ev.get("file")
  line = ev.get("line")
  if not uri:
    # Non-IaC findings point at the artifact that fixes them so code
    # scanning UIs have a stable anchor; the policy backup is the fallback.
    deliverable = str(f.get("deliverable") or "")
    cand = deliverable.split(" ")[0].split("&")[0].strip().strip("`")
    uri = cand if cand and "." in cand and "/" not in cand[:1] else f"iam_policy_backup_{project_id}.json"
  try:
    start = max(1, int(line))
  except (TypeError, ValueError):
    start = 1
  loc = {
      "physicalLocation": {
          "artifactLocation": {"uri": str(uri)[2:] if str(uri).startswith("./") else str(uri)},
          "region": {"startLine": start},
      }
  }
  if f.get("principal"):
    loc["logicalLocations"] = [{"name": short_principal(f["principal"]),
                                "fullyQualifiedName": f["principal"], "kind": "member"}]
  return loc


def build_unified_sarif(
    envelope: Dict[str, Any], findings: Sequence[Dict[str, Any]]
) -> Dict[str, Any]:
  """Builds `scopeguard.sarif.json` (SARIF 2.1.0) for all IaC-relevant findings.

  The GitOps guardrail already emits a complete SARIF run (rules + coverage
  properties); when present it is merged verbatim as its own run and IaC
  violations are not duplicated in the ScopeGuard run.

  Args:
    envelope: Assessment envelope.
    findings: Unified findings.

  Returns:
    SARIF log dict.
  """
  project_id = envelope.get("project_id", "")
  gitops_mod = (envelope.get("modules") or {}).get("gitops_pr_guardrail") or {}
  gitops_sarif = (gitops_mod.get("payload") or {}).get("sarif") or {}
  gitops_runs = [r for r in (gitops_sarif.get("runs") or []) if isinstance(r, dict)]
  skip_iac = bool(gitops_runs)

  rules: Dict[str, Dict[str, Any]] = {}
  results = []
  for f in findings:
    cat = f.get("category", "")
    if cat not in IAC_RELEVANT_CATEGORIES or (skip_iac and cat == "iac_violation"):
      continue
    rule_id = f"SG/{cat}"
    sev = f.get("severity", "MEDIUM")
    rule = rules.setdefault(rule_id, {
        "id": rule_id,
        "name": "".join(w.title() for w in cat.split("_")),
        "shortDescription": {"text": f.get("category_label") or cat},
        "defaultConfiguration": {"level": _SARIF_LEVEL.get(sev, "warning")},
        "properties": {"tags": ["security", "iam"], "security-severity": _SECURITY_SEVERITY.get(sev, "5.5")},
    })
    # A rule's severity badge reflects its worst finding.
    if float(_SECURITY_SEVERITY.get(sev, "0")) > float(rule["properties"]["security-severity"]):
      rule["properties"]["security-severity"] = _SECURITY_SEVERITY[sev]
      rule["defaultConfiguration"]["level"] = _SARIF_LEVEL.get(sev, "warning")
    results.append({
        "ruleId": rule_id,
        "level": _SARIF_LEVEL.get(sev, "warning"),
        "message": {"text": f"{f.get('title', '')}. {f.get('recommended_action', '')}".strip()},
        "locations": [_sarif_location(f, project_id)],
        # Stable ID lets code scanning track the same alert across runs.
        "partialFingerprints": {"scopeguardFindingId/v1": f.get("id", "")},
        "properties": {
            "severity": sev,
            "priority": f.get("priority", ""),
            "principal": f.get("principal", ""),
            "source_skill": f.get("source_skill", ""),
        },
    })

  sg_run = {
      "tool": {"driver": {
          "name": "ScopeGuard",
          "informationUri": "https://github.com/google/scopeguard",
          "semanticVersion": SCHEMA_VERSION,
          "rules": sorted(rules.values(), key=lambda r: r["id"]),
      }},
      "automationDetails": {"id": f"scopeguard/{project_id}/{envelope.get('run_id', '')}"},
      "results": results,
  }
  return {
      "$schema": _SARIF_SCHEMA,
      "version": "2.1.0",
      "runs": [sg_run] + gitops_runs,
      "properties": {
          "schema_version": SCHEMA_VERSION,
          "generated_at": utc_now_iso(),
          "run_id": envelope.get("run_id", ""),
          "project_id": project_id,
          "merged_gitops_runs": len(gitops_runs),
      },
  }


def write_findings_exports(
    envelope: Dict[str, Any],
    out_dir: Path,
    findings: Optional[Sequence[Dict[str, Any]]] = None,
) -> Dict[str, str]:
  """Writes the four ART-7 exports into `out_dir`.

  Each export is written independently so one failure is logged without
  losing the others.

  Args:
    envelope: Assessment envelope.
    out_dir: Destination directory.
    findings: Optional pre-computed findings.

  Returns:
    Mapping of export name -> written path (failed exports omitted).
  """
  out_dir = Path(out_dir)
  findings = list(findings) if findings is not None else build_findings(envelope)
  run_id = str(envelope.get("run_id", ""))
  generated_at = utc_now_iso()
  jobs: List[tuple] = [
      (FINDINGS_CSV, lambda p: write_findings_csv(findings, p, run_id)),
      (FINDINGS_JSONL, lambda p: write_findings_jsonl(findings, p, run_id, generated_at)),
      (SCC_IMPORT_JSON, lambda p: _write_json(p, build_scc_import(envelope, findings))),
      (SARIF_JSON, lambda p: _write_json(p, build_unified_sarif(envelope, findings))),
  ]
  written: Dict[str, str] = {}
  for name, job in jobs:
    try:
      written[name] = str(job(out_dir / name))
    except Exception:  # pylint: disable=broad-except
      logger.exception("Failed to write export %s", name)
  return written


# -----------------------------------------------------------------------------
# ART-9 bundles
# -----------------------------------------------------------------------------
BUNDLE_MODES = ("owner", "folder", "principal")
_UNASSIGNED = "unassigned"


def _bundle_key_slug(text: str) -> str:
  """Filesystem-safe bundle folder name (no path traversal)."""
  slug = re.sub(r"[^A-Za-z0-9._-]+", "-", str(text or "")).strip("-.")
  return slug[:80] or _UNASSIGNED


def _owner_of(labels: Any) -> str:
  """Reads an owner/team value from a label or metadata dict."""
  if not isinstance(labels, Mapping):
    return ""
  for key in ("owner", "team", "owner_team", "scopeguard_owner", "app_owner"):
    val = labels.get(key)
    if val:
      return str(val)
  return ""


def principal_owner_map(envelope: Dict[str, Any]) -> Dict[str, str]:
  """Collects principal -> owner from any labels/metadata in the envelope.

  Sources (first match wins): `envelope.principal_owners`, audit
  `principal_mappings[].owner|labels`, federation SA inventory labels.

  Args:
    envelope: Assessment envelope.

  Returns:
    Mapping of IAM member (and bare email) -> owner string.
  """
  owners: Dict[str, str] = {}

  def _put(member: str, owner: str) -> None:
    if member and owner:
      owners.setdefault(member, owner)
      owners.setdefault(member.split(":", 1)[-1], owner)

  for member, owner in (envelope.get("principal_owners") or {}).items():
    _put(member, str(owner))
  modules = envelope.get("modules") or {}
  analysis = ((modules.get("recommender_audit") or {}).get("payload") or {}).get("analysis") or {}
  for pm in analysis.get("principal_mappings") or []:
    _put(pm.get("principal", ""), pm.get("owner") or _owner_of(pm.get("labels")))
  fed = (modules.get("federation_architect") or {}).get("payload") or {}
  for key in ("service_accounts", "sa_inventory", "key_details", "wif_candidates"):
    for sa in fed.get(key) or []:
      if isinstance(sa, Mapping):
        email = sa.get("email") or sa.get("service_account") or ""
        _put(f"serviceAccount:{email}" if email else "", sa.get("owner") or _owner_of(sa.get("labels")))
  return owners


def _project_folder(envelope: Dict[str, Any]) -> str:
  """Best-effort folder key for the project (folder_path / org auditor parent)."""
  path = envelope.get("folder_path")
  if isinstance(path, list) and path:
    return str(path[-1])
  org = ((envelope.get("modules") or {}).get("org_hierarchy_auditor") or {}).get("payload") or {}
  for key in ("parent", "folder_id", "parent_resource"):
    if org.get(key):
      return str(org[key])
  return envelope.get("parent") or "no-folder"


def bundle_key_for(
    finding_or_item: Dict[str, Any],
    mode: str,
    owners: Mapping[str, str],
    folder: str,
) -> str:
  """Returns the bundle key for one finding or remediation-plan item.

  Args:
    finding_or_item: Finding or plan item (must carry `principal`).
    mode: `owner`, `folder` or `principal`.
    owners: Output of `principal_owner_map`.
    folder: Project folder key.

  Returns:
    Raw (un-slugged) bundle key.
  """
  principal = str(finding_or_item.get("principal") or "")
  if mode == "folder":
    return folder
  if mode == "principal":
    return short_principal(principal) if principal else "project-wide"
  return owners.get(principal) or owners.get(principal.split(":", 1)[-1]) or _UNASSIGNED


def write_bundles(
    envelope: Dict[str, Any],
    out_dir: Path,
    mode: str,
    findings: Optional[Sequence[Dict[str, Any]]] = None,
    plan_renderer: Optional[Callable[..., str]] = None,
) -> Dict[str, List[str]]:
  """Writes `bundles/<key>/` subsets for teams (ART-9).

  Each bundle gets filtered `findings.csv` / `findings.jsonl` and a
  `REMEDIATION_PLAN.md` restricted to its principals. The caller indexes each
  bundle folder with `lib.artifact_index`.

  Args:
    envelope: Assessment envelope.
    out_dir: Run output directory (bundles are created under it).
    mode: One of BUNDLE_MODES.
    findings: Optional pre-computed findings.
    plan_renderer: Optional override of
      `recommendation_synthesizer.synthesize_remediation_plan` (tests).

  Returns:
    Mapping of bundle folder path -> list of written file paths.

  Raises:
    ValueError: If `mode` is not supported.
  """
  if mode not in BUNDLE_MODES:
    raise ValueError(f"--bundle-by must be one of {BUNDLE_MODES}, got {mode!r}")
  if plan_renderer is None:
    from .recommendation_synthesizer import synthesize_remediation_plan  # pylint: disable=import-outside-toplevel
    plan_renderer = synthesize_remediation_plan
  findings = list(findings) if findings is not None else build_findings(envelope)
  owners = principal_owner_map(envelope)
  folder = _project_folder(envelope)
  run_id = str(envelope.get("run_id", ""))

  groups: Dict[str, List[Dict[str, Any]]] = {}
  for f in findings:
    groups.setdefault(bundle_key_for(f, mode, owners, folder), []).append(f)

  written: Dict[str, List[str]] = {}
  root = Path(out_dir) / "bundles"
  for key, subset in sorted(groups.items()):
    bdir = root / _bundle_key_slug(key)
    files: List[str] = []
    try:
      files.append(str(write_findings_csv(subset, bdir / FINDINGS_CSV, run_id)))
      files.append(str(write_findings_jsonl(subset, bdir / FINDINGS_JSONL, run_id)))
      plan_md = plan_renderer(
          envelope,
          findings=findings,
          include=lambda it, _k=key: bundle_key_for(it, mode, owners, folder) == _k,
          subtitle=f"bundle `{key}` (by {mode})",
      )
      files.append(str(_write_text(bdir / "REMEDIATION_PLAN.md", plan_md)))
    except Exception:  # pylint: disable=broad-except
      logger.exception("Failed to write bundle %s", key)
    written[str(bdir)] = files
  return written


# -----------------------------------------------------------------------------
# ART-14 redaction
# -----------------------------------------------------------------------------
_SA_RE = re.compile(
    # Google-managed service-agent domains (gcp-sa-*) are not customer projects.
    r"\b([A-Za-z0-9][A-Za-z0-9._-]*)@(?!gcp-sa-)([a-z][a-z0-9-]{4,61}[a-z0-9])\.iam\.gserviceaccount\.com\b"
)
_SERVICE_AGENT_RE = re.compile(
    r"\bservice-(\d+)@([a-z0-9-]+\.iam\.gserviceaccount\.com)\b"
)
# Default SAs whose local part embeds the project number / project id.
_COMPUTE_SA_RE = re.compile(r"\b(\d+)-compute@developer\.gserviceaccount\.com\b")
_APPSPOT_SA_RE = re.compile(r"\b([a-z][a-z0-9-]{4,61}[a-z0-9])@appspot\.gserviceaccount\.com\b")
_TYPED_EMAIL_RE = re.compile(
    r"\b(user|group|principal|domain):([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})"
)
_EMAIL_RE = re.compile(r"(?<![A-Za-z0-9._%+-])([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})")
_NUMERIC_RES_RE = re.compile(r"\b(projects|organizations|folders|billingAccounts)/(\d{6,})\b")
_LONG_NUMBER_RE = re.compile(r"(?<![\w.-])(\d{10,21})(?![\w.-])")
_WIF_SUBJECT_RE = re.compile(r"(principal(?:Set)?://[^\s\"'`|)]*?/(?:subject|attribute\.[a-z_]+)/)([^\s\"'`|)]+)")


def _salt() -> str:
  """Redaction salt; set SCOPEGUARD_REDACT_SALT to defeat dictionary lookups."""
  return os.environ.get("SCOPEGUARD_REDACT_SALT", "scopeguard-shareable-v1")


def redact_token(value: str, salt: Optional[str] = None) -> str:
  """Stable short token for a sensitive value (same input -> same token)."""
  digest = hashlib.sha256(f"{salt if salt is not None else _salt()}|{value.lower()}".encode()).hexdigest()
  return f"h{digest[:10]}"


def redact_text(text: str, salt: Optional[str] = None) -> str:
  """Redacts emails, project numbers and external IDs in free text.

  Rules (ART-14):
    * `user:/group:/domain:` emails -> `user:<token>` (type prefix kept,
      domain dropped).
    * Service accounts keep their account id; the project part is hashed:
      `ci-sa@<token>.iam.gserviceaccount.com`. Service agents
      (`service-<number>@...`) have the number hashed.
    * Other emails -> `<token>`.
    * `projects/<number>`-style resource numbers and bare 10-21 digit IDs
      (project numbers, SA unique IDs, org/folder IDs) -> tokens.
    * Workload-identity subjects (`.../subject/<id>`) -> tokens.

  Args:
    text: Input text (Markdown, CSV or serialized JSON).
    salt: Optional salt override (tests).

  Returns:
    Redacted text.
  """
  def tok(value: str) -> str:
    return redact_token(value, salt)

  out = _COMPUTE_SA_RE.sub(lambda m: f"{tok(m.group(1))}-compute@developer.gserviceaccount.com", text)
  out = _APPSPOT_SA_RE.sub(lambda m: f"{tok(m.group(1))}@appspot.gserviceaccount.com", out)
  out = _SERVICE_AGENT_RE.sub(lambda m: f"service-{tok(m.group(1))}@{m.group(2)}", out)
  out = _SA_RE.sub(lambda m: f"{m.group(1)}@{tok(m.group(2))}.iam.gserviceaccount.com", out)
  out = _TYPED_EMAIL_RE.sub(lambda m: f"{m.group(1)}:{tok(m.group(2))}", out)
  # Remaining emails, except the (already redacted) SA / service-agent forms.
  out = _EMAIL_RE.sub(
      lambda m: m.group(1) if m.group(1).endswith(".iam.gserviceaccount.com") or
      m.group(1).endswith(".gserviceaccount.com") else tok(m.group(1)),
      out,
  )
  out = _NUMERIC_RES_RE.sub(lambda m: f"{m.group(1)}/{tok(m.group(2))}", out)
  out = _WIF_SUBJECT_RE.sub(lambda m: f"{m.group(1)}{tok(m.group(2))}", out)
  out = _LONG_NUMBER_RE.sub(lambda m: tok(m.group(1)), out)
  return out


REDACTABLE_SUFFIXES = (".md", ".json", ".jsonl", ".csv")


def redact_json_value(value: Any, salt: Optional[str] = None) -> Any:
  """Recursively redacts strings (and keys) inside parsed JSON.

  Working on the parsed structure (not the serialized text) keeps the output
  valid JSON and leaves numeric fields such as sizes and counts untouched.

  Args:
    value: Parsed JSON value.
    salt: Optional salt override.

  Returns:
    Redacted copy.
  """
  if isinstance(value, str):
    return redact_text(value, salt)
  if isinstance(value, list):
    return [redact_json_value(v, salt) for v in value]
  if isinstance(value, dict):
    return {redact_text(str(k), salt): redact_json_value(v, salt) for k, v in value.items()}
  return value


def redact_file_text(text: str, suffix: str, salt: Optional[str] = None) -> str:
  """Redacts file content according to its type (.json/.jsonl structurally)."""
  suffix = suffix.lower()
  if suffix == ".json":
    return json.dumps(redact_json_value(json.loads(text), salt), indent=2, ensure_ascii=False) + "\n"
  if suffix == ".jsonl":
    lines = [json.dumps(redact_json_value(json.loads(ln), salt), sort_keys=True, ensure_ascii=False)
             for ln in text.splitlines() if ln.strip()]
    return "\n".join(lines) + ("\n" if lines else "")
  return redact_text(text, salt)


def write_shareable_copy(
    out_dir: Path,
    names: Iterable[str],
    salt: Optional[str] = None,
) -> List[str]:
  """Writes redacted copies of selected files into `<out_dir>/shareable/`.

  Originals are only read, never modified. Non-text or unknown suffixes are
  skipped (scripts and Terraform are never shared in redacted form because a
  redacted apply script would be wrong *and* dangerous).

  Args:
    out_dir: Run output directory.
    names: Relative file names to copy.
    salt: Optional salt override.

  Returns:
    Written shareable file paths.
  """
  out_dir = Path(out_dir)
  dest_root = out_dir / "shareable"
  written: List[str] = []
  for name in names:
    src = out_dir / name
    if src.suffix.lower() not in REDACTABLE_SUFFIXES or not src.is_file():
      continue
    try:
      redacted = redact_file_text(src.read_text(encoding="utf-8"), src.suffix, salt)
      written.append(str(_write_text(dest_root / name, redacted)))
    except (OSError, UnicodeDecodeError, ValueError):
      logger.exception("Skipping shareable copy of %s", name)
  return written


def severity_counts(findings: Sequence[Dict[str, Any]]) -> Dict[str, int]:
  """Counts findings by severity (CRITICAL..LOW), for summaries."""
  counts = {s: 0 for s in sorted(SEVERITY_RANK, key=SEVERITY_RANK.get, reverse=True)}
  for f in findings:
    if f.get("severity") in counts:
      counts[f["severity"]] += 1
  return counts
