# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0

"""Per-output-directory artifact index: `README.md` + `manifest.json` (ART-6).

Every run folder gets a human index (`README.md`) grouped Read / Review /
Apply / Evidence and a machine manifest (`manifest.json`) with, per file:
purpose, audience, group, `applies_changes` (⚠️ for `.sh` / `.tf`), producing
module, SHA-256, size, plus run-level `run_id`, `schema_version` and
`generated_at` (ISO-8601 UTC).

The SHA-256 hashes let auditors prove that the files they reviewed are the
files that were applied (tamper evidence for the change record).
"""

import fnmatch
import hashlib
import json
import logging
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from . import exports
from . import recommendation_synthesizer as rs
from .envelope_schema import SCHEMA_VERSION
from .exports import utc_now_iso

logger = logging.getLogger(__name__)

MANIFEST_JSON = "manifest.json"
README_MD = "README.md"
GROUP_ORDER = ("Read", "Review", "Apply", "Evidence")
_GROUP_BLURB = {
    "Read": "Start here: summaries and plans for humans.",
    "Review": "Proposed designs, workflows and tickets to review before any change.",
    "Apply": "Files that change IAM / infrastructure when executed. ⚠️ Review first; scripts are dry-run by default.",
    "Evidence": "Raw data, exports and audit trail for GRC and tooling.",
}
# API request bodies that must stay byte-identical to the GCP API schema and
# therefore intentionally carry no `schema_version` field.
SCHEMA_EXEMPT = ("deny-policies/deny_policy_v2.json",)

_ORCH = "scopeguard-orchestrator"
_AUDIT = "gcp-iam-recommender-audit"

# Folder -> producing module.
_FOLDER_MODULE = {
    "custom-roles": _AUDIT,
    "role-designs": "gcp-iam-role-architect",
    "simulator": "gcp-iam-breakglass-simulator",
    "federation-wif": "gcp-iam-federation-architect",
    "jit-pam": "gcp-iam-jit-pam-architect",
    "deny-policies": "gcp-iam-deny-policy-architect",
    "org-hierarchy": "gcp-iam-org-hierarchy-auditor",
    "gitops-guardrail": "gcp-iam-gitops-pr-guardrail",
    "compliance": "gcp-iam-compliance-mapper",
    "finding-remediation": "gcp-iam-finding-remediator",
    "finding-remediator": "gcp-iam-finding-remediator",
    "bundles": _ORCH,
    "shareable": _ORCH,
}

# Ordered (glob, purpose, audience, group, module-or-None). First match wins;
# globs are matched against the relative POSIX path and the basename.
_RULES: Sequence[Tuple[str, str, Tuple[str, ...], str, Optional[str]]] = (
    ("EXECUTIVE_SUMMARY.md", "One-page posture KPIs, top risks and decision asks.", ("security",), "Read", _ORCH),
    ("REMEDIATION_PLAN.md", "Change batches P0-P3: what, why, risk, files to apply, rollback.", ("devops",), "Read", _ORCH),
    ("EVIDENCE.md", "Data sources, insight IDs, gates and traceability for audit.", ("auditor",), "Evidence", _ORCH),
    ("scopeguard_recommendations_*.md", "Full detailed recommendations (all modules).", ("security", "devops"), "Read", _ORCH),
    ("scopeguard_scope_recommendations_*.md", "Org / folder fleet rollup summary.", ("security",), "Read", _ORCH),
    ("findings.csv", "All findings as CSV (formula-injection safe) for spreadsheets / ticketing.", ("security", "auditor"), "Evidence", _ORCH),
    ("findings.jsonl", "All findings as JSON Lines for SIEM / data pipelines.", ("security", "auditor"), "Evidence", _ORCH),
    ("scc_findings_import.json", "SCC custom-source finding import file (not sent to SCC).", ("security",), "Evidence", _ORCH),
    ("scopeguard.sarif.json", "Unified SARIF 2.1.0 for GitHub / GitLab code scanning.", ("devops", "security"), "Evidence", _ORCH),
    ("assessment_envelope_*.json", "Complete assessment envelope (all module results).", ("auditor",), "Evidence", _ORCH),
    ("scope_rollup_*.json", "Org / folder fleet rollup data.", ("auditor",), "Evidence", _ORCH),
    ("sweep_progress.json", "Live progress of an org / folder sweep.", ("devops",), "Evidence", _ORCH),
    ("iam_policy_backup_*.json", "Pre-change IAM policy backup (etag-pinned restore source).", ("devops", "auditor"), "Evidence", _AUDIT),
    ("audit_bundle_*.json", "Raw telemetry bundle (policy, Recommender insights, audit logs).", ("auditor",), "Evidence", _AUDIT),
    ("analysis_results_*.json", "Recommender audit analysis results.", ("auditor",), "Evidence", _AUDIT),
    ("principal_mapping.json", "Principal -> recommended role mapping.", ("devops",), "Evidence", _AUDIT),
    ("role_traceability.json", "Permission -> evidence traceability for custom roles.", ("auditor",), "Evidence", _AUDIT),
    ("rollback_runbook.sh", "Condition-aware rollback runbook (dry-run by default).", ("devops",), "Apply", _AUDIT),
    ("custom-roles/personas/*.yaml", "Model A persona custom role (recommended default).", ("devops", "security"), "Review", _AUDIT),
    ("custom-roles/capabilities/*.yaml", "Model B capability custom role.", ("devops", "security"), "Review", _AUDIT),
    ("custom-roles/disjoint/*.yaml", "Model B capability custom role (legacy folder).", ("devops", "security"), "Review", _AUDIT),
    ("custom-roles/bundles.yaml", "Model B bundles: principal -> capability roles.", ("devops",), "Review", _AUDIT),
    ("custom-roles/*.yaml", "Custom role definition.", ("devops", "security"), "Review", _AUDIT),
    ("detailed_recommendations.md", "Legacy detailed audit report (superseded by REMEDIATION_PLAN.md).", ("security",), "Read", _AUDIT),
    ("iam_security_posture_report.md", "Legacy posture report (superseded by EXECUTIVE_SUMMARY.md).", ("security",), "Read", _AUDIT),
    ("scopeguard_audit.sarif.json", "Legacy audit SARIF (superseded by scopeguard.sarif.json).", ("devops",), "Evidence", _AUDIT),
    ("scc_findings_payload.json", "Legacy SCC payload (superseded by scc_findings_import.json).", ("security",), "Evidence", _AUDIT),
    ("jit-pam/pam_rollout.md", "PAM rollout guide and readiness checklist.", ("devops", "security"), "Read", None),
    ("deny-policies/deny_policy_spec.json", "Deny policy design spec (rules, exceptions, source).", ("security",), "Review", None),
    ("deny-policies/deny_policy_v2.json", "IAM v2 deny policy API body (attach after review).", ("devops",), "Review", None),
    ("deny-policies/deny_rollout.md", "Deny policy rollout guide (break-glass confirmation).", ("devops", "security"), "Read", None),
    ("federation-wif/WIF_MIGRATION.md", "Keyless WIF migration guide.", ("devops",), "Read", None),
    ("federation-wif/ci/*.yml", "CI pipeline snippet for keyless WIF auth.", ("devops",), "Review", None),
    ("gitops-guardrail/gitops_guardrail_report.md", "GitOps PR gate report (violations + coverage).", ("devops",), "Read", None),
    ("gitops-guardrail/gitops_pr_comment.md", "PR-comment-ready summary with offending HCL and least-privilege fix.", ("devops",), "Review", None),
    ("gitops-guardrail/scopeguard-iam-guardrail.yml", "GitHub Actions workflow enforcing the IAM PR gate.", ("devops",), "Review", None),
    ("gitops-guardrail/remediated_patch.tf", "GitOps Terraform patch removing violating grants.", ("devops",), "Apply", None),
    ("gitops-guardrail/*.sarif.json", "GitOps SARIF (merged into scopeguard.sarif.json).", ("devops",), "Evidence", None),
    ("finding-remediation/ticket_proposed_remediation.md", "Ticket text: proposed remediation for review.", ("security", "devops"), "Review", None),
    ("finding-remediation/canary_step1_bind_least_privilege.sh", "Canary Step 1: bind least-privilege custom role alongside legacy role (dry-run default).", ("devops",), "Apply", None),
    ("finding-remediation/canary_step2_remove_broad_role.sh", "Canary Step 2: revoke legacy broad role after --verify confirms clean usage (dry-run default).", ("devops",), "Apply", None),
    ("finding-remediation/AUTHORITATIVE_TERRAFORM_WARNING.md", "Warning: authoritative Terraform replaces all members.", ("devops",), "Read", None),
    ("finding-remediation/ticket_verification_note.*", "Post-change verification note for ticket closure.", ("auditor",), "Evidence", None),
    ("bundles/*/REMEDIATION_PLAN.md", "Team-scoped remediation plan.", ("devops",), "Read", _ORCH),
    ("*.sh", "Executable runbook / command script (dry-run by default).", ("devops",), "Apply", None),
    ("*.tf", "Terraform configuration that changes IAM when applied.", ("devops",), "Apply", None),
    ("*.tfvars", "Terraform variables for the generated module.", ("devops",), "Apply", None),
    ("*.yml", "Workflow / pipeline definition.", ("devops",), "Review", None),
    ("*.yaml", "Configuration / role definition.", ("devops",), "Review", None),
    ("*.md", "Report / guide.", ("security", "devops"), "Read", None),
    ("*.sarif.json", "SARIF report.", ("devops",), "Evidence", None),
    ("*.json", "Machine-readable data.", ("auditor",), "Evidence", None),
    ("*.csv", "Tabular export.", ("auditor",), "Evidence", None),
)

_SKIP_NAMES = {MANIFEST_JSON, README_MD, ".DS_Store"}
_SKIP_DIRS = {"__pycache__", ".git", ".terraform"}


def sha256_file(path: Path, chunk: int = 1 << 16) -> str:
  """Streams a file through SHA-256 (constant memory for large bundles)."""
  h = hashlib.sha256()
  with path.open("rb") as fh:
    for block in iter(lambda: fh.read(chunk), b""):
      h.update(block)
  return h.hexdigest()


def classify(rel_path: str) -> Dict[str, Any]:
  """Returns purpose / audience / group / module / applies_changes for a file.

  Args:
    rel_path: POSIX path relative to the indexed directory.

  Returns:
    Classification dict.
  """
  name = rel_path.rsplit("/", 1)[-1]
  top = rel_path.split("/", 1)[0] if "/" in rel_path else ""
  purpose, audience, group, module = "Generated artifact.", ("devops",), "Evidence", None
  for pattern, p, a, g, m in _RULES:
    if fnmatch.fnmatchcase(rel_path, pattern) or ("/" not in pattern and fnmatch.fnmatchcase(name, pattern)):
      purpose, audience, group, module = p, a, g, m
      break
  if module is None:
    module = _FOLDER_MODULE.get(top, _ORCH)
  lower = name.lower()
  applies = lower.endswith((".sh", ".tf", ".tfvars"))
  if applies:
    group = "Apply"  # executable / plan-able content is always in the Apply group
  return {
      "purpose": purpose,
      "audience": list(audience),
      "group": group,
      "module": module,
      "applies_changes": applies,
  }


def _iter_files(root: Path, exclude_dirs: Iterable[str]) -> List[Path]:
  """Lists indexable files under `root`, skipping excluded/hidden folders."""
  excluded = {e.strip("/") for e in exclude_dirs}
  files: List[Path] = []
  for path in sorted(root.rglob("*")):
    if not path.is_file():
      continue
    rel_parts = path.relative_to(root).parts
    if rel_parts[0] in excluded or any(p in _SKIP_DIRS or p.startswith(".") for p in rel_parts):
      continue
    if len(rel_parts) == 1 and path.name in _SKIP_NAMES:
      continue
    files.append(path)
  return files


def build_manifest(
    root: Path,
    run_id: str = "",
    project_id: str = "",
    exclude_dirs: Iterable[str] = ("shareable", "bundles"),
) -> Dict[str, Any]:
  """Builds the manifest document for one output directory.

  Args:
    root: Directory to index.
    run_id: Run identifier.
    project_id: Target project (blank for sweep-level folders).
    exclude_dirs: Top-level sub-folders with their own manifest.

  Returns:
    Manifest dict (not yet written).
  """
  root = Path(root)
  entries: List[Dict[str, Any]] = []
  total = 0
  for path in _iter_files(root, exclude_dirs):
    rel = path.relative_to(root).as_posix()
    try:
      size = path.stat().st_size
      digest = sha256_file(path)
    except OSError:
      logger.exception("Cannot hash %s; skipping from manifest.", rel)
      continue
    total += size
    entry = {"path": rel, **classify(rel), "sha256": digest, "size_bytes": size}
    if rel in SCHEMA_EXEMPT:
      entry["schema_version_exempt"] = True
    entries.append(entry)
  entries.sort(key=lambda e: (GROUP_ORDER.index(e["group"]) if e["group"] in GROUP_ORDER else 9, e["path"]))
  return {
      "schema_version": SCHEMA_VERSION,
      "generated_at": utc_now_iso(),
      "run_id": run_id,
      "project_id": project_id,
      "root": root.name,
      "hash_algorithm": "sha256",
      "file_count": len(entries),
      "total_bytes": total,
      "apply_files_count": sum(1 for e in entries if e["applies_changes"]),
      "schema_version_exempt": [e["path"] for e in entries if e.get("schema_version_exempt")],
      "files": entries,
  }


def _human_size(n: int) -> str:
  """Compact size for README tables."""
  for unit in ("B", "KB", "MB"):
    if n < 1024:
      return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
    n /= 1024.0
  return f"{n:.1f} GB"


def render_readme(manifest: Dict[str, Any], title: str = "") -> str:
  """Renders the README.md index for a manifest.

  Args:
    manifest: Output of `build_manifest`.
    title: Optional heading override.

  Returns:
    Markdown text.
  """
  heading = title or (
      f"ScopeGuard outputs: `{manifest.get('project_id')}`" if manifest.get("project_id")
      else f"ScopeGuard outputs: `{manifest.get('root')}`"
  )
  lines = [
      f"# {heading}",
      "",
      f"- **Run ID**: `{manifest.get('run_id') or 'n/a'}`",
      f"- **Generated**: `{manifest.get('generated_at')}` · schema `{manifest.get('schema_version')}`",
      f"- **Files**: `{manifest.get('file_count')}` · ⚠️ apply files: `{manifest.get('apply_files_count')}`",
      "- **Integrity**: SHA-256 for every file is in `manifest.json` "
      "(verify with `shasum -a 256 <file>`).",
      "",
      "Audience legend: **security** = security leadership · **devops** = engineers applying "
      "changes · **auditor** = GRC / audit.",
      "",
      "> [!WARNING]",
      "> ⚠️ marks files that change IAM or infrastructure when executed / applied. "
      "Nothing in this folder has been applied; review, then apply in the order of "
      "`REMEDIATION_PLAN.md`.",
      "",
  ]
  files = manifest.get("files") or []
  for group in GROUP_ORDER:
    rows = [f for f in files if f.get("group") == group]
    if not rows:
      continue
    lines.extend([
        f"## {group}",
        "",
        _GROUP_BLURB[group],
        "",
        "| File | Purpose | Audience | Module | Size |",
        "| :--- | :--- | :--- | :--- | ---: |",
    ])
    for f in rows:
      mark = "⚠️ " if f.get("applies_changes") else ""
      lines.append(
          f"| {mark}[`{f['path']}`]({f['path']}) | {f['purpose']} | "
          f"{', '.join(f.get('audience') or [])} | `{f['module']}` | {_human_size(int(f['size_bytes']))} |"
      )
    lines.append("")
  return "\n".join(lines)


def write_artifact_index(
    root: Path,
    run_id: str = "",
    project_id: str = "",
    exclude_dirs: Iterable[str] = ("shareable", "bundles"),
    title: str = "",
) -> Dict[str, str]:
  """Writes `manifest.json` and `README.md` into `root`.

  Args:
    root: Directory to index.
    run_id: Run identifier.
    project_id: Target project.
    exclude_dirs: Top-level folders skipped (they get their own index).
    title: Optional README heading.

  Returns:
    Dict with `manifest` and `readme` paths (empty on failure).
  """
  root = Path(root)
  try:
    manifest = build_manifest(root, run_id, project_id, exclude_dirs)
    m_path = root / MANIFEST_JSON
    r_path = root / README_MD
    m_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
                      encoding="utf-8", newline="\n")
    r_path.write_text(render_readme(manifest, title) + "\n", encoding="utf-8", newline="\n")
    return {"manifest": str(m_path), "readme": str(r_path)}
  except OSError:
    logger.exception("Failed to write artifact index for %s", root)
    return {}


def verify_manifest(root: Path) -> List[str]:
  """Re-hashes files listed in `manifest.json`; returns mismatching paths.

  Args:
    root: Indexed directory.

  Returns:
    Relative paths that are missing or whose SHA-256 changed.
  """
  root = Path(root)
  manifest = json.loads((root / MANIFEST_JSON).read_text(encoding="utf-8"))
  bad: List[str] = []
  for entry in manifest.get("files") or []:
    path = root / entry["path"]
    if not path.is_file() or sha256_file(path) != entry.get("sha256"):
      bad.append(entry["path"])
  return bad


# -----------------------------------------------------------------------------
# Run finalisation (called by the orchestrator once per project output dir)
# -----------------------------------------------------------------------------
# Root-level copies written by pre-2.1 pipelines; the canonical files now live
# in `gitops-guardrail/` (and the unified `scopeguard.sarif.json`).
STALE_ROOT_DUPLICATES = {
    "gitops_guardrail.sarif.json": "gitops-guardrail/gitops_guardrail.sarif.json",
    "gitops_guardrail_results.json": "gitops-guardrail/gitops_guardrail_results.json",
    "scopeguard-iam-guardrail.yml": "gitops-guardrail/scopeguard-iam-guardrail.yml",
}
AUDIENCE_DOC_NAMES = ("EXECUTIVE_SUMMARY.md", "REMEDIATION_PLAN.md", "EVIDENCE.md")


def remove_stale_root_duplicates(out_dir: Path) -> List[str]:
  """Deletes legacy root-level duplicates only when the canonical copy exists.

  Args:
    out_dir: Run output directory.

  Returns:
    Relative names that were removed.
  """
  removed: List[str] = []
  for name, canonical in STALE_ROOT_DUPLICATES.items():
    dup, keep = Path(out_dir) / name, Path(out_dir) / canonical
    if dup.is_file() and keep.is_file():
      try:
        dup.unlink()
        removed.append(name)
        logger.info("Removed stale duplicate %s (canonical: %s)", name, canonical)
      except OSError:
        logger.warning("Could not remove stale duplicate %s", name)
  return removed


def finalize_run_outputs(
    envelope: Dict[str, Any],
    out_dir: Path,
    bundle_by: str = "",
    redact: bool = False,
) -> Dict[str, Any]:
  """Writes audience docs, exports, bundles, shareable copies and indexes.

  Order matters: content files first, then a provisional manifest whose
  hashes are cited in `EVIDENCE.md`, then the final README/manifest so the
  manifest also covers `EVIDENCE.md` itself.

  Args:
    envelope: Final assessment envelope for the project.
    out_dir: Project output directory.
    bundle_by: Optional `owner|folder|principal` (ART-9).
    redact: Write `shareable/` redacted copies (ART-14).

  Returns:
    Report of written paths, suitable for the pipeline JSON output.
  """
  out_dir = Path(out_dir)
  out_dir.mkdir(parents=True, exist_ok=True)
  run_id = str(envelope.get("run_id", ""))
  pid = str(envelope.get("project_id", ""))
  report: Dict[str, Any] = {"documents": {}, "exports": {}, "bundles": {}, "shareable": [],
                            "removed_duplicates": [], "errors": []}

  findings = exports.build_findings(envelope)
  try:
    docs = rs.render_audience_documents(envelope, findings)
  except Exception as exc:  # pylint: disable=broad-except
    logger.exception("Audience document rendering failed")
    report["errors"].append(f"documents: {exc}")
    docs = {}
  for name, text in docs.items():
    if name == "EVIDENCE.md":
      continue  # written below once artifact hashes are known
    path = out_dir / name
    path.write_text(text.rstrip("\n") + "\n", encoding="utf-8", newline="\n")
    report["documents"][name] = str(path)

  report["exports"] = exports.write_findings_exports(envelope, out_dir, findings)
  report["removed_duplicates"] = remove_stale_root_duplicates(out_dir)

  # EVIDENCE.md cites the hashes of everything else in the run folder.
  try:
    prelim = build_manifest(out_dir, run_id, pid)
    hashes = {e["path"]: e["sha256"] for e in prelim["files"] if e["path"] != "EVIDENCE.md"}
    evidence = rs.synthesize_evidence(envelope, None, findings, artifact_hashes=hashes)
    ev_path = out_dir / "EVIDENCE.md"
    ev_path.write_text(evidence.rstrip("\n") + "\n", encoding="utf-8", newline="\n")
    report["documents"]["EVIDENCE.md"] = str(ev_path)
  except Exception as exc:  # pylint: disable=broad-except
    logger.exception("EVIDENCE.md rendering failed")
    report["errors"].append(f"evidence: {exc}")

  if bundle_by:
    try:
      bundles = exports.write_bundles(envelope, out_dir, bundle_by, findings)
      for bdir in bundles:
        idx = write_artifact_index(Path(bdir), run_id, pid, exclude_dirs=(),
                                   title=f"ScopeGuard bundle `{Path(bdir).name}` ({bundle_by}) — `{pid}`")
        bundles[bdir] = bundles[bdir] + list(idx.values())
      report["bundles"] = bundles
    except ValueError as exc:
      report["errors"].append(f"bundles: {exc}")

  report["index"] = write_artifact_index(out_dir, run_id, pid)

  if redact:
    names = list(AUDIENCE_DOC_NAMES) + [f"scopeguard_recommendations_{pid}.md"] + [
        exports.FINDINGS_CSV, exports.FINDINGS_JSONL, exports.SCC_IMPORT_JSON, exports.SARIF_JSON,
    ]
    report["shareable"] = exports.write_shareable_copy(out_dir, names)
    share_idx = write_artifact_index(
        out_dir / "shareable", run_id, pid, exclude_dirs=(),
        title=f"ScopeGuard shareable (redacted) outputs — `{pid}`",
    )
    report["shareable"].extend(share_idx.values())
  return report
