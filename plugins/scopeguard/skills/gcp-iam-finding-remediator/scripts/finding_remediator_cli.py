#!/usr/bin/env python3
# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0

"""ScopeGuard Inbound SCC & Wiz Finding-to-Fix Remediator CLI.

Ingests Google Cloud Security Command Center (SCC) findings and/or Wiz
Issue / Attack Path JSON exports, correlates each finding with the live project
IAM policy, ScopeGuard evidence-based custom roles and break-glass simulator
results, and generates review-ready remediation deliverables:

* `terraform/` - complete, plan-able module (custom roles + non-authoritative
  grants + README on revoking old bindings) and `remediation_patch.tf`
  (single-file variant).                                              (ART-1)
* `remediation_commands.sh` - safe-by-default gcloud runbook (dry-run, etag
  preflight, ordered add -> verify -> remove, atomic rollback).       (ART-2)
* `ticket_proposed_remediation.md` - pre-change "proposed remediation" note.
  `--verify` later writes `ticket_verification_note.md` / `.json` from live,
  read-only state.                                                    (ART-8)

Every number in the outputs comes from data the CLI actually has; checks that
did not run are reported as `n/a (not run: <reason>)` instead of 0.  (ART-4)

The CLI is strictly read-only: it never calls an IAM-mutating API.
"""

import argparse
import json
import logging
import os
from pathlib import Path
import re
import shlex
import sys
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple
from urllib import error as urllib_error
from urllib import parse as urllib_parse
from urllib import request as urllib_request

PLUGIN_ROOT = Path(__file__).resolve().parents[3]
if str(PLUGIN_ROOT) not in sys.path:
  sys.path.insert(0, str(PLUGIN_ROOT))
# Sibling helper modules (remediator_terraform / remediator_verify). Inserted
# explicitly because the orchestrator loads this file via importlib.
SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
  sys.path.insert(0, str(SCRIPT_DIR))

from lib.envelope_schema import SCHEMA_VERSION, generate_run_identifiers, utc_now_iso  # noqa: E402
from lib.gcp_client import GCPHTTPError, ScopeGuardGCPClient  # noqa: E402
from lib.gcs_publisher import (  # noqa: E402
    GCSAssessmentStore,
    add_gcs_publish_arguments,
    run_skill_gcs_preflight,
)
from lib.runbook_shell import render_change_runbook  # noqa: E402
import remediator_terraform  # noqa: E402
import remediator_verify  # noqa: E402

LOGGER = logging.getLogger("scopeguard.finding_remediator")

# Plan statuses. Only READY / HOLD_SIMULATED_403 plans produce IaC/commands.
STATUS_READY = "READY"
STATUS_HOLD = "HOLD_SIMULATED_403"
STATUS_NO_EVIDENCE = "BLOCKED_NO_ROLE_EVIDENCE"
STATUS_INVALID = "BLOCKED_INVALID_INPUT"
STATUS_NO_CHANGE = "NO_CHANGE_NEEDED"
ACTIONABLE_STATUSES = (STATUS_READY, STATUS_HOLD)

PLAN_FILE_NAME = "finding_remediations.json"

# Strict allow-lists: finding JSON is untrusted input that ends up in shell
# scripts, HCL and Markdown, so anything outside these shapes is rejected.
_MEMBER_RE = re.compile(
    r"^(user|serviceAccount|group|domain|principal|principalSet|deleted:serviceAccount|"
    r"deleted:user|deleted:group):[A-Za-z0-9@._%+\-:/=]+$"
)
_ROLE_RE = re.compile(
    r"^(roles/[A-Za-z0-9_.]+|projects/[a-z][a-z0-9\-]{4,28}[a-z0-9]/roles/[A-Za-z0-9_.]+|"
    r"organizations/[0-9]+/roles/[A-Za-z0-9_.]+)$"
)
_ROLE_ID_RE = re.compile(r"^[A-Za-z0-9_.]{3,64}$")


# Patterns for deterministic attack-path choke-point selection.
_IMPERSONATION_PERMS = (
    "iam.serviceaccounts.actas",
    "iam.serviceaccounts.getaccesstoken",
    "iam.serviceaccounts.implicitdelegation",
    "iam.serviceaccounts.signblob",
    "iam.serviceaccounts.signjwt",
)
_IMPERSONATION_TOKENS = (
    "actas",
    "getaccesstoken",
    "impersonat",
    "can_impersonate",
    "serviceaccounttokencreator",
)
_BROAD_ADMIN_ROLE_RE = re.compile(
    r"^(roles/owner|roles/editor|roles/iam\..*Admin|roles/resourcemanager\..*Admin)$"
)
_SA_EMAIL_RE = re.compile(r"([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.gserviceaccount\.com)")


def _normalize_member(raw: str) -> str:
  val = (raw or "").strip()
  if not val:
    return ""
  if ":" in val:
    return val
  if val.endswith(".gserviceaccount.com"):
    return f"serviceAccount:{val}"
  return f"user:{val}"


def _extract_sa_from_text(text: str) -> str:
  """Extracts a normalized `serviceAccount:<email>` member from a resource URI or label."""
  match = _SA_EMAIL_RE.search(str(text or ""))
  return f"serviceAccount:{match.group(1)}" if match else ""


def _parse_attack_path_graph(raw_path: Any) -> Dict[str, Any]:
  """Normalizes SCC/Wiz attack-path payloads into `{nodes, edges, hops}`."""
  nodes: List[Dict[str, Any]] = []
  edges: List[Dict[str, Any]] = []
  hops: List[str] = []

  if not raw_path:
    return {"nodes": nodes, "edges": edges, "hops": hops}

  # Unwrap nested `graph` key (common in Wiz Attack Path exports).
  if isinstance(raw_path, Mapping):
    graph = raw_path.get("graph") if isinstance(raw_path.get("graph"), Mapping) else raw_path
    raw_nodes = graph.get("nodes") or graph.get("pathNodes") or []
    raw_edges = graph.get("edges") or graph.get("pathEdges") or []
    if not raw_nodes and isinstance(raw_path.get("nodes"), list):
      raw_nodes = raw_path.get("nodes") or []
    if not raw_edges and isinstance(raw_path.get("edges"), list):
      raw_edges = raw_path.get("edges") or []

    for idx, n in enumerate(raw_nodes):
      if isinstance(n, Mapping):
        label = str(
            n.get("displayName")
            or n.get("name")
            or n.get("resource")
            or n.get("id")
            or f"node-{idx}"
        )
        res_type = str(n.get("resourceType") or n.get("type") or "")
        principal = _normalize_member(str(n.get("principal") or n.get("member") or ""))
        if not principal:
          principal = _extract_sa_from_text(
              f"{n.get('resource', '')} {n.get('externalId', '')} {label}"
          )
        node_roles = [str(r) for r in (n.get("roles") or []) if r]
        if n.get("role") and str(n["role"]) not in node_roles:
          node_roles.append(str(n["role"]))
        nodes.append({
            "id": str(n.get("id") or n.get("resource") or label),
            "name": label,
            "resource_type": res_type,
            "principal": principal,
            "roles": node_roles,
            "is_entry": bool(n.get("isEntry") or n.get("is_entry") or idx == 0),
        })
        hops.append(label)
        # SCC attackPath nodes can carry inline `attackSteps` describing edges.
        for step in n.get("attackSteps") or []:
          if isinstance(step, Mapping):
            step_desc = str(step.get("displayName") or step.get("description") or step.get("type") or "")
            edges.append({
                "source": principal or label,
                "target": str(step.get("target") or step.get("destination") or "downstream"),
                "edge_type": str(step.get("type") or "ATTACK_STEP"),
                "permissions": [str(p) for p in (step.get("permissions") or []) if p],
                "role": str(step.get("role") or ""),
                "critical": bool(step.get("critical") or step.get("isCritical")),
                "label": step_desc,
            })
      else:
        s = str(n)
        nodes.append({"id": s, "name": s, "resource_type": "", "principal": _extract_sa_from_text(s), "roles": [], "is_entry": idx == 0})
        hops.append(s)

    for e in raw_edges:
      if not isinstance(e, Mapping):
        continue
      src = str(e.get("source") or e.get("from") or e.get("sourceNode") or "")
      dst = str(e.get("destination") or e.get("target") or e.get("to") or e.get("targetNode") or "")
      perms = [str(p) for p in (e.get("permissions") or []) if p]
      if e.get("permission") and str(e["permission"]) not in perms:
        perms.append(str(e["permission"]))
      edge_type = str(e.get("edgeType") or e.get("type") or e.get("action") or "")
      role = str(e.get("role") or "")
      label = str(e.get("label") or edge_type or (perms[0] if perms else role) or "edge")
      edges.append({
          "source": src,
          "target": dst,
          "edge_type": edge_type,
          "permissions": perms,
          "role": role,
          "critical": bool(e.get("critical") or e.get("isCritical")),
          "label": label,
      })
      if not hops and src and dst:
        hops.append(f"{src} --[{label}]--> {dst}")
    return {"nodes": nodes, "edges": edges, "hops": hops}

  if isinstance(raw_path, list):
    for idx, item in enumerate(raw_path):
      if isinstance(item, Mapping):
        label = str(
            item.get("displayName")
            or item.get("name")
            or item.get("resource")
            or item.get("label")
            or f"hop-{idx}"
        )
        principal = _normalize_member(str(item.get("principal") or item.get("member") or "")) or _extract_sa_from_text(label)
        item_roles = [str(r) for r in (item.get("roles") or []) if r]
        if item.get("role") and str(item["role"]) not in item_roles:
          item_roles.append(str(item["role"]))
        nodes.append({
            "id": str(item.get("id") or label),
            "name": label,
            "resource_type": str(item.get("resourceType") or item.get("type") or ""),
            "principal": principal,
            "roles": item_roles,
            "is_entry": idx == 0,
        })
        if item.get("source") and (item.get("target") or item.get("destination")):
          perms = [str(p) for p in (item.get("permissions") or []) if p]
          if item.get("permission"):
            perms.append(str(item["permission"]))
          edges.append({
              "source": str(item["source"]),
              "target": str(item.get("target") or item.get("destination")),
              "edge_type": str(item.get("edgeType") or item.get("type") or ""),
              "permissions": perms,
              "role": str(item.get("role") or ""),
              "critical": bool(item.get("critical") or item.get("isCritical")),
              "label": label,
          })
        hops.append(label)
      else:
        s = str(item)
        hops.append(s)
        nodes.append({
            "id": f"hop-{idx}",
            "name": s,
            "resource_type": "",
            "principal": _extract_sa_from_text(s),
            "roles": re.findall(r"roles/[A-Za-z0-9_.]+", s),
            "is_entry": idx == 0,
        })
    # Synthesize consecutive edges when a string-only hop list was supplied.
    if not edges and len(hops) >= 2:
      for i in range(len(hops) - 1):
        combined = f"{hops[i]} {hops[i + 1]}"
        found_roles = re.findall(r"roles/[A-Za-z0-9_.]+", combined)
        found_perms = re.findall(r"iam\.serviceAccounts\.[A-Za-z]+", combined)
        edges.append({
            "source": hops[i],
            "target": hops[i + 1],
            "edge_type": "HOP",
            "permissions": found_perms,
            "role": found_roles[0] if found_roles else "",
            "critical": False,
            "label": found_perms[0] if found_perms else (found_roles[0] if found_roles else "hop"),
        })
  return {"nodes": nodes, "edges": edges, "hops": hops}


def _select_choke_point(
    attack_path: Any,
    analysis_data: Optional[Mapping[str, Any]] = None,
    principal: str = "",
    offending_roles: Sequence[str] = (),
) -> Optional[Dict[str, Any]]:
  """Deterministically selects the minimum-disruption IAM choke-point edge.

  Priority order:
    1. Prefer severing an `iam.serviceAccounts.actAs` / `getAccessToken`
       impersonation edge on a non-critical edge (`critical=False`).
    2. Otherwise, replace a broad basic/admin role (`roles/owner`,
       `roles/editor`, `roles/iam.*Admin`) on the entry SA with its
       evidence-backed `sg_persona_*` role from `analysis_data`.
    3. Fallback: pick the first IAM-bearing edge (or first hop transition) so
       attack paths always receive deterministic choke-point guidance.

  Args:
    attack_path: Normalized `{nodes, edges, hops}` dict, raw attackPath dict,
      or list of hop strings/dicts.
    analysis_data: ScopeGuard `recommender_audit` analysis dict containing
      `principal_mappings` (optional).
    principal: Fallback principal from the inbound finding.
    offending_roles: Fallback offending roles from the inbound finding.

  Returns:
    Dict with `{choke_point_edge, choke_point_strategy, rationale, hops}` or
    None when no attack path is present.
  """
  if isinstance(attack_path, Mapping) and "edges" in attack_path and "nodes" in attack_path:
    graph = {
        "nodes": list(attack_path.get("nodes") or []),
        "edges": list(attack_path.get("edges") or []),
        "hops": list(attack_path.get("hops") or []),
    }
  else:
    graph = _parse_attack_path_graph(attack_path)

  nodes = graph["nodes"]
  edges = graph["edges"]
  hops = graph["hops"]
  if not nodes and not edges and not hops:
    return None

  # Priority 1: non-critical service account impersonation edge (actAs / getAccessToken).
  for edge in edges:
    if edge.get("critical"):
      continue
    perms = [str(p) for p in (edge.get("permissions") or [])]
    perms_lower = [p.lower() for p in perms]
    edge_text = " ".join([
        str(edge.get("edge_type") or ""),
        str(edge.get("label") or ""),
        " ".join(perms),
    ]).lower()
    is_impersonation = any(p in _IMPERSONATION_PERMS for p in perms_lower) or any(
        tok in edge_text for tok in _IMPERSONATION_TOKENS
    )
    if is_impersonation:
      action = perms[0] if perms else (edge.get("label") or edge.get("edge_type") or "iam.serviceAccounts.actAs")
      src = _safe_text(edge.get("source") or "entry-principal", 100)
      dst = _safe_text(edge.get("target") or "target-sa", 100)
      return {
          "choke_point_edge": f"{src} --[{_safe_text(action, 80)}]--> {dst}",
          "choke_point_strategy": "sever_impersonation_edge",
          "rationale": (
              f"Minimum-disruption choke point: severing non-critical impersonation edge "
              f"`{_safe_text(action, 80)}` from `{src}` to `{dst}` breaks lateral movement "
              "along the attack path without disrupting primary workload permissions."
          ),
          "hops": hops,
      }

  # Priority 2: broad basic/admin role on the entry SA -> evidence-backed sg_persona_*.
  pm_by_member = {
      str(pm.get("principal") or ""): pm
      for pm in ((analysis_data or {}).get("principal_mappings") or [])
  }
  candidate_principals: List[Tuple[str, List[str]]] = []
  for node in nodes:
    node_principal = str(node.get("principal") or "")
    if node_principal:
      candidate_principals.append((node_principal, list(node.get("roles") or [])))
  if principal:
    candidate_principals.append((principal, list(offending_roles)))

  # Also collect roles mentioned on edges for each principal.
  edge_roles: List[str] = [str(e.get("role")) for e in edges if e.get("role")]
  for cand_principal, cand_roles in candidate_principals:
    combined_roles = list(dict.fromkeys(cand_roles + list(offending_roles) + edge_roles))
    broad_roles = [r for r in combined_roles if _BROAD_ADMIN_ROLE_RE.match(r)]
    if not broad_roles:
      continue
    broad_role = broad_roles[0]
    pm = pm_by_member.get(cand_principal, {})
    persona_id = str(pm.get("persona_role_id") or "")
    target_mapping = str(pm.get("target_mapping") or "")
    if persona_id.startswith("sg_persona_"):
      replacement_label = persona_id
    elif "sg_persona_" in target_mapping:
      replacement_label = target_mapping.rsplit("/", 1)[-1]
    else:
      replacement_label = ""
    if replacement_label:
      return {
          "choke_point_edge": f"{_safe_text(cand_principal, 100)} --[{broad_role} -> {replacement_label}]--> project",
          "choke_point_strategy": "replace_broad_role_with_persona",
          "rationale": (
              f"Minimum-disruption choke point: replacing broad role `{broad_role}` on entry "
              f"principal `{_safe_text(cand_principal, 100)}` with evidence-backed least-privilege "
              f"role `{replacement_label}` severs privilege escalation while preserving exercised API calls."
          ),
          "hops": hops,
      }
    return {
        "choke_point_edge": f"{_safe_text(cand_principal, 100)} --[{broad_role} -> sg_persona_*]--> project",
        "choke_point_strategy": "replace_broad_role_with_persona",
        "rationale": (
            f"Minimum-disruption choke point: broad role `{broad_role}` on entry principal "
            f"`{_safe_text(cand_principal, 100)}` enables privilege escalation; run `recommender_audit` "
            "to synthesize its evidence-backed `sg_persona_*` replacement role."
        ),
        "hops": hops,
    }

  # Fallback: select the first edge or hop transition deterministically.
  if edges:
    e0 = edges[0]
    src = _safe_text(e0.get("source") or "source", 100)
    dst = _safe_text(e0.get("target") or "target", 100)
    lbl = _safe_text(e0.get("label") or e0.get("role") or e0.get("edge_type") or "edge", 80)
    return {
        "choke_point_edge": f"{src} --[{lbl}]--> {dst}",
        "choke_point_strategy": "general_iam_edge",
        "rationale": (
            f"No non-critical impersonation edge or broad basic/admin role was matched; "
            f"selected the earliest attack-path edge (`{lbl}`) for review and least-privilege scoping."
        ),
        "hops": hops,
    }
  return {
      "choke_point_edge": " -> ".join(_safe_text(h, 80) for h in hops[:2]),
      "choke_point_strategy": "general_iam_edge",
      "rationale": "Selected the entry transition of the reported attack path for least-privilege scoping.",
      "hops": hops,
  }


def normalize_inbound_finding(raw_doc: Dict[str, Any], source_hint: str = "") -> Dict[str, Any]:
  """Normalizes an SCC Finding / Toxic Combination or Wiz Issue / Attack Path JSON."""
  # Unwrap SCC wrapper objects like `{"finding": {...}, "attackPath": {...}}`.
  inner = raw_doc.get("finding") if isinstance(raw_doc.get("finding"), Mapping) else raw_doc

  hint = source_hint.lower().strip()
  has_scc_markers = (
      "sourceProperties" in inner
      or "toxicCombination" in inner
      or "attackExposure" in inner
      or "iamBindings" in inner
      or str(inner.get("name", "")).startswith(("organizations/", "projects/", "folders/"))
  )
  has_wiz_markers = (
      str(raw_doc.get("source", "")).lower() == "wiz"
      or "entitySnapshot" in raw_doc
      or "issueId" in raw_doc
      or ("graph" in raw_doc and not has_scc_markers)
  )
  if hint == "wiz":
    is_wiz = True
  elif hint == "scc":
    is_wiz = False
  elif has_wiz_markers:
    is_wiz = True
  elif has_scc_markers:
    is_wiz = False
  else:
    is_wiz = "attackPath" in raw_doc

  if is_wiz:
    entity = raw_doc.get("entitySnapshot") or {}
    raw_ap = (
        raw_doc.get("attackPath")
        if raw_doc.get("attackPath") is not None
        else (raw_doc.get("graph") or ({"edges": raw_doc["edges"]} if raw_doc.get("edges") else None))
    )
    ap_graph = _parse_attack_path_graph(raw_ap)
    principal = _normalize_member(
        entity.get("externalId") or entity.get("name") or raw_doc.get("principal", "")
    )
    if not principal:
      principal = next((n["principal"] for n in ap_graph["nodes"] if n.get("principal")), "")
    ctrl = raw_doc.get("control") or {}
    roles = list(raw_doc.get("roles") or [])
    if not roles:
      for n in ap_graph["nodes"]:
        for r in n.get("roles") or []:
          if r not in roles:
            roles.append(r)
      for e in ap_graph["edges"]:
        r = e.get("role")
        if r and r not in roles:
          roles.append(r)
    finding_id = str(raw_doc.get("id") or raw_doc.get("issueId") or "wiz-finding-unknown")
    return {
        "source_platform": "Wiz",
        "finding_id": finding_id,
        "category": ctrl.get("id") or ctrl.get("name") or "WIZ_IAM_ISSUE",
        "title": ctrl.get("name") or raw_doc.get("title") or "Wiz GCP IAM Security Issue",
        "severity": str(raw_doc.get("severity", "HIGH")).upper(),
        "principal": principal,
        "offending_roles": roles,
        "attack_path": ap_graph["hops"],
        "attack_path_graph": ap_graph,
        "attack_exposure_score": raw_doc.get("exposureScore"),
        "source_guidance": raw_doc.get("remediationGuidance") or "",
    }

  # Cloud SCC Finding / Toxic Combination / Attack Exposure JSON schema.
  sp = inner.get("sourceProperties") or {}
  bindings = inner.get("iamBindings") or []
  toxic = inner.get("toxicCombination") or raw_doc.get("toxicCombination") or {}
  exposure = inner.get("attackExposure") or raw_doc.get("attackExposure") or {}
  raw_ap = (
      inner.get("attackPath")
      or raw_doc.get("attackPath")
      or sp.get("attackPath")
      or toxic.get("attackPath")
      or exposure.get("attackPath")
  )
  ap_graph = _parse_attack_path_graph(raw_ap)

  principal = _normalize_member(
      sp.get("Principal")
      or sp.get("principal")
      or (bindings[0].get("member", "") if bindings else "")
  )
  if not principal:
    principal = next((n["principal"] for n in ap_graph["nodes"] if n.get("principal")), "")

  roles: List[str] = list(sp.get("Roles") or sp.get("roles") or [])
  for b in bindings:
    r = b.get("role", "")
    if r and r not in roles:
      roles.append(r)
  if not roles:
    for n in ap_graph["nodes"]:
      for r in n.get("roles") or []:
        if r not in roles:
          roles.append(r)
    for e in ap_graph["edges"]:
      r = e.get("role")
      if r and r not in roles:
        roles.append(r)

  exposure_score = (
      toxic.get("attackExposureScore")
      if isinstance(toxic, Mapping) and toxic.get("attackExposureScore") is not None
      else (exposure.get("score") if isinstance(exposure, Mapping) else None)
  )

  finding_name = str(inner.get("name", "scc-finding"))
  short_id = finding_name.rsplit("/", 1)[-1]
  return {
      "source_platform": "Google Cloud SCC",
      "finding_id": short_id,
      "category": str(inner.get("category", "IAM_OVERPRIVILEGED")),
      "title": f"SCC {inner.get('category', 'IAM Finding')} on {principal or 'project'}",
      "severity": str(inner.get("severity", "HIGH")).upper(),
      "principal": principal,
      "offending_roles": roles,
      "attack_path": ap_graph["hops"],
      "attack_path_graph": ap_graph,
      "attack_exposure_score": exposure_score,
      "source_guidance": sp.get("Recommendation") or "",
  }


def fetch_live_scc_iam_findings(
    project_id: str, gcp_client: ScopeGuardGCPClient
) -> List[Dict[str, Any]]:
  """Queries Cloud SCC API for active IAM findings; degrades gracefully if disabled.

  Passes `include_quota_project=True` (required by securitycenter.googleapis.com
  under ADC) and filters server-side for IAM/identity/attack-path categories so
  high-volume container CVE findings do not crowd out IAM findings.
  """
  iam_tokens = (
      "IAM", "ROLE", "SERVICE_ACCOUNT", "KEY", "ADMIN",
      "OWNER", "EDITOR", "TOXIC", "ATTACK", "DELEGATION",
  )
  base_url = (
      "https://securitycenter.googleapis.com/v1/projects/"
      f"{urllib_parse.quote(project_id, safe='')}/sources/-/findings"
  )
  iam_filter = (
      'state="ACTIVE" AND ('
      'category:"IAM" OR category:"SERVICE_ACCOUNT" OR category:"ADMIN" '
      'OR category:"OWNER" OR category:"EDITOR" OR category:"ROLE" '
      'OR category:"API_KEY" OR category:"TOXIC" OR category:"ATTACK")'
  )
  urls = [
      f"{base_url}?filter={urllib_parse.quote(iam_filter, safe='')}&pageSize=100",
      f"{base_url}?filter={urllib_parse.quote('state=\"ACTIVE\"', safe='')}&pageSize=100",
  ]
  last_exc: Optional[Exception] = None
  for idx, url in enumerate(urls):
    try:
      resp = gcp_client.request_json(
          url=url,
          method="GET",
          service_key="securitycenter",
          include_quota_project=True,
      )
      out: List[Dict[str, Any]] = []
      for item in resp.get("listFindingsResults", []):
        finding = item.get("finding", {})
        cat = str(finding.get("category", "")).upper()
        if any(tok in cat for tok in iam_tokens):
          out.append(normalize_inbound_finding(finding, source_hint="scc"))
      return out
    except GCPHTTPError as exc:
      last_exc = exc
      # Fall back to the simpler filter only on HTTP 400 (filter syntax);
      # on 403/404 there is no reason to retry with a broader filter.
      if exc.status_code == 400 and idx == 0:
        continue
      break
    except (RuntimeError, OSError) as exc:
      last_exc = exc
      break
  LOGGER.warning("Live SCC findings unavailable for %s: %s", project_id, last_exc)
  return []


_WIZ_DEFAULT_AUTH_URL = "https://auth.app.wiz.io/oauth/token"
_WIZ_IAM_TOKENS = (
    "IAM", "ROLE", "SERVICE_ACCOUNT", "SERVICE ACCOUNT", "KEY", "ADMIN",
    "OWNER", "EDITOR", "PRIVILEGE", "ESCALAT", "IMPERSONAT", "FEDERAT",
    "WIF", "IDENTITY", "PERMISSION", "PRINCIPAL", "ACCESS",
)
_WIZ_ISSUES_GQL = """
query ScopeGuardGcpIssues($first: Int, $filterBy: IssueFilters) {
  issues(first: $first, filterBy: $filterBy) {
    nodes {
      id
      severity
      status
      createdAt
      control { id name description }
      entitySnapshot {
        id
        type
        name
        nativeType
        subscriptionExternalId
        providerId
      }
      serviceTickets { externalId name url }
    }
  }
}
"""


def fetch_live_wiz_iam_findings(
    project_id: str, timeout_seconds: int = 20
) -> List[Dict[str, Any]]:
  """Queries Wiz GraphQL API for open GCP IAM issues when Wiz env vars are set.

  Requires `WIZ_CLIENT_ID`, `WIZ_CLIENT_SECRET`, and `WIZ_API_URL` (e.g.
  `https://api.us1.app.wiz.io/graphql`). Optional `WIZ_AUTH_URL` defaults to
  `https://auth.app.wiz.io/oauth/token`. Silently returns `[]` when credentials
  are not configured; degrades gracefully on HTTP/network errors without ever
  logging secrets or tokens.
  """
  client_id = os.environ.get("WIZ_CLIENT_ID", "").strip()
  client_secret = os.environ.get("WIZ_CLIENT_SECRET", "").strip()
  api_url = os.environ.get("WIZ_API_URL", "").strip()
  auth_url = os.environ.get("WIZ_AUTH_URL", _WIZ_DEFAULT_AUTH_URL).strip() or _WIZ_DEFAULT_AUTH_URL
  if not (client_id and client_secret and api_url):
    return []
  # Enforce HTTPS to prevent accidental plaintext credential transmission.
  if not (api_url.startswith("https://") and auth_url.startswith("https://")):
    LOGGER.warning("Live Wiz query skipped: WIZ_API_URL and WIZ_AUTH_URL must use https://")
    return []

  try:
    token_body = urllib_parse.urlencode({
        "grant_type": "client_credentials",
        "audience": "wiz-api",
        "client_id": client_id,
        "client_secret": client_secret,
    }).encode("utf-8")
    token_req = urllib_request.Request(
        auth_url,
        data=token_body,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
    )
    with urllib_request.urlopen(token_req, timeout=timeout_seconds) as resp:
      token_data = json.loads(resp.read().decode("utf-8"))
    access_token = str(token_data.get("access_token") or "")
    if not access_token:
      LOGGER.warning("Live Wiz auth returned no access_token for %s", project_id)
      return []

    gql_payload = json.dumps({
        "query": _WIZ_ISSUES_GQL,
        "variables": {
            "first": 100,
            "filterBy": {
                "status": ["OPEN", "IN_PROGRESS"],
                "relatedEntity": {"cloudPlatform": ["GCP"]},
            },
        },
    }).encode("utf-8")
    gql_req = urllib_request.Request(
        api_url,
        data=gql_payload,
        method="POST",
        headers={
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    with urllib_request.urlopen(gql_req, timeout=timeout_seconds) as resp:
      gql_resp = json.loads(resp.read().decode("utf-8"))
  except (urllib_error.HTTPError, urllib_error.URLError, TimeoutError, ValueError, OSError) as exc:
    LOGGER.warning("Live Wiz findings unavailable for %s: %s", project_id, exc)
    return []

  nodes = ((gql_resp.get("data") or {}).get("issues") or {}).get("nodes") or []
  out: List[Dict[str, Any]] = []
  pid_lower = project_id.lower()
  for node in nodes:
    if not isinstance(node, dict):
      continue
    snap = node.get("entitySnapshot") or {}
    sub_id = str(snap.get("subscriptionExternalId") or snap.get("providerId") or "").lower()
    ent_name = str(snap.get("name") or "").lower()
    if pid_lower not in sub_id and pid_lower not in ent_name:
      continue
    ctrl = node.get("control") or {}
    haystack = " ".join([
        str(ctrl.get("name") or ""),
        str(ctrl.get("description") or ""),
        str(snap.get("type") or ""),
        str(snap.get("nativeType") or ""),
    ]).upper()
    if any(tok in haystack for tok in _WIZ_IAM_TOKENS):
      out.append(normalize_inbound_finding(node, source_hint="wiz"))
  return out


# ---------------------------------------------------------------------------
# Input sanitising helpers
# ---------------------------------------------------------------------------


def _safe_text(value: Any, limit: int = 160) -> str:
  """Flattens untrusted text for comments/titles (no newlines or shell metachars)."""
  text = re.sub(r"[\r\n\t]+", " ", str(value or ""))
  text = re.sub(r"[`$\\\"'<>|;&]", "", text)
  return text.strip()[:limit]


def _safe_change_id(finding_id: str, used: Dict[str, int]) -> str:
  """Builds a unique, shell/HCL-safe change ID derived from the finding ID."""
  base = re.sub(r"[^A-Za-z0-9._-]", "-", finding_id or "").strip("-.")[:60] or "finding"
  used[base] = used.get(base, 0) + 1
  return base if used[base] == 1 else f"{base}-{used[base]}"


def _binding_key(binding: Mapping[str, Any]) -> str:
  """Stable identity of a (role, condition) binding."""
  cond = binding.get("condition") or {}
  return json.dumps([binding.get("role", ""), cond.get("expression", "")], sort_keys=True)


def _clean_condition(cond: Optional[Mapping[str, Any]]) -> Optional[Dict[str, str]]:
  """Keeps only title/expression/description of an IAM condition."""
  if not cond or not cond.get("expression"):
    return None
  out = {"title": str(cond.get("title") or "scopeguard_condition"), "expression": str(cond["expression"])}
  if cond.get("description"):
    out["description"] = str(cond["description"])
  return out


# ---------------------------------------------------------------------------
# Custom role resolution
# ---------------------------------------------------------------------------


def parse_role_yaml(text: str) -> Dict[str, Any]:
  """Parses the flat custom-role YAML written by ScopeGuard (stdlib only).

  Supports the exact shape produced by `write_yaml_role`: scalar `title`,
  `description`, `stage` keys and an `includedPermissions` block list.
  """
  out: Dict[str, Any] = {"includedPermissions": []}
  in_perms = False
  for raw in text.splitlines():
    line = raw.rstrip()
    if not line.strip() or line.lstrip().startswith("#"):
      continue
    if in_perms and line.lstrip().startswith("- "):
      out["includedPermissions"].append(line.lstrip()[2:].strip().strip("'\""))
      continue
    in_perms = False
    if ":" in line and not line.startswith(" "):
      key, val = line.split(":", 1)
      key, val = key.strip(), val.strip()
      if key == "includedPermissions":
        in_perms = True
        continue
      if len(val) >= 2 and val[0] == val[-1] and val[0] in "'\"":
        val = val[1:-1]
      out[key] = val
  return out


def _find_role_yaml(output_dir: Optional[Path], role_id: str) -> Optional[Path]:
  """Locates an existing ScopeGuard role YAML for `role_id`.

  Searches the remediator output dir and its parent (the run output dir used
  by the orchestrator) under `custom-roles/personas`, `custom-roles/capabilities`
  and the legacy `custom-roles/` folder.
  """
  if not output_dir or not _ROLE_ID_RE.match(role_id or ""):
    return None
  for base in (output_dir, output_dir.parent):
    for sub in ("custom-roles/personas", "custom-roles/capabilities", "custom-roles"):
      candidate = base / sub / f"{role_id}.yaml"
      if candidate.is_file():
        return candidate
  return None


def _resolve_target(pm: Mapping[str, Any], project_id: str) -> Tuple[str, str]:
  """Returns (custom_role_id, predefined_role) targeted by a principal mapping."""
  persona = str(pm.get("persona_role_id") or "")
  if _ROLE_ID_RE.match(persona):
    return persona, ""
  mapping = str(pm.get("target_mapping") or "").strip()
  match = re.match(r"^projects/([^/]+)/roles/([A-Za-z0-9_.]+)$", mapping)
  if match:
    return match.group(2), ""
  if _ROLE_RE.match(mapping) and mapping.startswith("roles/"):
    return "", mapping
  if ":" in mapping:  # legacy "Custom role: <id> (...)"
    cand = mapping.split(":", 1)[1].strip().split(" ", 1)[0].strip("`")
    if _ROLE_ID_RE.match(cand):
      return cand, ""
  return "", ""


def _resolve_role_spec(
    role_id: str,
    analysis: Mapping[str, Any],
    output_dir: Optional[Path],
    project_id: str,
) -> Optional[Dict[str, Any]]:
  """Builds {role_id, title, description, stage, permissions, source, yaml_path}.

  Preference: on-disk YAML (exactly what reviewers saw) > envelope analysis.
  Returns None when no evidence-based definition exists; the remediator never
  fabricates permission sets.
  """
  if not role_id:
    return None
  yaml_path = _find_role_yaml(output_dir, role_id)
  if yaml_path:
    try:
      doc = parse_role_yaml(yaml_path.read_text(encoding="utf-8"))
      if doc.get("includedPermissions"):
        return {
            "role_id": role_id,
            "title": doc.get("title") or role_id,
            "description": doc.get("description") or "",
            "stage": doc.get("stage") or "GA",
            "permissions": sorted(set(doc["includedPermissions"])),
            "source": f"yaml:{yaml_path.name}",
            "yaml_path": yaml_path,
        }
    except OSError as exc:
      LOGGER.warning("Unable to read role YAML %s: %s", yaml_path, exc)
  for key in ("custom_roles_model_a", "custom_roles_model_b_disjoint"):
    roles = analysis.get(key) or {}
    spec = roles.get(role_id)
    if not spec:
      spec = next((s for s in roles.values() if s.get("role_id") == role_id), None)
    if spec and spec.get("includedPermissions"):
      return {
          "role_id": spec.get("role_id", role_id),
          "title": spec.get("title") or role_id,
          "description": spec.get("description") or "",
          "stage": spec.get("stage") or "GA",
          "permissions": sorted(set(spec["includedPermissions"])),
          "source": f"envelope:{key}",
          "yaml_path": None,
      }
  return None


def _write_role_yaml(path: Path, spec: Mapping[str, Any], project_id: str) -> None:
  """Writes a gcloud-compatible custom role YAML (same shape as recommender audit)."""
  def _q(val: Any) -> str:
    return json.dumps(str(val or ""))  # JSON strings are valid YAML scalars

  lines = [
      f"# Custom IAM Role Definition for project: {project_id}",
      f"# Role ID: {spec['role_id']}",
      f"title: {_q(spec.get('title'))}",
      f"description: {_q(spec.get('description'))}",
      f"stage: {_q(spec.get('stage') or 'GA')}",
      "includedPermissions:",
  ] + [f"  - {p}" for p in spec.get("permissions") or []]
  path.parent.mkdir(parents=True, exist_ok=True)
  path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# Simulator correlation (ART-4)
# ---------------------------------------------------------------------------


def _extract_audit_log_confidence(simulation_data: Optional[Mapping[str, Any]]) -> Optional[str]:
  """Extracts the worst-case `audit_log_confidence` (LOW < MEDIUM < HIGH) from simulation data."""
  if not isinstance(simulation_data, Mapping):
    return None
  candidates: List[str] = []
  for container in (
      simulation_data,
      simulation_data.get("summary") or {},
      simulation_data.get("payload") or {},
  ):
    if isinstance(container, Mapping) and container.get("audit_log_confidence"):
      candidates.append(str(container["audit_log_confidence"]).strip().upper())
  payload = simulation_data.get("payload") or {}
  if isinstance(payload, Mapping):
    for r in payload.get("principal_replays") or []:
      if isinstance(r, Mapping) and r.get("audit_log_confidence"):
        candidates.append(str(r["audit_log_confidence"]).strip().upper())
  if not candidates:
    return None
  # Conservative ordering: if any level reports LOW, treat the run as LOW.
  for level in ("LOW", "MEDIUM", "HIGH"):
    if level in candidates:
      return level
  return candidates[0]


def _simulation_index(simulation_data: Optional[Mapping[str, Any]]) -> Tuple[Dict[str, Dict[str, Any]], str, Dict[str, Any]]:
  """Indexes break-glass simulator replays by principal.

  Accepts a module entry (`{status, summary, payload}`) or the raw
  `breakglass_simulation.json` document (`{summary, payload}`).

  Returns:
    (replays_by_principal, not_run_reason, summary). `not_run_reason` is empty
    when simulator data is available.
  """
  if not simulation_data:
    return {}, "break-glass simulator results not available for this run", {}
  status = str(simulation_data.get("status", "COMPLETED"))
  if status not in ("COMPLETED", ""):
    return {}, f"break-glass simulator status is {status}", {}
  payload = simulation_data.get("payload") or {}
  replays = payload.get("principal_replays")
  if replays is None:
    return {}, "simulator payload has no principal_replays", {}
  index = {str(r.get("principal", "")): dict(r) for r in replays if r.get("principal")}
  return index, "", dict(simulation_data.get("summary") or {})


def _na(reason: str) -> str:
  """Standard ART-4 marker for checks that did not run."""
  return f"n/a (not run: {reason})"


# ---------------------------------------------------------------------------
# Plan building
# ---------------------------------------------------------------------------


def _gcloud_cmd(verb: str, project_id: str, member: str, binding: Mapping[str, Any]) -> str:
  """Human-readable gcloud command (for portal display / plan JSON)."""
  cond = _clean_condition(binding.get("condition"))
  cond_arg = (
      "--condition=None"
      if not cond
      else f"--condition-from-file=<condition {shlex.quote(cond['title'])}.json>"
  )
  return (
      f"gcloud projects {verb}-iam-policy-binding {shlex.quote(project_id)} "
      f"--member={shlex.quote(member)} --role={shlex.quote(binding['role'])} {cond_arg}"
  )


def build_remediation_plans(
    project_id: str,
    inbound_findings: Sequence[Mapping[str, Any]],
    analysis_data: Optional[Mapping[str, Any]],
    policy: Mapping[str, Any],
    simulation_data: Optional[Mapping[str, Any]],
    output_dir: Optional[Path],
) -> Tuple[List[Dict[str, Any]], Dict[str, Dict[str, Any]], Dict[str, Any]]:
  """Correlates findings with policy, roles and simulator data.

  Returns:
    (plans, custom_roles_by_id, simulation_context).
  """
  analysis = analysis_data or {}
  policy_available = bool(policy.get("bindings") or policy.get("etag"))
  live_by_member: Dict[str, List[Dict[str, Any]]] = {}
  for b in policy.get("bindings") or []:
    entry = {"role": b.get("role", "")}
    cond = _clean_condition(b.get("condition"))
    if cond:
      entry["condition"] = cond
    for m in b.get("members") or []:
      live_by_member.setdefault(m, []).append(entry)

  pm_by_member = {
      pm.get("principal", ""): pm for pm in analysis.get("principal_mappings") or []
  }
  sim_index, sim_reason, sim_summary = _simulation_index(simulation_data)
  audit_log_confidence = _extract_audit_log_confidence(simulation_data)
  roles: Dict[str, Dict[str, Any]] = {}
  plans: List[Dict[str, Any]] = []
  used_ids: Dict[str, int] = {}

  for finding in inbound_findings:
    finding_id = str(finding.get("finding_id") or "unknown")
    principal = str(finding.get("principal") or "")
    ap_input = finding.get("attack_path_graph") or finding.get("attack_path") or []
    choke = _select_choke_point(
        ap_input,
        analysis_data=analysis,
        principal=principal,
        offending_roles=finding.get("offending_roles") or (),
    )
    attack_path_summary: Optional[Dict[str, Any]] = None
    if choke:
      attack_path_summary = {
          "hops": choke["hops"],
          "hop_count": len(choke["hops"]),
          "source_tool": finding.get("source_platform", "External"),
          "inbound_finding_id": finding_id,
          "choke_point_edge": choke["choke_point_edge"],
          "choke_point_strategy": choke["choke_point_strategy"],
          "rationale": choke["rationale"],
      }
      if finding.get("attack_exposure_score") is not None:
        attack_path_summary["attack_exposure_score"] = finding["attack_exposure_score"]

    plan: Dict[str, Any] = {
        "source_platform": finding.get("source_platform", "External"),
        "finding_id": finding_id,
        "change_id": _safe_change_id(finding_id, used_ids),
        "category": finding.get("category", ""),
        "title": _safe_text(finding.get("title"), 200),
        "severity": str(finding.get("severity") or "HIGH").upper(),
        "principal": principal,
        "attack_path": list(finding.get("attack_path") or []),
        "attack_path_summary": attack_path_summary,
        "source_guidance": finding.get("source_guidance", ""),
        "add_bindings": [],
        "remove_bindings": [],
        "already_absent_roles": [],
        "rejected_roles": [],
        "replacement_role": "",
        "replacement_permissions_count": 0,
        "replacement_role_source": "",
        "status": STATUS_READY,
        "status_reason": "",
        "policy_source": "live_policy" if policy_available else "finding_or_assessment_snapshot",
    }
    plans.append(plan)

    if not _MEMBER_RE.match(principal):
      plan["status"] = STATUS_INVALID
      plan["status_reason"] = "Principal is missing or not a valid IAM member string."
      plan["offending_roles"] = []
      _attach_simulation(plan, sim_index, sim_reason)
      continue

    raw_roles = [str(r) for r in finding.get("offending_roles") or []]
    offending = [r for r in raw_roles if _ROLE_RE.match(r)]
    plan["rejected_roles"] = [r for r in raw_roles if not _ROLE_RE.match(r)]
    pm = pm_by_member.get(principal, {})
    if not offending:
      offending = [b["role"] for b in live_by_member.get(principal, [])]
    plan["offending_roles"] = offending

    # Replacement role: evidence-based custom role, or predefined target.
    role_id, predefined = _resolve_target(pm, project_id)
    spec = _resolve_role_spec(role_id, analysis, output_dir, project_id)
    if spec:
      roles[spec["role_id"]] = spec
      replacement = f"projects/{project_id}/roles/{spec['role_id']}"
      plan["replacement_permissions_count"] = len(spec["permissions"])
      plan["replacement_role_source"] = spec["source"]
    elif predefined:
      replacement = predefined
      plan["replacement_role_source"] = "principal_mapping:predefined_role"
    else:
      plan["status"] = STATUS_NO_EVIDENCE
      plan["status_reason"] = (
          "No evidence-based replacement role for this principal (run the "
          "recommender_audit stage first). ScopeGuard does not fabricate "
          "permission sets; no IaC or commands were generated."
      )
      _attach_simulation(plan, sim_index, sim_reason)
      continue
    plan["replacement_role"] = replacement

    # Old bindings to revoke - condition-aware, from the live policy when we
    # have it, otherwise from the assessment snapshot / finding.
    offending_set = {r for r in offending if r != replacement}
    if policy_available:
      live = live_by_member.get(principal, [])
      removes = [b for b in live if b["role"] in offending_set]
      plan["already_absent_roles"] = sorted(offending_set - {b["role"] for b in live})
      replacement_bound = any(b["role"] == replacement for b in live)
    else:
      before = [
          {"role": b.get("role", ""), **({"condition": _clean_condition(b.get("condition"))} if _clean_condition(b.get("condition")) else {})}
          for b in pm.get("bindings_before") or []
      ]
      removes = [b for b in before if b["role"] in offending_set] or [
          {"role": r} for r in sorted(offending_set)
      ]
      replacement_bound = False
    dedup: Dict[str, Dict[str, Any]] = {}
    for b in removes:
      dedup.setdefault(_binding_key(b), b)
    plan["remove_bindings"] = list(dedup.values())

    if not plan["remove_bindings"] and replacement_bound:
      plan["status"] = STATUS_NO_CHANGE
      plan["status_reason"] = "Offending roles are already absent and the replacement role is bound."
      _attach_simulation(plan, sim_index, sim_reason)
      continue

    # Preserve the scope of the old access: if EVERY removed binding carries the
    # same condition, the replacement inherits it (never broader than before).
    add: Dict[str, Any] = {"role": replacement}
    conds = [b.get("condition") for b in plan["remove_bindings"]]
    if conds and all(conds) and len({json.dumps(c, sort_keys=True) for c in conds}) == 1:
      add["condition"] = conds[0]
    if not replacement_bound:
      plan["add_bindings"] = [add]
    _attach_simulation(plan, sim_index, sim_reason)
    if isinstance(plan["simulated_403_denials"], int) and plan["simulated_403_denials"] > 0:
      plan["status"] = STATUS_HOLD
      plan["status_reason"] = (
          f"Break-glass simulator replay found {plan['simulated_403_denials']} simulated HTTP 403 "
          "denial(s) for this principal. Add the missing permissions before removing old access."
      )

  sim_context = {
      "available": not sim_reason,
      "not_run_reason": sim_reason,
      "summary": sim_summary,
      "audit_log_confidence": audit_log_confidence,
  }
  return plans, roles, sim_context


def _attach_simulation(plan: Dict[str, Any], sim_index: Mapping[str, Any], sim_reason: str) -> None:
  """Copies the principal's simulator verdict onto the plan (ART-4)."""
  if sim_reason:
    plan["simulated_403_denials"] = None
    plan["simulated_403_display"] = _na(sim_reason)
    plan["simulation_verdict"] = None
    return
  replay = sim_index.get(plan.get("principal", ""))
  if not replay:
    plan["simulated_403_denials"] = None
    plan["simulated_403_display"] = _na("principal not included in the simulator replay")
    plan["simulation_verdict"] = None
    return
  denials = int(replay.get("simulated_403_denials") or 0)
  plan["simulated_403_denials"] = denials
  plan["simulation_verdict"] = replay.get("verdict")
  plan["simulation_replay_coverage_pct"] = replay.get("replay_coverage_pct")
  plan["simulation_replayed_api_calls"] = replay.get("replayed_api_calls")
  plan["simulation_uncovered_permissions"] = list(replay.get("uncovered_permissions") or [])
  plan["simulation_role_simulated"] = replay.get("proposed_model_a_role")
  plan["simulated_403_display"] = (
      f"{denials} simulated HTTP 403(s) over {replay.get('replayed_api_calls', 'n/a')} replayed "
      f"call(s) for this principal (coverage {replay.get('replay_coverage_pct', 'n/a')}%, "
      f"verdict {replay.get('verdict', 'n/a')})"
  )


# ---------------------------------------------------------------------------
# Ticket note (ART-8 proposed remediation)
# ---------------------------------------------------------------------------


def _roles_md(bindings: Sequence[Mapping[str, Any]]) -> str:
  """Formats bindings as Markdown inline code, marking conditional ones."""
  out = []
  for b in bindings:
    cond = b.get("condition")
    out.append("`" + str(b["role"]) + "`" + (f" (condition: `{cond.get('title')}`)" if cond else ""))
  return ", ".join(out) or "none"


def _attack_path_choke_point_md(summary: Mapping[str, Any]) -> List[str]:
  """Renders the Attack-Path Choke-Point block for ticket_proposed_remediation.md."""
  block = [
      "",
      "**Attack-Path Choke-Point**",
      f"- Source tool: `{summary.get('source_tool', 'External')}` (inbound finding `{summary.get('inbound_finding_id', 'unknown')}`)",
  ]
  if summary.get("attack_exposure_score") is not None:
    block.append(f"- Attack exposure score: `{summary['attack_exposure_score']}`")
  if summary.get("hops"):
    block.append("- Path hops: " + " -> ".join(_safe_text(h, 120) for h in summary["hops"]))
  block += [
      f"- Choke-point edge: `{summary.get('choke_point_edge', 'n/a')}`",
      f"- Rationale: {summary.get('rationale', '')}",
  ]
  return block


def render_proposed_ticket(
    project_id: str,
    run_id: str,
    generated_at: str,
    etag: str,
    plans: Sequence[Mapping[str, Any]],
    sim_context: Mapping[str, Any],
    canary: bool = False,
    canary_reason: str = "",
) -> Tuple[str, Dict[str, str]]:
  """Renders ticket_proposed_remediation.md and per-finding note snippets."""
  sim_sum = sim_context.get("summary") or {}
  audit_conf = sim_context.get("audit_log_confidence")
  project_sim = (
      f"{sim_sum.get('simulated_403_denials', 'n/a')} simulated HTTP 403(s) project-wide "
      f"(verdict {sim_sum.get('cutover_verdict', 'n/a')})"
      if sim_context.get("available") else _na(sim_context.get("not_run_reason", "unknown"))
  )
  lines = [
      f"# Proposed remediation (PRE-CHANGE) - `{project_id}`",
      "",
      "> [!IMPORTANT]",
      "> This note describes a PROPOSED change. Do not close the external finding until",
      "> the change is applied and `finding_remediator_cli.py --verify` reports `VERIFIED`",
      "> (see `ticket_verification_note.md`).",
      "",
      f"- **Generated (UTC)**: {generated_at}  **Run**: `{run_id}`",
      f"- **Policy etag at assessment**: `{etag or 'n/a (live policy not read)'}`",
      f"- **Break-glass simulator (project-wide)**: {project_sim}",
  ]
  if audit_conf:
    lines.append(f"- **Audit log confidence**: `{audit_conf}`")
  lines += [
      "- **Change owner**: `<name / team>`  **Approver**: `<name>`  **Change ticket**: `<JIRA/SNOW-ID>`",
      "- **Planned change window (UTC)**: `<YYYY-MM-DD HH:MM>`",
      "",
  ]
  if canary:
    reason_label = (
        "auto-recommended because `audit_log_confidence == LOW`"
        if "low" in canary_reason
        else "requested via `--canary`"
    )
    lines += [
        "## Dual-Bind Canary Cutover (2-Step Zero-Breakage Rollout)",
        "",
        f"Canary cutover mode is **ENABLED** ({reason_label}). Execute in two safe phases:",
        "",
        "1. **Step 1 — Dual-Bind Least Privilege (`canary_step1_bind_least_privilege.sh`)**:",
        "   Creates the evidence-backed `sg_persona_*` custom role(s) and binds them **alongside**",
        "   existing broad roles (zero breakage risk; dry-run by default, pass `--apply` to execute).",
        "2. **Step 2 — Verify & Remove Broad Role (`canary_step2_remove_broad_role.sh`)**:",
        "   Observe workloads for 24–72h and run",
        f"   `python3 finding_remediator_cli.py --project {project_id} --output-dir <this dir> --verify --verify-hours 24`.",
        "   Once clean usage is confirmed, run `./canary_step2_remove_broad_role.sh` (dry-run)",
        "   and then `./canary_step2_remove_broad_role.sh --apply` to remove the old broad role(s).",
        "",
    ]
  notes: Dict[str, str] = {}
  for p in plans:
    block = [
        f"## [{p['source_platform']}] `{p['finding_id']}` - {p['title']} ({p['severity']})",
        "",
        f"- **External finding ID**: `{p['finding_id']}` ({p['source_platform']}, category `{_safe_text(p.get('category'))}`)",
        f"- **Principal**: `{p['principal']}`",
        f"- **Status**: `{p['status']}`" + (f" - {p['status_reason']}" if p.get("status_reason") else ""),
        f"- **Finding owner**: `<owner>`  **Workload owner**: `<owner>`",
        "",
    ]
    if p["status"] in ACTIONABLE_STATUSES:
      block += [
          "**What**",
          f"- Grant: {_roles_md(p['add_bindings']) if p['add_bindings'] else 'none (replacement already bound)'}"
          + (f" ({p['replacement_permissions_count']} permissions, source `{p['replacement_role_source']}`)" if p["replacement_permissions_count"] else ""),
          f"- Revoke (after verification): {_roles_md(p['remove_bindings'])}",
      ]
      if p.get("already_absent_roles"):
        block.append(f"- Already absent in live policy (no action): {', '.join('`' + r + '`' for r in p['already_absent_roles'])}")
      block += [
          "",
          "**Why**",
          f"- {_safe_text(p.get('source_guidance'), 400) or 'Reported as over-privileged by ' + p['source_platform'] + '.'}",
      ]
      if p.get("attack_path"):
        block.append("- Attack path: " + " -> ".join(_safe_text(s, 120) for s in p["attack_path"]))
      if p.get("attack_path_summary"):
        block += _attack_path_choke_point_md(p["attack_path_summary"])
      block += [
          "",
          "**Risk**",
          f"- Break-glass replay for this principal: {p['simulated_403_display']}",
      ]
      if p.get("simulation_uncovered_permissions"):
        block.append("- Uncovered permissions: " + ", ".join("`" + x + "`" for x in p["simulation_uncovered_permissions"][:20]))
      if p.get("simulation_role_simulated") and p.get("replacement_role") and not str(p["replacement_role"]).endswith("/" + str(p["simulation_role_simulated"])):
        block.append(f"- Note: simulator replayed `{p['simulation_role_simulated']}`, not `{p['replacement_role']}`; re-run the simulator if they differ.")
      block += [
          "",
          "**Rollback**",
          "- `remediation_commands.sh` writes a full `get-iam-policy` backup before the first change; restore with",
          "  `./remediation_commands.sh --rollback <backup.json>` (etag-pinned `set-iam-policy`, restores conditions).",
          f"- Per-finding manual inverse: re-add {_roles_md(p['remove_bindings'])} and remove "
          f"{_roles_md(p['add_bindings'])} (commands in `finding_remediations.json` -> `rollback_commands`).",
          "",
          "**Verification steps**",
          f"1. Dry-run: `./remediation_commands.sh --only {p['change_id']}` (or `terraform plan` in `terraform/`).",
          f"2. Apply grants: `./remediation_commands.sh --apply --only {p['change_id']} --phase add`; let workloads run.",
          f"3. Revoke old access: `./remediation_commands.sh --apply --only {p['change_id']} --phase remove`.",
          f"4. Evidence: `python3 finding_remediator_cli.py --project {project_id} --output-dir <this dir> --verify --verify-hours 24`.",
          "5. Close the external finding only if its verification result is `VERIFIED`.",
          "",
      ]
    else:
      if p.get("attack_path_summary"):
        block += _attack_path_choke_point_md(p["attack_path_summary"])
        block.append("")
      block += ["No change is proposed for this finding; see status above.", ""]
    notes[p["finding_id"]] = "\n".join(block)
    lines += block
  if not plans:
    lines.append("No inbound findings were supplied.")
  return "\n".join(lines) + "\n", notes


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def run_finding_remediator(
    project_id: str,
    inbound_findings: List[Dict[str, Any]],
    analysis_data: Optional[Dict[str, Any]] = None,
    policy_data: Optional[Dict[str, Any]] = None,
    gcp_client: Optional[ScopeGuardGCPClient] = None,
    output_dir: Optional[Path] = None,
    simulation_data: Optional[Dict[str, Any]] = None,
    authoritative: bool = False,
    run_id: str = "",
    canary: bool = False,
) -> Dict[str, Any]:
  """Correlates inbound SCC/Wiz findings with ScopeGuard telemetry and builds fixes.

  Args:
    project_id: Target project.
    inbound_findings: Normalised findings (see `normalize_inbound_finding`).
    analysis_data: `modules.recommender_audit.payload.analysis` (optional).
    policy_data: Live IAM policy (fetched read-only when omitted).
    gcp_client: Client used when the policy must be fetched.
    output_dir: Where deliverables are written (nothing is written if None).
    simulation_data: break-glass simulator module entry or
      `breakglass_simulation.json` content, used for real 403 numbers.
    authoritative: Opt in to authoritative `google_project_iam_binding`.
    run_id: Run identifier for provenance (generated when empty).
    canary: Emit 2-step dual-bind canary cutover scripts (also auto-enabled
      when `simulation_data` reports `audit_log_confidence == "LOW"`).

  Returns:
    Module entry `{summary, payload, status}`.
  """
  generated_at = utc_now_iso()
  run_id = run_id or generate_run_identifiers("finding-remediator")["run_id"]
  policy = policy_data or {}
  policy_error = ""
  if not policy:
    try:
      client = gcp_client or ScopeGuardGCPClient(quota_project=project_id)
      policy = client.fetch_project_iam_policy(project_id)
    except Exception as exc:  # pylint: disable=broad-except
      policy_error = f"{getattr(exc, 'status_code', '') or type(exc).__name__}: {str(exc)[:200]}"
      LOGGER.warning("Live IAM policy unavailable; using finding data only: %s", policy_error)
      policy = {}
  etag = str(policy.get("etag") or "")

  plans, roles, sim_context = build_remediation_plans(
      project_id, inbound_findings, analysis_data, policy, simulation_data, output_dir
  )
  actionable = [p for p in plans if p["status"] in ACTIONABLE_STATUSES]
  blocked = [p for p in plans if p["status"] not in ACTIONABLE_STATUSES]

  # Dual-bind canary mode: explicit --canary or auto-recommended on LOW audit log confidence.
  audit_log_confidence = sim_context.get("audit_log_confidence")
  canary_auto = audit_log_confidence == "LOW"
  canary_enabled = bool(canary or canary_auto)
  if canary and canary_auto:
    canary_reason = "explicit_and_low_confidence"
  elif canary:
    canary_reason = "explicit_flag"
  elif canary_auto:
    canary_reason = "auto_low_audit_log_confidence"
  else:
    canary_reason = "disabled"

  # Role YAMLs referenced by the runbook (relative to the script directory).
  roles_to_create: List[Dict[str, str]] = []
  for role_id in sorted(roles):
    spec = roles[role_id]
    if spec.get("yaml_path") and output_dir:
      rel = os.path.relpath(spec["yaml_path"], output_dir)
    else:
      rel = f"custom-roles/personas/{role_id}.yaml"
      if output_dir:
        _write_role_yaml(output_dir / rel, spec, project_id)
    spec["yaml_relpath"] = rel
    roles_to_create.append({"role_id": role_id, "yaml_path": rel})

  # ART-1: Terraform module + single-file patch.
  tf_files = remediator_terraform.render_terraform_module(
      project_id,
      actionable,
      roles,
      blocked=blocked,
      authoritative=authoritative,
      canary=canary_enabled,
      canary_reason=canary_reason,
  )
  # ART-2: safe gcloud runbook, one change per finding.
  changes = []
  for p in actionable:
    verify = [f"Finding {p['finding_id']} ({p['source_platform']}, {p['severity']})."]
    verify.append(f"Break-glass replay: {p['simulated_403_display']}.")
    if p["status"] == STATUS_HOLD:
      verify.append("HOLD: simulated 403s found - do NOT run --phase remove until the role is fixed.")
    verify.append("Confirm workloads are healthy before removing old bindings.")
    changes.append({
        "id": p["change_id"],
        "title": _safe_text(f"{p['source_platform']} {p['severity']}: {p['principal']}", 120),
        "principal": p["principal"],
        "add": p["add_bindings"],
        "remove": p["remove_bindings"],
        "verify": "\n".join(_safe_text(v, 300) for v in verify),
    })
  runbook = render_change_runbook(
      project_id=project_id,
      run_id=run_id,
      title=f"ScopeGuard SCC/Wiz finding remediation - {project_id}",
      changes=changes,
      expected_etag=etag,
      roles_to_create=roles_to_create,
      script_name="remediation_commands.sh",
  )

  # Optional 2-step Dual-Bind Canary scripts (dry-run by default with --apply).
  canary_scripts: Dict[str, str] = {}
  if canary_enabled:
    step1_changes = [
        {
            "id": c["id"],
            "title": c["title"],
            "principal": c["principal"],
            "add": c["add"],
            "remove": [],
            "verify": "Canary Step 1: dual-bind least-privilege role alongside existing broad role (zero breakage risk).",
        }
        for c in changes
    ]
    step2_changes = [
        {
            "id": c["id"],
            "title": c["title"],
            "principal": c["principal"],
            "add": [],
            "remove": c["remove"],
            "verify": "Canary Step 2: run finding_remediator_cli.py --verify to confirm clean usage before removing broad roles.",
        }
        for c in changes
    ]
    canary_scripts["canary_step1_bind_least_privilege.sh"] = render_change_runbook(
        project_id=project_id,
        run_id=run_id,
        title=f"ScopeGuard Canary Step 1 (Dual-Bind Least Privilege) - {project_id}",
        changes=step1_changes,
        expected_etag=etag,
        roles_to_create=roles_to_create,
        script_name="canary_step1_bind_least_privilege.sh",
    )
    canary_scripts["canary_step2_remove_broad_role.sh"] = render_change_runbook(
        project_id=project_id,
        run_id=run_id,
        title=f"ScopeGuard Canary Step 2 (Remove Broad Roles After --verify) - {project_id}",
        changes=step2_changes,
        expected_etag="",
        roles_to_create=[],
        script_name="canary_step2_remove_broad_role.sh",
    )

  ticket_md, ticket_notes = render_proposed_ticket(
      project_id,
      run_id,
      generated_at,
      etag,
      plans,
      sim_context,
      canary=canary_enabled,
      canary_reason=canary_reason,
  )

  # Per-plan portal fields (back-compatible keys).
  for p in plans:
    p["apply_commands"] = [_gcloud_cmd("add", project_id, p["principal"], b) for b in p["add_bindings"]] + [
        _gcloud_cmd("remove", project_id, p["principal"], b) for b in p["remove_bindings"]
    ]
    p["rollback_commands"] = [_gcloud_cmd("add", project_id, p["principal"], b) for b in p["remove_bindings"]] + [
        _gcloud_cmd("remove", project_id, p["principal"], b) for b in p["add_bindings"]
    ]
    if p["status"] in ACTIONABLE_STATUSES:
      p["strategy"] = (
          f"Grant `{p['replacement_role']}` then revoke {len(p['remove_bindings'])} broad binding(s) "
          f"after verification."
      )
      p["terraform_hcl"] = remediator_terraform.render_terraform_module(
          project_id, [p], {k: v for k, v in roles.items() if p["replacement_role"].endswith("/" + k)},
          authoritative=authoritative,
      )["terraform/main.tf"]
    else:
      p["strategy"] = p["status_reason"]
      p["terraform_hcl"] = ""
    p["ticket_closure_note"] = ticket_notes.get(p["finding_id"], "")

  # ART-4: totals only from data that exists; None + display text otherwise.
  with_sim = [p["simulated_403_denials"] for p in actionable if isinstance(p.get("simulated_403_denials"), int)]
  if with_sim:
    sim_total: Optional[int] = sum(with_sim)
    sim_display = f"{sim_total} simulated HTTP 403(s) across {len(with_sim)} of {len(actionable)} remediated principal(s)"
  else:
    sim_total = None
    sim_display = _na(sim_context["not_run_reason"] or "no remediated principal was included in the simulator replay")
  if not plans:
    readiness = "NO_FINDINGS_SUPPLIED"
  elif not actionable:
    readiness = "BLOCKED_NO_ACTIONABLE_PLANS"
  elif any(p["status"] == STATUS_HOLD for p in actionable):
    readiness = "HOLD_SIMULATED_403"
  else:
    readiness = "READY_FOR_PR_REVIEW"
  summary = {
      "findings_ingested": len(plans),
      "findings_actionable": len(actionable),
      "findings_blocked": len(blocked),
      "status_counts": {s: sum(1 for p in plans if p["status"] == s) for s in sorted({p["status"] for p in plans})},
      "sources_integrated": sorted({p["source_platform"] for p in plans}),
      # Kept for backward compatibility: count of CRITICAL/HIGH findings with
      # a PROPOSED (not yet applied) fix.
      "critical_or_high_fixed": sum(1 for p in actionable if p["severity"] in ("CRITICAL", "HIGH")),
      "critical_or_high_actionable": sum(1 for p in actionable if p["severity"] in ("CRITICAL", "HIGH")),
      "simulated_403_denials": sim_total,
      "simulated_403_display": sim_display,
      "simulation_available": sim_context["available"],
      "audit_log_confidence": audit_log_confidence,
      "canary_mode": canary_enabled,
      "canary_reason": canary_reason,
      "attack_paths_analyzed": sum(1 for p in plans if p.get("attack_path_summary")),
      "custom_roles_in_module": len(roles),
      "terraform_mode": "authoritative" if authoritative else "non_authoritative",
      "live_policy_etag": etag,
      "policy_read_error": policy_error,
      "remediation_readiness": readiness,
  }
  artifacts = {
      "terraform_module_dir": "terraform/",
      "terraform_files": sorted(k for k in tf_files if k.startswith("terraform/")),
      "remediation_patch_tf": "remediation_patch.tf",
      "remediation_commands_sh": "remediation_commands.sh",
      "ticket_proposed_remediation_md": "ticket_proposed_remediation.md",
      "role_yamls": {r["role_id"]: r["yaml_path"] for r in roles_to_create},
      "plan_json": PLAN_FILE_NAME,
  }
  if canary_enabled:
    artifacts["canary_step1_script"] = "canary_step1_bind_least_privilege.sh"
    artifacts["canary_step2_script"] = "canary_step2_remove_broad_role.sh"
  if authoritative:
    artifacts["authoritative_warning"] = "AUTHORITATIVE_TERRAFORM_WARNING.md"
  payload = {
      "schema_version": SCHEMA_VERSION,
      "generated_at": generated_at,
      "run_id": run_id,
      "live_policy_etag": etag,
      "remediation_plans": plans,
      "remediation_terraform_hcl": tf_files["remediation_patch.tf"],
      "remediation_runbook_sh": runbook,
      "canary_scripts": canary_scripts,
      "ticket_proposed_remediation_md": ticket_md,
      # Back-compat key consumed by the portal download button.
      "ticket_closure_notes_md": ticket_md,
      "simulation_context": sim_context,
      "artifacts": artifacts,
  }

  if output_dir:
    _write_outputs(
        output_dir,
        project_id,
        tf_files,
        runbook,
        ticket_md,
        summary,
        payload,
        authoritative,
        canary_scripts=canary_scripts,
    )

  return {"summary": summary, "payload": payload, "status": "COMPLETED"}


def _write_outputs(
    output_dir: Path,
    project_id: str,
    tf_files: Mapping[str, str],
    runbook: str,
    ticket_md: str,
    summary: Mapping[str, Any],
    payload: Mapping[str, Any],
    authoritative: bool,
    canary_scripts: Optional[Mapping[str, str]] = None,
) -> None:
  """Writes every deliverable to `output_dir` (errors are logged and re-raised)."""
  try:
    output_dir.mkdir(parents=True, exist_ok=True)
    for rel, content in tf_files.items():
      path = output_dir / rel
      path.parent.mkdir(parents=True, exist_ok=True)
      path.write_text(content, encoding="utf-8")
    sh_path = output_dir / "remediation_commands.sh"
    sh_path.write_text(runbook, encoding="utf-8")
    sh_path.chmod(0o755)
    for cname, cbody in (canary_scripts or {}).items():
      cpath = output_dir / cname
      cpath.write_text(cbody, encoding="utf-8")
      cpath.chmod(0o755)
    (output_dir / "ticket_proposed_remediation.md").write_text(ticket_md, encoding="utf-8")
    # The pre-change note used to be named like a closure statement (ART-8).
    stale = output_dir / "ticket_closure_notes.md"
    if stale.exists():
      stale.unlink()
    if authoritative:
      warning = remediator_terraform.AUTHORITATIVE_WARNING
      (output_dir / "AUTHORITATIVE_TERRAFORM_WARNING.md").write_text(
          f"# Authoritative Terraform warning - `{project_id}`\n\n{warning}\n", encoding="utf-8"
      )
      print(f"\n!!! {warning}\n", file=sys.stderr)
    doc = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": payload["generated_at"],
        "run_id": payload["run_id"],
        "project_id": project_id,
        "live_policy_etag": payload["live_policy_etag"],
        "summary": summary,
        "payload": payload,
    }
    (output_dir / PLAN_FILE_NAME).write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
  except OSError as exc:
    LOGGER.error("Failed writing remediation outputs to %s: %s", output_dir, exc)
    raise


def run_verify_mode(
    project_id: str,
    output_dir: Path,
    gcp_client: Any,
    hours: int = 24,
    plan_file: Optional[Path] = None,
) -> Dict[str, Any]:
  """Implements `--verify`: read-only post-change verification (ART-8).

  Args:
    project_id: Target project.
    output_dir: Directory holding `finding_remediations.json`; the
      verification note and JSON are written here.
    gcp_client: Client for the live policy read and Cloud Logging query.
    hours: PERMISSION_DENIED lookback window.
    plan_file: Override path to the plan JSON.

  Returns:
    The verification document that was written.
  """
  plan_path = plan_file or (output_dir / PLAN_FILE_NAME)
  plans: List[Dict[str, Any]] = []
  assessment_etag = ""
  audit_log_confidence: Optional[str] = None
  load_error = ""
  try:
    doc = json.loads(plan_path.read_text(encoding="utf-8"))
    payload = doc.get("payload") or {}
    doc_summary = doc.get("summary") or {}
    plans = list(payload.get("remediation_plans") or [])
    assessment_etag = str(doc.get("live_policy_etag") or payload.get("live_policy_etag") or "")
    sim_ctx = payload.get("simulation_context") or {}
    audit_log_confidence = (
        doc_summary.get("audit_log_confidence")
        or sim_ctx.get("audit_log_confidence")
        or (sim_ctx.get("summary") or {}).get("audit_log_confidence")
    )
  except (OSError, ValueError) as exc:
    load_error = f"Could not load remediation plan {plan_path}: {exc}"
    LOGGER.error(load_error)

  report = remediator_verify.run_verification(
      project_id=project_id,
      plans=plans,
      assessment_etag=assessment_etag,
      fetch_policy=lambda: gcp_client.fetch_project_iam_policy(project_id),
      gcp_client=gcp_client,
      hours=hours,
      audit_log_confidence=audit_log_confidence,
  )
  generated_at = utc_now_iso()
  report["plan_load_error"] = load_error
  out = {"schema_version": SCHEMA_VERSION, "generated_at": generated_at, **report}
  note = remediator_verify.render_verification_note(report, generated_at)
  if load_error:
    note = f"> [!WARNING]\n> {load_error}\n\n" + note
  try:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "ticket_verification_note.md").write_text(note, encoding="utf-8")
    (output_dir / "ticket_verification_note.json").write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
  except OSError as exc:
    LOGGER.error("Failed writing verification note: %s", exc)
  return out


def _load_docs(text: str) -> List[Dict[str, Any]]:
  """Parses a JSON finding document or list of documents."""
  doc = json.loads(text)
  return doc if isinstance(doc, list) else [doc]


def main() -> int:
  logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
  parser = argparse.ArgumentParser(
      description="Ingest SCC & Wiz IAM findings and generate reviewable least-privilege fixes."
  )
  parser.add_argument("--project", required=True, help="Target GCP Project ID.")
  parser.add_argument("--scc-finding-file", default="", help="Path to Cloud SCC Finding JSON file.")
  parser.add_argument("--wiz-issue-file", default="", help="Path to Wiz Issue / Attack Path JSON file.")
  parser.add_argument("--finding-json", default="", help="Raw inline SCC or Wiz JSON string.")
  parser.add_argument(
      "--fetch-live-scc",
      dest="fetch_live_scc",
      action="store_true",
      default=None,
      help="Pull live active IAM findings from Security Command Center API (auto-enabled when no finding file is passed).",
  )
  parser.add_argument(
      "--no-fetch-live-scc",
      dest="fetch_live_scc",
      action="store_false",
      help="Disable live Security Command Center API lookup.",
  )
  parser.add_argument(
      "--fetch-live-wiz",
      dest="fetch_live_wiz",
      action="store_true",
      default=None,
      help="Pull live open GCP IAM issues from Wiz GraphQL API when WIZ_CLIENT_ID, WIZ_CLIENT_SECRET, and WIZ_API_URL are set (auto-enabled when configured).",
  )
  parser.add_argument(
      "--no-fetch-live-wiz",
      dest="fetch_live_wiz",
      action="store_false",
      help="Disable live Wiz GraphQL API lookup even when Wiz env vars are set.",
  )
  parser.add_argument("--output-dir", required=True, help="Directory to write remediation patch & notes.")
  parser.add_argument(
      "--envelope-file", default="",
      help="Local assessment envelope (latest.json) supplying recommender_audit analysis and "
           "breakglass_simulator results when GCS is not used.",
  )
  parser.add_argument(
      "--simulation-file", default="",
      help="Local breakglass_simulation.json for real simulated-403 numbers.",
  )
  parser.add_argument(
      "--authoritative", action="store_true",
      help="Emit AUTHORITATIVE google_project_iam_binding resources (removes unlisted members). "
           "Default is non-authoritative google_project_iam_member.",
  )
  parser.add_argument(
      "--canary", action="store_true",
      help="Emit 2-step dual-bind canary cutover scripts (canary_step1_bind_least_privilege.sh "
           "and canary_step2_remove_broad_role.sh). Auto-enabled when audit_log_confidence == LOW.",
  )
  parser.add_argument(
      "--verify", action="store_true",
      help="Post-change verification (read-only): re-read the live policy and audit logs for the "
           "plans in --output-dir and write ticket_verification_note.md/.json.",
  )
  parser.add_argument("--verify-hours", type=int, default=24, help="PERMISSION_DENIED lookback for --verify (hours).")
  parser.add_argument("--plan-file", default="", help=f"Override path to {PLAN_FILE_NAME} for --verify.")
  add_gcs_publish_arguments(parser)
  args = parser.parse_args()

  gcp_client = ScopeGuardGCPClient(quota_project=args.project)
  output_dir = Path(args.output_dir)

  if args.verify:
    # Verification is local evidence generation: no GCS preflight/publish.
    result = run_verify_mode(
        project_id=args.project,
        output_dir=output_dir,
        gcp_client=gcp_client,
        hours=max(1, args.verify_hours),
        plan_file=Path(args.plan_file) if args.plan_file else None,
    )
    print(json.dumps({"finding_remediator_verification": result.get("summary"),
                      "note": str(output_dir / "ticket_verification_note.md")}, indent=2))
    return 0 if result.get("summary", {}).get("failed", 0) == 0 else 3

  store = GCSAssessmentStore(gcp_client=gcp_client)
  gcs_check = run_skill_gcs_preflight(args, args.project, store=store)

  inbound: List[Dict[str, Any]] = []
  try:
    if args.scc_finding_file:
      inbound.extend(normalize_inbound_finding(d, "scc") for d in _load_docs(Path(args.scc_finding_file).read_text(encoding="utf-8")))
    if args.wiz_issue_file:
      inbound.extend(normalize_inbound_finding(d, "wiz") for d in _load_docs(Path(args.wiz_issue_file).read_text(encoding="utf-8")))
    if args.finding_json:
      inbound.extend(normalize_inbound_finding(d) for d in _load_docs(args.finding_json))
  except (OSError, ValueError) as exc:
    LOGGER.error("Unable to read inbound findings: %s", exc)
    return 2
  has_file_input = bool(args.scc_finding_file or args.wiz_issue_file or args.finding_json)
  auto_scc = args.fetch_live_scc if args.fetch_live_scc is not None else (not has_file_input)
  auto_wiz = args.fetch_live_wiz if args.fetch_live_wiz is not None else (not has_file_input)
  if auto_scc:
    inbound.extend(fetch_live_scc_iam_findings(args.project, gcp_client))
  if auto_wiz:
    inbound.extend(fetch_live_wiz_iam_findings(args.project))

  # Prior assessment: local envelope file wins, else GCS latest.json.
  prior: Dict[str, Any] = {}
  if args.envelope_file:
    try:
      prior = json.loads(Path(args.envelope_file).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
      LOGGER.warning("Ignoring unreadable --envelope-file: %s", exc)
  elif gcs_check:
    prior = store.get_json_object(gcs_check["bucket"], f"{args.project}/latest.json") or {}
  modules = (prior or {}).get("modules", {})
  analysis_data = modules.get("recommender_audit", {}).get("payload", {}).get("analysis")
  simulation_data = modules.get("breakglass_simulator") or None
  if args.simulation_file:
    try:
      simulation_data = json.loads(Path(args.simulation_file).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
      LOGGER.warning("Ignoring unreadable --simulation-file: %s", exc)

  policy_data: Dict[str, Any] = {}
  try:
    policy_data = gcp_client.fetch_project_iam_policy(args.project)
  except Exception as exc:  # pylint: disable=broad-except
    LOGGER.warning("Live IAM policy read failed: %s", exc)

  mod_entry = run_finding_remediator(
      project_id=args.project,
      inbound_findings=inbound,
      analysis_data=analysis_data,
      policy_data=policy_data,
      gcp_client=gcp_client,
      output_dir=output_dir,
      simulation_data=simulation_data,
      authoritative=args.authoritative,
      canary=args.canary,
  )

  publish_info = None
  if gcs_check:
    publish_info = store.publish_assessment_run(
        bucket=gcs_check["bucket"],
        region=gcs_check["region"],
        project_id=args.project,
        trigger_mode="finding-remediator",
        updated_modules={"finding_remediator": mod_entry},
        live_policy_etag=policy_data.get("etag", ""),
        local_output_dir=output_dir,
    )

  print(
      json.dumps(
          {"finding_remediator_summary": mod_entry["summary"], "gcs_publish": publish_info},
          indent=2,
      )
  )
  return 0


if __name__ == "__main__":
  sys.exit(main())
