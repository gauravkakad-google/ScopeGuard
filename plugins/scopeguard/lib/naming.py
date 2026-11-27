# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0

"""Deterministic naming conventions for ScopeGuard-generated custom roles.

Two role kinds are produced:

* Persona roles (Model A)     -> ``<prefix>persona_<workload>``
  Named after WHO uses the role (a workload / team); one binding per principal.
* Capability roles (Model B)  -> ``<prefix>cap_<domain>_<access>[_<qualifier>]``
  Named after WHAT the role grants; strictly disjoint and composed into
  per-principal bundles.

GCP constraints honoured here: role IDs may only contain ``[A-Za-z0-9_.]`` and
must be <= 64 characters; titles <= 100 characters; descriptions <= 256
characters. Deleted role IDs cannot be reused for ~37 days, so names are derived
only from stable inputs (service + access level), never from list order.

Pure standard library; no I/O.
"""

import hashlib
import os
import re
from typing import Dict, Iterable, List, Optional, Sequence

DEFAULT_ROLE_PREFIX = "sg_"
ROLE_ID_MAX_LEN = 64
TITLE_MAX_LEN = 100
DESCRIPTION_MAX_LEN = 256

_ROLE_ID_RE = re.compile(r"^[A-Za-z0-9_.]{3,64}$")

# Service prefix -> human-friendly capability domain. Unlisted services fall
# back to the service prefix itself (e.g. "pubsub").
SERVICE_DOMAINS: Dict[str, str] = {
    "bigquery": "analytics",
    "bigquerystorage": "analytics",
    "dataform": "analytics",
    "storage": "storage",
    "logging": "logging",
    "monitoring": "monitoring",
    "cloudtrace": "monitoring",
    "cloudsql": "cloudsql",
    "run": "cloudrun",
    "cloudfunctions": "functions",
    "aiplatform": "vertexai",
    "discoveryengine": "search",
    "secretmanager": "secrets",
    "artifactregistry": "artifacts",
    "cloudbuild": "build",
    "resourcemanager": "project",
    "serviceusage": "project",
    "iam": "iam",
    "compute": "compute",
    "container": "gke",
    "pubsub": "pubsub",
    "datastore": "firestore",
    "cloudkms": "kms",
}

# Permission verb (last dotted segment) -> access word. Order matters: the first
# matching rule wins, so the most privileged checks come first.
_ACCESS_RULES = (
    ("admin", re.compile(r"^(setIamPolicy|.*[Aa]dmin.*)$")),
    ("impersonate", re.compile(r"^(actAs|getAccessToken|getOpenIdToken|signBlob|signJwt|implicitDelegation)$")),
    ("audit", re.compile(r"^getIamPolicy$")),
    ("connect", re.compile(r"^(connect|login)$")),
    ("invoke", re.compile(r"^(invoke|predict|call|query|search|converse|answer)$")),
    ("run", re.compile(r"^(execute.*|run.*)$")),
    ("deploy", re.compile(r"^(deploy|uploadArtifacts|setTraffic)$")),
    ("read", re.compile(r"^(get.*|list.*|read.*|download.*|access|view.*|lookup|export|search.*)$")),
    ("write", re.compile(r".*")),  # create/update/delete/patch/updateData/etc.
)

# Access words ordered from least to most privileged; used to name blocks that
# mix several access words after the most privileged one present.
ACCESS_ORDER = ("read", "audit", "connect", "invoke", "run", "deploy", "write", "impersonate", "admin")

# Permissions that must ALWAYS sit in their own visibly-named capability role
# so reviewers see the risk in the binding itself (never buried in a bundle).
SENSITIVE_CAPABILITIES: Dict[str, str] = {
    "iam.serviceAccounts.actAs": "sa_impersonate",
    "iam.serviceAccounts.getAccessToken": "sa_token_create",
    "iam.serviceAccounts.getOpenIdToken": "sa_token_create",
    "iam.serviceAccounts.signBlob": "sa_token_create",
    "iam.serviceAccounts.signJwt": "sa_token_create",
    "iam.serviceAccounts.implicitDelegation": "sa_token_create",
    "iam.serviceAccountKeys.create": "sa_key_create",
    "secretmanager.versions.access": "secrets_read",
    "resourcemanager.projects.setIamPolicy": "iam_policy_admin",
    "iam.roles.create": "iam_role_admin",
    "iam.roles.update": "iam_role_admin",
}


def role_prefix(explicit: Optional[str] = None) -> str:
  """Resolves the role ID prefix (CLI flag > env SCOPEGUARD_ROLE_PREFIX > sg_).

  Args:
    explicit: Value of a `--role-prefix` CLI flag, if provided.

  Returns:
    A sanitized prefix that ends with an underscore.
  """
  raw = explicit or os.environ.get("SCOPEGUARD_ROLE_PREFIX") or DEFAULT_ROLE_PREFIX
  cleaned = re.sub(r"[^A-Za-z0-9_]", "_", raw.strip()).lower()
  if not cleaned:
    cleaned = DEFAULT_ROLE_PREFIX
  return cleaned if cleaned.endswith("_") else cleaned + "_"


def slug(text: str) -> str:
  """Converts free text / emails / camelCase into a lowercase snake slug."""
  value = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", str(text or ""))
  value = re.sub(r"[^A-Za-z0-9]+", "_", value).strip("_").lower()
  return re.sub(r"_+", "_", value)


def _clip_role_id(role_id: str) -> str:
  """Truncates an ID to the GCP limit, keeping it unique with a short hash."""
  if len(role_id) <= ROLE_ID_MAX_LEN:
    return role_id
  digest = hashlib.sha256(role_id.encode("utf-8")).hexdigest()[:6]
  return f"{role_id[: ROLE_ID_MAX_LEN - 7].rstrip('_')}_{digest}"


def is_valid_role_id(role_id: str) -> bool:
  """Returns True when the ID satisfies the GCP custom role ID grammar."""
  return bool(_ROLE_ID_RE.match(role_id or ""))


def workload_slug(member: str) -> str:
  """Derives a stable workload slug from an IAM member string.

  Examples:
    serviceAccount:data-pipeline-worker-sa@p.iam.gserviceaccount.com -> data_pipeline_worker
    user:alice.smith@corp.com -> alice_smith
    group:data-analysts@corp.com -> data_analysts
  """
  local = str(member or "").split(":", 1)[-1].split("@", 1)[0]
  s = slug(local)
  s = re.sub(r"_(sa|svc|service_account)$", "", s)
  return s or "principal"


def persona_role_id(workload: str, prefix: Optional[str] = None) -> str:
  """Builds a Model A persona role ID: ``<prefix>persona_<workload>``."""
  return _clip_role_id(f"{role_prefix(prefix)}persona_{slug(workload) or 'workload'}")


def capability_role_id(
    domain: str, access: str, qualifier: str = "", prefix: Optional[str] = None
) -> str:
  """Builds a Model B capability role ID: ``<prefix>cap_<domain>_<access>[_<q>]``."""
  parts = [slug(domain) or "misc", slug(access) or "write"]
  if qualifier:
    parts.append(slug(qualifier))
  return _clip_role_id(f"{role_prefix(prefix)}cap_{'_'.join(parts)}")


def service_of(permission: str) -> str:
  """Returns the service prefix of a permission (``bigquery.tables.get`` -> bigquery)."""
  return str(permission or "").split(".", 1)[0]


def domain_of(permission: str) -> str:
  """Maps a permission to its capability domain."""
  svc = service_of(permission)
  return SERVICE_DOMAINS.get(svc, svc or "misc")


def access_of(permission: str) -> str:
  """Maps a permission's verb to one of the fixed access words."""
  verb = str(permission or "").rsplit(".", 1)[-1]
  for word, pattern in _ACCESS_RULES:
    if pattern.match(verb):
      return word
  return "write"


def _dominant(values: Iterable[str], order: Optional[Sequence[str]] = None) -> str:
  """Returns the most frequent value (ties broken by `order`, then alphabetically)."""
  counts: Dict[str, int] = {}
  for v in values:
    counts[v] = counts.get(v, 0) + 1
  if not counts:
    return ""
  rank = {v: i for i, v in enumerate(order or ())}
  return sorted(counts, key=lambda v: (-counts[v], rank.get(v, len(rank)), v))[0]


def capability_name_parts(permissions: Iterable[str]) -> Dict[str, str]:
  """Derives (domain, access, secondary_domain) naming parts for a permission block.

  The access word is the MOST PRIVILEGED one present (a block with read+write is
  named `write`) so names never under-state what a role grants.
  """
  perms = sorted(set(permissions))
  sensitive = {SENSITIVE_CAPABILITIES[p] for p in perms if p in SENSITIVE_CAPABILITIES}
  if len(sensitive) == 1 and all(p in SENSITIVE_CAPABILITIES for p in perms):
    name = next(iter(sensitive))
    domain, _, access = name.partition("_")
    return {"domain": domain, "access": access or "admin", "secondary": ""}
  domains = [domain_of(p) for p in perms]
  primary = _dominant(domains)
  others = sorted({d for d in domains if d != primary})
  accesses = {access_of(p) for p in perms}
  access = max(accesses, key=ACCESS_ORDER.index) if accesses else "write"
  # Resource noun (middle segment, e.g. bigquery.TABLES.getData) of the primary
  # domain; the most readable qualifier when two blocks share domain+access.
  resources = [slug(p.split(".")[1]) for p in perms if domain_of(p) == primary and p.count(".") >= 2]
  return {
      "domain": primary,
      "access": access,
      "secondary": others[0] if others else "",
      "resource": _dominant(resources),
  }


def assign_unique_capability_ids(
    blocks: Dict[str, Iterable[str]], prefix: Optional[str] = None
) -> Dict[str, str]:
  """Assigns deterministic, collision-free capability role IDs to blocks.

  Collision resolution: append (1) the dominant resource noun, (2) the secondary
  domain, (3) both, then (4) a short hash of the block's sorted permissions. Both are stable across runs for the
  same permission content, avoiding role-name churn.

  Args:
    blocks: Mapping of an internal block key -> permissions in that block.
    prefix: Optional role prefix override.

  Returns:
    Mapping of block key -> role ID.
  """
  proposals: Dict[str, Dict[str, str]] = {
      key: capability_name_parts(perms) for key, perms in blocks.items()
  }
  base_ids = {
      key: capability_role_id(p["domain"], p["access"], prefix=prefix) for key, p in proposals.items()
  }
  out: Dict[str, str] = {}
  by_base: Dict[str, List[str]] = {}
  for key, rid in base_ids.items():
    by_base.setdefault(rid, []).append(key)
  for rid, keys in sorted(by_base.items()):
    if len(keys) == 1:
      out[keys[0]] = rid
      continue
    taken = set(out.values())
    for key in sorted(keys):
      p = proposals[key]
      digest = hashlib.sha256("\n".join(sorted(blocks[key])).encode("utf-8")).hexdigest()[:4]
      # Most readable first: resource noun, secondary domain, both, then hash.
      options = [
          p.get("resource", ""),
          p["secondary"],
          "_".join(x for x in (p.get("resource", ""), p["secondary"]) if x),
          "_".join(x for x in (p.get("resource", ""), p["secondary"], digest) if x),
      ]
      candidate = ""
      for qualifier in options:
        if not qualifier:
          continue
        candidate = capability_role_id(p["domain"], p["access"], qualifier, prefix)
        if candidate not in taken and candidate not in base_ids.values():
          break
      taken.add(candidate)
      out[key] = candidate
  # Final guard: a qualified name could still equal an unrelated base ID that
  # was assigned in another group. Re-qualify later duplicates with a longer,
  # content-derived hash so IDs stay unique AND stable.
  seen: Dict[str, str] = {}
  for key in sorted(out):
    rid = out[key]
    if rid in seen:
      p = proposals[key]
      digest = hashlib.sha256("\n".join(sorted(blocks[key])).encode("utf-8")).hexdigest()[:8]
      rid = capability_role_id(p["domain"], p["access"], digest, prefix)
      out[key] = rid
    seen[rid] = key
  return out


def assign_unique_persona_ids(
    members: Iterable[str], prefix: Optional[str] = None
) -> Dict[str, str]:
  """Assigns collision-free persona role IDs to IAM members (Model A).

  Two members can share a workload slug (e.g. ``user:ops@a.com`` and
  ``serviceAccount:ops@p.iam.gserviceaccount.com``). Later duplicates get the
  member type and, if still colliding, a short hash of the full member.

  Args:
    members: IAM member strings (``type:email``).
    prefix: Optional role prefix override.

  Returns:
    Mapping of member -> persona role ID.
  """
  out: Dict[str, str] = {}
  taken: set = set()
  for member in sorted(set(members)):
    workload = workload_slug(member)
    rid = persona_role_id(workload, prefix)
    if rid in taken:
      mtype = slug(str(member).split(":", 1)[0]) if ":" in str(member) else "member"
      rid = persona_role_id(f"{workload}_{mtype}", prefix)
    if rid in taken:
      digest = hashlib.sha256(str(member).encode("utf-8")).hexdigest()[:6]
      rid = persona_role_id(f"{workload}_{digest}", prefix)
    taken.add(rid)
    out[member] = rid
  return out


# Tokens rendered upper-case in human titles (IDs stay lower-case slugs).
_TITLE_ACRONYMS = frozenset(
    {"sa", "iam", "kms", "gke", "gcs", "ci", "cd", "cicd", "rag", "api", "sql",
     "vpc", "dns", "ai", "ml", "pam", "wif", "scc"}
)


def _humanize(words: str) -> str:
  """Title-cases space-separated words, keeping well-known acronyms upper."""
  return " ".join(
      w.upper() if w.lower() in _TITLE_ACRONYMS else w.capitalize()
      for w in words.split()
  )


def persona_title(workload: str) -> str:
  """Human title for a persona role (<= 100 chars)."""
  words = _humanize(slug(workload).replace("_", " "))
  return f"SG Persona · {words}"[:TITLE_MAX_LEN]


def capability_title(role_id: str) -> str:
  """Human title for a capability role derived from its ID (<= 100 chars)."""
  tail = _humanize(role_id.split("cap_", 1)[-1].replace("_", " "))
  return f"SG Capability · {tail}"[:TITLE_MAX_LEN]


def role_description(
    kind: str, perm_count: int, used_by: Sequence[str], source: str, run_id: str
) -> str:
  """Builds the audit-context description stored on the role (<= 256 chars).

  Custom roles cannot carry labels, so provenance lives in the description.
  """
  users = ", ".join(sorted(used_by)[:4]) + (" …" if len(used_by) > 4 else "")
  text = (
      f"ScopeGuard {kind} | perms: {perm_count} | used by: {users or 'n/a'} | "
      f"source: {source} | run {run_id}"
  )
  return text[:DESCRIPTION_MAX_LEN]


def short_principal(member: str) -> str:
  """Short display name: ``serviceAccount:x-sa@p.iam...`` -> ``x-sa``."""
  return str(member or "").split(":", 1)[-1].split("@", 1)[0] or str(member or "")
