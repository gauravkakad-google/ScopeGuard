# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0

"""Exact, strictly-disjoint capability partitioning for Model B custom roles.

Given persona permission sets (Model A), this module splits the union of all
permissions into *capability blocks* such that:

1. Blocks are pairwise disjoint (R_i ∩ R_j = ∅).
2. Every persona's permission set is EXACTLY the union of some blocks, so a
   principal's bundle grants what it needs and nothing more (no over-grant).
3. Sensitive permissions (actAs, token minting, secret access, setIamPolicy)
   always sit in their own visibly-named block.

Algorithm: a permission's "signature" is the frozenset of personas that need
it. Permissions with identical signatures form one block. This is the coarsest
partition satisfying (1) and (2), i.e. it minimises the number of roles without
ever over-granting. Complexity O(P · N) for P permissions and N personas.

Pure standard library; deterministic output for identical input.
"""

from typing import Any, Dict, FrozenSet, Iterable, List, Mapping, Optional, Set

from lib import naming

# Projects allow at most 300 custom roles; warn well before that.
CUSTOM_ROLE_SOFT_LIMIT = 100


def partition_capabilities(
    personas: Mapping[str, Iterable[str]], prefix: Optional[str] = None
) -> Dict[str, Any]:
  """Partitions persona permission sets into disjoint, exactly-composable blocks.

  Args:
    personas: Mapping of persona key (e.g. Model A role ID) -> permissions.
    prefix: Optional role ID prefix override (defaults to ``sg_``).

  Returns:
    Dict with:
      ``capabilities``: role_id -> {permissions, used_by, sensitive}
      ``bundles``: persona key -> sorted list of capability role IDs
      ``verification``: {pairwise_overlap, exact_cover, over_grant, warnings}
  """
  persona_sets: Dict[str, Set[str]] = {k: set(v) for k, v in personas.items() if v}

  # 1. Group permissions by the exact set of personas that need them.
  signature_of: Dict[str, Set[str]] = {}
  for persona, perms in persona_sets.items():
    for perm in perms:
      signature_of.setdefault(perm, set()).add(persona)

  blocks: Dict[str, Set[str]] = {}
  block_users: Dict[str, FrozenSet[str]] = {}
  for perm, users in signature_of.items():
    sig = frozenset(users)
    # 2. Sensitive permissions get their own block per (signature, capability).
    sensitive_tag = naming.SENSITIVE_CAPABILITIES.get(perm, "")
    key = "|".join(sorted(sig)) + ("#" + sensitive_tag if sensitive_tag else "")
    blocks.setdefault(key, set()).add(perm)
    block_users[key] = sig

  # 3. Deterministic, collision-free names derived from block content.
  ids = naming.assign_unique_capability_ids(blocks, prefix=prefix)

  capabilities: Dict[str, Dict[str, Any]] = {}
  bundles: Dict[str, List[str]] = {p: [] for p in persona_sets}
  for key, perms in blocks.items():
    rid = ids[key]
    capabilities[rid] = {
        "permissions": sorted(perms),
        "used_by": sorted(block_users[key]),
        "sensitive": "#" in key,
    }
    for persona in block_users[key]:
      bundles[persona].append(rid)
  for persona in bundles:
    bundles[persona] = sorted(bundles[persona])

  return {
      "capabilities": dict(sorted(capabilities.items())),
      "bundles": dict(sorted(bundles.items())),
      "verification": verify_partition(persona_sets, capabilities, bundles),
  }


def verify_partition(
    persona_sets: Mapping[str, Set[str]],
    capabilities: Mapping[str, Mapping[str, Any]],
    bundles: Mapping[str, List[str]],
) -> Dict[str, Any]:
  """Proves disjointness and exact cover; returns counts for reports and tests."""
  seen: Dict[str, str] = {}
  overlap = 0
  for rid, cap in capabilities.items():
    for perm in cap["permissions"]:
      if perm in seen:
        overlap += 1
      seen[perm] = rid
  over_grant: Dict[str, int] = {}
  under_grant: Dict[str, int] = {}
  for persona, needed in persona_sets.items():
    granted: Set[str] = set()
    for rid in bundles.get(persona, []):
      granted |= set(capabilities[rid]["permissions"])
    if granted - needed:
      over_grant[persona] = len(granted - needed)
    if needed - granted:
      under_grant[persona] = len(needed - granted)
  warnings: List[str] = []
  if len(capabilities) > CUSTOM_ROLE_SOFT_LIMIT:
    warnings.append(
        f"{len(capabilities)} capability roles exceed the soft limit of "
        f"{CUSTOM_ROLE_SOFT_LIMIT}; prefer Model A persona roles for this project."
    )
  return {
      "pairwise_overlap": overlap,
      "exact_cover": not over_grant and not under_grant,
      "over_grant": over_grant,
      "under_grant": under_grant,
      "capability_count": len(capabilities),
      "max_bundle_size": max((len(v) for v in bundles.values()), default=0),
      "warnings": warnings,
  }
