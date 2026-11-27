#!/usr/bin/env bash
# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0
#
# Installs the ScopeGuard 11-skill plugin into Antigravity's global plugins
# directory (~/.gemini/config/plugins/scopeguard) and configures absolute skill
# script paths so it runs cleanly from any workspace.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="${SCRIPT_DIR}/plugins/scopeguard"
DEST_DIR="${SCOPEGUARD_INSTALL_DIR:-${HOME}/.gemini/config/plugins/scopeguard}"

if [[ ! -d "${SRC_DIR}" ]]; then
  echo "Error: Expected plugin directory at ${SRC_DIR}" >&2
  exit 1
fi

mkdir -p "${DEST_DIR}"
rsync -a --delete \
  --exclude='__pycache__' \
  --exclude='*.pyc' \
  --exclude='.DS_Store' \
  "${SRC_DIR}/" "${DEST_DIR}/"

python3 - "${DEST_DIR}" << 'PYEOF'
import glob, pathlib, sys
dest = pathlib.Path(sys.argv[1])
prefix = str(dest / "skills") + "/"
count = 0
for p in sorted(glob.glob(str(dest / "skills" / "*" / "SKILL.md"))):
    path = pathlib.Path(p)
    txt = path.read_text(encoding="utf-8")
    updated = txt.replace("plugins/scopeguard/skills/", prefix)
    if updated != txt:
        path.write_text(updated, encoding="utf-8")
        count += 1
print(f"Installed ScopeGuard plugin to {dest} ({count} SKILL.md files configured).")
PYEOF

echo "Verification: checking orchestrator CLI..."
python3 "${DEST_DIR}/skills/scopeguard-orchestrator/scripts/scopeguard_pipeline.py" --help >/dev/null
echo "Done! Start a new Antigravity / agy CLI session to use ScopeGuard."
