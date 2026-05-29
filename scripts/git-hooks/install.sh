#!/usr/bin/env bash
# Install the touchstone pre-commit hook into .git/hooks/.
#
# Idempotent: re-running replaces the symlink. Original hook (if any) is
# preserved as `.git/hooks/pre-commit.bak`.
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
SRC="$REPO_ROOT/scripts/git-hooks/pre-commit"
DST="$REPO_ROOT/.git/hooks/pre-commit"
TARGETS="$REPO_ROOT/scripts/git-hooks/targets.txt"

chmod +x "$SRC"

if [[ -e "$DST" && ! -L "$DST" ]]; then
    echo "[install] preserving existing $DST as $DST.bak"
    mv "$DST" "$DST.bak"
elif [[ -L "$DST" ]]; then
    rm "$DST"
fi

ln -s "$SRC" "$DST"
echo "[install] linked $DST → $SRC"

if [[ ! -f "$TARGETS" ]]; then
    cat > "$TARGETS" <<'EOF'
# Targets the pre-commit hook will run `surface.incremental impacted` against.
# One target id per line; the id must correspond to a directory under
# surface/tasks/<target>/ (Phase 1.1 cluster index).
linux-6.1.72-netfilter
EOF
    echo "[install] seeded default targets: $TARGETS"
fi

echo "[install] done — pre-commit hook active."
echo "          set VERI_AGENT_PRECOMMIT_STRICT=1 to make it blocking."
