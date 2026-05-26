#!/usr/bin/env bash
# Phase 0.4e — smoke-run the kernel-idiom static analyzers (Smatch / Coccinelle /
# Sparse) over net/netfilter/ of the 6.1.72 source.  The goal is "tools execute on a
# smoke input"; Phase 1 will scale these into the real Stage A.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="${ROOT}/linux/source"
OUT="${ROOT}/scoping"
SUBSYS="${SUBSYS:-net/netfilter}"

mkdir -p "${OUT}"
cd "${SRC}"

# 1. Sparse — kernel-aware lint via `make C=1`.  Run scoped to the subsystem only
#    (touching the whole kernel takes ~20 min and isn't needed for the smoke).
echo "[scoping] sparse on ${SUBSYS}/"
{
  echo "# sparse $(sparse --version 2>&1) — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  make -k C=2 "${SUBSYS}/" CHECK=sparse 2>&1 | head -2000 || true
} > "${OUT}/sparse.out"
echo "[scoping]   -> $(wc -l <"${OUT}/sparse.out") lines, $(grep -c -E 'warning|error' "${OUT}/sparse.out" || true) findings"

# 2. Coccinelle — run the kernel's own free-list / null-deref scripts shipped under
#    scripts/coccinelle/ on the subsystem.  These are the same .cocci files
#    `make coccicheck M=...` uses; we drive spatch directly so the output is parsable.
echo "[scoping] coccinelle on ${SUBSYS}/"
{
  echo "# coccinelle $(spatch --version 2>&1 | head -1) — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  for sp in scripts/coccinelle/free/kfree.cocci \
            scripts/coccinelle/null/deref_null.cocci \
            scripts/coccinelle/api/memdup.cocci; do
    [[ -f "$sp" ]] || continue
    echo "## $sp"
    spatch --very-quiet -D report --no-includes --include-headers \
           --sp-file "$sp" --dir "${SUBSYS}" 2>/dev/null | head -200 || true
  done
} > "${OUT}/cocci.out"
echo "[scoping]   -> $(wc -l <"${OUT}/cocci.out") lines"

# 3. Smatch — built from source on demand (no apt package).  This is the smoke,
#    so we only run the dereference checker on the subsystem.
if ! command -v smatch >/dev/null; then
  echo "[scoping] smatch not installed; building from source"
  if [[ ! -d "${ROOT}/scoping/smatch.git" ]]; then
    git clone --depth 1 https://repo.or.cz/smatch.git "${ROOT}/scoping/smatch.git" >/dev/null 2>&1 \
      || git clone --depth 1 https://github.com/error27/smatch "${ROOT}/scoping/smatch.git"
  fi
  ( cd "${ROOT}/scoping/smatch.git" && make -j"$(nproc)" >/dev/null )
  export PATH="${ROOT}/scoping/smatch.git:${PATH}"
fi

echo "[scoping] smatch on ${SUBSYS}/"
{
  echo "# smatch $(smatch --version 2>&1 || echo '(no version flag)') — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  # Smatch runs as CHECK=… inside make C=1.  Scope to subsystem.
  make -k C=2 CHECK="smatch -p=kernel --file-output" "${SUBSYS}/" 2>&1 | head -2000 || true
  echo "## Per-file .smatch reports (if any):"
  find "${SUBSYS}" -name '*.c.smatch' -print 2>/dev/null | head -50 || true
} > "${OUT}/smatch.out"
echo "[scoping]   -> $(wc -l <"${OUT}/smatch.out") lines"

echo "[scoping] done — see ${OUT}/{sparse,cocci,smatch}.out"
