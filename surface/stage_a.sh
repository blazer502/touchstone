#!/usr/bin/env bash
# Phase 1.2 — Stage A reachability/taint driver.
#
# Runs the three Stage-A passes in order over a (source_root, scope, target)
# tuple, producing:
#   surface/entrypoints/<target>.json   — attacker-entry catalog
#   surface/slice/<target>.json         — sound over-approximated keep_set
#                                          with attached static-analyzer hints
#
# Defaults map to the Phase-0.4 kernel target (Linux 6.1.72 / net/netfilter).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SOURCE_ROOT="${SOURCE_ROOT:-${ROOT}/eval/kernelctf/linux/source}"
SCOPE="${SCOPE:-net/netfilter}"
TARGET="${TARGET:-linux-6.1.72-netfilter}"
SMATCH_OUT="${SMATCH_OUT:-${ROOT}/eval/kernelctf/scoping/smatch.out}"
SPARSE_OUT="${SPARSE_OUT:-${ROOT}/eval/kernelctf/scoping/sparse.out}"

cd "${ROOT}"

echo "[stage_a] (1/3) entry-point catalog"
python3 -m surface.entrypoints \
  --source-root "${SOURCE_ROOT}" --scope "${SCOPE}" --target "${TARGET}"

echo "[stage_a] (2/3) reachability slice"
python3 -m surface.reachability \
  --source-root "${SOURCE_ROOT}" --scope "${SCOPE}" --target "${TARGET}"

if [[ -f "${SMATCH_OUT}" || -f "${SPARSE_OUT}" ]]; then
  echo "[stage_a] (3/3) static-analyzer hints"
  python3 -m surface.static_hints \
    --slice "surface/slice/${TARGET}.json" \
    ${SMATCH_OUT:+--smatch "${SMATCH_OUT}"} \
    ${SPARSE_OUT:+--sparse "${SPARSE_OUT}"} \
    --scope "${SCOPE}"
else
  echo "[stage_a] (3/3) no static-analyzer outputs found; skipping hint pass"
fi

echo "[stage_a] done — see surface/{entrypoints,slice}/${TARGET}.json"
