#!/usr/bin/env bash
# Build the Linux 6.1.72 KASAN+KCOV+UBSAN kernel.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="${ROOT}/linux/source"
JOBS="${JOBS:-$(nproc)}"

cd "${SRC}"
echo "[build] make -j${JOBS} bzImage ($(grep ^CONFIG_KASAN= .config))"
time make -j"${JOBS}" bzImage 2> >(tee "${ROOT}/artifacts/build-stderr.log" >&2) | tee "${ROOT}/artifacts/build-stdout.log" >/dev/null

OUT="${ROOT}/artifacts/bzImage"
cp arch/x86/boot/bzImage "${OUT}"
echo "[build] bzImage at ${OUT} ($(du -h "${OUT}" | cut -f1))"
