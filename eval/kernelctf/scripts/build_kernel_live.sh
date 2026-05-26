#!/usr/bin/env bash
# Build the live-LTS-instance KASAN+KCOV+UBSAN kernel into a separate output dir
# (keeps the Phase-0.4 historical build at linux/source/arch/x86/boot/bzImage
# untouched, so both targets coexist on disk).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="${ROOT}/linux/source"
OUT="${KBUILD_OUTPUT:-${ROOT}/linux/build-live}"
JOBS="${JOBS:-$(nproc)}"
ARTDIR="${ROOT}/artifacts"

[[ -d "${OUT}" && -f "${OUT}/.config" ]] || {
  echo "missing live config at ${OUT}/.config; run make_config_live.sh first" >&2
  exit 1
}

cd "${SRC}"
echo "[build-live] make -j${JOBS} O=${OUT} bzImage"
time make -j"${JOBS}" O="${OUT}" bzImage \
  2> >(tee "${ARTDIR}/build-live-stderr.log" >&2) \
  | tee "${ARTDIR}/build-live-stdout.log" >/dev/null

DST="${ARTDIR}/bzImage-live"
cp "${OUT}/arch/x86/boot/bzImage" "${DST}"
echo "[build-live] bzImage at ${DST} ($(du -h "${DST}" | cut -f1))"
