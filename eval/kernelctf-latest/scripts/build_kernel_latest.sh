#!/usr/bin/env bash
# Build the latest-LTS hunt-mode kernel into a separate output dir.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="${ROOT}/linux/source"
OUT="${KBUILD_OUTPUT:-${ROOT}/linux/build-latest}"
JOBS="${JOBS:-$(nproc)}"
ARTDIR="${ROOT}/artifacts"
mkdir -p "${ARTDIR}"

[[ -d "${OUT}" && -f "${OUT}/.config" ]] || {
  echo "missing build config at ${OUT}/.config; run make_config_latest.sh first" >&2
  exit 1
}

cd "${SRC}"
echo "[build-latest] make -j${JOBS} O=${OUT} bzImage"
time make -j"${JOBS}" O="${OUT}" bzImage \
  2> >(tee "${ARTDIR}/build-latest-stderr.log" >&2) \
  | tee "${ARTDIR}/build-latest-stdout.log" >/dev/null

DST="${ARTDIR}/bzImage-latest"
cp "${OUT}/arch/x86/boot/bzImage" "${DST}"
echo "[build-latest] bzImage at ${DST} ($(du -h "${DST}" | cut -f1))"
