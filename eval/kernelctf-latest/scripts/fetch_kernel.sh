#!/usr/bin/env bash
# Fetch the pinned LTS-6.12 source tarball from kernel.org cdn.
# Pin recorded in eval/kernelctf-latest/TARGET.md.
set -euo pipefail

VERSION="${VERSION:-6.12.91}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="${DEST:-${ROOT}/linux}"
TARBALL_URL="https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-${VERSION}.tar.xz"

if [[ -d "${DEST}/source" && -f "${DEST}/source/Makefile" ]]; then
  echo "[fetch] kernel source already present at ${DEST}/source — skipping"
  exit 0
fi

mkdir -p "${DEST}"
cd "${DEST}"
if [[ ! -f "linux-${VERSION}.tar.xz" ]]; then
  echo "[fetch] downloading ${TARBALL_URL}"
  curl -fSL -o "linux-${VERSION}.tar.xz" "${TARBALL_URL}"
fi
echo "[fetch] extracting"
tar -xf "linux-${VERSION}.tar.xz"
mv "linux-${VERSION}" source
echo "[fetch] done -> ${DEST}/source"
