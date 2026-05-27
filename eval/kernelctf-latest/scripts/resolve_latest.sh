#!/usr/bin/env bash
# Resolve the *current* kernelCTF LTS-6.12 instance to an exact tag.
# Mirrors what kernelctf/get_latest_lts_cos_versions.py does for the lts-6.12 row.
set -euo pipefail

VERSION_MAJOR="${VERSION_MAJOR:-6.12}"
LATEST_TAG=$(git ls-remote --tags --sort='-v:refname' \
    https://github.com/gregkh/linux "v${VERSION_MAJOR}.*[0-9]" \
    | head -1 | awk '{print $2}' | sed 's|refs/tags/||')

if [[ -z "${LATEST_TAG}" ]]; then
  echo "ERROR: could not resolve latest v${VERSION_MAJOR}.* tag" >&2
  exit 1
fi
# Strip leading 'v' for the numeric form.
LATEST_NUM="${LATEST_TAG#v}"
echo "TAG=${LATEST_TAG}"
echo "VERSION=${LATEST_NUM}"
