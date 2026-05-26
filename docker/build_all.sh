#!/usr/bin/env bash
# Build every tool-family image at the versions pinned in docs/toolchain.lock.
# Usage:
#   ./docker/build_all.sh [tool...]      # build only listed tools, or all if empty
#
# Image naming convention: veri-agent/<tool>:<version>.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LOCK="$ROOT/docs/toolchain.lock"
DOCKER="${DOCKER:-docker}"

# Pull pinned versions from the lock file (KEY=VALUE format).
# shellcheck disable=SC1090
set -a; . "$LOCK"; set +a

# tool -> (Dockerfile, tag, extra build args)
declare -A DOCKERFILE TAG ARGS
register() { DOCKERFILE[$1]="$2"; TAG[$1]="$3"; ARGS[$1]="$4"; }

register clang         clang.Dockerfile         "veri-agent/clang:${LLVM_VERSION}"        "--build-arg LLVM_VERSION=${LLVM_VERSION} --build-arg BASE_IMAGE=${BASE_IMAGE}"
register cbmc          cbmc.Dockerfile          "veri-agent/cbmc:${CBMC_VERSION}"         "--build-arg CBMC_VERSION=${CBMC_VERSION} --build-arg BASE_IMAGE=${BASE_IMAGE}"
register esbmc         esbmc.Dockerfile         "veri-agent/esbmc:${ESBMC_VERSION}"       "--build-arg ESBMC_VERSION=${ESBMC_VERSION} --build-arg BASE_IMAGE=${BASE_IMAGE}"
register framac        framac.Dockerfile        "veri-agent/framac:${FRAMAC_VERSION}"     "--build-arg FRAMAC_VERSION=${FRAMAC_VERSION} --build-arg BASE_IMAGE=${BASE_IMAGE}"
register klee          klee.Dockerfile          "veri-agent/klee:${KLEE_VERSION}"         "--build-arg KLEE_VERSION=${KLEE_VERSION}"
register angr          angr.Dockerfile          "veri-agent/angr:${ANGR_VERSION}"         "--build-arg ANGR_VERSION=${ANGR_VERSION}"
register aflpp         aflpp.Dockerfile         "veri-agent/aflpp:${AFLPP_VERSION}"       "--build-arg AFLPP_VERSION=${AFLPP_VERSION}"
register syzkaller     syzkaller.Dockerfile     "veri-agent/syzkaller:${SYZKALLER_COMMIT}" "--build-arg SYZKALLER_COMMIT=${SYZKALLER_COMMIT}"
register kernel-static kernel-static.Dockerfile "veri-agent/kernel-static:latest"          "--build-arg SMATCH_COMMIT=${SMATCH_COMMIT} --build-arg COCCINELLE_VERSION=${COCCINELLE_VERSION} --build-arg SPARSE_VERSION=${SPARSE_VERSION} --build-arg BASE_IMAGE=${BASE_IMAGE}"
register codeql        codeql.Dockerfile        "veri-agent/codeql:${CODEQL_VERSION}"     "--build-arg CODEQL_VERSION=${CODEQL_VERSION} --build-arg BASE_IMAGE=${BASE_IMAGE}"
register svf           svf.Dockerfile           "veri-agent/svf:${SVF_VERSION}"           "--build-arg LLVM_VERSION=${LLVM_VERSION} --build-arg SVF_VERSION=${SVF_VERSION}"
register symcc         symcc.Dockerfile         "veri-agent/symcc:${SYMCC_COMMIT}"        "--build-arg LLVM_VERSION=${LLVM_VERSION} --build-arg SYMCC_COMMIT=${SYMCC_COMMIT}"
register s2e           s2e.Dockerfile           "veri-agent/s2e:${S2E_VERSION}"           "--build-arg S2E_VERSION=${S2E_VERSION} --build-arg BASE_IMAGE=${BASE_IMAGE}"

# Build order matters: clang must build before svf and symcc (they FROM it).
ORDER=(clang cbmc esbmc framac klee angr aflpp syzkaller kernel-static codeql svf symcc s2e)

tools=("$@")
[[ ${#tools[@]} -eq 0 ]] && tools=("${ORDER[@]}")

for t in "${tools[@]}"; do
  [[ -z "${DOCKERFILE[$t]:-}" ]] && { echo "unknown tool: $t" >&2; exit 1; }
  echo "=== building $t -> ${TAG[$t]} ==="
  # shellcheck disable=SC2086
  $DOCKER build -t "${TAG[$t]}" \
    -f "$ROOT/docker/${DOCKERFILE[$t]}" \
    ${ARGS[$t]} \
    "$ROOT/docker"
done
