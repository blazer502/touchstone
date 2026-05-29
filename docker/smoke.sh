#!/usr/bin/env bash
# Run a one-shot smoke command in each built image to confirm the tool actually
# executes. Each tool's CMD self-checks (prints --version or similar).
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LOCK="$ROOT/docs/toolchain.lock"
set -a; . "$LOCK"; set +a
DOCKER="${DOCKER:-docker}"

declare -A TAG CMD
register() { TAG[$1]="$2"; CMD[$1]="$3"; }

register clang         "touchstone/clang:${LLVM_VERSION}"         "clang --version"
register cbmc          "touchstone/cbmc:${CBMC_VERSION}"          "cbmc --version"
register esbmc         "touchstone/esbmc:${ESBMC_VERSION}"        "esbmc --version"
register framac        "touchstone/framac:${FRAMAC_VERSION}"      "frama-c -version"
register klee          "touchstone/klee:${KLEE_VERSION}"          "klee --version"
register angr          "touchstone/angr:${ANGR_VERSION}"          "python -c 'import angr; print(angr.__version__)'"
register aflpp         "touchstone/aflpp:${AFLPP_VERSION}"        "afl-fuzz -h 2>&1 | head -3"
register syzkaller     "touchstone/syzkaller:${SYZKALLER_COMMIT}" "syz-manager -version || ls /opt/syzkaller/bin"
register kernel-static "touchstone/kernel-static:latest"          "smatch --version; spatch --version | head -1; sparse --version"
register codeql        "touchstone/codeql:${CODEQL_VERSION}"      "codeql version"
register svf           "touchstone/svf:${SVF_VERSION}"            "wpa --version 2>&1 | head -5"
register symcc         "touchstone/symcc:${SYMCC_COMMIT}"         "symcc --version 2>&1 | head -3"
register s2e           "touchstone/s2e:${S2E_VERSION}"            "s2e --help 2>&1 | head -3"

PASS=0; FAIL=0; MISS=0
for t in "${!TAG[@]}"; do
  img="${TAG[$t]}"
  if ! $DOCKER image inspect "$img" >/dev/null 2>&1; then
    echo "MISS   $t  ($img not built)"
    MISS=$((MISS+1)); continue
  fi
  if $DOCKER run --rm "$img" bash -c "${CMD[$t]}" >/dev/null 2>&1; then
    echo "PASS   $t  ($img)"
    PASS=$((PASS+1))
  else
    echo "FAIL   $t  ($img)"
    FAIL=$((FAIL+1))
  fi
done

echo
echo "summary: PASS=$PASS  FAIL=$FAIL  MISS=$MISS"
[[ $FAIL -eq 0 ]]
