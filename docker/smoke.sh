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

register clang         "veri-agent/clang:${LLVM_VERSION}"         "clang --version"
register cbmc          "veri-agent/cbmc:${CBMC_VERSION}"          "cbmc --version"
register esbmc         "veri-agent/esbmc:${ESBMC_VERSION}"        "esbmc --version"
register framac        "veri-agent/framac:${FRAMAC_VERSION}"      "frama-c -version"
register klee          "veri-agent/klee:${KLEE_VERSION}"          "klee --version"
register angr          "veri-agent/angr:${ANGR_VERSION}"          "python -c 'import angr; print(angr.__version__)'"
register aflpp         "veri-agent/aflpp:${AFLPP_VERSION}"        "afl-fuzz -h 2>&1 | head -3"
register syzkaller     "veri-agent/syzkaller:${SYZKALLER_COMMIT}" "syz-manager -version || ls /opt/syzkaller/bin"
register kernel-static "veri-agent/kernel-static:latest"          "smatch --version; spatch --version | head -1; sparse --version"
register codeql        "veri-agent/codeql:${CODEQL_VERSION}"      "codeql version"
register svf           "veri-agent/svf:${SVF_VERSION}"            "wpa --version 2>&1 | head -5"
register symcc         "veri-agent/symcc:${SYMCC_COMMIT}"         "symcc --version 2>&1 | head -3"
register s2e           "veri-agent/s2e:${S2E_VERSION}"            "s2e --help 2>&1 | head -3"

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
