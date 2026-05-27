#!/usr/bin/env bash
# Render the syz-manager config template for a specific subsystem.
# Inputs:
#   $1  subsystem label (e.g. "bpf", "net-sched", "fs")
#   $2  path to a JSON array of syscall names produced by run_stage_a.sh
# Output:
#   syzkaller/manager-<subsystem>.cfg
#
# This does NOT launch syz-manager. It only materializes the config and
# the workdir skeleton so the operator can sanity-check the surface before
# kicking off a fuzz run.
set -euo pipefail

SUBSYS="${1:?usage: $0 <subsystem> <enable_syscalls.json>}"
SYSCALLS_JSON="${2:?usage: $0 <subsystem> <enable_syscalls.json>}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TPL="${ROOT}/syzkaller/manager.cfg.template"
OUT="${ROOT}/syzkaller/manager-${SUBSYS}.cfg"

[[ -f "${TPL}" ]] || { echo "missing template ${TPL}" >&2; exit 1; }
[[ -f "${SYSCALLS_JSON}" ]] || { echo "missing syscalls JSON ${SYSCALLS_JSON}" >&2; exit 1; }

# Render the enable_syscalls block from JSON to a comma-separated list of "name".
SYSCALL_BLOCK=$(python3 -c '
import json,sys
data=json.load(open(sys.argv[1]))
names=data if isinstance(data,list) else data.get("syscalls", [])
print(",\n    ".join(json.dumps(n) for n in names))
' "${SYSCALLS_JSON}")

mkdir -p "${ROOT}/syzkaller/workdir-${SUBSYS}/corpus" \
         "${ROOT}/syzkaller/workdir-${SUBSYS}/crashes"

sed -e "s|__ROOT__|${ROOT}|g" \
    -e "s|__SUBSYSTEM__|${SUBSYS}|g" \
    "${TPL}" \
  | python3 -c '
import sys,re
text=sys.stdin.read()
block=sys.argv[1]
text=text.replace("\"__SYSCALL_LIST_PLACEHOLDER__\"", block)
print(text)
' "${SYSCALL_BLOCK}" \
  > "${OUT}"

echo "[render_syz_config] wrote ${OUT}"
echo "[render_syz_config] workdir = ${ROOT}/syzkaller/workdir-${SUBSYS}/"
echo "[render_syz_config] NOTE: this is a SETUP artifact. Do NOT launch syz-manager yet."
