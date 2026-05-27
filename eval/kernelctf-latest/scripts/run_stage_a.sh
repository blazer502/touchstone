#!/usr/bin/env bash
# Run Phase-1.2 Stage A (attacker-controlled entry-point catalog +
# reachability over-approximation) against a chosen subsystem of the
# latest-LTS kernel source. Pure analysis, no fuzzing.
#
# Output:
#   surface/entrypoints/linux-6.12.91-<subsys>.json
#   surface/slice/linux-6.12.91-<subsys>.json
#   eval/kernelctf-latest/syzkaller/enable_syscalls-<subsys>.json
#       (heuristic mapping from entry-point dispatcher class to
#        syz-manager enable_syscalls list — used by render_syz_config.sh)
set -euo pipefail

SUBSYS="${1:?usage: $0 <subsystem-path> e.g. net/sched or kernel/bpf}"
SUBSYS_LABEL="$(echo "${SUBSYS}" | tr '/' '-')"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(cd "${ROOT}/../.." && pwd)"
SRC_ROOT="${ROOT}/linux/source"
SCOPE_DIR="${SRC_ROOT}/${SUBSYS}"
TARGET="linux-6.12.91-${SUBSYS_LABEL}"

[[ -d "${SCOPE_DIR}" ]] || { echo "subsystem not found: ${SCOPE_DIR}" >&2; exit 1; }

cd "${REPO_ROOT}"

echo "[stage_a-latest] target=${TARGET} scope=${SUBSYS}"

# Phase 1.1 — task decomposition (produces surface/tasks/<target>/_index.json
# that reachability.py reads for cluster boundaries).
python3 -m surface.decompose \
  --source-root "${SRC_ROOT}" \
  --scope "${SUBSYS}" \
  --target "${TARGET}"

# Phase 1.2a — attacker-controlled entry-point catalog.
python3 -m surface.entrypoints \
  --source-root "${SRC_ROOT}" \
  --scope "${SUBSYS}" \
  --target "${TARGET}"

# Phase 1.2b — sound over-approximate reachability slice.
python3 -m surface.reachability \
  --source-root "${SRC_ROOT}" \
  --scope "${SUBSYS}" \
  --target "${TARGET}"

# Derive an enable_syscalls list from the dispatcher classes in entrypoints.
# Conservative heuristic mapping; the router widens or narrows at fuzz time.
python3 - <<PY
import json, pathlib
ep = json.load(open("${REPO_ROOT}/surface/entrypoints/${TARGET}.json"))
classes = sorted({e.get("dispatcher_class","") for e in ep.get("entries", []) if e.get("dispatcher_class")})
class_to_syscall = {
    "genetlink":           ["sendmsg\$NETLINK", "syz_genetlink_*"],
    "nftables_netlink":    [],   # surface removed in lts-6.12 config; skip
    "ipset_netlink":       ["syz_ipset_*"],
    "ipvs_netlink":        ["sendmsg\$IPVS_*"],
    "packet_hook":         ["sendmsg\$packet", "socket\$packet", "recvmsg\$packet"],
    "iptables_setsockopt": ["setsockopt\$inet_*"],
    "ip_setsockopt":       ["setsockopt\$inet_*"],
    "nfnetlink":           ["sendmsg\$nl_netfilter"],
    "file_operations":     ["openat", "read", "write", "ioctl", "mmap"],
    "proto_ops":           ["socket", "connect", "sendmsg", "recvmsg", "setsockopt", "getsockopt"],
    "ctl_table":           ["openat\$proc", "write"],
}
syscalls = sorted({s for c in classes for s in class_to_syscall.get(c, [])})
out = {
    "subsystem": "${SUBSYS}",
    "target": "${TARGET}",
    "dispatcher_classes": classes,
    "syscalls": syscalls or ["openat", "read", "write", "ioctl"],
    "note": "Heuristic mapping. Router refines at fuzz launch.",
}
p = pathlib.Path("${ROOT}/syzkaller/enable_syscalls-${SUBSYS_LABEL}.json")
p.parent.mkdir(parents=True, exist_ok=True)
p.write_text(json.dumps(out, indent=2))
print(f"[stage_a-latest] dispatcher classes: {classes}")
print(f"[stage_a-latest] enable_syscalls -> {p}")
PY
