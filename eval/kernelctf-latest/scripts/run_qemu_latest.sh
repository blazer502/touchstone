#!/usr/bin/env bash
# Boot the latest-LTS hunt-mode kernel + setup-mode initramfs in QEMU.
# This is a SETUP smoke (no exploit, no fuzzer): boots the kernel, runs the
# init script's surface inventory + KASAN sanity, captures dmesg.
#
# Verdict semantics:
#   - LIVE-VERDICT: ready   -> PASS  (kernel healthy, restrictions applied)
#   - LIVE-VERDICT: boot-kasan -> FAIL (build/config broken)
#   - any KASAN report      -> FAIL  (setup is unsound)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
KERNEL="${ROOT}/artifacts/bzImage-latest"
INITRD="${ROOT}/artifacts/initramfs-latest.cpio.gz"
LOG="${ROOT}/artifacts/dmesg-latest-setup.log"

[[ -f "${KERNEL}" ]] || { echo "missing ${KERNEL}" >&2; exit 1; }
[[ -f "${INITRD}" ]] || { echo "missing ${INITRD}" >&2; exit 1; }

ACCEL=""
if [[ -w /dev/kvm ]]; then ACCEL="-enable-kvm -cpu host"; else ACCEL="-cpu qemu64"; fi

echo "[qemu-latest] using ${ACCEL}"
timeout 90 qemu-system-x86_64 \
  ${ACCEL} \
  -m 2048 \
  -smp 2 \
  -kernel "${KERNEL}" \
  -initrd "${INITRD}" \
  -append "console=ttyS0 panic=1 nokaslr oops=panic" \
  -nographic -no-reboot \
  -serial mon:stdio \
  -display none \
  | tee "${LOG}"

echo "[qemu-latest] log saved to ${LOG}"

if grep -qE "BUG: KASAN|KASAN: " "${LOG}"; then
  echo "[qemu-latest] FAIL — KASAN fired during boot smoke; setup is unsound"
  grep -B2 -A20 -E "BUG: KASAN|KASAN: " "${LOG}" | head -40
  exit 1
fi

if grep -q "LIVE-VERDICT: ready" "${LOG}"; then
  echo "[qemu-latest] PASS — kernel boots, restrictions applied"
  exit 0
fi

echo "[qemu-latest] INCONCLUSIVE — no LIVE-VERDICT line found"
exit 2
