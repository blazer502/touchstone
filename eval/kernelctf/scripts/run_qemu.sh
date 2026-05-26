#!/usr/bin/env bash
# Boot the KASAN-instrumented 6.1.72 kernel + initramfs in QEMU and capture serial.
# Output: artifacts/dmesg-cve-2024-1086.log
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
KERNEL="${ROOT}/artifacts/bzImage"
INITRD="${ROOT}/artifacts/initramfs.cpio.gz"
LOG="${ROOT}/artifacts/dmesg-cve-2024-1086.log"

[[ -f "${KERNEL}" ]] || { echo "missing ${KERNEL}" >&2; exit 1; }
[[ -f "${INITRD}" ]] || { echo "missing ${INITRD}" >&2; exit 1; }

# -no-reboot exits QEMU when the guest calls poweroff -f.
# console=ttyS0 sends kernel + init output to the serial port (-nographic).
# nokaslr + noapic for deterministic addresses in the dmesg trace.
# Use -enable-kvm if /dev/kvm is usable; fall back gracefully.
ACCEL=""
if [[ -w /dev/kvm ]]; then ACCEL="-enable-kvm -cpu host"; else ACCEL="-cpu qemu64"; fi

echo "[qemu] using ${ACCEL}"
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

echo "[qemu] log saved to ${LOG}"
echo "[qemu] checking for KASAN report..."
if grep -E "BUG: KASAN|KASAN: " "${LOG}" >/dev/null; then
  echo "[qemu] KASAN report present ✓"
  grep -B2 -A20 -E "BUG: KASAN|KASAN: " "${LOG}" | head -80
  exit 0
else
  echo "[qemu] no KASAN report found ✗"
  exit 1
fi
