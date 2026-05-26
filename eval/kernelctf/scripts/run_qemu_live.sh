#!/usr/bin/env bash
# Boot the live-LTS-instance kernel + live initramfs in QEMU and capture serial.
# Verdict semantics are inverted relative to scripts/run_qemu.sh:
#   - Phase 0.4 (historical):  KASAN report fires ⇒ smoke PASS
#   - Phase 4.2 (live):        KASAN report absent ⇒ smoke PASS
# i.e. the live kernel is the *negative control*; the historical exploit must
# fail to fire because the restrictions removed its surface.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
KERNEL="${ROOT}/artifacts/bzImage-live"
INITRD="${ROOT}/artifacts/initramfs-live.cpio.gz"
LOG="${ROOT}/artifacts/dmesg-live-lts-cos.log"

[[ -f "${KERNEL}" ]] || { echo "missing ${KERNEL}" >&2; exit 1; }
[[ -f "${INITRD}" ]] || { echo "missing ${INITRD}" >&2; exit 1; }

ACCEL=""
if [[ -w /dev/kvm ]]; then ACCEL="-enable-kvm -cpu host"; else ACCEL="-cpu qemu64"; fi

echo "[qemu-live] using ${ACCEL}"
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

echo "[qemu-live] log saved to ${LOG}"

if grep -qE "BUG: KASAN|KASAN: " "${LOG}"; then
  echo "[qemu-live] FAIL — KASAN fired on live kernel; restrictions did not hold"
  grep -B2 -A20 -E "BUG: KASAN|KASAN: " "${LOG}" | head -40
  exit 1
fi

if grep -q "LIVE-VERDICT: no-kasan" "${LOG}"; then
  echo "[qemu-live] PASS — historical CVE-2024-1086 exploit failed to trigger (restrictions held)"
  exit 0
fi

echo "[qemu-live] INCONCLUSIVE — no LIVE-VERDICT line found in serial log"
exit 2
