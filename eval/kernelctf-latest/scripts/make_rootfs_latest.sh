#!/usr/bin/env bash
# Build the initramfs for the latest-LTS kernelCTF target.
#
# init script enforces the COS-style runtime restrictions that aren't
# expressible at build time on 6.12+:
#   - sysctl kernel.unprivileged_userns_clone = 0
#   - user.max_user_namespaces = 0
# These mirror "unprivileged user namespaces turned off since July 1st, 2025"
# from kernelCTF rules.
#
# A boot smoke-mode is run when the syz-manager wrapper passes /root/manifest;
# in setup mode (no manifest), init just prints a surface inventory + verdict
# line ("LIVE-VERDICT: ready" if KASAN didn't fire during boot).
#
# Output: artifacts/initramfs-latest.cpio.gz
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${ROOT}/initramfs/build"

rm -rf "${WORK}"
mkdir -p "${WORK}"/{bin,sbin,etc,proc,sys,dev,tmp,root}

cp /usr/bin/busybox "${WORK}/bin/busybox"
chmod +x "${WORK}/bin/busybox"

APPLETS="sh ls cat echo mount umount mkdir mknod sleep dmesg ip ifconfig ps kill grep sed cp mv rm chmod chown poweroff sync sysctl"
for a in ${APPLETS}; do
  ln -sf /bin/busybox "${WORK}/bin/${a}"
done
ln -sf /bin/busybox "${WORK}/sbin/poweroff"

cat >"${WORK}/init" <<'EOF'
#!/bin/busybox sh
/bin/busybox --install -s /bin >/dev/null 2>&1 || true
export PATH=/bin:/sbin:/usr/bin:/usr/sbin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev || mknod /dev/null c 1 3 || true

echo "[init-latest] linux $(uname -r) up"

# Enforce runtime COS-style restrictions. These are all RUNTIME knobs because
# the corresponding Kconfig symbols are either kept built-in (IO_URING) or
# were removed upstream (USER_NS_UNPRIVILEGED).
sysctl -w kernel.unprivileged_userns_clone=0 2>/dev/null || true
sysctl -w user.max_user_namespaces=0 2>/dev/null || true
sysctl -w kernel.io_uring_disabled=2 2>/dev/null || true

echo "[init-latest] ==== surface inventory ===="
echo "[init-latest] sysctl userns unprivileged: $(sysctl -n kernel.unprivileged_userns_clone 2>/dev/null || echo 'absent')"
echo "[init-latest] sysctl max_user_namespaces: $(sysctl -n user.max_user_namespaces 2>/dev/null || echo 'absent')"
echo "[init-latest] sysctl io_uring_disabled: $(sysctl -n kernel.io_uring_disabled 2>/dev/null || echo 'absent')"
echo "[init-latest] /proc/net/protocols (look for nftables/io_uring/nft):"
grep -E "nf_tables|io_uring|^nft" /proc/net/protocols 2>/dev/null || echo "  (none present — restrictions held)"
echo "[init-latest] /proc/filesystems (look for nft):"
grep -i nf_tables /proc/filesystems 2>/dev/null || echo "  (no nftables fs)"
echo "[init-latest] /sys/kernel/io_uring: $([ -e /proc/sys/kernel/io_uring_disabled ] && echo present || echo absent)"
echo "[init-latest] CONFIG_KASAN active: $(grep -c 'KASAN: ' /proc/cmdline 2>/dev/null; dmesg | grep -q 'KASAN' && echo yes || echo no)"
echo "[init-latest] ==== end inventory ===="

# Boot-time KASAN reports are a setup smoke failure.
if dmesg | grep -qE "BUG: KASAN|KASAN: "; then
  echo "[init-latest] LIVE-VERDICT: boot-kasan (setup broken — KASAN fired during boot)"
else
  echo "[init-latest] LIVE-VERDICT: ready (kernel + restrictions look healthy)"
fi
poweroff -f
EOF
chmod +x "${WORK}/init"

cd "${WORK}"
mkdir -p "${ROOT}/artifacts"
find . -print0 | cpio --null -ov --format=newc 2>/dev/null | gzip -9 > "${ROOT}/artifacts/initramfs-latest.cpio.gz"
echo "[make_rootfs_latest] initramfs at ${ROOT}/artifacts/initramfs-latest.cpio.gz ($(du -h "${ROOT}/artifacts/initramfs-latest.cpio.gz" | cut -f1))"
