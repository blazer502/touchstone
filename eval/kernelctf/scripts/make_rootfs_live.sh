#!/usr/bin/env bash
# Build the live-target initramfs.
#
# The init script runs the CVE-2024-1086 historical exploit as a *negative
# control* — on the live kernel (nftables off, unprivileged userns off,
# io_uring off) it MUST NOT trigger the KASAN report we saw in Phase 0.4. If it
# does, the restrictions weren't applied and the live config is unsound.
#
# Output: artifacts/initramfs-live.cpio.gz
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${ROOT}/rootfs/build-live"
EXPLOIT="${ROOT}/exploits/CVE-2024-1086/exploit"

[[ -x "${EXPLOIT}" ]] || { echo "missing ${EXPLOIT}" >&2; exit 1; }

rm -rf "${WORK}"
mkdir -p "${WORK}"/{bin,sbin,etc,proc,sys,dev,tmp,root}

cp /usr/bin/busybox "${WORK}/bin/busybox"
chmod +x "${WORK}/bin/busybox"

cp "${EXPLOIT}" "${WORK}/root/exploit"
chmod +x "${WORK}/root/exploit"

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

echo "[init-live] linux $(uname -r) up"
echo "[init-live] surface inventory ----"
# nftables family file is gone if NF_TABLES=n.
if [ -d /proc/sys/net/netfilter ]; then ls /proc/sys/net/netfilter; fi
echo "[init-live] /proc/net/protocols (look for nftables/io_uring): "
grep -E "nf_tables|io_uring|^nft" /proc/net/protocols 2>/dev/null || echo "  (neither present)"
echo "[init-live] sysctl userns unprivileged: "
sysctl -n kernel.unprivileged_userns_clone 2>/dev/null || echo "  (sysctl absent — CONFIG_USER_NS_UNPRIVILEGED=n)"
echo "[init-live] /sys/kernel/io_uring: $([ -e /proc/sys/kernel/io_uring_disabled ] && echo present || echo absent)"

echo "[init-live] running historical CVE-2024-1086 exploit as negative control"
(timeout 20 /root/exploit; echo "[init-live] exploit exit=$?") || true
echo "[init-live] ---- dmesg tail ----"
dmesg | tail -n 200
echo "[init-live] ---- end dmesg ----"
# Print a structured verdict line the QEMU wrapper greps for.
if dmesg | grep -qE "BUG: KASAN|KASAN: "; then
  echo "[init-live] LIVE-VERDICT: kasan-fired (restriction failed)"
else
  echo "[init-live] LIVE-VERDICT: no-kasan (restriction held)"
fi
poweroff -f
EOF
chmod +x "${WORK}/init"

cd "${WORK}"
find . -print0 | cpio --null -ov --format=newc 2>/dev/null | gzip -9 > "${ROOT}/artifacts/initramfs-live.cpio.gz"
echo "[make_rootfs_live] initramfs at ${ROOT}/artifacts/initramfs-live.cpio.gz ($(du -h "${ROOT}/artifacts/initramfs-live.cpio.gz" | cut -f1))"
