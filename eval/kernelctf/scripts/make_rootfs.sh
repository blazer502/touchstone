#!/usr/bin/env bash
# Build a minimal initramfs: busybox + the CVE-2024-1086 exploit + an init script
# that runs it and dumps dmesg.  Output: artifacts/initramfs.cpio.gz.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${ROOT}/rootfs/build"
EXPLOIT="${ROOT}/exploits/CVE-2024-1086/exploit"

[[ -x "${EXPLOIT}" ]] || { echo "missing ${EXPLOIT}" >&2; exit 1; }

rm -rf "${WORK}"
mkdir -p "${WORK}"/{bin,sbin,etc,proc,sys,dev,tmp,root}

# Busybox provides all standard utilities as a single static binary.
cp /usr/bin/busybox "${WORK}/bin/busybox"
chmod +x "${WORK}/bin/busybox"

# Drop the exploit binary into /root so it's clearly visible in dmesg output.
cp "${EXPLOIT}" "${WORK}/root/exploit"
chmod +x "${WORK}/root/exploit"

# Build out the standard busybox symlinks so PATH lookup works for the exploit's
# /bin/sh fallbacks and so dmesg / mount are available.
APPLETS="sh ls cat echo mount umount mkdir mknod sleep dmesg ip ifconfig ps kill grep sed cp mv rm chmod chown poweroff sync"
for a in ${APPLETS}; do
  ln -sf /bin/busybox "${WORK}/bin/${a}"
done
ln -sf /bin/busybox "${WORK}/sbin/poweroff"

# Init script — boot, run exploit, dump dmesg tail, poweroff.
cat >"${WORK}/init" <<'EOF'
#!/bin/busybox sh
/bin/busybox --install -s /bin >/dev/null 2>&1 || true
export PATH=/bin:/sbin:/usr/bin:/usr/sbin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev || mknod /dev/null c 1 3 || true

echo "[init] linux $(uname -r) up"
echo "[init] running /root/exploit (CVE-2024-1086 trigger)"
# Don't let an exploit crash hang the VM — give it 20s, then dump dmesg either way.
(timeout 20 /root/exploit; echo "[init] exploit exit=$?") || true
echo "[init] ---- dmesg tail ----"
dmesg | tail -n 200
echo "[init] ---- end dmesg ----"
echo "[init] poweroff"
poweroff -f
EOF
chmod +x "${WORK}/init"

# Pack into cpio.gz.
cd "${WORK}"
find . -print0 | cpio --null -ov --format=newc 2>/dev/null | gzip -9 > "${ROOT}/artifacts/initramfs.cpio.gz"
echo "[make_rootfs] initramfs at ${ROOT}/artifacts/initramfs.cpio.gz ($(du -h "${ROOT}/artifacts/initramfs.cpio.gz" | cut -f1))"
