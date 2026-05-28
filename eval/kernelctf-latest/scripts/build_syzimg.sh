#!/usr/bin/env bash
# Build syzimg.img — the syz-manager guest disk for the kernelctf-latest hunt.
#
# Lessons baked in (Phase 9b directed-campaign debugging):
#   - SIZE: a 1 GB image FILLS under a sustained multi-VM run -> the guest hits
#     "No space left on device", syz-executor mkdtemp fails (SYZFAIL: ...), and
#     fuzzing STALLS (coverage flatlines, exec/sec collapses). Use >= 8 GB.
#   - IP: the minimal Debian image's DHCP times out under QEMU user-mode
#     networking, so `networking.service` fails and sshd is unreachable. Pin
#     eth0 to the deterministic user-net address 10.0.2.15/24 (gw 10.0.2.2).
#   - NIC (handled in the manager configs, NOT here): the hunt kernel has
#     CONFIG_VIRTIO_NET=y but CONFIG_E1000 unset, so every manager-*.cfg sets
#     vm.network_device = virtio-net-pci (syz-manager defaults to e1000, which
#     this kernel can't drive).
#
# Prereqs: host `debootstrap` + passwordless `sudo` + the veri-agent/syzkaller
# image (docker/syzkaller.Dockerfile). create-image.sh runs on the HOST because
# it needs debootstrap, which is not in the syzkaller image.
#
# Output (both gitignored — this script regenerates them):
#   eval/kernelctf-latest/initramfs/build/{syzimg.img, syzimg.id_rsa[.pub]}
#
# Usage:  ./build_syzimg.sh [SIZE_MB]   (default 8192)
set -euo pipefail

SIZE_MB="${1:-8192}"
IMAGE="${SYZKALLER_IMAGE:-veri-agent/syzkaller:master}"
DOCKER="${DOCKER:-sudo docker}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="${ROOT}/initramfs/build"

command -v debootstrap >/dev/null || { echo "need host debootstrap" >&2; exit 1; }

mkdir -p "${BUILD}"
cd "${BUILD}"

# create-image.sh prompts interactively if an ssh key already exists; clear
# stale artifacts so the build is non-interactive.
sudo rm -f syzimg.img syzimg.id_rsa syzimg.id_rsa.pub
sudo rm -rf syzimg

echo "[build_syzimg] debootstrapping ${SIZE_MB} MB bookworm image (this takes minutes)…"
${DOCKER} run --rm "${IMAGE}" cat /opt/syzkaller/tools/create-image.sh > /tmp/veri-create-image.sh
sudo bash /tmp/veri-create-image.sh -d bookworm -f minimal -s "${SIZE_MB}" -o syzimg

# Pin eth0 static (QEMU user-net) — DHCP is unreliable on the minimal image.
echo "[build_syzimg] pinning eth0 static 10.0.2.15/24…"
sudo mkdir -p /mnt/veri-syzimg
sudo mount -o loop syzimg.img /mnt/veri-syzimg
sudo tee /mnt/veri-syzimg/etc/network/interfaces >/dev/null <<'EOF'
source /etc/network/interfaces.d/*

auto lo
iface lo inet loopback

auto eth0
iface eth0 inet static
  address 10.0.2.15
  netmask 255.255.255.0
  gateway 10.0.2.2
EOF
sudo umount /mnt/veri-syzimg && sudo rmdir /mnt/veri-syzimg
sudo rm -rf syzimg   # remove the chroot, keep the image

echo "[build_syzimg] done: ${BUILD}/syzimg.img ($(stat -c%s syzimg.img) bytes) + syzimg.id_rsa"
