#!/usr/bin/env bash
# Generate the live-LTS-instance kernel config: KASAN+KCOV+UBSAN + COS-style
# attack-surface restrictions from PLAN §5b.B.4 ("latest LTS, COS config,
# unprivileged userns off, io_uring + nftables disabled").
#
# Soundness lever (recorded in docs/soundness-assumptions.md): adding a CONFIG_*
# option to this list narrows the live-hunt surface; removing one re-introduces
# surface that the historical exploit ruleset already covers. Either side moves
# the live target — keep the diff against config-6.1.72-kasan.txt small.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="${SRC:-${ROOT}/linux/source}"
OUT="${KBUILD_OUTPUT:-${ROOT}/linux/build-live}"
mkdir -p "${OUT}"
cd "${SRC}"

# Start from x86_64 defconfig in the live build dir.
make O="${OUT}" x86_64_defconfig

FRAG="$(mktemp)"
cat >"${FRAG}" <<'EOF'
# === Debug / detectors (auditable PoVs) ===
CONFIG_DEBUG_KERNEL=y
CONFIG_DEBUG_INFO=y
CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT=y
CONFIG_KASAN=y
CONFIG_KASAN_GENERIC=y
CONFIG_KASAN_INLINE=y
CONFIG_KCOV=y
CONFIG_UBSAN=y
CONFIG_UBSAN_BOUNDS=y
CONFIG_SLUB_DEBUG=y
CONFIG_SLUB_DEBUG_ON=y
CONFIG_PANIC_ON_OOPS=n
CONFIG_BUG_ON_DATA_CORRUPTION=y
CONFIG_PROVE_LOCKING=y
CONFIG_LOCKDEP=y
CONFIG_DEBUG_LIST=y

# Deterministic addresses.
CONFIG_RANDOMIZE_BASE=n
CONFIG_RANDOMIZE_MEMORY=n

# === COS-style restrictions ===
# 1. unprivileged userns off — sysctl is the runtime knob, but defaulting it
#    to disabled at boot mirrors the GKE/COS image.
CONFIG_USER_NS=y
CONFIG_USER_NS_UNPRIVILEGED=n
# 2. io_uring disabled. IO_URING is `default y` behind EXPERT, and BLK_DEV_UBLK
#    `select`s it — both must be flipped before olddefconfig will honor =n.
CONFIG_EXPERT=y
CONFIG_BLK_DEV_UBLK=n
CONFIG_IO_URING=n
# 3. nftables disabled (the historical CVE-2024-1086 surface).
CONFIG_NF_TABLES=n
CONFIG_NFT_CT=n
CONFIG_NFT_LIMIT=n
CONFIG_NFT_NAT=n
CONFIG_NFT_OBJREF=n
# Keep the conntrack/iptables surface — they're enabled in COS too.
CONFIG_NETFILTER=y
CONFIG_NETFILTER_ADVANCED=y
CONFIG_NF_CONNTRACK=y
CONFIG_NF_NAT=y
CONFIG_NETFILTER_NETLINK=y

# === Boot / init / serial (same as Phase 0.4) ===
CONFIG_BLK_DEV_INITRD=y
CONFIG_VIRTIO=y
CONFIG_VIRTIO_PCI=y
CONFIG_VIRTIO_NET=y
CONFIG_VIRTIO_BLK=y
CONFIG_VIRTIO_CONSOLE=y
CONFIG_SERIAL_8250=y
CONFIG_SERIAL_8250_CONSOLE=y
CONFIG_TTY=y
CONFIG_PRINTK=y
CONFIG_MODULE_SIG=n
CONFIG_SECURITY_LOCKDOWN_LSM=n
EOF

./scripts/kconfig/merge_config.sh -O "${OUT}" -m "${OUT}/.config" "${FRAG}" >/dev/null
make O="${OUT}" olddefconfig

# Verify the restrictions stuck. A live-LTS kernel MUST NOT have these.
echo "[make_config_live] verifying COS restrictions"
must_be_off=( CONFIG_NF_TABLES CONFIG_IO_URING CONFIG_USER_NS_UNPRIVILEGED )
for opt in "${must_be_off[@]}"; do
  if grep -qE "^${opt}=y" "${OUT}/.config"; then
    echo "ERROR: ${opt} is enabled in live config" >&2
    exit 1
  fi
done
must_be_on=( CONFIG_KASAN CONFIG_KCOV )
for opt in "${must_be_on[@]}"; do
  if ! grep -q "^${opt}=y" "${OUT}/.config"; then
    echo "ERROR: ${opt} not enabled" >&2
    exit 1
  fi
done

DEST_CFG="${ROOT}/configs/config-6.1.72-live-lts-cos.txt"
mkdir -p "$(dirname "${DEST_CFG}")"
cp "${OUT}/.config" "${DEST_CFG}"
echo "[make_config_live] frozen config at ${DEST_CFG}"
echo "[make_config_live] live build dir: ${OUT}"
