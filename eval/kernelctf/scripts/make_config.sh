#!/usr/bin/env bash
# Generate a minimal x86_64 KASAN+KCOV+UBSAN+nftables+userns config for Linux 6.1.72.
# Starts from defconfig (the syzkaller config is overkill for a single-bug repro) and
# layers on debug + the surface CVE-2024-1086 needs.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="${SRC:-${ROOT}/linux/source}"
cd "${SRC}"

# Start from x86_64 defconfig.
make x86_64_defconfig

# Append fragments we need. Use scripts/kconfig/merge_config.sh for safety.
FRAG="$(mktemp)"
cat >"${FRAG}" <<'EOF'
# === Debug / detectors required for the KASAN smoke ===
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

# Slow but deterministic on x86_64.
CONFIG_RANDOMIZE_BASE=n
CONFIG_RANDOMIZE_MEMORY=n

# === Surface needed by CVE-2024-1086 (nf_tables + userns + verdicts) ===
CONFIG_USER_NS=y
CONFIG_NAMESPACES=y
CONFIG_NET_NS=y
CONFIG_NETFILTER=y
CONFIG_NETFILTER_ADVANCED=y
CONFIG_NF_TABLES=y
CONFIG_NF_TABLES_INET=y
CONFIG_NF_TABLES_IPV4=y
CONFIG_NF_TABLES_IPV6=y
CONFIG_NFT_CT=y
CONFIG_NFT_LIMIT=y
CONFIG_NFT_NAT=y
CONFIG_NFT_OBJREF=y
CONFIG_NF_CONNTRACK=y
CONFIG_NF_NAT=y
CONFIG_NETFILTER_NETLINK=y
CONFIG_NETLINK_DIAG=y

# === Initramfs / virtio / serial we need to actually boot a tiny system ===
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

# Disable signing/lockdown; not needed and slows boot.
CONFIG_MODULE_SIG=n
CONFIG_SECURITY_LOCKDOWN_LSM=n
EOF

./scripts/kconfig/merge_config.sh -m .config "${FRAG}" >/dev/null
make olddefconfig

# Sanity-check the key options actually ended up =y in the final .config.
echo "[make_config] verifying critical options"
required=( CONFIG_KASAN CONFIG_KCOV CONFIG_NF_TABLES CONFIG_USER_NS )
for opt in "${required[@]}"; do
  if ! grep -q "^${opt}=y" .config; then
    echo "ERROR: ${opt} did not stick in .config" >&2
    grep -E "^${opt}[= ]" .config || echo "  (no line at all)" >&2
    exit 1
  fi
done

# Copy a frozen snapshot back into the repo for reproducibility.
DEST_CFG="${ROOT}/configs/config-6.1.72-kasan.txt"
mkdir -p "$(dirname "${DEST_CFG}")"
cp .config "${DEST_CFG}"
echo "[make_config] frozen config at ${DEST_CFG}"
