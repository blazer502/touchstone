#!/usr/bin/env bash
# Generate the hunt-mode config for the latest kernelCTF LTS-6.12 instance.
#
# Recipe (anchored to kernelctf/build_release.sh + the hunt-mode sanitizer
# delta):
#   1. fetch COS lakitu_defconfig from cos-6.12 branch (base64-decoded) -> .config
#   2. sed s/=m/=y/g  (build everything into the kernel, per build_release.sh:112)
#   3. assemble ONE combined fragment from
#        (a) lts-6.12.config   -- the official kernelCTF overlay
#        (b) hunt-mode delta   -- KASAN+KCOV+UBSAN+SLUB_DEBUG_ON+LOCKDEP, no
#                                 KASLR, virtio/initramfs/serial for QEMU,
#                                 and the COS attack-surface restrictions
#                                 (IO_URING off, USER_NS_UNPRIVILEGED off,
#                                 BLK_DEV_UBLK off, EXPERT on).
#      Merging in one shot is important: an interim olddefconfig between
#      (a) and (b) locks symbols at their defaults before (b) has a chance
#      to set EXPERT=y, which is the visibility gate for IO_URING.
#   4. merge_config.sh -m  +  olddefconfig
#   5. verify must-be-{on,off} invariants
#
# Soundness lever: changing any line in the hunt-mode delta widens or
# narrows the *hunt* surface, NOT the deployed surface. The deployed
# surface is whatever the lakitu+overlay produces. Keep the two distinct.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="${SRC:-${ROOT}/linux/source}"
OUT="${KBUILD_OUTPUT:-${ROOT}/linux/build-latest}"
mkdir -p "${OUT}"

[[ -f "${SRC}/Makefile" ]] || {
  echo "missing kernel source at ${SRC}; run fetch_kernel.sh first" >&2; exit 1; }

cd "${SRC}"

# --- step 1: fetch lakitu_defconfig (COS cos-6.12) ----------------------------
LAKITU_B64="${ROOT}/configs/lakitu_defconfig.b64"
LAKITU_PLAIN="${ROOT}/configs/lakitu_defconfig"
mkdir -p "$(dirname "${LAKITU_B64}")"
if [[ ! -s "${LAKITU_PLAIN}" ]]; then
  echo "[make_config_latest] fetching lakitu_defconfig from cos-6.12 branch"
  curl -fsSL -o "${LAKITU_B64}" \
    'https://cos.googlesource.com/third_party/kernel/+/refs/heads/cos-6.12/arch/x86/configs/lakitu_defconfig?format=text'
  base64 -d "${LAKITU_B64}" > "${LAKITU_PLAIN}"
fi
cp "${LAKITU_PLAIN}" "${OUT}/.config"

# --- step 2: =m -> =y (everything built-in, per build_release.sh:112) ---------
sed -i 's/=m/=y/g' "${OUT}/.config"

# --- step 3: assemble the combined fragment -----------------------------------
OVERLAY="${ROOT}/configs/lts-6.12.config"
if [[ ! -s "${OVERLAY}" ]]; then
  curl -fsSL -o "${OVERLAY}" \
    'https://raw.githubusercontent.com/google/security-research/master/kernelctf/kernel_configs/lts-6.12.config'
fi

FRAG="$(mktemp)"
cat "${OVERLAY}" >"${FRAG}"
cat >>"${FRAG}" <<'EOF'

# === Deployed-kernel alignment notes (NOT restrictions) =====================
# lakitu_defconfig already ships:
#   CONFIG_EXPERT=y
#   CONFIG_IO_URING=y            (kept built-in; kernelCTF "io_uring disabled"
#                                 is a runtime sysctl, not a build-time strip)
#   CONFIG_BLK_DEV_UBLK is not set
#   CONFIG_USER_NS=y             (CONFIG_USER_NS_UNPRIVILEGED was removed in
#                                 newer kernels; "unprivileged user namespaces
#                                 turned off since July 1st, 2025" is the
#                                 sysctl kernel.unprivileged_userns_clone=0)
# Both runtime restrictions are set in the initramfs init script.

# === Hunt-mode detectors (auditable PoVs) ==================================
CONFIG_DEBUG_KERNEL=y
CONFIG_DEBUG_INFO=y
CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT=y
CONFIG_KASAN=y
CONFIG_KASAN_GENERIC=y
CONFIG_KASAN_INLINE=y
CONFIG_KCOV=y
CONFIG_KCOV_INSTRUMENT_ALL=y
CONFIG_KCOV_ENABLE_COMPARISONS=y
CONFIG_UBSAN=y
CONFIG_UBSAN_BOUNDS=y
CONFIG_SLUB_DEBUG=y
CONFIG_SLUB_DEBUG_ON=y
CONFIG_PANIC_ON_OOPS=n
CONFIG_BUG_ON_DATA_CORRUPTION=y
CONFIG_PROVE_LOCKING=y
CONFIG_LOCKDEP=y
CONFIG_DEBUG_LIST=y
# Deterministic addresses (lets symbolizer cross-reference vmlinux).
CONFIG_RANDOMIZE_BASE=n
CONFIG_RANDOMIZE_MEMORY=n

# === QEMU boot / initramfs / serial console ================================
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

# === Strip secure-boot-shaped bits that lakitu carries =====================
CONFIG_MODULE_SIG=n
CONFIG_SECURITY_LOCKDOWN_LSM=n
CONFIG_SYSTEM_REVOCATION_LIST=n
CONFIG_SYSTEM_TRUSTED_KEYRING=n
EOF

# --- step 4: merge once + olddefconfig ----------------------------------------
./scripts/kconfig/merge_config.sh -O "${OUT}" -m "${OUT}/.config" "${FRAG}" >/dev/null
make O="${OUT}" olddefconfig

# --- step 5: verify invariants ------------------------------------------------
echo "[make_config_latest] verifying invariants"
must_be_off=( CONFIG_NF_TABLES \
              CONFIG_RANDOMIZE_BASE CONFIG_RANDOMIZE_MEMORY \
              CONFIG_BLK_DEV_UBLK CONFIG_MODULE_SIG )
for opt in "${must_be_off[@]}"; do
  if grep -qE "^${opt}=y" "${OUT}/.config"; then
    echo "ERROR: ${opt} is enabled (must be off)" >&2; exit 1
  fi
done
# CONFIG_IO_URING stays =y to match the deployed kernel. Runtime restriction
# happens via /proc/sys/kernel/io_uring_disabled in the initramfs init.
must_be_on=( CONFIG_KASAN CONFIG_KASAN_GENERIC CONFIG_KCOV CONFIG_UBSAN \
             CONFIG_SLUB_DEBUG_ON CONFIG_DEBUG_INFO CONFIG_EXPERT \
             CONFIG_DEBUG_KERNEL CONFIG_IO_URING CONFIG_USER_NS )
for opt in "${must_be_on[@]}"; do
  if ! grep -q "^${opt}=y" "${OUT}/.config"; then
    echo "ERROR: ${opt} is not enabled (must be on)" >&2; exit 1
  fi
done

DEST_CFG="${ROOT}/configs/config-6.12.91-hunt.txt"
cp "${OUT}/.config" "${DEST_CFG}"
echo "[make_config_latest] frozen config at ${DEST_CFG}"
echo "[make_config_latest] build dir: ${OUT}"
