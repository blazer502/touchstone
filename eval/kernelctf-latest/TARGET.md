# kernelCTF latest-LTS target (pinned)

Source: https://google.github.io/security-research/kernelctf/rules.html
       + https://github.com/google/security-research/tree/master/kernelctf

## Pinned at 2026-05-27

- **Instance:** `lts-6.12`
- **Kernel tag:** `v6.12.91` (from `gregkh/linux`, resolved via
  `git ls-remote --tags --sort='-v:refname' https://github.com/gregkh/linux 'v6.12.*[0-9]'`)
  - Commit: `57eaf35b038699cf6e54645352a0802dc912eae3`
- **Base config:** COS `lakitu_defconfig` from
  `https://cos.googlesource.com/third_party/kernel/+/refs/heads/cos-6.12/arch/x86/configs/lakitu_defconfig?format=text`
  (base64-encoded; snapshot string declares 6.12.68 — normalized by `make olddefconfig`).
- **Overlay:** `lts-6.12.config` (60 bytes):
    ```
    # CONFIG_NF_TABLES is not set
    CONFIG_SYSTEM_TRUSTED_KEYS=""
    ```
- **Build recipe (verbatim, from `kernelctf/build_release.sh`):**
  1. fetch `lakitu_defconfig` → use as `.config`
  2. `sed -i s/=m/=y/g .config`  (everything built-in)
  3. `cp lts-6.12.config kernel/configs/ && make lts-6.12.config`
  4. `make olddefconfig`
  5. `make -j$(nproc)`

## Implicit kernelCTF semantic restrictions (already in lakitu_defconfig)

- `CONFIG_USER_NS_UNPRIVILEGED` defaulted off (sysctl-level, per kernelCTF rules
  "unprivileged user namespaces turned off since July 1st, 2025").
- `CONFIG_IO_URING` disabled (per rules text).
- `CONFIG_NF_TABLES=n` (overlay).

These restrictions remove three classic attack surfaces from the running kernel —
this is the *deployed* configuration to be hunted, not a vanilla LTS build.

## Hunt-mode delta on top of the official build (our addition)

For *finding* bugs (vs. shipping deployed binaries), we layer KASAN+KCOV+UBSAN+
SLUB_DEBUG_ON+LOCKDEP onto the above. These are NOT in the official kernelCTF
build because they are debug aids that change runtime behavior. A confirmed
crash under the hunt-mode kernel still has to be re-verified against an
*official* lts-6.12 build to count as a kernelCTF-eligible PoV — that
re-verification step lives in Phase 4.x (TBD).

## Authoritative artifacts published by Google

- Pre-built bzImage: `https://storage.googleapis.com/kernelctf-build/releases/lts-<tag>/bzImage`
  (e.g. `releases/lts-6.12.91/bzImage`) — production-shape, no sanitizers.
- Source-of-truth manifest of currently-fielded releases:
  Google's `get_latest_lts_cos_versions.py` (run by their CI). We mirror its
  resolution logic in `scripts/resolve_latest.sh`.
