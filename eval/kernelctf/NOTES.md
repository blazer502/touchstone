# kernelCTF — historical-reproduction smoke

End-to-end smoke test of the kernel toolchain: fetch one *historical*
kernelCTF submission's exact LTS version + config, build with KASAN+KCOV,
boot under QEMU via kctf, run syzkaller against the relevant subsystem with
the published PoC's syscall surface, confirm KASAN reports the known bug.

kernelCTF is a field target; this run is a toolchain smoke, not a scored benchmark.

---

## Submission picked: CVE-2024-1086

`nf_tables` skb double-free; `NF_DROP_ERR` verdict sanitization gap.

| | |
|---|---|
| kernelCTF dir | `pocs/linux/kernelctf/CVE-2024-1086_lts_mitigation` (`google/security-research`) |
| LTS environment | `lts-6.1.72` |
| Upstream patch | `f342de4e2f33e0e39165d8639387aa6c19dff660` |
| Affected | Linux 3.15 – 6.8-rc1 |

**Why this CVE:**

- **Small triggering surface.** A few `nft_*` netlink messages with a chosen rule that returns `NF_DROP_ERR(>0)`. No LPE machinery to hit the bug itself — only KASAN-detectable corruption.
- **Reliable.** 99.6 % success across n=1000 on kernelCTF; on KASAN+slub_debug the double-free fires deterministically (KASAN poisons the freed slab on first `kfree`).
- **Subsystem already on radar** (`net/netfilter/`), so the static scoping done here is reusable by Stage A later.
- **Pure netlink/userns.** No kernelCTF-specific binary deps, no `/flag` lookup needed to observe the KASAN report.

We extract only the *trigger* (the nft setup that produces a `NF_DROP_ERR`
verdict path) and run it on our own KASAN-instrumented build. We do **not**
ship the kernelCTF LPE primitives.

---

## Reproduction plan

1. **`linux/`** — checkout `linux-6.1.72` (from `linux-stable.git`, depth-1 tag).
2. **`linux/.config`** — `tinyconfig`-style minimal x86_64 base + syzbot KASAN+KCOV+UBSAN+nftables+userns options. Built by `scripts/make_config.sh`; the resulting `.config` is checked in for reproducibility.
3. **`rootfs/`** — minimal initramfs from `busybox-static` + small `init` + the trigger binary. Initramfs because it boots in 1–2 s vs. ~10 s for a debootstrap image, and the bug fires before `/sbin/init` finishes.
4. **`exploits/CVE-2024-1086-trigger/`** — the minimal trigger only (the part of the published exploit that builds the malformed nft ruleset and sends a packet).
5. **`scripts/run_qemu.sh`** — `qemu -enable-kvm -cpu host -smp 4 -m 2G`, serial console, `panic_on_warn` off. Boots straight into `init`, which runs the trigger and dumps `dmesg`.
6. **Success** — `artifacts/dmesg-cve-2024-1086.log` contains `BUG: KASAN:` originating in `net/netfilter/nf_tables_core.c` or `nft_immediate.c`.

---

## Static scoping

`scoping/run_scoping.sh` runs Smatch + Coccinelle + Sparse over
`net/netfilter/` of the 6.1.72 source. Output to
`scoping/{smatch,cocci,sparse}.out`. This is a toolchain smoke — full
soundness/coverage analysis runs as part of Stage A.

---

## Cost / disk budget

| Item | Size |
|---|---|
| Source tree (depth-1 6.1.72 tag) | ~1.4 GB |
| Build artifacts (KASAN debug) | 6–8 GB |
| Initramfs | ~5 MB |
| Static-scoping image (`veri-agent/kernel-static:latest`) | ~2.5 GB |
| **Total worst case** | **~12 GB** (host had 121 GB free at start) |
