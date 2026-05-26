# kernelCTF Phase-0.4 — sanity-only historical reproduction

Phase 0.4 in PLAN §6 calls for: "Fetch one *historical* kernelCTF submission's exact LTS
version + config; build with KASAN+KCOV; boot under QEMU via kctf; run syzkaller against the
relevant subsystem with the published PoC's syscall surface and confirm KASAN reports the
known bug." This is a **smoke test of the kernel toolchain**, not a scored benchmark —
kernelCTF is a field target.

## Submission picked

- **CVE-2024-1086** (`nf_tables` skb double-free; verdict drop-error sanitization).
- kernelCTF dir: `pocs/linux/kernelctf/CVE-2024-1086_lts_mitigation` in
  `google/security-research`. LTS environment: `lts-6.1.72`. Patch commit upstream:
  `f342de4e2f33e0e39165d8639387aa6c19dff660`. Affected: Linux 3.15 – 6.8-rc1.
- Why this CVE:
  - **Small triggering surface.** Bug is a double-free reachable via a few `nft_*` netlink
    messages with a chosen rule that returns `NF_DROP_ERR(>0)` — no LPE machinery needed
    to hit *the bug itself*, only KASAN-detectable corruption.
  - **Reliable.** Submission notes 99.6% success across n=1000 on the kernelCTF environment;
    on a debug kernel (KASAN+slub_debug) the double-free fires deterministically because
    KASAN poisons the freed slab on first `kfree`.
  - **Subsystem already on the LLM-funnel radar** (`net/netfilter/`), so the static
    scoping done in 0.4e is reusable later in Phase 1.
  - **Pure netlink/userns** — no kernelCTF-specific binary deps, no `/flag` lookup needed
    to observe the KASAN report.
- We do **not** need the full kernelCTF LPE; we extract the *trigger* (nft setup that
  produces a `NF_DROP_ERR` verdict path) and run it on our own KASAN-instrumented build of
  Linux 6.1.72.

## Reproduction plan

1. `linux/` — checkout `linux-6.1.72` source tree (from `linux-stable.git`, depth-1 tag).
2. `linux/.config` — start from `tinyconfig`-style minimal x86_64 base, add the syzkaller
   "syzbot" KASAN+KCOV+UBSAN+nftables+userns options. Config script is
   `scripts/make_config.sh`; the resulting `.config` is checked in for reproducibility.
3. `rootfs/` — minimal initramfs built from `busybox-static` (apt) + a small `init`
   script + our trigger binary. Initramfs because it boots in 1–2 s vs. ~10 s for a
   debootstrap disk image, and the bug fires before `/sbin/init` finishes.
4. `exploits/CVE-2024-1086-trigger/` — minimal trigger (just the part of the published
   exploit that builds the malformed nft ruleset + sends a packet). We do **not** ship the
   kernelCTF LPE primitives — only the syscall sequence that hits the double-free.
5. `scripts/run_qemu.sh` — QEMU command line: `-enable-kvm -cpu host -smp 4 -m 2G`,
   serial console, panic_on_warn off, KASAN report visible. Boots straight into our
   `init`, which runs the trigger and dumps `dmesg`.
6. Success = the dmesg captured to `artifacts/dmesg-cve-2024-1086.log` contains
   `BUG: KASAN:` originating in `net/netfilter/nf_tables_core.c` or `nft_immediate.c`.

## Static scoping (0.4e)

`scoping/run_scoping.sh` runs Smatch + Coccinelle + Sparse over `net/netfilter/` of the
6.1.72 source. Output goes to `scoping/{smatch,cocci,sparse}.out`. This is a smoke run —
the 0.4 "Done when" only requires the tools to *execute on a smoke input*; full
soundness/coverage analysis is Phase 1.

## Cost / disk budget

- Source tree (depth-1 6.1.72 tag): ~1.4 GB
- Build artifacts (KASAN debug): ~6–8 GB
- Initramfs: ~5 MB
- Static-scoping image (`veri-agent/kernel-static:latest`): ~2.5 GB once built
- Total: ~12 GB worst case. Host free space at start was 121 GB.
