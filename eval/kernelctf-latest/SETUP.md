# kernelCTF-latest setup — status

Setup-only pass for the latest kernelCTF LTS instance. NO fuzzing has been run.

## Deployed-kernel alignment

The hunt kernel matches the deployed kernelCTF kernel (lts-6.12.91) on every
Kconfig symbol except the **hunt-mode delta** — sanitizers, debug aids, QEMU
boot bits, no KASLR. The two restrictions that the rules page lists as
"disabled" (io_uring, unprivileged user namespaces) are **runtime sysctl
restrictions** on the deployed kernel, not build-time strips — both Kconfig
symbols stay built-in in the official `lakitu_defconfig`. The hunt kernel
matches that exactly: `CONFIG_IO_URING=y`, `CONFIG_USER_NS=y`, and the
initramfs init sets `kernel.io_uring_disabled=2`,
`kernel.unprivileged_userns_clone=0`, `user.max_user_namespaces=0` before
any test runs. The only build-time strip is `CONFIG_NF_TABLES=n`, which
matches `kernel_configs/lts-6.12.config` verbatim.

## Submission eligibility (rules-side, not config-side)

The current kernelCTF rules **exclude io_uring and nftables bugs from
submission rewards**. Both surfaces stay present in our hunt config
(NF_TABLES=n is the only build-time strip; io_uring is built-in to match
deployed) so that the agent doesn't falsely prune *adjacent* code, but the
syz-manager `disable_syscalls` list filters `io_uring_*` and `nf_tables_*`
out of the fuzzer's program-generation surface so hunt time isn't spent
on ineligible categories.

**Eligible hunt subsystems** (in rough order of historical kernelCTF ROI):
`kernel/bpf`, `net/sched`, `mm/`, `fs/`, `drivers/vhost`, `kernel/sched`,
`kernel/locking`, `block/`, perf, scheduler, AF_VSOCK.

## Pinned target

See `TARGET.md`. tl;dr: `lts-6.12.91` from `gregkh/linux`
(commit `57eaf35b03`), COS `lakitu_defconfig` from cos-6.12 +
`lts-6.12.config` overlay + hunt-mode sanitizer delta on top.

## Ready-to-use artifacts

| Artifact | Path | Status |
|---|---|---|
| Kernel source | `linux/source/` (1.8 GB, 6.12.91) | ✓ extracted |
| Frozen hunt-mode config | `configs/config-6.12.91-hunt.txt` | ✓ KASAN+KCOV+UBSAN+SLUB_DEBUG_ON+LOCKDEP, NF_TABLES=n, IO_URING=y (matches deployed; runtime sysctl gates it), no KASLR |
| bzImage | `artifacts/bzImage-latest` (57 MB) | ✓ built (gcc-11, 1m18s wall, version-stamped 6.12.91) |
| Initramfs (setup-mode) | `artifacts/initramfs-latest.cpio.gz` (1.1 MB) | ✓ enforces userns sysctl restrictions at boot |
| Boot dmesg | `artifacts/dmesg-latest-setup.log` | ✓ LIVE-VERDICT: ready — restrictions applied, no boot-time KASAN |
| Syzkaller image | `touchstone/syzkaller:2b01f00eb6f2` (3.42 GB Docker image) | ✓ built from google/syzkaller master @ 2b01f00eb6f2, Go 1.26 base; `syz-manager` + 7 syz-* binaries on PATH |
| Stage-A surface (netfilter) | `surface/{entrypoints,slice,tasks}/linux-6.12.91-net-netfilter*` | ✓ 252 sources → 26 clusters → 1145 entries / 767 unique funcs → 21.4% pruned (keep=3172/4038) |
| Syz-manager config template | `syzkaller/manager.cfg.template` | ✓ rendered per-subsystem via `render_syz_config.sh` |
| Syz-manager config (net-netfilter) | `syzkaller/manager-net-netfilter.cfg` + `workdir-net-netfilter/` | ✓ enable_syscalls list derived from Stage-A dispatcher classes |
| Agent.loop candidates | `agent/smoke/candidates_kernelctf_latest.json` | ✓ closed-loop dry-run: k-latest-1=inconclusive (boot smoke, no exploit), k-latest-2=confirmed (historical positive control) |

## How to hunt (when ready)

The actual hunt is gated on operator order. The wiring below is staged but
not launched.

```bash
# 1. Pick a subsystem to hunt in. The existing Stage-A run covers net/netfilter,
#    which is a degraded surface in lts-6.12 (NF_TABLES=n). For more
#    interesting hunting, re-run Stage-A on a subsystem with active surface:
bash eval/kernelctf-latest/scripts/run_stage_a.sh kernel/bpf
# (NOTE: surface/entrypoints.py only knows netfilter-shaped dispatcher types.
#  Extending it to net/sched (Qdisc_ops, tcf_proto_ops, ...) or kernel/bpf
#  (bpf_prog_ops, bpf_link_ops, ...) is a one-time engineering step the
#  hunt operator does first — recorded in SETUP.md so it isn't forgotten.)

# 2. Render the syz-manager config for that subsystem:
bash eval/kernelctf-latest/scripts/render_syz_config.sh \
     <subsys-label> eval/kernelctf-latest/syzkaller/enable_syscalls-<subsys>.json

# 3. Launch syz-manager (THIS is the gate the operator opens):
sudo docker run --rm -d --name syz-latest \
   --device /dev/kvm \
   -v $(pwd)/eval/kernelctf-latest:/work \
   touchstone/syzkaller:2b01f00eb6f2 \
   syz-manager -config /work/syzkaller/manager-<subsys>.cfg

# 4. Watch crashes/ for new KASAN reports; feed them to agent.loop via
#    candidates_kernelctf_latest.json (replacing the boot-smoke dmesg_path
#    with the new crash log).
```

## Deferred (not yet done — intentional)

- **Production-profile LLM (Qwen2.5-Coder-32B + 7B)**. Disk is at 92 GB free;
  a Coder-32B pull is ~65 GB. The host's HF cache already has plain Instruct
  variants (`Qwen2.5-32B-Instruct`, `Qwen2.5-7B-Instruct`) which are
  adequate as a fallback. Launching the production profile costs ~20 GB
  VRAM per replica and serves nothing at rest. **Decision: bring up at
  hunt-launch time, sized to the chosen subsystem.**
- **Stage-A dispatcher-type catalog for kernel/bpf, net/sched, fs/**. The
  Phase-1.2 catalog was authored against netfilter. Each new subsystem
  needs ~3-5 dispatcher types added to `surface/entrypoints.py`
  `DISPATCHER_TYPES`. **Decision: add when the operator picks a target;
  trivial and per-subsystem.**
- **Pre-built syzkaller corpus**. syz-manager auto-corpuses; no seed corpus
  needed for a cold hunt. We can also drop in a published corpus later.
- **Real `syz-manager` launch**. Per operator order only.
- **Reproducer/repro pipeline**. syz-repro is in the image; wire-up
  happens when a crash lands.

## Files added by this setup

```
eval/kernelctf-latest/
├── TARGET.md            ← pinned target spec
├── SETUP.md             ← this file
├── scripts/
│   ├── resolve_latest.sh        ← resolve latest LTS-6.12 tag from gregkh
│   ├── fetch_kernel.sh          ← kernel.org tarball pull
│   ├── make_config_latest.sh    ← lakitu + lts-6.12.config + hunt-mode
│   ├── build_kernel_latest.sh   ← bzImage build
│   ├── make_rootfs_latest.sh    ← setup-mode initramfs (sysctl restrictions)
│   ├── run_qemu_latest.sh       ← boot smoke (no exploit)
│   ├── run_stage_a.sh           ← decompose + entrypoints + reachability
│   └── render_syz_config.sh     ← syz-manager config from Stage-A surface
├── configs/             ← lakitu_defconfig, lts-6.12.config, config-6.12.91-hunt.txt
├── linux/               ← source/ + build-latest/
├── artifacts/           ← bzImage-latest, initramfs-latest.cpio.gz, dmesg-*.log
├── initramfs/build/     ← initramfs working tree
└── syzkaller/           ← manager.cfg.template + per-subsystem renders + workdirs

surface/{entrypoints,slice,tasks}/linux-6.12.91-net-netfilter*
agent/smoke/candidates_kernelctf_latest.json
docker/syzkaller.Dockerfile   ← bumped to golang:1.26-bookworm
docs/toolchain.lock           ← SYZKALLER_COMMIT pinned to 2b01f00eb6f2
```
