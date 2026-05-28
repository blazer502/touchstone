# Kernel Hunt Plan — kernelCTF live LTS (status + resume guide)

Persisted handoff for the kernel-side hunt so it can be paused and resumed
without relearning the setup. Captures the goal, the built pipeline, the
current state, exactly how to restart, the open directions, and the gotchas.

## Goal

Find a **novel, reproducible, unprivileged-user-triggerable** kernel bug in the
live LTS hunt kernel (`lts-6.12.91`, KASAN+KCOV+UBSAN+LOCKDEP+SLUB_DEBUG_ON, COS-style
restrictions), then weaponize it into an LPE PoV (kernelCTF model: ~90%-reproducible).

## Threat model (locked — see `docs/soundness-assumptions.md` "Kernel threat model")

**Unprivileged local user, no capabilities.** Enforced at fuzz time:
all `eval/kernelctf-latest/syzkaller/manager-*.cfg` use `sandbox: setuid`
(NOT `sandbox: none`). Capability-gated paths `EPERM` out, so any counted crash
is unprivileged-reachable by construction. Root-only crashes are out of scope.

## What's built (the pipeline — DONE, committed)

| Piece | Where | Commit |
|---|---|---|
| Crash-reproducer (N-run determinism + minimize; kernel = QEMU+KASAN replay) | `schemas/reproducer.py`, `oracle/repro/` | Phase 8 `9a6452c` |
| Exploitability triage (primitive + severity + controllability) | `schemas/exploit_triage.py`, `exploit/` | 9a `f9726fc` |
| syzkaller toolchain image + R2 kernel synth + `run_syz_manager` | `oracle/repro/kernel.py`, `docker/syzkaller.Dockerfile` | 9b `04a5a58` |
| NIC fix (virtio-net-pci) — runtime loop connects | manager configs | 9b.4 `7d53aef` |
| 8GB image build recipe + directed campaign config | `scripts/build_syzimg.sh`, `manager-campaign.cfg` | 9b.5 `3f28311` |
| setuid threat model across all configs | manager configs + soundness doc | 9b.6 `0a80230` |

End-to-end loop (each link validated individually): directed fuzz → crash bucket
→ `syz-repro`/`syz-prog2c` → R2 reproducer → R3 `repro_rate` → 9a triage.

## Current state (2026-05-28)

- Directed campaign was running against **Candidate A** (perf↔mm↔cpu_hotplug
  lock-order, corroborated in Phase 6/7) under `sandbox: setuid`, ~368 exec/sec,
  ~15k coverage PCs, clean (0 ENOSPC, no executor artifacts under setuid).
- **No novel bug found.** Only executor artifacts so far (SIGBUS / guest-ENOSPC),
  all triaged `not-a-bug` (0 false confirmations — soundness gate held on live data).
  Reference: the 8h root-sandbox run found 12 crash buckets but **0 reproduced**.
- Campaign + 30-min reporting loop **stopped** (this handoff). Resume below.

## How to resume

```bash
cd /home/chanyoung/veri-agent
# 1. (if syzimg.img absent — it's gitignored) build the 8GB guest:
eval/kernelctf-latest/scripts/build_syzimg.sh 8192
# 2. launch the directed campaign (setuid, virtio-net, 8GB):
sudo docker run --rm --name veri-syz-campaign --device /dev/kvm \
  -p 127.0.0.1:50004:50004 \
  -v "$(pwd)/eval/kernelctf-latest":/work veri-agent/syzkaller:master \
  syz-manager -config /work/syzkaller/manager-campaign.cfg > run-logs/campaign.log 2>&1 &
# 3. monitor: run-logs/campaign.log, workdir-campaign/crashes/, http 127.0.0.1:50004
# 4. on a REAL (non-suppressed) bucket <B>:
python3 -m oracle.repro.kernel synth --bucket-dir <B> --crash-class <cls> --out /tmp/synth.json
python3 -m exploit.triage --evidence <B>/report0 --unit campaign:<hash>
# 5. (optional) recurring reporting:  /loop 30m <report prompt>
# stop:  sudo docker stop veri-syz-campaign   (+ CronDelete the loop job)
```

## Open directions (pick up here)

1. **Long campaign** (hours–days) to actually surface a bug — the gating unknown; finding+reproducing a novel bug is probabilistic.
2. **Lever A — broaden** `enable_syscalls` (more subsystems → more interaction surface; trades focus for reach).
3. **Lever B — lean on LOCKDEP (most promising for Candidate A).** The hunt kernel has LOCKDEP, so a lock-*order* inversion fires `WARNING: possible circular locking dependency` even with no memory crash → 9a triage routes it as a lead. Candidate A is a lock-order bug, so a directed perf+mm run watched for lockdep splats is the best shot at it.
4. **`syz-repro`-from-crash-log** is wired but VM-gated: needs `syzimg.img` (have) AND a captured `log0` (the campaign produces it). The `syz-prog2c` synthesis leg works now.
5. **Phase 10 — weaponization (UNBUILT, gated on a real exploitable bug):** crash → primitive construction (heap groom, UAF reclaim, infoleak/KASLR defeat) → control-flow hijack → LPE PoV. This is the last link to "trigger exploits" and the biggest remaining gap.
6. **True directed greybox (BEACON):** stock syz-manager can't do distance-directed fuzzing; current "directed" = focused `enable_syscalls`. A real BEACON/SelectFuzz integration (6.3 scorer → syz-manager instrumentation) is a deeper hook.

## Gotchas (don't relearn these)

- **NIC:** hunt kernel has `CONFIG_VIRTIO_NET=y`, `CONFIG_E1000` unset → `vm.network_device: virtio-net-pci` (syz-manager defaults to e1000, which this kernel can't drive → no SSH).
- **IP:** the minimal Debian image's DHCP times out under QEMU user-net → eth0 pinned static `10.0.2.15/24` (gw `10.0.2.2`) in `build_syzimg.sh`.
- **Image size:** ≥8GB, else the guest hits `No space left on device`, `SYZFAIL: mkdtemp`, and fuzzing stalls (coverage flatlines).
- **Sandbox:** `setuid` (threat model), never `none` for the hunt.
- **vmlinux** for coverage symbolization is in `eval/kernelctf-latest/linux/build-latest/`.
