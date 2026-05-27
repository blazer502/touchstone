# kernelCTF-latest CPU-only bounded hunt — 2026-05-27

## Setup

| Component | Choice / Detail |
|---|---|
| Host | 48-core Intel Xeon Gold 6136 (AVX-512), 376 GB RAM, no GPU |
| Target | `lts-6.12.91` (kernelCTF current LTS), commit `57eaf35b03` |
| Kernel cfg | COS `lakitu_defconfig` + `lts-6.12.config` + hunt-mode delta (KASAN+KCOV+UBSAN+SLUB_DEBUG_ON+LOCKDEP, no KASLR, NF_TABLES=n, IO_URING runtime-disabled, USER_NS unprivileged off). `+CONFIG_E1000=y, +CONFIG_E1000E=y` added for syzkaller QEMU. |
| LLM (dense, CPU) | `qwen2.5-coder:7b-instruct` Q4_K_M (4.7 GB) via ollama on `:11434`. Coder-tuned 7B dense — best speed/quality tradeoff on AVX-512 CPU. Effective ~11 tok/s warm-idle, ~0.5-5 tok/s under fuzz CPU pressure. |
| Gateway | `llm.gateway` extended with `cpu` profile (`VERI_PROFILE=cpu`) — proxies `synthesizer`/`router` roles to ollama. |
| Syzkaller | image `veri-agent/syzkaller:2b01f00eb6f2` (master @ pinned commit, Go 1.26 base). |
| VM disk | 2 GB Debian bookworm via `tools/create-image.sh` + `/etc/network/interfaces` patched for hotplug ens/eth wildcards. |

## Run 1 — broad cold-start fuzz

- Config: `manager-broad.cfg` (no `enable_syscalls`, all syscalls in scope minus `io_uring_*`, `nf_tables_*` — the kernelCTF-ineligible ones).
- 4 KASAN VMs × 4 procs each, 30-min wall cap.
- **Result:**
  - 189,050 programs executed, ~100/sec sustained
  - 4,673 corpus, 73,322 PC coverage
  - **0 unique crashes, 0 bugs**

## Run 2 — bpf+perf focused fuzz

- Config: `manager-bpf-sched.cfg` — `enable_syscalls: bpf$*, perf_event_open*, socket$inet_*, sendmsg$nl_route, …`. kernel/bpf is high-ROI per kernelCTF history.
- 6 KASAN VMs × 6 procs each, 30-min wall cap.
- **Result:**
  - 1 crash dir (32 stack samples) — **all categorized "suppressed report" by syzkaller, Count=0 unique bugs**
  - Inspecting the samples: every dump is `RIP: 0033` (userspace) + `asm_exc_page_fault` landing in `__get_user_*`/`__put_user_*`/`x64_setup_rt_frame`. These are **syz-executor user-space faults the kernel correctly handled**, not kernel bugs.
  - `agent.loop` over this crash via `tier1_kasan` (no KASAN BUG banner in any logN) → `inconclusive` ✓

## End-to-end pipeline check

| Candidate | Disposition | Why |
|---|---|---|
| `k-latest-1-boot-smoke` (no exploit in initramfs) | `inconclusive` ✓ | no KASAN report in boot dmesg |
| `k-latest-2-historical-positive-control` (CVE-2024-1086 dmesg from 6.1.72) | `confirmed` ✓ | Tier-1 kasan_replay matched `BUG: KASAN: use-after-free at ip_rcv+0x6b1/0x730` |
| `kctf-latest-workdir-bpf-sched-b83ebc0f` (suppressed report) | `inconclusive` ✓ | log has only userspace page-fault dumps; no `BUG: KASAN:` banner |

## Interpretation

**No new CVE found** in 60 minutes of bounded CPU-only fuzzing. This is the realistic outcome:

1. `lts-6.12.91` is the current kernelCTF LTS — every easy-to-find bug in this surface has already been reported, fixed upstream, and is filtered out by syzkaller's known-bug database.
2. Cold-start fuzz with no seed corpus, no targeted descriptors, and `KASAN+SLUB_DEBUG_ON+LOCKDEP` triple sanitizers means very slow exploration of the unfuzzed corners. Coverage plateaued at ~73k PCs in 30 min — that's nowhere near saturating bpf alone.
3. Published kernelCTF submissions average **weeks of focused fuzz time + targeted analysis**; not a 30–60 min bounded run.

What *did* work end-to-end on CPU only:
- Hunt-mode kernel boots clean under QEMU/KVM with all restrictions held.
- 6 KASAN VMs sustained ~100 progs/sec each.
- `qwen2.5-coder:7b-instruct` (dense, CPU) serves both `synthesizer` and `router` roles via the existing `llm.gateway`.
- `agent.loop` correctly distinguishes a real KASAN UAF (positive control) from a no-crash boot from a syzkaller-suppressed userspace fault.

## How to extend

For an actual CVE-finding run on this hardware:
- Switch to a **seeded** syz corpus (download from syzbot / OSS-Fuzz).
- Target a specific subsystem with **extended Stage A** (currently only netfilter dispatcher types are catalogued in `surface/entrypoints.py`; net/sched / kernel/bpf need ~3-5 dispatcher types each — see `SETUP.md` "Deferred").
- Run continuously for **days, not minutes**, with periodic crash triage through `agent.loop`.
- For the verifier-first arm (veri-agent's design), run `surface.stage_b.refine_unit` over Stage-A candidates and let the CPU LLM synthesize ACSL contracts overnight (the per-unit budget is small; thousands of units fit in 8h at 11 tok/s).
