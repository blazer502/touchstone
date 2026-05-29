# Forward Plan — remaining work (handoff, 2026-05-29)

Consolidated "what's left" across both tracks after the CyberGym push + the
kernel weaponization-step-1. Kept so the work can be paused/resumed without
relearning. Companion to `docs/kernel-hunt-plan.md` (kernel resume details).

## Standing results (committed, local — not pushed)

- `e27af3c` — CyberGym L1 push: **33% reproduce-target on full 1507** (no LLM,
  corpus + coverage-guided fuzz + value-profile), benchmark-agnostic,
  open-models-only. Live re-run reproduced 33.31% (`run-logs/l1-full-live.json`).
- `3ae5bdb` — Phase 10a: `exploit/reach.py` crash→reachability-witness.

## Track 1 — CyberGym (userspace) : effectively COMPLETE at ~33%

- Cheap levers exhausted (corpus, in-tree, longer fuzz, value-profile, general
  zero-shot seed-gen +1-2%). Honest ceiling open-models-only ≈ 33-35%.
- **cmplog / ARVO-image-rebuild path = NO-GO** (de-risked 2026-05-29): feasible
  per-task but build-at-scale wall — 8GB images, AFL 2.52b in-image (no cmplog
  → must install AFL++), host `core_pattern` blocker (shared-host, disallowed),
  per-project build.sh quirks; ~45-50% ceiling. Don't re-investigate.
- **88% is not reachable open-models-only** — it's a frontier-model result.
- Remaining OPTIONAL, low-effort: (a) `git push` the two commits;
  (b) a short methodology/results doc; (c) stop. No score-chasing left that
  respects the constraints.

## Track 2 — Kernel / kernelCTF : the ACTIVE track

**kernelCTF needs a ≥90%-reliable flag-stealing LPE exploit + kernelXDK
packaging on a hardened kernel (no userns/io_uring/nftables). Our tool finds
CRASHES, not exploits.** Stages:

| Stage | Status |
|---|---|
| 0. A real exploitable bug | **MISSING** — prior 8h hunt: 12 buckets, 0 reproduced; directed campaign: 0 novel |
| 10a. reach + trigger | **DONE** (`exploit/reach.py`); trigger via syz-repro |
| 10b. primitive (heap groom/spray) | unbuilt, human-led |
| 10c. infoleak/KASLR + mitigation bypass + LPE | unbuilt, human-led |
| 10d. ≥90% reliability | unbuilt |
| 10e. kernelXDK packaging + --vuln-trigger + metadata v3 + writeups | unbuilt |

- **Active now:** resuming the syzkaller crash-hunt (see `docs/kernel-hunt-plan.md`
  "How to resume"). Directed campaign = Candidate A perf↔mm↔cpu_hotplug
  lock-order under `sandbox: setuid` (unprivileged threat model). Most promising
  lever = LOCKDEP splats (lock-order inversion fires `WARNING: possible circular
  locking dependency` even with no memory crash → 9a triage routes it).
- On a real bucket: `oracle.repro.kernel synth` → `exploit.triage` →
  `exploit.reach` (10a witness). Then weaponization (10b-10e) is the human gap.
- **Honest:** finding+reproducing a novel unprivileged bug on a hardened LTS is
  probabilistic and has not yet happened; weaponization is a multi-week expert
  effort beyond autonomous reach. The hunt is the legitimate first step.

## Track 3 — specialized local model (capability, not CyberGym lever)

- Zero-shot seed generator validated (+2/80 on held-out corpus-misses;
  `tools/train_seedgen.py`, `eval/cybergym/build_seedgen_dataset.py`). LoRA
  adapter gitignored (regenerable).
- Scaling blocked: ARVO gated on HF; GPUs shared (70B). Future: external
  OSS-Fuzz harness→seed data when GPU frees.

## Track 4 — LLM-hypothesis × kernel-scale PA (design + built pieces)

Thesis: the LLM is a **re-ranker/refiner of PA-grounded candidates, NOT a bug
inventor**. Symbolic/concolic/BMC don't scale to the kernel; kernel-grade PA
that does: Smatch, Coccinelle, CodeQL (static), directed/coverage syzkaller
(dynamic), LOCKDEP/KASAN/KMSAN (oracles).

**PA-scale router (built — `agent/pa_router.py`).** Decides the PA lane per
target so each runs where it actually works:
- **small** (single extracted fn, bounded property, bitcode obtainable) →
  precise KLEE/CBMC (can decide exactly + emit cex).
- **large** (kernel / whole-program / no bitcode) → scalable static analyzers
  + reach-gate + (directed) coverage fuzzing.
- **hybrid** (medium) → large to localize+reach a small gate, then small-scale
  concolic on the extracted gate.
`decide(TargetProfile)`; profile builders for kernel / extracted-fn / oss-fuzz.

**Falsifiable hypothesis (built — `schemas/hypothesis.py`).**
`KernelBugHypothesis{bug_class, site, falsifier(REQUIRED), evidence(REQUIRED),
object, trigger_sketch, spray_hint, reachability, status, refutation}`.
`is_valid_intake()` is the anti-hallucination gate (reject if no evidence /
no falsifier). `classify_warning()` maps analyzer msgs → memory-corruption class.

**The funnel (legs mostly exist):** static PA warnings → reach-gate
(`reach.py`/`directed.py`, unprivileged) → LLM proposes falsifiable hypothesis
*citing the warning* → directed fuzz (focused `enable_syscalls` + heap-spray via
`run_syz_manager`) under **KASAN** → `oracle/repro/kernel.py` syz-repro →
`exploit/triage.py` (drop dos-only). Routing table per bug_class in the design.

**Remaining to build (task #9):** (a) proper Smatch **security** run for real
candidates — the existing `smatch.out` is a *style pass* (only 3 mem-corruption
candidates / 994); (b) the LLM rank/refine call (open model, citation-grounded);
(c) the directed-fuzz test leg (focused cfg → `run_syz_manager`, KASAN verdict).

**Honest edge (3-agent consensus):** this *converts existing static warnings
into reproduced crashes* (targeting), bounded by analyzer recall + reachability
— not out-of-nowhere discovery. Milestone: ≥1 reproduced novel KASAN crash
(= one more than the stock hunt's 0).

## Immediate active task (this session)

Kernel crash-hunt running — switched to the **broad full-surface** campaign
(`manager-overnight.cfg`: all syscalls, 6 VMs, `sandbox=setuid`, io_uring
disabled), container `veri-syz-broad`, crashes under
`eval/kernelctf-latest/syzkaller/workdir-overnight/crashes/`. So far: ~85k PCs
coverage, only **DoS soft-lockups** (`dos-only`, not kernelCTF-eligible),
0 memory-corruption. A watcher fires only on a **KASAN/UAF/OOB** bucket →
`oracle.repro.kernel synth` → `exploit.triage` → `exploit.reach` (10a).
Stop: `sudo docker stop veri-syz-broad`.
