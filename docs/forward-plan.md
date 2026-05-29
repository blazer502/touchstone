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

## Immediate active task (this session)

Kernel crash-hunt running (background, `run-logs/campaign.log`, http
`127.0.0.1:50004`, crashes under `eval/kernelctf-latest/syzkaller/workdir-campaign/crashes/`).
Monitor for non-suppressed buckets → synth → triage → reach-witness.
Stop: `sudo docker stop veri-syz-campaign`.
