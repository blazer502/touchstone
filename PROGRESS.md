# PROGRESS

Checklist tracking PLAN.md §6 phased milestones. Status legend: TODO / DOING / DONE / BLOCKED.

## Phase 0 — Skeleton + no-LLM baseline

- [DONE]  0.1 Toolchain, pinned & containerized — `docs/toolchain.lock` pins versions for clang, CBMC, ESBMC, Frama-C, KLEE, S2E, SymCC, angr, AFL++, syzkaller, Smatch/Coccinelle/Sparse, CodeQL, SVF, and serving stack. Per-tool Dockerfiles in `docker/*.Dockerfile`. `docker/build_all.sh` and `docker/smoke.sh` drive build + smoke. CBMC image built and verified end-to-end on `docker/smoke/cbmc_oob.c` (correctly reports OOB). Remaining images are recipe-ready but not yet built (will build on demand in later sub-steps; building all up front would burn ~hours of CPU and ~30+GB of disk before they're needed). `config/budget.yaml` and `config/models.yaml` stubbed with the schema downstream phases will read.
- [TODO] 0.2 LLM serving smoke test — vLLM/SGLang per `config/models.yaml`, OpenAI-format gateway, GPU util report. Wire `config/budget.yaml`.
- [TODO] 0.3 First eval bring-up — clone CyberGym, pull 10-task subset + Docker envs + PoC server. Also build SQLite OSS-Fuzz target. Tier-1-only run on one solvable task with known PoC, zero LLM.
- [TODO] 0.4 Kernel target bring-up (kernelCTF, sanity only) — historical LTS + config, KASAN+KCOV, QEMU/kctf boot, syzkaller reproduces published PoC. Smatch/Coccinelle/Sparse over the subsystem.
- [TODO] 0.5 Eval + metrics harness — CyberGym adapter (primary), SV-COMP/Magma/Juliet (soundness gate), field runners for kernelCTF-historical + live lib. Metric logger.

**Phase 0 done when:** CyberGym 10-task harness builds & scores a known PoC; one solvable task reproduces via Tier-1 + sanitizers; one kernelCTF historical bug reproduces under KASAN; smoke runs on all tools; LLM endpoint serves; metric harness logs baseline row — all with no LLM in analysis path.

## Phase 1 — Component (1) pruning

- [TODO] 1.1 Stage A0 — design-pattern-aligned task decomposition (`surface/tasks/*.json`).
- [TODO] 1.2 Stage A — reachability/taint (Smatch/Coccinelle/Sparse/SVF/CodeQL), entry-point catalog, soundness-assumption doc.
- [TODO] 1.3 Stage B — Frama-C/EVA primary + CBMC/ESBMC bounded, fixed contracts (no LLM yet).
- [TODO] 1.4 Proof cache (`surface/proofcache/`), content-addressed, dependency graph invalidation.
- [TODO] 1.5 Measure attack-surface reduction + soundness gate on Juliet/Magma.

**Phase 1 done when:** measurable reduction, missed-bug count = 0 on labeled set.

## Phase 2 — Component (2) oracle (no LLM)

- [TODO] 2.1 Tier 1 — syzkaller + sanitizers (kernel), AFL++/libFuzzer + ASan/MSan/UBSan (userspace), hand-written harnesses.
- [TODO] 2.2 Tier 2 — S2E (kernel), KLEE/SymCC (userspace), angr (binary).
- [TODO] 2.3 Tier 3 — CBMC/ESBMC harness + assertions.
- [TODO] 2.4 Router skeleton (hand-coded heuristic, no LLM yet).
- [TODO] 2.5 Measure precision and per-tier latency/escalation.

**Phase 2 done when:** injected Magma bugs confirmed deterministically with near-zero false confirmations.

## Phase 3 — LLM acceleration

- [TODO] 3.1 Synthesizer-generated ACSL contracts + loop invariants for Stage B.
- [TODO] 3.2 LLM harness/driver/constraint generation per tier.
- [TODO] 3.3 LLM router replaces heuristic.
- [TODO] 3.4 Headline ablation on CyberGym 10-task subset: verification-accelerated vs. baseline.

**Phase 3 done when:** LLM measurably improves proved-safe coverage and/or CyberGym success and/or time-to-PoC, without breaking Phase-1 soundness gate.

## Phase 4 — Full closed loop on field targets

- [TODO] 4.1 Close hypothesize→route→verify→prune/confirm→PoV loop.
- [TODO] 4.2 kernelCTF live LTS instance (latest LTS + COS config + restrictions).
- [TODO] 4.3 Live library hunt (SQLite/OpenSSL/libxml2) via OSS-Fuzz harness.
- [TODO] 4.4 Surface-reduction + cost metrics end-to-end.

**Phase 4 done when:** system autonomously produces at least one reproducible PoV on a real target and reports surface-reduction + cost metrics.

---

## Log

- 2026-05-26: PROGRESS.md created; repo layout scaffolded per PLAN §5; tool/host inventory taken (Ubuntu 22.04, clang-14, KLEE installed but missing libtcmalloc4, Docker 29.2.1, Python 3.10.12, 4× RTX A6000 49GB). Most analysis tools (CBMC/ESBMC/Frama-C/Smatch/Coccinelle/Sparse/CodeQL/SVF/AFL++/syzkaller/S2E/SymCC/angr) not yet on host — will be containerized.
- 2026-05-26: Phase 0.1 complete — Dockerfile per tool family written and pinned; `docker/build_all.sh`+`docker/smoke.sh` driver scripts; CBMC image (`veri-agent/cbmc:6.4.0`) built and verified (correctly detects OOB on `docker/smoke/cbmc_oob.c`). `docs/soundness-assumptions.md`, `config/budget.yaml`, `config/models.yaml` initialized. Host user is not in `docker` group → scripts respect `DOCKER=${DOCKER:-docker}` so `DOCKER="sudo docker"` works in this environment. Next: Phase 0.2 LLM serving smoke test (requires deciding whether to bring up vLLM on-host or via container; will note as decision point).
