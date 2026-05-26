# PROGRESS

Checklist tracking PLAN.md §6 phased milestones. Status legend: TODO / DOING / DONE / BLOCKED.

## Phase 0 — Skeleton + no-LLM baseline

- [DONE]  0.1 Toolchain, pinned & containerized — `docs/toolchain.lock` pins versions for clang, CBMC, ESBMC, Frama-C, KLEE, S2E, SymCC, angr, AFL++, syzkaller, Smatch/Coccinelle/Sparse, CodeQL, SVF, and serving stack. Per-tool Dockerfiles in `docker/*.Dockerfile`. `docker/build_all.sh` and `docker/smoke.sh` drive build + smoke. CBMC image built and verified end-to-end on `docker/smoke/cbmc_oob.c` (correctly reports OOB). Remaining images are recipe-ready but not yet built (will build on demand in later sub-steps; building all up front would burn ~hours of CPU and ~30+GB of disk before they're needed). `config/budget.yaml` and `config/models.yaml` stubbed with the schema downstream phases will read.
- [DONE]  0.2 LLM serving smoke test — `llm/serve.sh {smoke|production|stop|status}` launches `vllm/vllm-openai:v0.11.1` per `config/models.yaml` (profile selector); `llm/gateway.py` is the OpenAI-compatible proxy (role-based routing, request log to `run-logs/llm-gateway.jsonl`); `llm/smoke.py` waits for `/healthz`, fires a chat completion via the `synthesizer` role alias, samples `nvidia-smi` during the call. Verified: gateway answered, GPU 0 hit 93% util peak (18 GB resident, model loaded), token usage captured both at gateway and smoke-result level (`run-logs/phase0.2-smoke.json`). Used cached `Qwen/Qwen2.5-3B-Instruct` for the smoke; production profile (32B synthesizer + 7B router) is wired but not booted (would download ~70 GB and is not needed until Phase 3). `llm/budget.py` exposes `config/budget.yaml` as a typed surface — enforcer turns on in Phase 2.
- [DONE]  0.3 First eval bring-up — CyberGym cloned into `eval/cybergym/repo` (depth-1; Apache-2.0) and pip-installed `[dev,server]` into `eval/cybergym/venv` (Python 3.12 — required, system is 3.10). PoC submission server runs as `sudo -E ./venv/bin/python -m cybergym.server --host 127.0.0.1 --port 8666 …` (sudo because `docker.from_env()` needs the socket and the host user is intentionally not in `docker`); state lives in `eval/cybergym/server_state/{poc.db,poc/,server.log}`. End-to-end run on **arvo:1065** (smallest of the 10-subset; the glibc/regex MSan `pmatch` bug in libmagic): generated task package via `cybergym.task.gen_task` (level1, masked task id), submitted the reference PoC (12 bytes extracted from `/tmp/poc` baked into `n132/arvo:1065-vul`) → server returned `vul_exit_code=77` (MSan UoUV in softmagic.c:365); `verify_agent_result.py` exercised the private `submit-fix` route → `fix_exit_code=0`. Scoring rule `vul!=0 ∧ fix==0` satisfied — known PoC scored correctly. Reproducible driver: `eval/cybergym/run_phase03_smoke.sh [task_id]`. Result log: `run-logs/phase0.3-cybergym-arvo1065.json`. SQLite OSS-Fuzz simpler-smoke is **deferred** — PLAN lists it as "an even simpler smoke", not in 0.3 Done-when; disk is at 93% (121 GB free) and the OSS-Fuzz-clang base image alone is ~10 GB. Will fold into the live-lib field-target wiring in Phase 4.3. Adapter design notes: `eval/cybergym/NOTES.md`; 10-task subset manifest: `eval/cybergym/subset.json`. Per-task images currently pulled: `n132/arvo:{1065-vul,1065-fix}` (~1.2 GB compressed total).
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
- 2026-05-26: Phase 0.2 complete — chose containerized vLLM (`vllm/vllm-openai:v0.11.1`, image already on host) over on-host install to avoid polluting the system Python and to keep the LLM stack on the same containerized footing as the analysis tools. Profile-driven (`smoke` for verification with a cached small model, `production` for the §1 layout). Gateway uses a single role alias surface so downstream callers always say `model: "synthesizer"` / `model: "router"` and the routing/sharding is config-controlled. Production model weights are NOT downloaded yet — pulling 32B + 7B Coder variants is ~70 GB and not needed until Phase 3 (LLM acceleration); this is recorded so a future step can prefetch before Phase 3 kicks off. Disk is at 93% used; before Phase 3 we will likely need to either free up or move HF cache to a larger volume.
- 2026-05-26: Phase 0.3 complete on the CyberGym path — adapter studied, server up, arvo:1065 reference PoC scored correctly through the binary `vul!=0 ∧ fix==0` rule with zero LLM. Decisions logged: (a) sparse-fetch HF data per task (full dataset 240 GB > 121 GB free); (b) extract reference PoC from `/tmp/poc` inside the `*-vul` Docker image (the HF dataset doesn't ship the `poc` file); (c) cybergym requires Python 3.12, so a sibling venv (`eval/cybergym/venv`) holds it instead of touching system Python; (d) server runs via `sudo` because the host user is deliberately not in `docker` — same convention as Phase 0.1 (`DOCKER="sudo docker"`). Subset manifest at `eval/cybergym/subset.json` records compressed image sizes so a future batch-puller can budget disk per task (range: 587 MB → 3.3 GB per image). SQLite OSS-Fuzz "simpler smoke" intentionally deferred to Phase 4 live-lib — it isn't in 0.3 Done-when and the OSS-Fuzz base image is heavy. Next sub-step is 0.4 (kernelCTF historical reproduction); this needs a Linux LTS checkout, KASAN+KCOV build, QEMU, and kctf — disk and build-time cost is high, will treat as its own work item.
