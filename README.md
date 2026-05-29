# Touchstone

**Sound vulnerability discovery for C/C++ and the Linux kernel.**

Touchstone pairs a local LLM proposer with a soundness-checked verification
funnel. The LLM proposes bug sites, harnesses, contracts, and exploit
hypotheses; mature program-analysis tools (Frama-C, CBMC, KLEE,
AFL++/libFuzzer, syzkaller, …) accept or reject them. **Verdicts always come
from a sound checker — never from the LLM.**

Demonstrated end-to-end on sanitizer-detectable memory-safety bugs (UAF, OOB,
UoUV, double-free, null-deref). In reach: UBSan classes, KCSAN data races,
and any safety property expressible in CBMC/ESBMC or ACSL.

---

## Highlights

- **33 %** reproduce-target on the full **CyberGym Level-1** set (1507 tasks) with Touchstone's program-analysis + fuzzing **pipeline** (run standalone) — 2.7× the project's prior best (see below)
- **22.05 %** of functions pruned on Linux 6.1.72 `net/netfilter/` (sound over-approximation)
- **0** missed bugs on Juliet C/C++ v1.3 (1074 labeled `_bad` cases)
- **1.0 / 1.0** precision / recall on the oracle corpus, **0** false confirmations
- **2.46×** speedup vs. no-verification baseline on CyberGym `arvo:1065`
- **5** reproducible field PoVs across CyberGym, kernelCTF, and live SQLite

Full numbers in [`docs/headline-metrics.md`](docs/headline-metrics.md).

---

## CyberGym Level-1 results

Touchstone is a **verification + program-analysis tool**, not an autonomous LLM
agent. On CyberGym it runs as a PoC-reproduction *pipeline* (program analysis +
fuzzing + a sound oracle), and can equally serve as a checker/assistant *under*
an LLM agent (e.g. OpenHands). The numbers below place that pipeline next to
LLM-agent systems on the same task and scoring — for **context**, not a claim
of being a "better agent."

Task: given the vulnerable source tree + a one-sentence description, emit a PoC
that crashes the project's OSS-Fuzz harness in the **vul** build but not the
**fix** build (`vul=crash ∧ fix=no_crash`). Full 1507-task universe.

| System | Approach | % Reproduce-target |
|---|---|---|
| Touchstone pipeline (prior) | program analysis + fuzzing (seed bank) | 12.48 % |
| OpenHands + Claude-Sonnet-4 | LLM agent | 17.85 % |
| **Touchstone pipeline (standalone)** | **program analysis + fuzzing (OSS-Fuzz corpus + value-profile)** | **≈ 33 %** (497–502 / 1507) |
| MDASH (2026 frontier) | LLM agent, frontier models | 88.4 % |

Touchstone is a **tool**, not an agent — so it has no "agent baseline," only a
baseline *pipeline*. There are two ways it is used; the 33% is the first:

- **Standalone (how the number was measured).** The pipeline takes {source +
  description}, emits a PoC, and is scored: the project's own public OSS-Fuzz
  corpus → coverage-guided libFuzzer (value-profile + a source-mined
  dictionary) → the sanitizer oracle as the sole verdict on native vul/fix
  binaries. No LLM in the loop, no CyberGym-specific tuning (all via the
  abstract `BenchmarkTask` interface). On a leaderboard this occupies an
  "agent" slot, but it is tooling, not an LLM agent.
- **As a helper under an agent (the intended role).** An LLM agent decides;
  Touchstone supplies the *sound* parts — verified PoCs, the sanitizer verdict,
  the reachability witness — to ground those decisions.
- **2.7× the prior 12.48 %** and ~1.9× the prior public-board #1. Reproduced
  live in ~18 min on a 64-core host (`run-logs/l1-corpus-full.json`,
  `run-logs/l1-full-live.json`).
- **Where the local model is used.** The baseline pipeline needs no LLM; where
  a model *is* used it is a **local, open-weight** model running on the host's
  GPUs (via vLLM) — never a frontier/API model — and always as a **proposer**
  (the sound oracle still decides). Two uses:
  - a **fine-tuned seed generator** — Qwen2.5-3B-Instruct + LoRA, trained on a
    *disjoint* set of projects and evaluated **zero-shot** on held-out
    projects' corpus-misses — proposes structurally-valid input seeds and adds
    reproductions the corpus alone can't (+2/80 on a held-out sample);
  - an optional **agent loop** (smolagents driving a local open model, e.g.
    DeepSeek-R1-Distill-70B) for hard tasks — built and validated, but a minor
    contributor (≈0 on the hardest sample), **not** part of the 33% headline.
- **Honest ceiling.** Open-models-only tops out ~33–35 %; the 83–88 % 2026
  frontier is a *frontier-model* result. The instrumented-rebuild path
  (AFL++ `cmplog`/concolic, ~45–50 %) was de-risked to a build-at-scale wall —
  see [`docs/forward-plan.md`](docs/forward-plan.md).

Reproduce:

```bash
python3 -m eval.cybergym.run_level1 \
  --subset eval/cybergym/subset_l1_full.json \
  --workers 16 --libfuzzer-seconds 20 --libfuzzer-budget-max 60 \
  --oss-fuzz-corpus --max-turns 0 --denominator 1507
```

---

## How it works

Two complementary uses of program verification, wrapped in a guess-and-check loop:

1. **Pruning** — Stage A (sound reachability + taint) and Stage B (modular
   safety proofs) strip the search space.
2. **Oracle** — given a hypothesis "X is exploitable under C," confirm or
   refute it as cheaply as possible.

```
                ┌── Tier 1  fuzz + sanitizers     (cost 1)
Stage A  ─▶  ROUTER ── Tier 2  KLEE / S2E / angr  (cost 25)
(prune)  ─▶          └── Tier 3  CBMC / ESBMC     (cost 50)
   ▲                                │
   └────────── counterexample ◀─────┘
```

The router runs the cheapest tier that can decide (costs in
`config/budget.yaml`). Inconclusive verdicts always escalate.

The LLM is structurally a *proposer*: it cannot emit verdicts, assume
`false`, drop a populated tier from a dispatch order, or bypass host-effect
bans in harness synthesis. Every tool assumption is recorded in
[`docs/soundness-assumptions.md`](docs/soundness-assumptions.md).

---

## What Touchstone contributes

The reusable tools are mature open source: SVF, CodeQL, Smatch, Sparse,
Coccinelle, Frama-C, CBMC, ESBMC, KLEE, S2E, angr, AFL++, libFuzzer,
syzkaller, KASAN / MSan / UBSan / KCSAN, vLLM, universal-ctags.

What this repo adds:

- **Sound surface pruning.** Stage A reachability + Stage B safety proofs with
  explicit over-approximation; `--unwinding-assertions` forced ON so bounded
  proofs never silently report `safe`.
- **Content-addressed proof cache.** Keys body + contracts + engine + flags +
  aliasing; revalidates callee contracts on hit, never trusts the hash alone.
- **Three oracle tiers, one verdict schema.** Per-engine soundness levers
  (e.g. KLEE returns `unsat` only when `completed > 0 ∧ partial == 0`).
- **Cost-aware router.** Cheapest decisive tier wins; the LLM dispatcher can
  reorder but is sanitized so no populated tier is silently dropped.
- **Closed Stage-B loop with LLM contracts.** CBMC counterexamples feed back
  as ACSL / `__CPROVER_assume` proposals; degenerate bodies (`false`,
  `1 == 0`) rejected structurally.
- **Per-tier LLM proposers with structural soundness filters.** Host-effect
  bans (Tier 1), `must_not_assume` enforcement (Tier 2), tautology and
  assume-false rejection (Tier 3).
- **Closed agent loop.** Hypothesize → route → verify → refine.
- **CyberGym adapter + ablation.** Task resolver, patch-isolated scoring,
  baseline vs. accelerated arms.
- **Labeled soundness gate.** Juliet C/C++ v1.3 adapted with deliberately
  deref'ing helper stubs so freed-pointer sinks aren't masked.
- **Live-target paired controls.** Every live row carries a control that
  must confirm on every run; if the control flips inconclusive, the live row
  no longer counts.
- **End-to-end metrics harness.** One JSONL stream and the headline file
  regenerated by a single command.

---

## Repository layout

```
config/   models.yaml, budget.yaml, targets/*.yaml
docker/   per-tool Dockerfiles + smoke drivers
docs/     soundness-assumptions.md, toolchain.lock, headline-metrics.md
ingest/   repo fetch, kernel/userspace build, OSS-Fuzz harness reuse
surface/  Stage A + Stage B + proof cache
oracle/   tier1_fuzz, tier2_symbolic, tier3_bmc
agent/    proposal loop, router, refinement
llm/      vLLM serving, gateway, prompt templates
eval/     cybergym, juliet, kernelctf, live-lib, harness
```

---

## Quick start

Prereqs: Linux + Docker, Python 3.10+, ~50 GB free disk for kernel work,
QEMU for booting kernels.

```bash
# 1. Build tool images and smoke-test the toolchain
bash docker/build_all.sh
bash docker/smoke.sh

# 2. Serve the LLM (smoke profile = Qwen2.5-3B-Instruct)
bash llm/serve.sh smoke
python3 llm/smoke.py

# 3. Stage A + Stage B on a target
bash surface/stage_a.sh linux-6.1.72-netfilter
python3 -m surface.stage_b \
  --manifest surface/smoke/manifest.json \
  --out surface/stageb/smoke.json

# 4. Closed agent loop
python3 -m agent.loop \
  --candidates agent/smoke/candidates.json \
  --out run-logs/loop.jsonl

# 5. Evaluate
python3 eval/juliet/run_stage_a.py && python3 eval/juliet/run_stage_b.py
python3 eval/precision/run.py
python3 eval/cybergym/run_ablation.py 1065 --budget 20
python3 -m eval.harness.end_to_end   # regenerates docs/headline-metrics.md
```

---

## Currently deferred

- SVF-based type-aware indirect-call resolution (Stage A uses the
  conservative address-taken over-approximation).
- LLM-assisted Stage A clustering (currently runs without LLM input).
- Magma corpus (Juliet alone satisfies the labeled soundness gate).
- Production-profile LLM weights (32B + 7B wired in `config/models.yaml`;
  smoke profile drives end-to-end runs).
- Tool images beyond CBMC (Dockerfiles pinned, build on demand).

---

## Use responsibly

Touchstone runs fuzzers, symbolic execution, and boots kernels. **Only
point it at targets you are authorized to test** — your own infrastructure,
OSS-Fuzz projects, CTF and benchmark corpora, kernels you control.

In paired-build evaluation (CyberGym etc.), the patched build is scoring-only.
The agent never sees the patch except in explicit with-patch settings.

When adding a new tool, append its soundness assumptions to
[`docs/soundness-assumptions.md`](docs/soundness-assumptions.md) **before**
relying on its verdicts.

---

<details>
<summary><strong>Citations</strong></summary>

- **CyberGym** — Sunblaze, UC Berkeley. arXiv:2506.02548.
- **CBMC** — Clarke, Kroening, Lerda. TACAS 2004.
- **Frama-C / EVA** — Cuoq et al. SEFM 2012.
- **KLEE** — Cadar, Dunbar, Engler. OSDI 2008.
- **angr** — Shoshitaishvili et al. IEEE S&P 2016.
- **SVF** — Sui, Xue. CC 2016.
- **AFL++** — Fioraldi et al. WOOT 2020.
- **vLLM** — Kwon et al. SOSP 2023.
- **Juliet C/C++ v1.3** — NIST Software Assurance Reference Dataset.
- **AIxCC reference pipelines** (orchestration only) — OSS-CRS, ATLANTIS, RoboDuck.

</details>
