# veri-agent

**Verification-accelerated vulnerability-discovery agent for C / C++ and the Linux kernel.**

veri-agent finds memory-safety bugs in C/C++ code (including the Linux kernel)
by combining a local LLM proposer with a soundness-checked verification funnel.
The LLM proposes candidate bug sites, harnesses, contracts, and exploit
hypotheses; sound program-analysis tools (Frama-C, CBMC, KLEE, AFL++/libFuzzer,
syzkaller, …) dispose of them. **Final verdicts always come from a sound
checker — never from the LLM.**

The result is a guess-and-check loop that is:

- **Sound by construction** — every prune and every "confirmed" verdict is
  backed by a real engine, with assumptions tracked in
  [`docs/soundness-assumptions.md`](docs/soundness-assumptions.md).
- **Cost-aware** — a router runs the cheapest oracle tier that can decide a
  hypothesis (fuzz → symbolic → bounded model-checking), so most cases never
  reach BMC.
- **Reproducible** — every confirmed PoV ships with a deterministic
  reproduction artifact and the sanitizer or symbolic trace that backs it.

---

## Highlights

On a labeled corpus, a real benchmark, and live targets:

| | Result |
|---|---|
| Attack-surface reduction (Linux 6.1.72 `net/netfilter/`) | **22.05 %** of functions pruned, sound over-approximation |
| Labeled soundness gate (Juliet C/C++ v1.3, memory-safety CWEs) | **0** missed bugs across 1074 labeled `_bad` cases |
| Oracle precision (mixed corpus, N=11) | precision **1.0**, recall **1.0**, **0** false confirmations |
| CyberGym `arvo:1065` ablation | **1/1** confirmed PoV vs **0/1** baseline, **2.46×** faster |
| Field PoVs (CyberGym, kernelCTF, live SQLite) | **5** reproducible PoVs |

Detailed numbers, including per-tier latency and token budgets, are in
[`docs/headline-metrics.md`](docs/headline-metrics.md).

---

## How it works

Two complementary uses of program verification, wrapped in an LLM-driven loop:

1. **Attack-surface minimization (pruning).** Soundly remove regions that
   cannot contribute to an exploitable bug.
2. **Exploitability oracle.** Given a hypothesis ("location X is exploitable
   under condition C"), confirm or refute it as fast as possible.

```
                +-----------------------------------------------------------+
attacker-entry  |  STAGE A: scalable sound over-approx reachability / taint |  prune unreachable
source code --->|  (SVF / CodeQL / Smatch / Coccinelle / Sparse)            |--------------------+
                +-----------------------------------------------------------+                    |
                                          | reachable+tainted slice                              |
                                          v                                                      |
                +-----------------------------------------------------------+                    |
                |  STAGE B: modular sound safety proof on slice             |  prune provably    |
                |  (Frama-C/EVA + CBMC/ESBMC), LLM-synthesized contracts    |  safe islands      |
                +-----------------------------------------------------------+                    |
                                          | candidate bug sites (minimized attack surface)       |
                                          v                                                      |
   +--------------------------- AGENT LOOP (local LLM) -------------------------------+           |
   |  propose exploit hypothesis -> ROUTER picks oracle tier -> verify -> refine      |           |
   +---------------------------------------------------------------------------------+           |
                   |             |                |                                               |
                   v             v                v                                               |
            Tier 1 (fast)   Tier 2 (symbolic)  Tier 3 (BMC)    <--- all feed counterexamples ----+
            fuzz+sanitizer  S2E / KLEE         CBMC / ESBMC          back to STAGE B + agent
```

**Funnel economics.** Each tier has a cost weight (tier1=1, tier2=25, tier3=50
in [`config/budget.yaml`](config/budget.yaml)). The router picks the cheapest
tier that can decide; inconclusive verdicts always escalate.

**Soundness rule.** The LLM is structurally constrained to be a *proposer*:
contract synthesis rejects degenerate bodies (e.g. `false`, `1 == 0`), Tier-2
driver synthesis rejects `klee_assume` on `must_not_assume` symbols, Tier-1
harness synthesis blocks host-effect calls (`system`, `exec*`, `fork`,
`socket`, …), and the router's LLM dispatcher can only reorder tiers — it
cannot drop a populated tier or emit a verdict. Every assumption a tool
relies on is recorded in [`docs/soundness-assumptions.md`](docs/soundness-assumptions.md).

---

## Components

### Reused open-source tools

| Purpose | Tools |
|---|---|
| Stage A reachability / taint | Smatch, Coccinelle, Sparse, SVF, CodeQL |
| Stage B sound proof | Frama-C/EVA, CBMC, ESBMC |
| Tier 1 (fast) oracles | syzkaller + KASAN/KMSAN/KCSAN/UBSAN/KCOV (kernel); AFL++/libFuzzer + ASan/MSan/UBSan (userspace) |
| Tier 2 (symbolic) oracles | S2E (kernel); KLEE, SymCC/SymQEMU (userspace); angr (binary) |
| Tier 3 (BMC) oracles | CBMC, ESBMC |
| LLM serving | vLLM; Qwen2.5-3B-Instruct (smoke), Qwen3.6-32B/35B-A3B or DeepSeek-V4-Flash (production) |
| Evaluation | CyberGym, SV-COMP, Magma, Juliet C/C++ v1.3 |
| Field targets | Google kernelCTF; live SQLite / OpenSSL / libxml2 via OSS-Fuzz |
| Symbol extraction | universal-ctags |

Orchestration draws on AIxCC reference pipelines (OSS-CRS, ATLANTIS,
RoboDuck); the loop itself is a fresh implementation.

### What this repo adds

- **Pattern-aligned task decomposition** (`surface/decompose.py`) — clusters a
  target tree by subdirectory and filename-prefix family, labels files by
  design pattern (`ops_vtable`, `container_of`, `refcount`, `rcu`,
  `allocator`, `parser_sm`), and emits per-cluster manifests with
  `depends_on` edges that drive compositional ordering and proof-cache
  invalidation.
- **Sound reachability / taint with explicit over-approximation**
  (`surface/stage_a.sh`, `surface/reachability.py`). Static-analyzer findings
  (Smatch, Sparse) are ingested as priority signals only, never as pruning
  evidence.
- **Modular sound safety proof** (`surface/stage_b.py`) — containerized CBMC
  and Frama-C/EVA behind a single verdict schema; `--unwinding-assertions` is
  forced ON so loops exceeding the bound surface as `inconclusive`, never
  silently `safe`.
- **Content-addressed proof cache** (`surface/proof_cache.py`) — keys each
  proof on normalized body SHA + property + engine + version + unwind +
  assumed-contracts + build-flags + aliasing assumptions. Cache hits revalidate
  callee contracts, never trusting the hash alone.
- **Three oracle tiers behind one verdict schema**
  (`oracle/tier1_fuzz/`, `oracle/tier2_symbolic/`, `oracle/tier3_bmc/`).
  Verdicts mirror Stage B's schema and carry per-engine soundness levers
  (e.g. KLEE returns `unsat` only when `completed > 0 ∧ partial == 0` with no
  external warnings).
- **Heuristic + LLM-backed router** (`agent/router.py`, `agent/router_llm.py`).
  Dispatches in cost order, stops on the cheapest decisive verdict, and
  sanitizes any LLM-proposed ordering to guarantee no tier is silently
  dropped.
- **LLM-synthesized contracts in a closed Stage-B loop**
  (`surface/contract_synth.py`, `surface.stage_b.refine_unit`). Counterexamples
  from CBMC feed back as ACSL / `__CPROVER_assume` proposals; only the
  engine's verdict is recorded.
- **Per-tier LLM proposer with structural soundness filters**
  (harness / driver / contract synthesizers under `oracle/*/harness_synth.py`,
  `oracle/tier2_symbolic/driver_synth.py`).
- **Closed agent loop** (`agent/loop.py`) — Hypothesis → router → verify →
  refine, with refinement specs feeding back to Stage B.
- **CyberGym adapter and ablation** (`eval/cybergym/`) — task-id resolver,
  PoC output contract, differential scoring with patch isolation,
  sanitizer-parity, baseline vs. accelerated arms.
- **Labeled soundness gate** (`eval/juliet/`) — adapts NIST SARD Juliet
  C/C++ v1.3 (CWE-476 / 415 / 416 / 121) to Stage A/B with carefully written
  helper stubs so freed-pointer sinks aren't silently masked.
- **Live-target paired positive controls** (`eval/kernelctf/`,
  `eval/live-lib/`) — every live row ships a control that must confirm on
  every run; if the control flips to `inconclusive`, the live row no longer
  counts as a green run.
- **End-to-end metrics harness** (`eval/harness/`) — writes a single JSONL
  stream and the human-readable headline in `docs/headline-metrics.md`.

---

## Repository layout

```
config/         models.yaml, budget.yaml, targets/*.yaml
docker/         per-tool Dockerfiles, build + smoke drivers
docs/           soundness-assumptions.md, toolchain.lock, headline-metrics.md
ingest/         repo fetch, kernel/userspace build, OSS-Fuzz harness reuse
surface/        Stage A (reachability/taint) + Stage B (Frama-C/CBMC) + proof cache
oracle/
  tier1_fuzz/        syzkaller + AFL++/libFuzzer drivers, sanitizer configs
  tier2_symbolic/    S2E, KLEE, SymCC drivers + constraint-hint generators
  tier3_bmc/         CBMC/ESBMC harness + assertion generators
agent/          proposal loop, router, refinement, counterexample handling
llm/            vLLM serving, gateway, prompt + contract templates
eval/           cybergym (primary), sv-comp, magma, juliet, kernelctf, live-lib, harness
run-logs/       per-run JSON/JSONL artifacts
```

---

## Quick start

veri-agent is containerized — each tool lives in its own image so you can
build only what you need.

### Prerequisites

- Linux host with Docker.
- Python 3.10+.
- A local LLM endpoint compatible with vLLM, or set `LLM_PROFILE=smoke` to
  use the `Qwen/Qwen2.5-3B-Instruct` smoke profile.
- For kernel work: QEMU, a kernel source tree, and ~50 GB of disk.

### Build tool images and smoke-test

```bash
bash docker/build_all.sh
bash docker/smoke.sh
```

### Serve the LLM (smoke profile)

```bash
bash llm/serve.sh smoke
python3 llm/smoke.py
```

### Run Stage A / B on a target

```bash
# Sound reachability + taint on Linux netfilter
bash surface/stage_a.sh linux-6.1.72-netfilter

# Modular safety proof on a unit manifest
python3 -m surface.stage_b \
  --manifest surface/smoke/manifest.json \
  --out surface/stageb/smoke.json
```

### Run the closed agent loop

```bash
python3 -m agent.loop \
  --candidates agent/smoke/candidates.json \
  --out run-logs/loop.jsonl
```

### Evaluate

```bash
# Labeled soundness gate
python3 eval/juliet/run_stage_a.py
python3 eval/juliet/run_stage_b.py

# Oracle precision corpus
python3 eval/precision/run.py

# CyberGym baseline vs. accelerated ablation
python3 eval/cybergym/run_ablation.py 1065 --budget 20

# End-to-end roll-up (regenerates docs/headline-metrics.md)
python3 -m eval.harness.end_to_end
```

---

## Currently deferred

- **SVF-based type-aware indirect-call resolution.** Stage A uses the
  conservative address-taken over-approximation.
- **LLM-assisted Stage A0 relabeling.** The clustering pass currently runs
  without LLM input.
- **Magma corpus.** Juliet alone satisfies the labeled soundness gate; Magma
  rolls into live-library hunting once per-project build harnesses exist.
- **Production-profile LLM weights.** The 32B + 7B production layout is wired
  in `config/models.yaml` but not booted; the smoke profile drives all
  end-to-end runs.
- **Tool images beyond CBMC.** CBMC is built and verified end-to-end; the
  other `docker/*.Dockerfile` recipes are pinned and build on demand.

---

## Use responsibly

veri-agent runs fuzzers, symbolic execution, and boots kernels. **Only point
it at targets you are authorized to test** — your own infrastructure,
OSS-Fuzz projects, CTF and benchmark corpora, kernels you control. Patches,
when used during evaluation, are scoring-only and are never fed back to the
agent except in explicit with-patch settings (e.g. CyberGym).

If you add a new tool or oracle, append its soundness assumptions to
[`docs/soundness-assumptions.md`](docs/soundness-assumptions.md) **before**
relying on its verdicts.

---

## Citations

- **CyberGym** — *CyberGym: Evaluating AI Agents' Real-World Cybersecurity Capabilities at Scale.* Sunblaze, UC Berkeley. arXiv:2506.02548.
- **CBMC** — Clarke, Kroening, Lerda. *A Tool for Checking ANSI-C Programs.* TACAS 2004.
- **Frama-C / EVA** — Cuoq, Kirchner, Kosmatov, Prevosto, Signoles, Yakobowski. *Frama-C: A Software Analysis Perspective.* SEFM 2012.
- **KLEE** — Cadar, Dunbar, Engler. *KLEE: Unassisted and Automatic Generation of High-Coverage Tests for Complex Systems Programs.* OSDI 2008.
- **angr** — Shoshitaishvili et al. *SoK: (State of) The Art of War: Offensive Techniques in Binary Analysis.* IEEE S&P 2016.
- **SVF** — Sui, Xue. *SVF: Interprocedural Static Value-Flow Analysis in LLVM.* CC 2016.
- **AFL++** — Fioraldi, Maier, Eißfeldt, Heuse. *AFL++: Combining Incremental Steps of Fuzzing Research.* WOOT 2020.
- **vLLM** — Kwon et al. *Efficient Memory Management for Large Language Model Serving with PagedAttention.* SOSP 2023.
- **Juliet C/C++ v1.3** — NIST Software Assurance Reference Dataset (SARD).
- **AIxCC reference pipelines** (orchestration only) — OSS-CRS, ATLANTIS, RoboDuck.
