# veri-agent

Verification-Accelerated Vulnerability-Discovery Agent for C/C++ (including the
Linux kernel). Specification: `PLAN.md`. Per-phase build log: `PROGRESS.md`.
End-to-end headline metrics: `docs/headline-metrics.md`. Soundness ledger:
`docs/soundness-assumptions.md`.

**Status:** all four PLAN.md phases complete. Phase 4 acceptance gate `PASS` —
5 reproducible field PoVs, 22.05 % attack-surface reduction on Linux 6.1.72
`net/netfilter/`, Juliet soundness gate `missed_bug_count = 0`, oracle precision /
recall = 1.0 / 1.0 with 0 false confirmations.

---

## Architecture (from PLAN §0)

The agent uses open-source program verification in two roles:

1. **Attack-surface minimization (pruning)** — soundly remove regions that
   cannot contribute to an exploitable bug.
2. **Exploitability oracle** — given a hypothesis ("location X is exploitable
   via condition C"), confirm or refute it as fast as possible.

The control flow is a **guess-and-check (neuro-symbolic) loop**: a local LLM
proposes (candidate bug sites, function contracts, loop invariants, harnesses,
exploit conditions, PoV inputs) and a sound checker disposes (the
verification / fuzzing / symbolic tools below). Counterexamples feed back to
the LLM. **The LLM only ever proposes; the final safe/unsafe verdict always
comes from a sound tool** — this is what keeps pruning sound (PLAN §0, §8).

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

(Diagram reproduced verbatim from `PLAN.md`.)

Per PLAN §7, the **funnel economics** are a hard constraint: the cheapest tier
that can decide a hypothesis runs first. `config/budget.yaml` assigns a cost
weight per tier (tier1=1, tier2=25, tier3=50); the router prefers the cheapest
tier that can decide.

---

## Components: existing tools we reuse vs. what this repo contributes

The system is a composition of mature open-source tools listed in PLAN §9
("Open-Source Tool Summary"). The contribution sits in the boundary between
them: how the tools are composed into a sound funnel, the proof cache, the
router, the LLM-as-proposer enforcement, and the closed-loop / soundness-gate
infrastructure.

### Reused from prior research and open source (PLAN §9)

| Purpose | Tools |
|---|---|
| Orchestration / build / budget | OSS-CRS (base), ATLANTIS / RoboDuck (reference), OSS-Fuzz harnesses |
| Stage A reachability/taint | Smatch, Coccinelle, Sparse, SVF, CodeQL |
| Stage B sound proof | Frama-C/EVA (primary), CBMC, ESBMC |
| Oracle Tier 1 (fast) | syzkaller + KASAN/KMSAN/KCSAN/UBSAN/KCOV (kernel); AFL++/libFuzzer + ASan/MSan/UBSan (userspace) |
| Oracle Tier 2 (symbolic) | S2E (kernel); KLEE, SymCC/SymQEMU (userspace); angr (binary) |
| Oracle Tier 3 (BMC) | CBMC, ESBMC |
| LLM serving | vLLM; Qwen2.5-3B-Instruct (smoke profile); Qwen3.6-32B/35B-A3B or DeepSeek-V4-Flash + small router (production profile, not booted) |
| Eval benchmarks | CyberGym (primary), SV-COMP, Magma, Juliet |
| Field targets | Google kernelCTF, live SQLite/OpenSSL/libxml2 via OSS-Fuzz |
| Symbol extraction | universal-ctags |

OSS-CRS / ATLANTIS / RoboDuck are listed by PLAN §4 / §9 as orchestration
references; we studied them and reimplemented the loop fresh.

### What this repo contributes

Each item below maps to specific files. The phrasing is taken from
`PLAN.md`, `PROGRESS.md`, and `docs/soundness-assumptions.md` so the
contribution is described in the project's own terms.

1. **Stage A0 — design-pattern-aligned task decomposition** (PLAN §2).
   `surface/decompose.py` clusters a target tree by subdirectory then by
   filename-prefix family, pattern-labels each file (ops_vtable, container_of,
   refcount, rcu, allocator, parser_sm), and emits per-cluster JSON +
   `_index.json` with `depends_on` edges. Run on Linux 6.1.72 `net/netfilter/`:
   245 sources → 24 clusters, 124 323 LOC. The cluster graph drives both
   compositional ordering and proof-cache invalidation.
2. **Stage A — scalable sound reachability / taint** (PLAN §2). Driver
   `surface/stage_a.sh` runs three passes: `surface/entrypoints.py` (18 kernel
   dispatcher struct types, allowlist-based), `surface/reachability.py`
   (per-function call graph + BFS from entries + indirect-call over-approximation
   per PLAN §2 "Soundness note"), and `surface/static_hints.py` (Smatch / Sparse
   findings ingested as priority signals only, never as pruning evidence —
   recorded as `static-hints | non-soundness role` in
   `docs/soundness-assumptions.md`). Result on `net/netfilter/`: keep =
   3029 / 3886 (22.1 % pruned), with all 9 CVE-2024-1086 critical-path sites
   in the keep set.
3. **Stage B — modular sound safety proof** (PLAN §2). `surface/stage_b.py`
   wraps containerized CBMC and Frama-C/EVA behind a single verdict schema
   (`unit, property, engine, verdict ∈ {safe, unsafe, inconclusive}, unwind,
   evidence, soundness_note, assumed_contracts`). `--unwinding-assertions` is
   forced ON so a loop exceeding the unwind bound surfaces as `inconclusive`,
   never silently `safe` (`Stage B / CBMC bounded loops` in the soundness
   ledger).
4. **Content-addressed proof cache** (PLAN §2 "Verification reuse").
   `surface/proof_cache.py` keys each proof on the full proof-dependence set
   from PLAN §2: normalized body SHA + property + engine + engine version +
   unwind + sorted assumed-contracts SHA + sorted build-flags SHA +
   aliasing-assumption SHA. The PLAN §2 "Soundness rule" — *"a cache hit is
   only valid if the current assumed callee contracts still hold for the
   current code; verify contract compatibility on hit, do not trust the hash
   alone"* — is enforced at `lookup()`, with `current_contracts=None`
   treated as a miss (conservative). Cluster-granularity
   `transitive_dependents()` reads the Stage A0 `depends_on` edges from
   `surface/tasks/<target>/_index.json` for invalidation.
5. **Tier-1 / Tier-2 / Tier-3 oracle drivers behind one verdict schema**
   (PLAN §3). `oracle/tier1_fuzz/` (libFuzzer + AFL++ + sanitizers,
   syzkaller / KASAN-replay), `oracle/tier2_symbolic/` (KLEE, angr, SymCC + S2E
   image-presence stubs), and `oracle/tier3_bmc/` (shared CBMC engine with
   Stage B) each return verdicts that mirror the Stage B schema. Per-engine
   soundness levers are structural in the drivers — for example,
   `klee_driver.py` only emits `unsat` when `completed > 0 AND partial == 0
   AND no klee_warning external` (recorded as `KLEE | partial-completed
   paths` and `KLEE | environment modeling` in the ledger); a `.ktest` for a
   `*.err` site is reported as `sat` but is only a *candidate* PoV until
   Tier-1 replay reconfirms (PLAN §3 Tier-2 "Verdict").
6. **Router (heuristic + LLM-backed)** (PLAN §3 "router", §7 "funnel
   economics"). `agent/router.py` dispatches in cost order and stops on the
   cheapest decisive verdict; inconclusive always escalates, never `safe`
   (`router | cheapest-decisive tier` in the ledger). The optional LLM
   dispatcher (`agent/router_llm.py`) picks **ordering only** — never a
   verdict; `_sanitize_order` drops foreign tiers, collapses duplicates, and
   **appends** any populated tier the LLM omitted (`llm-router | sanitize on
   the way in`), so a buggy LLM proposal can degrade funnel cost but cannot
   exclude a populated tier or weaken precision. On gateway error or
   malformed JSON, dispatch falls back to the heuristic.
7. **Stage B closed loop with LLM-synthesized contracts** (PLAN §2 "LLM
   acceleration hook"). `surface/contract_synth.py` proposes ACSL /
   `__CPROVER_assume` contracts from CBMC counterexamples;
   `surface/stage_b.refine_unit` injects the proposal at the `/* @CONTRACTS */`
   marker and re-runs CBMC. The PLAN §8 rule — *"the LLM proposes; the tool
   decides"* — is enforced structurally: only the engine's verdict is recorded
   even when the LLM "claims" the contract proves safety
   (`contract-synth | verdict authority`). The accumulated assumed contracts
   ride on the verdict, so the proof-cache key from item 4 hashes them.
   `_extract_contract_lines` rejects degenerate bodies (`""`, `0`, `1 == 0`,
   `false`) so the LLM cannot assume `false` to "prove" anything
   (`contract-synth | no degenerate contracts`).
8. **Per-tier LLM proposer with structural soundness filters** (PLAN §3 LLM
   hooks, PLAN §8). Tier-1 harness synthesizer
   (`oracle/tier1_fuzz/harness_synth.py`) rejects host-effect calls
   (`system / execve / exec* / fork / popen / socket / connect / fopen`) and
   requires a `LLVMFuzzerTestOneInput` symbol
   (`tier1-harness-synth | banned host-effect calls`,
   `… | required entrypoint`). Tier-2 driver synthesizer
   (`oracle/tier2_symbolic/driver_synth.py`) rejects any `klee_assume`
   mentioning a `must_not_assume` symbol — caught the live Qwen-3B model
   trying `klee_assume(d != 0)` on the divide-by-zero smoke
   (`tier2-driver-synth | must-not-assume symbols`). Tier-3 harness
   synthesizer (`oracle/tier3_bmc/harness_synth.py`) emits a typed JSON
   proposal `{preconditions, assertion}` and rejects tautological assertions
   and assume-false preconditions (`tier3-harness-synth | no tautological
   assertion`). Each filter implements PLAN §8 structurally.
9. **Closed agent loop** (PLAN §4). `agent/loop.py` walks one PLAN §4
   iteration per candidate: assemble Hypothesis → `router.route()` → map the
   router verdict to the disposition set `{confirmed, pruned, candidate,
   inconclusive, no_dispatch}` → on `bmc_unsafe` / `inconclusive` *with a
   refinement spec attached*, invoke `surface.stage_b.refine_unit` (item 7) so
   the counterexample channel feeds back into Stage B (PLAN §4 step 4).
10. **CyberGym adapter and ablation** (PLAN §5c). `eval/cybergym/adapter.py`
    implements PLAN §5c.C1 – C6 (task-id resolver, PoC output contract,
    differential scoring with patch isolation per C3, sanitizer parity,
    batch runner, submit-feedback loop). `eval/cybergym/seed_generators.py`
    pairs a baseline `RandomSeedGenerator` (PLAN §5c.D3 "No-verification
    baseline mode") against `LLMGuidedSeedGenerator` (PLAN §5c.D1 + D2
    "Verification-based scoping" + "Description-driven seeding"). Headline
    on arvo:1065 (Phase 3.4): accelerated 1/1 confirmed vs baseline 0/1,
    2.46× faster.
11. **Labeled soundness gate (Juliet)** (PLAN §2 "Acceptance", §5b.A.3).
    `eval/juliet/` adapts NIST SARD's Juliet C/C++ v1.3 to the Stage A/B
    pipeline (CWE476 / CWE415 / CWE416 / CWE121, 1486 .c files, 1074
    labeled `_bad` entries). `eval/juliet/stubs.c` provides no-op
    testcasesupport helpers but deliberately dereferences `*line` in
    `printLine`/`printWLine` because Juliet's UAF testcases pass the freed
    pointer to that sink — a true no-op would mask the deref and CBMC would
    falsely report `safe` (`juliet/stageB | helper stubs`). Result: Stage A
    `missed_bug_count = 0` over 1074 labeled `_bad`; Stage B 12 / 12 unsafe.
12. **Live-target paired positive control** (PLAN §5b.B). For both
    Phase-4.2 (kernelCTF live LTS+COS) and Phase-4.3 (live SQLite), the live
    candidate ships paired with a positive control that MUST confirm on
    every run — if the control flips to `inconclusive`, the live row no
    longer counts as a green field run (`kernelctf-live | paired positive
    control`, `live-lib | paired positive control`). This is what makes "the
    live kernel is hardened" / "no novel crash in budget" auditable rather
    than asserted.
13. **End-to-end metrics harness** (PLAN §6 step 0.5). `eval/harness/`
    walks every phase adapter and writes a single JSONL stream
    (`run-logs/phase0.5-baseline.jsonl`, 78 rows at Phase 4 close) plus a
    human-readable headline at `docs/headline-metrics.md` via
    `eval/harness/end_to_end.py`.

### Intentionally deferred (per PROGRESS.md decisions)

- **SVF-based type-aware indirect-call resolution.** Stage A uses the
  conservative address-taken over-approximation; SVF integration is the
  PLAN §3 hook noted in `reachability | indirect-call resolution`.
- **LLM-assisted Stage A0 relabeling.** PLAN §2 mentions the router model
  *assisting* clustering; Phase 1 is explicitly no-LLM, so the relabel hook
  is a Phase-3 add-on.
- **Magma.** Juliet alone satisfies the Phase-1.5 `missed_bug_count = 0`
  gate; the Phase-2.5 precision corpus uses CyberGym + kernelCTF +
  handwritten cases. Magma rolls into Phase-4.3 live-library hunting if the
  per-project build harnesses are stood up.
- **Production-profile LLM weights.** `config/models.yaml` wires the
  32B + 7B layout per PLAN §1, but the smoke profile
  (`Qwen/Qwen2.5-3B-Instruct`) is what runs through Phases 0–4; the
  ~70 GB production weights are deferred to live production runs.
- **Remaining tool images.** CBMC is built and verified end-to-end; the
  other `docker/*.Dockerfile` recipes are pinned and build on demand to
  avoid burning ~30+ GB up front (PLAN §6 Phase 0 deferral note in
  `PROGRESS.md`).

---

## Repository layout (from PLAN §5)

```
config/         models.yaml, budget.yaml, targets/*.yaml
docker/         per-tool Dockerfiles, build+smoke drivers
docs/           soundness-assumptions.md, toolchain.lock, headline-metrics.md
ingest/         repo fetch, build (kernel + userspace), OSS-Fuzz harness reuse
surface/        Stage A (reachability/taint) + Stage B (Frama-C/CBMC) + entry-point catalogs + proof cache
oracle/
  tier1_fuzz/   syzkaller + AFL++/libFuzzer drivers, sanitizer configs, harness generators
  tier2_symbolic/  S2E, KLEE, SymCC drivers + constraint-hint generators
  tier3_bmc/    CBMC/ESBMC harness + assertion generators
agent/          proposal loop, router, refinement, counterexample handling
llm/            vLLM serving, gateway, prompt+contract templates
eval/           cybergym/ (primary), sv-comp, magma, juliet + field-runners (kernelctf, live-lib) + metrics
run-logs/       per-phase JSON/JSONL artifacts
```

---

## How to reproduce the headline

Each phase has a deterministic driver. Run them in order; each writes to
`run-logs/`.

```bash
# Phase 0 — Skeleton + no-LLM baseline (PLAN §6)
bash docker/build_all.sh && bash docker/smoke.sh
bash llm/serve.sh smoke && python3 llm/smoke.py
bash eval/cybergym/run_phase03_smoke.sh 1065
bash eval/kernelctf/scripts/fetch_kernel.sh   # then make_config / build / make_rootfs / run_qemu
python3 -m eval.harness.run_baseline

# Phase 1 — Component (1) pruning
bash surface/stage_a.sh linux-6.1.72-netfilter
python3 -m surface.stage_b --manifest surface/smoke/manifest.json --out surface/stageb/smoke.json
python3 -m surface.test_proof_cache
python3 eval/juliet/run_stage_a.py && python3 eval/juliet/run_stage_b.py

# Phase 2 — Component (2) oracle (no LLM)
python3 -m oracle.tier1_fuzz.userspace fuzz ...
python3 -m oracle.tier2_symbolic.klee_driver ...
python3 -m oracle.tier3_bmc.cbmc_driver ...
python3 -m agent.router --smoke agent/smoke/hypotheses.json
python3 eval/precision/run.py                   # Phase 2.5 acceptance gate

# Phase 3 — LLM acceleration
python3 -m surface.stage_b_refine_cli --manifest surface/smoke/manifest.json --out run-logs/phase3.1-synth-smoke.json
python3 oracle/smoke/run_harness_synth.py
python3 -m eval.precision.run --dispatcher llm
python3 eval/cybergym/run_ablation.py 1065 --budget 20

# Phase 4 — Full closed loop on field targets
python3 -m agent.loop --candidates agent/smoke/candidates.json --out run-logs/phase4.1-loop.jsonl
bash eval/kernelctf/scripts/make_config_live.sh && bash eval/kernelctf/scripts/build_kernel_live.sh \
  && bash eval/kernelctf/scripts/make_rootfs_live.sh && bash eval/kernelctf/scripts/run_qemu_live.sh
python3 eval/live-lib/run_phase43.py
python3 -m eval.harness.end_to_end
```

---

## Guardrails (PLAN §8)

- **Final verdict authority = sound checker, never the LLM.** Enforced
  structurally in `surface/contract_synth.py`,
  `oracle/tier1_fuzz/harness_synth.py`,
  `oracle/tier2_symbolic/driver_synth.py`,
  `oracle/tier3_bmc/harness_synth.py`.
- **Scope ethically/legally:** only run against authorized targets (own
  infra, OSS-Fuzz projects, CTF/benchmark corpora, kernels you control).
- **Reproducibility:** every confirmed PoV ships with a deterministic
  reproduction artifact and the sanitizer/symbolic trace that backs it
  (see the field-PoV table in `docs/headline-metrics.md`).
- **Document soundness assumptions** — `docs/soundness-assumptions.md`. If
  you add a new tool, append its assumptions before relying on its verdict.

---

## Citations

- CyberGym: *CyberGym: Evaluating AI Agents' Real-World Cybersecurity Capabilities at Scale.* Sunblaze, UC Berkeley. arXiv:2506.02548.
- CBMC: Clarke, Kroening, Lerda. *A Tool for Checking ANSI-C Programs.* TACAS 2004.
- Frama-C / EVA: Cuoq, Kirchner, Kosmatov, Prevosto, Signoles, Yakobowski. *Frama-C: A Software Analysis Perspective.* SEFM 2012.
- KLEE: Cadar, Dunbar, Engler. *KLEE: Unassisted and Automatic Generation of High-Coverage Tests for Complex Systems Programs.* OSDI 2008.
- angr: Shoshitaishvili et al. *SoK: (State of) The Art of War: Offensive Techniques in Binary Analysis.* IEEE S&P 2016.
- SVF: Sui, Xue. *SVF: Interprocedural Static Value-Flow Analysis in LLVM.* CC 2016.
- AFL++: Fioraldi, Maier, Eißfeldt, Heuse. *AFL++: Combining Incremental Steps of Fuzzing Research.* WOOT 2020.
- vLLM: Kwon et al. *Efficient Memory Management for Large Language Model Serving with PagedAttention.* SOSP 2023.
- Juliet C/C++ v1.3 — NIST Software Assurance Reference Dataset (SARD).
- AIxCC reference pipelines (orchestration only): OSS-CRS, ATLANTIS, RoboDuck.
