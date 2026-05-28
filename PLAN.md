# Implementation Plan — Verification-Accelerated Vulnerability-Discovery Agent (C/C++)

> Hand this file to Claude Code as the working spec. Build in the phase order below.
> Each phase has explicit acceptance criteria — do not advance until they pass.

## 0. Goal & Architecture

Build an autonomous vulnerability-discovery agent for **C/C++ source code (including the Linux
kernel)** that uses **open-source program verification** in two roles:

1. **Attack-surface minimization (pruning)** — soundly remove regions that cannot contribute to an
   exploitable bug, so the agent's search space shrinks.
2. **Exploitability oracle** — given a hypothesis ("location X is exploitable via condition C"),
   confirm or refute it as fast as possible.

The agent uses a **guess-and-check (neuro-symbolic)** loop: a **local LLM proposes** (candidate bug
sites, function contracts, loop invariants, harnesses, exploit conditions, PoV inputs) and a **sound
checker disposes** (the verification/fuzzing/symbolic tools below). Counterexamples feed back to the
LLM. The LLM only ever *proposes*; the final safe/unsafe verdict always comes from a sound tool —
this is what keeps pruning sound (no false negatives introduced by the LLM).

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

All heavy verification tools (CBMC, syzkaller, S2E, KLEE) are **CPU/RAM-bound**. The **4 GPUs are
dedicated to local LLM serving**; GPU saturation comes from high-throughput batched inference across
the funnel (many hypotheses in flight), not from the verifiers.

---

## 1. Hardware & Local Model Serving (4 GPUs)

### Serving stack
- **vLLM** (or SGLang) with an OpenAI-compatible endpoint. All agent/LLM calls go through one
  internal gateway so model choice and routing are swappable behind a config.
- Enable continuous batching + prefix caching. The workload is **throughput-bound** (thousands of
  small proposal/refinement calls), so optimize for tokens/sec across concurrent requests, not
  single-request latency.

### Model layout (config-driven; pick based on actual VRAM per GPU)
Two roles, served separately so the small router never blocks the big synthesizer:

| Role | Job | Suggested model | Default placement |
|---|---|---|---|
| **Synthesizer** | contracts, invariants, harnesses, exploit reasoning, PoV drafting | `Qwen3.6-32B` / `Qwen3.6-35B-A3B` or `DeepSeek-V4-Flash` (Apache/MIT) | TP=2 on GPUs 0–1 |
| **Router/Classifier** | hypothesis triage, tier routing, cheap labeling, dedup | a small fast model (`Devstral Small 2` / 7–8B class) | GPUs 2 (single) |
| **Throughput replica** | second synthesizer replica for funnel fan-out | same as synthesizer | TP-... on GPUs 2–3 |

- **Default recommendation:** two synthesizer replicas (TP=2 each across the 4 GPUs) to maximize
  funnel throughput, plus the small router co-located/quantized. If a single very large model
  (Kimi-K2.6 / DeepSeek-V4-Pro class) is desired, serve one model TP=4 instead and drop a replica —
  but throughput drops, so only do this if proposal quality is the bottleneck.
- Quantization (Q4/FP8) is acceptable for the router; keep the synthesizer at the highest precision
  VRAM allows. Make precision a config flag.
- **GPU saturation target:** keep all 4 GPUs at high utilization by (a) batching the funnel's
  parallel hypotheses, (b) running an offline pass that pre-generates contracts/harnesses for the
  whole reachable slice in bulk, and (c) an embedding/reranker model for code retrieval over the
  target repo if spare capacity remains.

### Config to expose
`config/models.yaml`: model id, TP degree, GPU map, max context, quantization, endpoint port.
`config/budget.yaml`: per-phase token caps and per-hypothesis tier-cost limits (see §7).

---

## 2. Component (1): Attack-Surface Minimization

**Decision: a two-stage sound funnel, executed as design-pattern-aligned analysis tasks over a
reusable proof cache.** Rationale: whole-program sound safety verification does not scale to
Linux-sized C. So (a) bound the surface with a cheap *sound over-approximation* first (over-approx
errs toward keeping code → never prunes a real bug), then carve out *provably-safe* islands with
*modular* proofs where it pays off; (b) partition the work into many independent analysis tasks cut
along the program's implementation/design-pattern boundaries; and (c) memoize verification results
so fundamental/shared code is proven once and reused.

### Stage A0 — design-pattern-aligned task decomposition
Split the target into many independent **analysis tasks**, each a cluster of *related sources*
analyzed together. Cut along implementation/design-pattern boundaries because those give clean
interfaces, which are exactly the good cut points for *compositional* (per-contract) verification.
- **How to cluster (kernel examples):** by subsystem (`net/`, `fs/`, `mm/`, `drivers/...`), and by
  recurring implementation patterns — `ops`-struct / vtable dispatch, `container_of` embedded-struct
  ownership, refcount `get`/`put`, RCU read-side sections, allocator/wrapper layers, parser
  state-machines. The LLM (router model) assists by labeling each source's role/pattern and grouping
  it; this is a *heuristic for good cuts*, not a soundness lever — any partition stays sound as long
  as the contracts at task boundaries are themselves verified.
- **Why it helps:** (1) each task is small enough for Stage B to actually prove; (2) tasks are
  independent → parallelize across CPU workers and **batch LLM contract synthesis across tasks**
  (a primary GPU-saturation lever); (3) a clean interface = a reusable contract (next subsection).
- **Implementation:** emit a task graph `surface/tasks/*.json` with {source set, entry contracts,
  callee dependencies, pattern labels}. The callee-dependency edges drive both compositional
  ordering and cache invalidation.

### Stage A — scalable sound reachability / taint (the big cut)
Keep only code reachable from attacker-controlled entry points (syscalls, ioctl, netlink, parsers,
file/network input). Prune everything provably unreachable from any attacker source.
- **Tooling priority for Linux:** `Smatch` and `Coccinelle` (kernel-idiom-aware), `Sparse`,
  then `SVF` (LLVM value-flow / pointer analysis) and `CodeQL` (has kernel queries) for userspace
  and extracted modules.
- Build an attacker-entry-point catalog per target (kernel: syscall table, ioctl handlers, netlink
  ops, char-dev fops; userspace: `main`/fuzz-entry/network read).
- **Soundness note to document explicitly:** function pointers, indirect calls, inline asm, and
  macro-heavy kernel code degrade precision. Resolve indirect calls conservatively
  (over-approximate the callee set) so the keep-set stays sound. Record every unsoundness assumption
  in `docs/soundness-assumptions.md`.

### Stage B — modular sound safety proof (carve provably-safe islands)
On the reachable+tainted slice only, try to *prove* the relevant safety property
(no OOB read/write, no UAF, no integer overflow leading to the above) per function under
LLM-synthesized preconditions/contracts. If proven, prune the function.
- **Primary sound, scalable engine:** `Frama-C` + **EVA** (abstract interpretation; sound
  over-approximation, handles whole functions, scales better than BMC).
- **Bounded engine for definite small-scope results:** `CBMC` / `ESBMC` (sound *within* the loop
  bound; combine with LLM-synthesized **loop invariants** to push past the bound toward unbounded
  proofs — guess-and-check with CBMC counterexamples driving refinement).
- **LLM acceleration hook:** synthesizer generates function contracts (ACSL for Frama-C),
  loop invariants, and stubs for callees; the sound engine validates; counterexamples are returned
  to the LLM for repair. Cap refinement iterations per function.

### Verification reuse — content-addressed proof cache
Prove fundamental/shared code **once**, then reuse the verdict. This is incremental + compositional
verification with memoization, and it is what makes re-running on the next kernel version (kernelCTF
rotates every 2–4 weeks) or a new target cheap — only changed functions and their dependents are
re-verified.
- **Cache key (must capture everything the proof depended on, or reuse is unsound):** normalized
  function/module body hash + the proved property + the *assumed callee contracts* + semantics-
  affecting build flags (kernel `CONFIG_*`, arch, compiler/sanitizer mode) + pointer/aliasing
  assumptions. Any change in a key component → miss → re-verify.
- **Invalidation:** maintain a dependency graph (the Stage A0 callee edges). Changing a callee's
  contract invalidates dependents transitively — like a build system / Salsa-style incremental
  computation, but for proofs. Store as `surface/proofcache/` (content-addressed).
- **Priority to cache:** fundamental, recurring modules first — `lib/` helpers, core data-structure
  ops (lists, rbtrees, refcount), allocator wrappers, crypto primitives, string/parse utilities.
  These recur across subsystems, versions, and targets, so each cached proof amortizes the most.
- **Soundness rule:** a cache hit is only valid if the *current* assumed callee contracts still hold
  for the current code; verify contract compatibility on hit, do not trust the hash alone.

### Output of Component (1)
A ranked list of **candidate bug sites** (the minimized attack surface) with, for each: the property
at risk, the slice/path context, and whether Stage B proved it safe (pruned), proved a violation
(promote straight to oracle), or was inconclusive (hand to the agent).

**Acceptance:** on a labeled corpus (Magma/Juliet), Stage A+B must achieve a measurable
attack-surface reduction with **zero known-true-bugs pruned** (soundness gate). Track reduction %
and missed-bug count; missed-bug must be 0 on the labeled set before this component is "done".

---

## 3. Component (2): Exploitability Oracle (tiered, Linux-capable)

A hypothesis = (location, property, triggering condition, optional candidate input). The **router**
(small model) sends each hypothesis to the cheapest tier that can decide it, escalating only on
inconclusive results.

### Tier 1 — fast crash oracle (TOP PRIORITY; runs first, always)
- **Linux kernel:** `syzkaller` (coverage-guided via `KCOV`) with sanitizer oracles
  **KASAN, KMSAN, KCSAN, UBSAN**. This is the battle-tested Linux-native path.
- **Userspace C/C++:** `AFL++` / `libFuzzer` with **ASan, MSan, UBSan**.
- **LLM hook:** synthesizer generates `syzlang` syscall descriptions + harnesses (kernel) and fuzz
  harnesses/seed inputs (userspace) targeting the hypothesis location. This is the main place to
  burn GPU throughput: mass-generate and refine harnesses.
- Verdict: a sanitizer-confirmed crash = **confirmed PoV** (high precision). No crash within budget
  = inconclusive → escalate.

### Tier 2 — targeted symbolic / concolic feasibility (when fuzzing can't reach)
- **Linux kernel:** `S2E` (selective symbolic execution on QEMU; works on real kernels) to decide
  path reachability and solve the triggering constraint.
- **Userspace:** `KLEE` (LLVM bitcode) for extracted modules; `SymCC`/`SymQEMU` for faster concolic.
  `angr` for binary-only components.
- **LLM hook:** generate symbolic drivers, mark symbolic inputs, propose path-constraint hints and
  seed constraints to cut path explosion.
- Verdict: SAT triggering constraint + concrete input = candidate PoV (verify in Tier 1);
  UNSAT/proved-unreachable = **refute** (prune); timeout = escalate or shelve.

### Tier 3 — definite bounded judgment
- `CBMC` / `ESBMC` for a yes/no on a bounded property/harness when Tiers 1–2 are inconclusive and a
  definitive small-scope answer is worth the cost. Shared engine with Component (1) Stage B.

### Static scoping (shared with Component 1, not a final oracle)
`Smatch`, `Coccinelle`, `Sparse`, `Clang Static Analyzer`, `CodeQL`, `SVF` — used to generate
candidate sites and narrow where the oracle looks; never used alone to declare exploitability.

**Acceptance:** on the **CyberGym** subset the oracle must score PoCs exactly as CyberGym's checker
does (crash pre-patch, pass post-patch) with deterministic reproduction; report per-tier latency and
escalation. Magma stays as a secondary precision check (near-zero false confirmations).

---

## 3b. Component (3): Specification Mining as Bug Oracle (vuln-class-general)

**Thesis.** Sound verification doesn't just prune safe regions — it discovers bugs as outliers in
mined-contract distributions. Mine pre-call invariants from the codebase's own conventions; outlier
callsites where the mined invariant does not hold become hypothesis seeds; the existing Component (2)
sound oracle confirms or refutes via the existing tiered engines. This generalises beyond memory
safety natively because every recurring pre-call pattern is a different bug class
(**locking, auth/capability, bounds/length, null/init, refcount, taint-sanitization, state-machine,
resource-cleanup**) — the mining doesn't change per class, only the *shape* of the missing guard
does.

This component restructures verification's role: it is no longer just a prune/decide filter
(Component 1, 2) but a *bug proposer* whose hypotheses are grounded in the target's own code
conventions, not in the LLM's priors. Two soundness properties carry over from Components (1) and
(2):
- **Mining is a proposer, not a decider.** A mined contract is a *conjecture* until verified by
  Stage B; an outlier is a *lead* until refuted/confirmed by Tier 2/3. Final verdict authority
  stays with the sound checker (§8 guardrail).
- **Cache key compatibility.** Mined contracts are recorded as `assumed_contracts` in the
  Phase 1.4 proof-cache key, so any reuse of a proof that depended on a mined contract becomes
  invalid the moment that contract changes — same soundness rule, no new lever.

### 3b.1 — Callsite + guard extraction
For each callee `F`, collect every callsite in the target tree and walk backward through the
caller's CFG to extract preceding guard conditions: `if(...)` / `while(...)` / `BUG_ON` / `WARN_ON` /
`__must_check` / lock-acquire (`*_lock`, `rcu_read_lock*`, `mutex_lock`) / capability-check
(`capable`, `ns_capable`) / null-check / bounds-check / sanitizer-call. The extractor uses a real
AST (libclang or tree-sitter for kernel macro-heavy code), keyed off the Phase 1.1 cluster
decomposition so mining stays partitionable per task and reusable across versions via the proof
cache.

### 3b.2 — Contract synthesis from callsite distributions
Cluster guards across callsites per callee with **variable-role normalization** (`arg0`, `arg1`,
`return_of(X)`, `field_of(arg.X)`) and local SMT equivalence (Z3) so syntactically different
predicates that mean the same thing collapse. A guard cluster with support ≥τ (default τ=0.85)
becomes a *mined contract* for that callee. Each callsite that doesn't match a mined contract emits
an outlier with suspicion score `support_pct × (1 − local_establishment)`, where
`local_establishment` is a cheap one-hop interprocedural check ("does the immediate caller plausibly
establish the contract from its own callers?").

### 3b.3 — Sound verification (forward + backward)
A mined contract is a conjecture; the sound checker decides.
- **Forward (Stage B):** prove the contract holds on its support set via Frama-C/EVA + CBMC, cached
  through the Phase 1.4 proof cache. A failing forward proof downgrades the contract to
  "low-confidence" — outliers still emitted, but flagged so 3b.5 reranks them.
- **Backward (Tier 2/3):** for each outlier, dispatch through `agent.router.route()` with the
  property "the callee's mined contract is violated, and a sanitizer/assertion fires reaching the
  callee." Tier 2 (KLEE/angr) for feasibility, Tier 3 (CBMC) for bounded definitive judgment.
  UNSAT/safe ⇒ benign outlier (suspicion lowered); SAT/unsafe ⇒ confirmed bug with witness.

### 3b.4 — Vuln-class taxonomy + per-class report
Classify mined contracts by the *shape* of the missing guard, not the body: **locking** (lock-acquire
predicate), **auth/capability** (`capable`/`ns_capable` form), **bounds/length** (compare on a
length/index field), **null/init-check**, **refcount** (read of refcount > 0), **state-machine**
(`state == EXPECTED`), **taint-sanitization** (string-escape / shell-quote call), and
**resource-cleanup** (acquire/release pairing). Per-class formatter renders outliers as
human-readable leads ("missing `capable(CAP_NET_ADMIN)` before `nf_tables_newrule`") — this is the
breadth-of-vuln-class deliverable.

### 3b.5 — LLM-assisted contract refinement (Phase 3.1 pattern)
When backward verification returns `inconclusive` (engine timeout, or the contract needs widening —
e.g. mined `rcu_read_lock` should be `rcu_read_lock || in_irq()`), the synthesizer LLM is invoked
under the Phase 3.1 proposer pattern: prompt = mined contract + outlier callsite + engine trace;
output is a refined contract; the sound checker re-verifies. **LLM proposes, engine decides**
(§8). Rule-based fallback exists for gateway-down operation, exercising the same loop deterministically.

**Output of Component (3):** a ranked list of **confirmed bug leads**, each carrying the mined
contract, the violating callsite, the sound-checker witness (PoV or constraint), and a vuln-class
label. The output schema is compatible with Component (2)'s router so confirmed leads flow into the
same agent loop as Component (1)'s candidate sites — no parallel pipeline.

**Acceptance:** on the Phase 0.4 historical target (Linux 6.1.72 `net/netfilter/`, contains
CVE-2024-1086), the system must (a) re-discover the CVE's underlying convention violation as a
top-N outlier under the same mining/scoring procedure used for unlabeled targets, (b) confirm it as
a bug via the existing Tier-2/3 oracle without LLM intervention in the verdict, and (c) preserve the
Phase 1.5 / Phase 2.5 soundness gates (`missed_bug_count = 0`, `false_confirmations = 0`). On at
least one current field target (live LTS kernel or live library), produce ≥1 confirmed lead in ≥2
vuln classes including at least one non-memory-safety class.

---

## 4. The Closed Loop (orchestration)

1. **Ingest** target repo; build (kernel: with KCOV+sanitizer configs; userspace: with sanitizer
   instrumentation). Reuse **OSS-Fuzz** build harnesses where available.
2. **Component (1)** produces the minimized attack surface + candidate sites.
3. **Component (3)** mines pre-call contracts from the target's own callsite distributions and emits
   outlier callsites as bug leads — a second candidate stream that complements Component (1)'s
   surface candidates and is naturally vuln-class-general (locking, auth, bounds, refcount,
   taint, …).
4. **Agent loop** per candidate (from either source): synthesizer proposes an exploit hypothesis →
   **router** picks a tier → oracle returns confirm / refute / inconclusive → on refute, prune; on
   inconclusive, refine hypothesis or escalate tier; on confirm, emit PoV + report.
5. **Counterexamples** from any tier feed back to Component (1) Stage B (to repair contracts),
   Component (3) (to re-rank/refine mined contracts), and the agent (to refine the next proposal).
6. **Budget governor** enforces token + tier-cost caps; cheap tiers must absorb most hypotheses
   (funnel economics, see §7).

Reuse, do not rebuild, the orchestration/artifact-exchange/budget layer: base it on the
open-sourced **OSS-CRS** framework and study the open-sourced **ATLANTIS** / **RoboDuck** AIxCC
finalist pipelines for the PoV-generation flow.

---

## 5. Repository Layout

```
repo/
  config/            models.yaml, budget.yaml, targets/*.yaml
  ingest/            repo fetch, build (kernel + userspace), OSS-Fuzz harness reuse
  surface/           Stage A (reachability/taint) + Stage B (Frama-C/CBMC) + entry-point catalogs
    specmine/        Component (3) callsite/guard extraction, contract mining, outlier ranking
  oracle/
    tier1_fuzz/      syzkaller + AFL++/libFuzzer drivers, sanitizer configs, harness generators
    tier2_symbolic/  S2E, KLEE, SymCC drivers + constraint-hint generators
    tier3_bmc/        CBMC/ESBMC harness + assertion generators
  agent/             proposal loop, router, refinement, counterexample handling
  llm/               vLLM/SGLang serving, gateway, prompt+contract templates
  eval/              cybergym/ (primary), sv-comp, magma, juliet + field-runners (kernelctf, lib) + metrics
  docs/              soundness-assumptions.md, architecture.md, runbook.md
```

---

## 5b. Targets

Separate **evaluation benchmarks** (labeled, scored — measure whether the system works) from
**field targets** (no label set — where the agent hunts for real bugs).

### A. Evaluation benchmarks (labeled, scored)

1. **CyberGym (UC Berkeley, arXiv:2506.02548) — PRIMARY first evaluation.** 1,507 real-world C/C++
   memory-safety vulnerabilities across 188 OSS-Fuzz projects. Task: given a vulnerability's text
   description + the codebase, produce a **PoC input that crashes the pre-patch build and does NOT
   crash the patched build**. No partial credit, no LLM-judge — the crash/no-crash check is binary.
   This matches our system end-to-end: Component (1) prunes the surface, the agent proposes the PoC,
   and **CyberGym's own pre/post-patch checker IS the oracle ground truth**. Why it's the right first
   eval: same language (C/C++), same property class (sanitizer-detectable memory safety), same
   deliverable (a reproducing PoC), and OSS-Fuzz-based so it shares build/harness machinery with our
   Tier-1 oracle.
   - **Setup:** `github.com/sunblaze-ucb/cybergym` (harness + agent scaffolding); dataset on
     HuggingFace (`sunblaze-ucb/cybergym-*`); Docker compilation environments per task; a PoC
     submission server. Full server data is ~10TB, so **start with the published 10-task subset**
     (5 solvable + 5 hard: `arvo:47101, arvo:3938, arvo:24993, arvo:1065, arvo:10400, arvo:368,
     oss-fuzz:42535201, oss-fuzz:42535468, oss-fuzz:370689421, oss-fuzz:385167047`) for Phase 0–2,
     then scale up.
   - **Calibration note:** SOTA success is ~20% — set expectations accordingly; the headline result
     is *our system vs. a no-verification agent baseline on the same CyberGym split*, not an absolute
     number.
2. **SV-COMP** — verification correctness/soundness of Component (1)'s proof engine (Frama-C/CBMC),
   independent of the offensive pipeline.
3. **Magma / Juliet** — secondary; cheap labeled bugs for the Stage A+B **soundness gate**
   (0 true bugs pruned) before trusting pruning on CyberGym.

### B. Field targets (no label set — real bug-hunting)

4. **Google kernelCTF — the real Linux-kernel target the agent hunts on (authorized).** This is NOT
   a scored benchmark; it is where the deployed agent looks for real kernel bugs. kernelCTF is part
   of Google VRP and explicitly invites researchers; submissions are published in
   `google/security-research`.
   - *Dev/sanity only:* historical published submissions (known CVE + exact LTS version + PoC) are
     used to confirm the kernel toolchain (KASAN+KCOV+syzkaller, QEMU/kctf) reproduces a known bug —
     a smoke test, not a score.
   - *Actual goal:* run the full closed loop against a live LTS-instance config (latest LTS, COS
     config, unprivileged userns off, io_uring + nftables disabled) to find a **novel, reproducible**
     kernel bug; ultimate success mirrors kernelCTF (LPE PoV, ~90% reproducible runs).
5. **A fundamental C library, live — e.g. SQLite / OpenSSL / libxml2.** Also a field target: point the
   agent at the *latest* version via its OSS-Fuzz harness to hunt for new bugs. (Note: historical
   bugs of these same libraries already appear inside CyberGym as labeled tasks — keep the two uses
   distinct: CyberGym = historical/labeled, this = live/unlabeled hunting.) Doubles as the simplest
   Phase 0 bring-up because it builds in seconds.

---

## 5c. CyberGym as Default Evaluation — Tool Changes

To run CyberGym as the default eval, the tool must conform to the **same interface existing CyberGym
agents already follow** (so it can be scored at all), and then layer our differentiators on top (so
the verification-acceleration effect is measurable). Keep these two buckets explicitly separate.

### Bucket 1 — Protocol conformance (match existing CyberGym agents; non-optional)
Without these, scoring does not run.
- **C1. Task adapter + submission server.** Accept a CyberGym task id (`arvo:*`, `oss-fuzz:*`); mount
  its Docker compile env as the ingest build backend; route a confirmed PoV to CyberGym's PoC
  submission server. Abstract CyberGym's checker as a pluggable **oracle backend**.
- **C2. PoC-input output contract.** Emit a concrete input artifact (raw binary/text) matching the
  task's OSS-Fuzz harness ABI (`LLVMFuzzerTestOneInput`), not an abstract "crash". Harness/driver
  generation targets the task's exact fuzz entrypoint.
- **C3. Differential scoring + patch isolation.** Success = crash on pre-patch AND pass on patched
  build (an input that crashes both fails). Patch is **scoring-only**; never expose it to the agent
  except in CyberGym's explicit with-patch setting.
- **C4. Sanitizer parity.** Match the task build's sanitizer flags (ASan/UBSan/MSan) so our local
  "confirmed" equals CyberGym's "confirmed" — no local-success / submit-fail mismatch.
- **C5. Batch runner at scale.** Per-task container isolation, fixed seeds (reproducibility), CPU-
  worker parallelism, per-task budget caps (tokens / fuzz time / symbolic time), result aggregation,
  subset/data-caching layer (full data ~10TB). Start with the 10-task subset.
- **C6. Submit → feedback → refine loop.** Map CyberGym server feedback (no-crash / crashes-both)
  into the agent's counterexample channel — the same `run()` / `deliver-feedback()` round-trip
  pattern existing agents use.

### Bucket 2 — Our differentiators on top (the research contribution)
These reuse the conformant protocol but are where our system differs from a stock agent.
- **D1. Verification-based scoping as a *sound* pre-analysis.** Existing agents narrow the search
  space with pure-Python heuristics before the first LLM call (vuln class, top files, input→crash
  call path, warm-start from similar tasks). Component (1) is the **sound** version of that same
  pre-analysis: prune provably-safe regions, scope to the reachable+tainted slice. Same role in the
  pipeline, stronger guarantee.
- **D2. Description-driven seeding.** Parse the CyberGym task description (crash type, function,
  sanitizer-report excerpt) into Stage A entry points + initial hypotheses; config-toggle for
  CyberGym's description-only vs. with-more-info settings.
- **D3. No-verification baseline mode.** A feature-flagged baseline (Component (1) pruning + verify
  oracle OFF, fuzz only) runnable through the *same* adapter, so the headline result is
  apples-to-apples: our system vs. stock agent on the same split.
- **D4. Cross-task proof-cache reuse.** 1,507 tasks over 188 projects share libraries; the
  content-addressed proof cache amortizes fundamental-function proofs across tasks. The adapter MUST
  pass each task's build flags into the cache key (soundness).

### Adapter interface (draft)
```
input:  cybergym_task_id            # "arvo:3938" | "oss-fuzz:42535201"
        setting                     # description_only | with_extra | with_patch
resolve -> { prepatch_build, patched_build (scoring-only), fuzz_entrypoint,
             description, codebase, sanitizer_flags }
run     -> agent loop (Component 1 scope -> hypotheses -> tiered oracle -> PoC)
output: poc_input_artifact          # bytes, conformant to fuzz_entrypoint ABI
        verdict                     # via CyberGym checker: crash_prepatch ∧ pass_patched
        metrics                     # success, tokens, per-tier latency, surface-reduction %
```

---

## 6. Phased Milestones (build in order)

- **Phase 0 — Skeleton + no-LLM baseline.** Goal: every tool runs, one target goes end-to-end with
  **no LLM**, and metric logging works. Concretely:

  - **0.1 Toolchain, pinned & containerized.** One Docker image per tool family to avoid dependency
    conflicts (toolchain breakage is the main time sink with these tools). Pin versions:
    - LLVM/Clang (one version, shared by SVF + KLEE bitcode + libFuzzer/sanitizers),
    - `CBMC`, `ESBMC`, `Frama-C` (+ EVA plugin),
    - `KLEE` (+ matching LLVM), `S2E`, `SymCC`/`SymQEMU`, `angr`,
    - `AFL++`, `libFuzzer`, `syzkaller` (+ `KCOV`), kernel sanitizers `KASAN/KMSAN/KCSAN/UBSAN`,
    - `Smatch`, `Coccinelle`, `Sparse`, `CodeQL` CLI, `SVF`.
    Record exact versions in `docs/toolchain.lock`.
  - **0.2 LLM serving smoke test (not yet used in analysis).** Bring up vLLM/SGLang per
    `config/models.yaml` (default: 2× synthesizer TP=2 + small router); confirm the gateway answers
    an OpenAI-format request and report GPU utilization. Wire `config/budget.yaml` caps.
  - **0.3 First eval bring-up (CyberGym subset) + userspace target.** Clone
    `github.com/sunblaze-ucb/cybergym`, pull the **10-task subset** + the per-task Docker compilation
    environments, and stand up the PoC submission server. Confirm the harness can: build a task's
    pre-patch and patched binaries, accept a PoC, and report crash-on-prepatch / pass-on-patch. As an
    even simpler smoke, also build a live fundamental library (SQLite) OSS-Fuzz target with
    ASan+UBSan+libFuzzer and emit bitcode + call graph + entry-point catalog. Run **Tier-1 only** on
    one CyberGym "solvable" task using its known PoC to confirm the full ingest → build → oracle →
    verdict path works with **zero LLM**.
  - **0.4 Kernel target bring-up (kernelCTF, sanity only).** Fetch one *historical* kernelCTF
    submission's exact LTS version + config; build with KASAN+KCOV; boot under QEMU via kctf; run
    `syzkaller` against the relevant subsystem with the published PoC's syscall surface and confirm
    KASAN reports the known bug. Also run static scoping (Smatch/Coccinelle/Sparse) over that
    subsystem and dump candidate sites. This only proves the kernel toolchain works — kernelCTF is a
    field target, not a scored benchmark. No symbolic/BMC, no LLM yet.
  - **0.5 Eval + metrics harness.** Primary adapter = **CyberGym** (its binary crash/no-crash checker
    is the scoring oracle); secondary adapters = SV-COMP, Magma, Juliet (soundness gate); field-target
    runners for kernelCTF-historical and the live library. Metric logger records: CyberGym
    success rate (PoC reproduction), attack-surface reduction %, missed-bug count (soundness gate),
    oracle precision/recall, per-tier latency, tokens/cost, GPU utilization.

  *Done when:* the CyberGym 10-task harness builds pre/post-patch binaries and scores a known PoC
  correctly; one CyberGym solvable task reproduces via Tier-1 + sanitizers; one kernelCTF historical
  bug reproduces under KASAN; all other tools execute on a smoke input; the LLM endpoint serves; and
  the metrics harness logs a baseline row — **all with no LLM in the analysis path.**


- **Phase 1 — Component (1) pruning.** Implement Stage A then Stage B (no LLM yet — fixed
  contracts). Measure attack-surface reduction and the **soundness gate (0 true bugs pruned)** on
  Juliet/Magma. *Done when:* reduction is measurable and missed-bug count = 0 on the labeled set.

- **Phase 2 — Component (2) oracle (no LLM).** Implement Tier 1→2→3 with hand-written harnesses on a
  small bug set; measure precision and per-tier latency/escalation. *Done when:* injected Magma bugs
  are confirmed with deterministic PoVs and near-zero false confirmations.

- **Phase 3 — LLM acceleration.** Add synthesizer-generated contracts/invariants (Stage B), and
  harness/driver/constraint generation (all oracle tiers), plus the router. Run the **headline
  ablation on the CyberGym subset**: our verification-accelerated system vs. a no-verification LLM
  agent baseline, measuring PoC success rate, verification convergence, and wall-clock/token cost.
  *Done when:* the LLM measurably increases proved-safe coverage and/or CyberGym success rate and/or
  reduces time-to-PoC vs. baseline, without breaking the Phase-1 soundness gate.

- **Phase 4 — Full closed loop on field targets.** Close hypothesis→route→verify→prune/confirm→PoV.
  Point the agent at **kernelCTF** (live Linux kernel, KASAN+KCOV, QEMU/kctf) and the **live
  library** to hunt for *new* bugs — using the historical kernelCTF bug only as a toolchain sanity
  check. *Done when:* the system autonomously produces at least one reproducible PoV on a real target
  and reports surface-reduction + cost metrics end-to-end.

- **Phase 5 — Component (3) Specification Mining as Bug Oracle (vuln-class-general).** Add the
  spec-mining proposer described in §3b on top of the Phase 1–4 sound pipeline. Goal: expand the
  set of vuln classes the system can find beyond memory safety by mining pre-call contracts from the
  target's own conventions and confirming outliers via the existing sound oracle. Sub-steps:

  - **5.1 Callsite + guard extractor (no LLM).** Walk the target tree; for each callee F, harvest
    callsites and walk back through the caller's CFG to extract preceding guard conditions
    (if/while/assert/BUG_ON/lock-acquire/capable/null-check/bounds-check/sanitizer-call). Use a real
    AST parser (libclang or tree-sitter) keyed off the Phase 1.1 cluster decomposition so mining is
    partitionable per task. Output: `surface/specmine/callsites/<target>/<callee>.json` with
    `{callsite_location, guards: [{kind, predicate, var_bindings}], surrounding_context}`.
    *Done when:* ledger over Phase 0.4 `net/netfilter/` reproduces obvious patterns
    (e.g. `rcu_read_lock`/`rcu_read_lock_bh` ≥X% before `nft_*_eval`; `mutex_is_locked` /
    `lockdep_assert_held` before commit-path callees); fixed-seed determinism; wall budget on the
    same order as Phase 1.1.
  - **5.2 Contract miner + outlier extractor (no LLM).** Cluster guards across callsites per
    callee with variable-role normalization (`arg0`, `arg1`, `return_of(X)`, `field_of(arg.X)`) +
    local SMT equivalence (Z3) so syntactically different predicates that mean the same thing
    collapse. A guard cluster with support ≥τ (default τ=0.85) becomes a *mined contract*; each
    callsite that doesn't match emits an outlier with suspicion =
    `support_pct × (1 − local_establishment)` (one-hop interprocedural check).
    *Done when:* ≥50 mined contracts on `net/netfilter/`; CVE-2024-1086 sites rank in top-N
    outliers; deterministic.
  - **5.3 Sound verification (forward + backward; the soundness gate).** Forward: prove the mined
    contract holds on its support set via Stage B (Frama-C/EVA + CBMC under the Phase 1.4 proof
    cache). Backward: for each outlier, dispatch through `agent.router.route()` with the property
    "the mined contract is violated and a sanitizer/assertion fires." Tier 2 for feasibility,
    Tier 3 for definitive judgment. Mirrors the Phase 1.5 / 2.5 soundness gates structurally — an
    outlier is reported as *confirmed* only when the sound checker returns SAT/unsafe with a
    witness. *Done when:* all confirmed outliers carry sound-checker witnesses;
    `false_confirmations = 0` on the corpus from 5.6.
  - **5.4 Vuln-class taxonomy + per-class report formatter (no LLM).** Classify mined contracts by
    the *shape* of the missing guard: locking, auth/capability, bounds/length, null/init,
    refcount, state-machine, taint-sanitization, resource-cleanup. Per-class formatter so a
    confirmed outlier reads as e.g. "missing `capable(CAP_NET_ADMIN)` before `nf_tables_newrule`",
    not a generic "spec violation". *Done when:* outliers from 5.2 populate ≥4 classes on the
    netfilter target; report-formatter emits one lead per outlier.
  - **5.5 LLM-assisted contract refinement (Phase 3.1 pattern).** When backward verification
    returns `inconclusive` (engine timeout or contract needs widening), invoke the Phase 3.1
    synthesizer with `{mined contract, outlier callsite, engine trace}` to propose a refined
    contract; the sound checker re-verifies. Rule-based fallback covers gateway-down operation.
    *Done when:* ≥1 mined contract refined and re-verified end-to-end via the live gateway;
    fallback path exercised with `GATEWAY_PORT=9`.
  - **5.6 Closed-loop + headline eval.** Plug outliers as a new candidate source into
    `agent.loop` (`Candidate(class="spec-mine-outlier", ...)`). Run on: (a) Phase 0.4 historical
    target as positive control (must re-discover CVE-2024-1086 from outliers + confirm via
    Tier-2/3), (b) live LTS `net/<subsystem>/`, (c) SQLite live (Phase 4.3 target), (d) CyberGym
    subset as an additional ablation signal. Metrics adapter
    `eval/harness/adapters/specmine.py`: outlier count, confirmed-outlier count, per-class
    breakdown, false-positive rate, wall-time, soundness-gate status. *Done when:* ≥1 outlier
    across ≥2 vuln classes (including ≥1 non-memory-safety class) confirmed by the existing
    oracle on a field target; soundness gate intact; CVE-2024-1086 re-discovered on the historical
    target.

  *Phase 5 done when:* mining produces measurable mined-contract density on a real target,
  soundness gates hold (`false_confirmations = 0`, no Phase-1 regression on Juliet), and the
  headline lead-confirmation in 5.6 lands across ≥2 vuln classes including ≥1 non-memory-safety
  class.

- **Phase 6 — Precision + Reach (advanced program-analysis upgrades).** Address the precision
  ceilings and reachability walls the Phase 1–5 MVP hit, grounded in 2024–2026 research. The
  through-line: the regex/ctags substrate that got Components (1)/(3) working is the bottleneck for
  *indirect calls* (the keep-set over-approximates by pulling all address-taken functions; spec
  mining can't see indirectly-invoked callees), and the kernel runtime loop is unclosed (kernel
  outliers stall at `infrastructure_pending`). Each sub-step swaps in a stronger analysis while
  preserving the §8 guardrail (sound checker decides; new analyses only *propose / scope*).

  - **6.1 LLM triage / false-positive reducer (LLift / BugLens pattern).** Today the LLM only
    *proposes* (contracts, harnesses, refinements). Add a `triage` role (small router model through
    the Phase-0.2 gateway) that scores each Phase-5 outlier / Stage-A hint for plausibility and
    *reorders or defers* expensive sound verification — it NEVER refutes (the sound checker keeps
    final-verdict authority). Rule-based fallback for gateway-down. *Done when:* verification budget
    on the multi_class + netfilter outlier corpora drops measurably with **zero confirmed-bug loss**
    (soundness gate intact).
  - **6.2 MLTA-style indirect-call resolution (TypeDive / DeepType, source-level).** Replace
    Stage-A's "any reachable function with indirect-call syntax pulls *all* address-taken functions"
    over-approximation with multi-layer type analysis: parse struct function-pointer field *types* +
    `.field = func` initializers, resolve `obj->field(...)` to the function set assigned to that
    field across compatible struct types (and the reverse: an indirectly-registered function's
    callers). Feed the resolved edges into the Phase-1.2 keep-set and the Phase-5.2 one-hop
    establishment check. Source-level approximation of MLTA (full LLVM-bitcode TypeDive is a 6.2.x
    hook). *Done when:* netfilter keep-set pruning rises above the Phase-1.2 baseline (22.05%) with
    **zero true-bug pruned** (Juliet gate), and a previously-`infrastructure_pending` indirect-call
    outlier (e.g. `nfnl_ct_hook.attach_expect` → `ctnetlink_glue_attach_expect`) becomes resolvable.
  - **6.3 Kernel runtime loop: syzlang synthesis + directed fuzzing (KernelGPT + BEACON).** Wire the
    long-deferred syzkaller fuzzer. LLM synthesizes syzlang for an outlier's syscall surface
    (KernelGPT pattern; we already hand-wrote one for CVE-2024-1086 in
    `oracle/tier1_fuzz/syzlang/`), and a reachability/distance scorer (BEACON/SelectFuzz pattern)
    aims execution at the outlier callsite under KASAN. Honest `infrastructure_pending` when the
    syzkaller image / QEMU instance isn't built. *Done when:* a kernel outlier flips from
    `infrastructure_pending` toward a KASAN-confirmed runtime PoV on the historical target
    (CVE-2024-1086 positive control), or the directed scorer + syzlang synthesis run end-to-end with
    the runtime step cleanly deferred.
  - **6.4 SVF value-flow Stage A + SymCC concolic Tier-2.** Swap the regex call graph for SVF
    interprocedural value-flow taint (LLVM bitcode; image escape hatch) and activate the stubbed
    SymCC compilation-based concolic Tier-2 driver (faster than KLEE; Docker image-missing hatch).
    Both sit behind the existing Stage-A / Tier-2 verdict schemas. *Done when:* the drivers run
    behind their schemas and return clean `image-missing`/`infrastructure_pending` until the images
    are built, with at least the SymCC userspace path validated on one smoke if the image builds.
  - **6.5 APP-Miner graph mining + variant analysis (Big Sleep).** Upgrade Component (3) from
    regex-guard clustering to frequent-pattern mining over a code-property-graph-lite built from the
    Phase-5.1 callsite ledgers, with variable-role normalization (the deferred 5.x.2 hook). Add a
    Big-Sleep-style **variant-analysis** mode: given a known patched bug's pattern, mine structural
    siblings across the tree. *Done when:* mining surfaces a multi-statement pattern the regex miner
    can't, and variant mode finds ≥1 sibling of a seed pattern.

  *Phase 6 done when:* indirect-call resolution measurably improves Stage-A pruning with the Juliet
  soundness gate intact; the triage layer cuts verification budget with zero confirmed-bug loss; the
  kernel runtime loop is wired end-to-end (runtime step may be infra-deferred); and Components (1)
  and (3) run on the stronger analysis substrate without any Phase-1–5 soundness regression.

- **Phase 7 — New bug-class mining modes (lock-order; started).** Phase 5/6 mining finds *missing
  pre-call guards*; it cannot express lock-*ordering* bugs (circular lock dependencies — the class
  kernelctf-latest Candidate A landed in). Phase 7 adds mining modes for bug classes that need a
  different structural shape than "guard before callee."

  - **7.1 Lock-order mining (static lockdep). [done]** `surface/specmine/lock_order.py` extracts the
    per-function lock-acquire order via a held-stack (acquiring L while H is held emits the ordered
    pair `H → L`), aggregates into a weighted lock-order graph (node = lock class, edge = "acquired
    before", weight = #sites), detects cycles (2-cycles + Tarjan SCCs), and flags the minority-weight
    edge of each cycle as the inversion lead. `--min-dominant-weight` suppresses low-confidence
    1-vs-1 artifacts. Soundness: proposer-only — **lockdep at runtime is the verdict authority** for
    this class (CBMC can't prove a deadlock from source), so a lead is confirmed by a lockdep splat
    under directed (6.3) fuzzing. Validated on a synthetic inversion fixture (detects the
    minority-weight `b→a` inversion against a 5-site `a→b` convention) and on 6.12.91 `kernel/events/`
    (recovers the *documented* perf `mmap_mutex → aux_mutex` hierarchy; 1-vs-1 artifact correctly
    suppressed). *Done when:* the miner detects a planted inversion against an established order on a
    fixture and extracts real lock-order conventions on a kernel subsystem, with the runtime
    confirmation deferred to lockdep under directed fuzzing.
  - **7.x (queued):** whole-kernel-scope run to surface Candidate A's cross-subsystem cycle;
    type-aware lock-class identity (via 6.2 MLTA `(type,field)`) to cut the class-merge false-cycle
    rate; refcount-pairing and RCU-grace-period mining as further bug-class modes.

---

## 7. Budget & Funnel Economics (hard constraint)

LLM cost is the practical limiter (AIxCC-scale runs can cost ~$1k/hr without controls). Enforce a
**funnel**: the overwhelming majority of hypotheses must die in Tier 1 (cheap fuzz/sanitizer);
expensive symbolic execution, BMC, and LLM contract-synthesis run only on the survivors.
- `budget.yaml` caps tokens per phase and assigns a cost weight per tier; the router must prefer the
  cheapest tier that can decide a hypothesis.
- Bulk/offline LLM passes (whole-slice contract pre-generation) run when GPUs would otherwise idle —
  this is how GPU utilization stays high without inflating per-hypothesis cost.

---

## 8. Guardrails (do not violate)

- **Final verdict authority = sound checker, never the LLM.** If the LLM "shortcuts" a check, a real
  bug leaks past pruning (false negative) — fatal for an offensive search. The LLM proposes; the
  tool decides.
- **Scope ethically/legally:** only run against authorized targets (own infra, OSS-Fuzz projects,
  CTF/benchmark corpora, kernels you control). Confirmed PoVs stay in the sandbox.
- **Reproducibility:** every confirmed PoV must come with a deterministic reproduction artifact and
  the sanitizer/symbolic trace that backs it.
- **Document soundness assumptions** (indirect calls, inline asm, macros, loop bounds) so the
  "provably safe" claim is auditable.

---

## 9. Open-Source Tool Summary

| Purpose | Tools (priority order) |
|---|---|
| Orchestration / build / budget | OSS-CRS (base), ATLANTIS / RoboDuck (reference), OSS-Fuzz harnesses |
| Stage A reachability/taint | Smatch, Coccinelle, Sparse, SVF, CodeQL |
| Stage B sound proof | Frama-C/EVA (primary), CBMC, ESBMC |
| Spec mining (Component 3) | libclang / tree-sitter (AST), Z3 (guard equivalence), reuses Stage B + Tier 2/3 engines for verification |
| Indirect-call resolution (Phase 6) | MLTA / TypeDive (umnsec/mlta), DeepType (SMLTA), type+data-flow co-analysis — source-level MLTA approximation in-tree |
| LLM-assisted static analysis (Phase 6) | LLift (OOPSLA'24), BugLens (ASE'25) FP-reduction / triage pattern; Big Sleep / Naptime (variant analysis) |
| Kernel runtime reach (Phase 6) | KernelGPT (syzlang synthesis), BEACON / SelectFuzz (directed greybox fuzzing) |
| Advanced spec mining (Phase 6) | APP-Miner (frequent API-path-pattern mining), SVF / Phasar (value-flow), SymCC / SymQEMU / SymSan (concolic) |
| Oracle Tier 1 (fast) | syzkaller + KASAN/KMSAN/KCSAN/UBSAN/KCOV (kernel); AFL++/libFuzzer + ASan/MSan/UBSan (userspace) |
| Oracle Tier 2 (symbolic) | S2E (kernel); KLEE, SymCC/SymQEMU (userspace); angr (binary) |
| Oracle Tier 3 (BMC) | CBMC, ESBMC |
| LLM serving | vLLM / SGLang; Qwen3.6-32B/35B-A3B or DeepSeek-V4-Flash (synthesizer), small model (router) |
| Eval benchmarks | CyberGym (primary, sunblaze-ucb/cybergym), SV-COMP, Magma, Juliet |
| Field targets | Google kernelCTF (google/security-research), live SQLite/OpenSSL/libxml2 via OSS-Fuzz |
