# Soundness Assumptions

> **The rule.** Every "provably safe" verdict this system emits depends on a chain
> of assumptions made by the underlying tool. If any of those assumptions is wrong,
> a real bug can be pruned — a false negative, the worst failure mode for an
> offensive search. Every such assumption MUST be recorded here so the claim is
> auditable.

## How to read this file

Each bullet pins one assumption to the code that enforces it:

> **`tool` — property.** What the tool assumes, why the assumption holds, and what
> breaks if it doesn't.

If you add a new tool, append its assumptions here before relying on its verdict.

## Where each section sits in the pipeline

```
   Stage A             Stage B               Router            Oracle Tiers
   ───────             ───────               ──────            ────────────
   reachability   ──▶  refine_unit    ──▶   dispatches   ──▶   T1  fast crash
   taint                                    in cost              (sanitizer/fuzz)
   over-approx         sound proof          order           T2  symbolic
   (entrypoints,       (Frama-C/EVA,        cheapest-           (KLEE / angr)
    callgraph)          CBMC)               decisive        T3  BMC
                                            wins                (CBMC / ESBMC)
                                                                       │
                                                                       ▼
                                                            uniform verdict vocabulary
                                                            (proved_safe / refuted /
                                                             candidate / confirmed /
                                                             bmc_unsafe / inconclusive)
```

## Contents

- Stage A — reachability / taint (sound over-approximation)
- Labeled-corpus soundness gate (Juliet, Phase 1.5)
- Stage B — sound proof
- Oracle Tier 1 — fast crash
- Oracle Tier 2 — symbolic
- Oracle Tier 3 — BMC
- Router (Phase 2.4)
- Precision corpus (Phase 2.5)
- LLM-synthesized contracts (Phase 3.1)
- LLM-synthesized harnesses/drivers per tier (Phase 3.2)
- LLM router (Phase 3.3)
- kernelCTF live LTS instance (Phase 4.2)
- Live-library hunt (Phase 4.3)
- Build environment

---

## Stage A — reachability / taint (sound over-approximation)

> The whole stage is conservative on purpose: anything dropped here must be
> provably unreachable. The bullets below are the knobs that decide whether a
> real path gets silently dropped.

- **`entrypoints` — dispatcher-type coverage.** `surface/entrypoints.py` recognises a *fixed* allowlist of kernel dispatcher struct types (nfnl_callback, nft_expr_ops, nft_set_ops, xt_match, xt_target, nf_hook_ops, file_operations, proto_ops, …). Surfaces routed through types not in the list are silently missed — adding a new dispatcher type to `DISPATCHER_TYPES` is the soundness lever. A missed dispatcher class shrinks the entry set and can leak a real bug — a false negative.

- **`entrypoints` — regex anchoring.** The detector matches `static [const] struct TYPE NAME …= {…}` at the line start. Initializers may not match if they span macros, are declared via `DEFINE_*` helpers, or sit inside `#ifdef` blocks we did not preprocess away. Document any new helper macro by adding a regex alternative.

- **`reachability` — indirect-call resolution.** `surface/reachability.py` over-approximates: when any reachable function contains indirect-call syntax (`obj->cb()`, `(*fp)()`, …), every function whose address appears as an initializer value is folded into the keep_set. Coarser than SVF/CodeQL's type-aware resolution but the same soundness guarantee (always conservative). Refining this is a Phase-3 SVF integration task; until then the keep ratio is intentionally high.

- **`reachability` — callee-graph scope.** Only `.c` files under `--scope` are walked; functions defined in headers or other subsystems are *not* in the call graph. A kept function may have an out-of-scope callee that itself reaches a bug — we cannot prune that callee, so the over-approximation stays sound, but the reduction % is bounded by scope choice.

- **`reachability` — callee resolver.** Regex callee extraction matches `\bIDENT\s*\(` and drops a curated blacklist of macros / control keywords (`CALL_BLACKLIST`). Unknown macros that wrap a real call (e.g. `WRITE_ONCE(p, fn(x))` patterns where the inner call would otherwise be invisible) are still captured because the regex walks the whole body. Macros that *expand to* a call without writing it textually (rare) would be missed; record these in `CALL_BLACKLIST`'s sibling list when found.

- **`SVF` — indirect-call resolution.** Function-pointer targets are over-approximated by SVF's Andersen-style pointer analysis; precision drops on type-cast / `void*` arithmetic patterns. The over-approximation stays sound (more callees ⇒ more reachable code ⇒ never prunes a real path). *Not yet wired*; SVF is the Phase-3 replacement for the address-taken heuristic above.

- **`Smatch / Sparse` — macro expansion.** Heavily macro'd kernel code may parse differently across versions; we re-run analysis per kernel `CONFIG_*` matrix.

- **`Coccinelle` — semantic patches.** SmPL patterns assume the structural shape of the AST; new dialects can silently miss patterns. Track which SmPL rules ran in `surface/tasks/*.json`.

- **`static-hints` — non-soundness role.** Smatch / Coccinelle / Sparse / CodeQL findings ingested via `surface/static_hints.py` are **priority signals only**, never pruning evidence. A missing hint never causes a function to be pruned; an extra hint never declares a function exploitable.

- **`all` — inline asm.** Inline assembly is opaque to all C front-ends; bodies containing `__asm__` are treated as worst-case (read/write any memory). Always reachable, never pruned.

## Labeled-corpus soundness gate (Juliet, Phase 1.5)

> The falsifiable gate. A labeled `_bad` case reaching `safe` is a soundness
> failure — no headline metric outranks this.

- **`juliet/stageA` — entry-point heuristic.** `eval/juliet/run_stage_a.py` treats every non-`static` function whose name matches `CWE\d+_..._(bad|good*|bad_sink|good*_sink|bad_source|good*_source)` as an entry. Juliet builds a single binary where `main_linux.cpp` dispatches by string lookup into the testcase API, so every such extern function is genuinely externally invokable. A missed naming pattern shrinks the entry set → labeled `_bad` could be pruned → soundness-gate failure surfaces in `missed_bug_count`. Re-running `run_stage_a.py` after adding a CWE keeps the gate honest.

- **`juliet/stageB` — helper stubs.** `eval/juliet/stubs.c` provides no-op definitions of testcasesupport helpers (printLine, printIntLine, …). `printLine`/`printWLine` deliberately dereference their argument (`volatile char c = line[0]`) because Juliet's UAF testcases pass the freed pointer to `printLine` as the sink — a true no-op would mask the deref and CBMC would falsely report `safe`. Any new sink-helper added to the stub must either deref its argument the same way or be replaced by a real Juliet helper if it is the bug-witnessing call. Confirmed by Phase 1.5 run-log: with deref'ing stubs, 12/12 labeled `_bad` reach `unsafe`; without, 1 falsely reached `safe`.

- **`juliet/stageB` — unwind bound choice.** Phase 1.5 runs CBMC at `--unwind=128`. Two CWE416 testcases contain `for(i=0;i<100;i++)` — `--unwind=32` left them `inconclusive` (not unsafe per the gate's strict reading, but defeats the verification claim). The unwind bound is a *quality* lever, not a soundness one: `inconclusive` is never recorded as a soundness failure, only `safe` on a `_bad` is.

## Stage B — sound proof

> Verdicts from this stage claim safety. They are only as sound as the engine's
> domain plus the contracts they assume.

- **`Frama-C / EVA` — abstract domain.** EVA is sound under its chosen domain (interval, congruence, gauges). Pre-/post-conditions assumed at function boundaries MUST themselves be verified or come from the proof cache with matching keys.

- **`CBMC / ESBMC` — bounded loops.** A verdict is sound only up to the configured `--unwind` bound. To extend to unbounded soundness we attach an LLM-synthesized loop invariant and have CBMC discharge it; without a verified invariant, the verdict is "safe under bound N", not "safe".

- **`proof-cache` — callee-contract identity.** A cache hit is valid only when the *current* callee contracts equal the assumed ones from cache time. Verified at hit; never trust the body hash alone.

## Oracle Tier 1 — fast crash

> "No crash" is never "safe". Always escalate inconclusive Tier-1 to Tier 2/3
> before pruning.

- **`sanitizers` — coverage of properties.** ASan covers heap/stack/global OOB and UAF; MSan covers uninit reads; UBSan covers UB classes. A "no crash" verdict from Tier 1 is NOT a safety claim — it only means the fuzzer didn't reach the bug within the budget. Always escalate inconclusive Tier-1 to Tier 2/3 before pruning.

- **`syzkaller` — syscall surface.** syzlang descriptions enumerate the surface explicitly; bugs reachable only via unmodeled syscalls / ioctls are unreachable to syzkaller. Track unmodeled surface in `surface/tasks/*.json`.

- **`KASAN` — instrumentation gaps.** KASAN reports use-after-free / OOB on slab + buddy allocations covered by the shadow map; non-shadowed memory (early-boot, percpu, vmemmap before init, EFI) is invisible. For the kernelCTF sanity boot, KASAN_INLINE + SLUB_DEBUG_ON are enabled (see `eval/kernelctf/configs/config-6.1.72-kasan.txt`).

## Oracle Tier 2 — symbolic

> A symbolic `unsat` only prunes when the environment is fully modeled. The
> drivers downgrade to `inconclusive` whenever they detect an unmodeled call or
> a partial path, so a model gap cannot drive an unsound prune.

- **`KLEE` — environment modeling.** KLEE relies on `klee-uclibc` and POSIX models; calls outside the model become `__klee_warning` and are unmodeled — they must be treated as "could do anything". `oracle/tier2_symbolic/klee_driver.py` detects "calling external" warnings and downgrades any otherwise-`unsat` verdict to `inconclusive`, so a model gap cannot cause an unsound prune.

- **`KLEE` — partial-completed paths.** The driver only emits `unsat` when `completed paths > 0 AND partially completed paths == 0`. A partial path = a fork that hit the wall/memory/fork budget mid-exploration, so its property obligation is unresolved. Treating partials as decided is the soundness lever for KLEE pruning.

- **`KLEE` — SAT verdict scope.** A `.ktest` produced for a `*.err` site is reported as `sat` but is *only* a candidate PoV — it must be re-confirmed by the Tier-1 oracle (`replay`/`replay-docker`) before it counts as an exploit. Symbolic SAT under an under-approximated environment is not a final verdict.

- **`S2E` — selective concretization.** Concretized arguments mask paths gated on those args; record which arguments stayed symbolic in each S2E task. The Phase-2.2 driver is the image-missing stub; the soundness obligation lands when the engine is actually run (Phase 4.2).

- **`angr` — SimProcedure coverage.** `angr.Project(..., auto_load_libs=False)` runs with the default SimProcedure set; library calls that fall outside that set use stub jumpkinds. `oracle/tier2_symbolic/angr_driver.py` counts states whose history reaches a "stub" jumpkind and downgrades the verdict to `inconclusive` if any are present, so an `unsat` is only emitted under a fully-modeled exploration. The set of activated SimProcedures is part of the (future) cache key.

- **`angr` — SAT verdict scope.** As with KLEE, an angr "found state" produces a concrete reproducing input but is a candidate, not a confirmed exploit; re-run it through the actual binary (Tier-1 replay) for confirmation. The Phase-2.2 smoke confirms `/tmp/angr-pov-…` round-trips through the real binary to `_exit(0)`.

## Oracle Tier 3 — BMC

> See also the Stage B / CBMC entries above; the engine is shared. The rules
> here govern how `oracle/tier3_bmc/cbmc_driver.py` maps CBMC output to verdicts.

- **`Tier-3 CBMC` — verdict semantics.** CBMC's `VERIFICATION SUCCESSFUL` is `safe` ONLY because `--unwinding-assertions` is forced ON by `oracle/tier3_bmc/cbmc_driver.py`; without it, a loop exceeding the bound would be silently labeled SUCCESSFUL (an unsoundness leak). `unwinding assertion : FAILURE` is mapped to `inconclusive`, never `safe` — recorded structurally in the driver's verdict-construction logic.

- **`Tier-3 CBMC` — cex → PoV scope.** The CBMC counterexample assignment that the driver extracts is a sound witness *for the harness as specified* (the inputs, the precondition `__CPROVER_assume`s, and the property `__CPROVER_assert`). It is NOT a runtime exploit on its own — to obtain a runtime PoV, wrap the assignment through the Tier-1 harness/replay path. The router treats Tier-3 `unsafe` as a definitive BMC bug-finding *for the harness*; promotion to a runtime exploit requires Tier-1 re-confirmation.

- **`Tier-3 ESBMC` — image-missing dispatch.** Until `veri-agent/esbmc:<ver>` is built, `oracle/tier3_bmc/esbmc_driver.py` returns `inconclusive` with `image-missing:<tag>` evidence. CBMC covers all Phase 2.3 obligations; ESBMC is held until Phase 2.5 demands the alternate engine for a CBMC-slow case. The future ESBMC verdict MUST also use `--unwinding-assertions` to keep the soundness rule above.

- **`Tier-3 harness` — nondet idiom.** `oracle/tier3_bmc/assertions.synthesize()` emits uninitialized locals (which CBMC treats as nondet) rather than `__CPROVER_nondet_*()`. Reason: CBMC requires extern declarations for the nondet builtins and the supported suffix set is not stable across versions; the uninitialized-locals idiom is equivalent and version-stable.

## Router (Phase 2.4 heuristic dispatcher)

> One uniform vocabulary maps every tier's output. The router never decides
> safety on its own; it only escalates.

- **`router` — cheapest-decisive tier.** `agent/router.py` dispatches in cost order from `config/budget.yaml` (tier1=1, tier2=25, tier3=50) and stops as soon as a tier returns a *decisive* verdict (Tier-1 crash, Tier-2 sat/unsat, Tier-3 safe/unsafe). Inconclusive verdicts ALWAYS escalate to the next tier — they are never treated as `safe`. This rule is the funnel economics of PLAN §7 and the never-prune-on-inconclusive rule of PLAN §3.

- **`router` — Tier-2 SAT promotion.** A Tier-2 `sat` produces only `candidate`. It becomes `confirmed` ONLY when the router's Tier-1 reconfirmation (the hypothesis's `tier1_replay` spec wrapping the symbolic PoV bytes) returns `crash`. Symbolic SAT alone, under KLEE/angr's environment models, can be spurious — PLAN §8 says the LLM/symbolic engine never replaces the sound runtime checker.

- **`router` — Tier-2 UNSAT → refuted.** `unsat` from Tier-2 is reported as `refuted` and is the router's "prune" verdict. It inherits the engine's own soundness caveats: KLEE only emits `unsat` when `completed > 0 ∧ partial == 0 ∧ no klee_warning external`, and angr only when no `stub` jumpkind states remain. The router does NOT relax either — `refuted` is exactly as sound as the underlying engine's `unsat`.

- **`router` — Tier-3 unsafe scope.** `bmc_unsafe` is the router's terminal verdict for a Tier-3 cex when no Tier-1 runtime harness is supplied. The cex is a sound BMC witness *for the harness as specified*; promotion to `confirmed` requires Tier-1 replay (same rule as the Tier-3 driver's own soundness note). The router never promotes a Tier-3 cex to a runtime PoV without that wrap.

- **`router` — no-dispatch ≠ safe.** A hypothesis with no executable specs returns `no_dispatch`. The harness treats this as `not_setup`, NEVER as `proved_safe` — absence of an analysis path is not evidence of safety.

## Precision corpus (Phase 2.5)

- **`precision` — confirmation set scope.** `eval/precision/run.py` computes "precision of confirmation" over verdicts ∈ `{confirmed, bmc_unsafe}` ONLY. `candidate` (Tier-2 SAT pending Tier-1 reconfirm) is intentionally excluded — it is the explicit "needs runtime reconfirm" verdict and counting it as a confirmation would inflate apparent precision and recall. A false confirmation = a `clean`-labeled hypothesis whose router verdict is in this set; the Phase 2 Done-when number is `false_confirmations == 0`.

- **`precision` — soundness violation.** Defined as a `buggy`-labeled hypothesis where the router emitted `proved_safe`. This is the offensive-search false-negative we cannot tolerate; the gate fails on any non-empty list, regardless of `precision`/`recall` headline numbers.

## LLM-synthesized contracts (Phase 3.1)

> The LLM proposes; the engine decides. Every safeguard here is structural so
> a model jailbreak cannot smuggle in an unsoundness.

- **`contract-synth` — verdict authority.** The LLM is the *proposer*; the sound verdict still comes from CBMC (or Frama-C/EVA). `surface/stage_b.refine_unit` always returns the engine's verdict — even when the LLM "claims" the contract proves safety, the loop re-runs CBMC under that contract and only the engine's `safe`/`unsafe`/`inconclusive` is recorded. PLAN §8.

- **`contract-synth` — accumulated_contracts.** Every synthesized contract is appended to `Verdict.assumed_contracts` and recorded under `RefinedVerdict.accumulated_contracts`. These feed the Phase 1.4 proof-cache key — a cache hit on an LLM-proven `safe` is invalid unless the same contracts are still claimed. A caller that drops a contract busts the cache.

- **`contract-synth` — no degenerate contracts.** `contract_synth._extract_contract_lines` rejects contracts whose body is `""`, `0`, `1 == 0`, or `false` — those would "prove" anything by assuming `false`. The LLM is also instructed not to propose "1 == 0" or "i != crash_index" style assume-the-bug-away preconditions; degenerate proposals are filtered structurally on top of the prompt.

- **`contract-synth` — rule fallback scope.** The deterministic `rule_based_synth` proposes only `__CPROVER_assume(<var> < <CAP>)` where `<CAP>` is a `#define`d buffer size and `<var>` is an unsigned input whose CBMC-trace value exceeds it. It cannot infer relational invariants, loop invariants, or function-boundary contracts — those require the LLM (or hand-written contracts). The rule path exists so the refinement loop is testable when the gateway is down; it is intentionally narrow.

- **`contract-synth` — injection anchor.** Contracts are inserted at the `/* @CONTRACTS */` marker in the harness `main()` (post-declaration scope). If no marker is present, the loop falls back to injecting before `return 0;` — but that only works when the buggy call has already constrained the symbolic values CBMC carries. Harness authors should use the marker explicitly to guarantee the contract lands before the call site.

## LLM-synthesized harnesses/drivers per tier (Phase 3.2)

- **`tier1-harness-synth` — verdict authority.** The LLM is the *proposer* of a libFuzzer harness; the runtime sanitizer (`oracle/tier1_fuzz/userspace.fuzz`) is the oracle. A "no crash" verdict on an LLM-generated harness is still inconclusive, not safe — same Tier-1 rule as a hand-written harness. PLAN §8.

- **`tier1-harness-synth` — banned host-effect calls.** `oracle/tier1_fuzz/harness_synth._filter_harness` rejects model output that contains `system/execve/execvp/execl/execlp/execv/exect/fork/popen/socket/connect/fopen`. The LLM is told in the system prompt; the filter is the structural backstop. A model jailbreak that smuggles a host-effect call into a harness we then `clang -o ... && ./harness` would be a sandbox break — the filter is the soundness lever, not the prompt.

- **`tier1-harness-synth` — required entrypoint.** The filter also requires `#include` and the literal `LLVMFuzzerTestOneInput` symbol in the proposal, with at least one `{` and `;`. Without these the proposal is not a libFuzzer harness and falls back to `rule_based_harness` (which only handles the canonical `f(const uint8_t *buf, size_t n)` signature shape and otherwise returns `rule_unsupported_signature`).

- **`tier2-driver-synth` — must-not-assume symbols.** `oracle/tier2_symbolic/driver_synth._filter_driver` rejects any `klee_assume` whose body mentions a symbol the caller listed in `SymbolicTarget.must_not_assume`. This makes "do not assume the bug away" *structural* rather than prompt-only — the live Qwen-3B model emitted `klee_assume(d != 0)` on the divide-by-zero smoke (which would prune the bug out of existence) and the filter caught it, falling back to the rule path. PLAN §8: the LLM proposes, the sound engine (KLEE) decides. A driver that assumes the bug away is not "sound", it's just "doesn't observe the bug" — same false-negative class the proof-cache soundness rules guard against.

- **`tier2-driver-synth` — no klee_assert injection.** The system prompt instructs the model not to add `klee_assert` unless the caller asked, because KLEE's `--exit-on-error-type` machinery already catches the canonical bug classes (div-by-zero, ptr, free, overflow, assert). An LLM-added assertion would change which paths KLEE prunes early, which can mask real bugs (early exit before a wider-scope failure).

- **`tier2-driver-synth` — banned host-effect calls.** Same allowlist as Tier-1. A KLEE driver that calls `system()` would execute it during concrete replay paths; the filter rejects it.

- **`tier3-harness-synth` — JSON proposal surface.** The LLM emits a single JSON object `{preconditions: [...], assertion: "..."}` rather than free-form C. The harness rendering uses the existing `assertions.synthesize` (no new C-injection path), so the LLM's surface is narrowed to two well-typed fields that `oracle/tier3_bmc/harness_synth._filter_proposal` can mechanically screen.

- **`tier3-harness-synth` — no tautological assertion.** `_filter_proposal` rejects assertions whose body is `1` / `true` / `0 == 0`, and preconditions whose body is `""` / `0` / `false` / `1 == 0` / `1==0`. A tautological assertion always succeeds, "proving" safety; a degenerate precondition (assume false) trivially establishes any property. Either path would let the LLM smuggle an unsoundness past CBMC. The filter is the same idea as `surface/contract_synth._extract_contract_lines`'s degeneracy rejection, applied at the property layer.

- **`tier3-harness-synth` — verdict authority.** The CBMC verdict (`oracle/tier3_bmc/cbmc_driver.run_cbmc_oracle`) is the sound output. The LLM only proposes which property to check and under what preconditions; CBMC independently emits `safe`/`unsafe`/`inconclusive` against that property. An LLM-proposed `assertion` that doesn't reflect the real bug class merely makes CBMC check a different property — never causes a false `safe`.

## LLM router (Phase 3.3)

- **`llm-router` — ordering-only authority.** `agent/router_llm.LLMDispatcher` only picks the *order* of populated tiers; it never returns a verdict. The engines (Tier-1 fuzz, Tier-2 KLEE/angr, Tier-3 CBMC) still produce the verdict, and `agent/router.route()` still maps that verdict onto the uniform vocabulary using the same rules as Phase 2.4. A buggy/poisoned LLM proposal can degrade the funnel's *cost* but cannot weaken precision or soundness — there is no router decision that translates into a verdict claim.

- **`llm-router` — sanitize on the way in.** `agent.router._sanitize_order` filters every dispatcher proposal against the populated-tier set: foreign tiers (names not in `available`) are dropped; duplicates collapse to first occurrence; any populated tier the proposer omitted is *appended* (not dropped). The append rule is structural: the LLM cannot accidentally *exclude* a populated tier, because excluding a Tier-3 spec on a small-bounded property would silently lose a `proved_safe` or `bmc_unsafe` verdict and the funnel would degrade to `inconclusive` on a case the engine could have decided.

- **`llm-router` — fallback on any failure.** On gateway error, malformed JSON, or an all-foreign / empty proposal, `route()` falls back to the deterministic heuristic order (`_dispatch_order`). The router is therefore never blocked on the LLM; the LLM is an opt-in speed lever, not a dependency. Verified with `GATEWAY_PORT=9` smoke (`run-logs/phase3.3-llm-dispatch-fallback.jsonl`): all three multi-tier hypotheses fell back cleanly and the heuristic produced the expected verdicts.

- **`llm-router` — single-tier short-circuit.** If only one tier is populated, the dispatcher returns it without calling the LLM (`len(available) <= 1` branch). This is both an optimization and a soundness simplification: there is no ordering decision to be made, so there is no surface for an LLM mistake.

## kernelCTF live LTS instance (Phase 4.2)

- **`kernelctf-live` — target-config soundness lever.** `eval/kernelctf/configs/config-6.1.72-live-lts-cos.txt` is the live-hunt surface. Adding a `CONFIG_*` *narrows* the surface (removes one syscall class from the hunt); removing one *widens* it (re-introduces surface the historical exploit's ruleset already covers). Either side moves the target — every commit that touches `make_config_live.sh` MUST justify the move and re-run `run_qemu_live.sh` to confirm the historical exploit still doesn't fire (or, if it now does, that's a re-introduced surface, not a soundness leak). The frozen config is the audit record.

- **`kernelctf-live` — absence-of-KASAN ≠ safety.** The live-LTS QEMU smoke reports PASS when the historical CVE-2024-1086 trigger does NOT fire KASAN. This is a *negative control* of the surface restrictions, not a safety proof of the live kernel. The agent loop wiring (`agent/smoke/candidates_kernelctf_live.json`) maps the same evidence through `tier1_kasan` and ends at `inconclusive` (no_crash ⇒ inconclusive, per Tier-1 rule), never `pruned`/`proved_safe` — only Stage B / Tier-3 may emit safe. Promoting "no KASAN on this trigger" to "this kernel has no nf_tables-class bugs" would be PLAN §8 violation territory.

- **`kernelctf-live` — paired positive control.** The live (k1) and historical (k2) candidates run through the same loop on the same dmesg-replay path; if either invariant breaks (k1 not `inconclusive` ⇒ restrictions failed; k2 not `confirmed` ⇒ the loop itself is degraded), the rollup row flips to fail. The pair check is what makes "the live kernel is hardened" auditable rather than asserted.

## Live-library hunt (Phase 4.3)

- **`live-lib` — no_crash ≠ safety.** The Phase-4.3 driver runs libFuzzer+ASan against host libsqlite3 3.37.2 (`eval/live-lib/run_phase43.py`) and the closed loop wires the same harness through `tier1_fuzz` (`agent/smoke/candidates_live_lib.json`). A `no_crash`/`inconclusive` result on the live target maps to disposition `inconclusive`, NOT `pruned`/`proved_safe` — only Stage B / Tier-3 may emit safe. Promoting "no crash in N seconds" to "this library is safe" would be PLAN §8 violation territory.

- **`live-lib` — paired positive control.** L2 (synthetic stack-OOB linking host libsqlite3) MUST confirm via Tier-1 on every Phase-4.3 run: it is the toolchain witness (clang-14 + ASan + `-lsqlite3` + libFuzzer reaching the harness). If L2 ever flips to `inconclusive`, the live (L1) verdict is no longer trustworthy and the live row in the metrics adapter does NOT count as a green field run. Same audit pattern as `kernelctf-live | paired positive control`.

- **`live-lib` — novel_pov reporting.** A `crash` on the L1 (live) candidate is a candidate **novel finding** and is recorded under `summary.novel_pov=true` plus a PoV artifact path in the JSONL row — but it does NOT auto-flip the gate; an operator audits the artifact and only then files the report. The agent never claims a confirmed vulnerability without a human in the loop on a live target.

## Specification mining (Component 3, Phase 5)

- **`specmine` — mining is a proposer, not a decider.** Phase 5.1 callsite/guard extraction (`surface/specmine/extract_callsites.py`), Phase 5.2 contract mining, and the resulting outliers are *conjectures*. A mined contract is only used to prune after Stage B verifies it forward; an outlier is only reported as a confirmed bug after Tier 2/3 returns SAT/unsafe with a witness. The §8 guardrail (sound checker is final-verdict authority) carries over verbatim — outliers never become confirmations without engine adjudication.

- **`specmine` — over-detection is safer than under-detection.** Phase 5.1's regex-based guard extraction is deliberately loose. Over-detecting a guard inflates support counts for mined contracts (mining sees a *stronger* convention than the codebase actually has), which **lowers** the outlier-suspicion of real outliers and slightly suppresses leads — annoying but not unsound. Under-detecting a guard *inflates* the outlier set with noise, which costs verifier budget but the §3b.3 backward refutation cleans it up. Both failure modes are downstream of the sound gate.

- **`specmine` — known regex limitations (documented, not silently masked).** The 5.1 extractor uses ctags + line-oriented regex (no full AST), so:
  - **Branch-local lock-release over-release.** A lock acquired before an if-block and released *inside* the if-true branch (paired with an early return) is recorded as "released function-wide". The held-set at later callsites is therefore weaker than reality. Mining under-counts the true "lock held before X" support. Mitigated by `lock_assert` detection (lockdep_assert_held / rcu_read_lock_held), which the kernel uses extensively at the sites we most care about.
  - **Macro-heavy guards.** Constructs hidden inside macros (`NF_HOOK(...)`, `rcu_dereference_check(...)`, `RCU_LOCKDEP_WARN(...)`) are not unfolded; their guard semantics are missed unless they textually contain a recognised primitive. Acceptable for an MVP; Phase 5's libclang/tree-sitter upgrade path is queued for a 5.x.2 hook.
  - **Indirect calls (`expr->ops->eval(...)`).** Mining only sees direct callsites — indirect dispatch is invisible. Means: contracts on callbacks invoked exclusively through ops-vtable dispatch (`nft_*_eval`, `nft_set_*_walk`) won't have any mining support yet. Same trade-off Stage A makes; address-taken expansion in 5.x.3 hook.
  Each limitation is **soft**: it bounds *what we can mine*, not whether the mining stays sound. The downstream Stage B forward proof + Tier 2/3 backward refutation in 5.3 is the actual soundness gate.

- **`specmine` — proof-cache compatibility.** When a mined contract is used as an `assumed_contract` during Stage B verification (Phase 1.4 cache key includes the sorted assumed-contracts SHA), the cache key changes the moment the mined contract does — so a cache hit on a proof that depended on a mined contract becomes invalid the moment that contract is revised. Same Phase 1.4 callee-contract identity rule applies; no new lever.

- **`specmine` — Phase 5.3 backward verification gate (`confirmed` requires UNSAFE + witness).** `surface/specmine/verify.py` only emits disposition `confirmed` when CBMC returns `unsafe` AND a `*.cbmc-pov.json` witness file was written — the counter-example assignment is the auditable artifact a human reviewer can replay. An engine UNSAFE without a recorded witness is downgraded to `inconclusive` (the verifier refuses to elevate without an auditable cex). `refuted` requires `verdict == safe` with engine-modeled completeness (no `inconclusive` signal from unwinding-assertion failure). `infrastructure_pending` and `proposer_deprioritized` are explicitly NOT confirmations: the first signals "harness machinery doesn't reach here yet" (kernel sources, non-lock contract classes), the second signals "5.2's one-hop establishment downgraded suspicion below the funnel floor". The `false_confirmations` counter in the verified.json stats is the structural gate — Phase 1.5 / 2.5 already enforce its analog for Stage B / Tier-2-3 oracles.

- **`specmine` — Phase 5.3 lock-state modelling is the harness's only model lever, and it is intentionally over-permissive.** The synthesised harness models each lock-state (rcu / spin / mutex / read / write / rwsem / sem / bh / irq) as a depth counter; `*_lock()` macros increment, `*_unlock()` decrement. This is sound for the *verifier's* purpose (a "missing acquire before the wrapper" path leaves the counter at 0, the assertion fires, CBMC reports unsafe — exactly the bug we want). The over-permissiveness is on the SAFE side: a caller body that takes a lock the kernel would actually consider distinct from another (e.g. acquires `&t->commit_mutex` then asserts on a `lockdep_assert_held(&t->commit_mutex)` mined contract from a DIFFERENT lock variable) will be reported `safe` because both translate to `__specmine_mutex_depth > 0`. The verifier therefore can erroneously REFUTE a real "wrong lock held" bug. This is a documented limitation — refining the model to track per-lock-variable counters is a 5.3.x hook. It does NOT affect the `confirmed` direction (we never falsely *promote* an outlier — only false-`refute`).

- **`specmine` — kernel source → `infrastructure_pending`, never `refuted`.** Phase 5.3's MVP harness synthesiser refuses to compile a CBMC harness for any source path under a recognised kernel subdirectory (`net/`, `fs/`, `drivers/`, `mm/`, `arch/`, `kernel/`, `security/`, `sound/`, `block/`, `ipc/`, `lib/`, `init/`). The reason is structural: CBMC cannot ingest the kernel build without dedicated stubs for `kmalloc`, `printk`, the `__user` annotation, inline asm, `CONFIG_*`-guarded code, and the rest. Until a 5.3.x hook stands up the kernel extraction path (or Phase 5.6's closed loop dispatches kernel outliers through the syzkaller/KASAN tier instead), every kernel outlier lands in `infrastructure_pending` cleanly — never `refuted`, never `confirmed`. This is the same soundness rule Phase 1.5's "missed_bug_count==0 because Stage A/B haven't analysed this region" pattern uses: absence of a verdict is honest; a fake verdict is unsound.

- **`specmine` — `--via-router` path uses `R_BMC_UNSAFE`, not `R_CONFIRMED`.** When the verifier is invoked with `--via-router` (Phase 5.6 will use this so spec-mining hypotheses flow through the same `agent.router.route()` as Phases 2-4 candidates), the router maps CBMC `unsafe` to `R_BMC_UNSAFE` (the "BMC has a witness, but no runtime replay has elevated it to a real PoV yet" verdict). Phase 5.3's disposition mapping treats `R_BMC_UNSAFE + witness_path` as `confirmed` for spec-mining purposes, because for *spec-mining* the BMC witness IS the structural confirmation (the missing-contract assertion fires under a feasible execution). Runtime replay through Tier-1 is the next-step elevation in Phase 5.6 (where applicable — for kernel locking bugs there is no userspace Tier-1 to elevate to; lockdep / KCSAN at runtime is the analog).

## Build environment

- **`kernel CONFIG_*` — cache key embeds every variant.** Every cached proof's key embeds the `CONFIG_*` set, arch, and compiler/sanitizer mode. Any drift = cache miss = re-verify.

---

If you add a new tool, append its assumptions to the relevant section before
relying on its verdict.
