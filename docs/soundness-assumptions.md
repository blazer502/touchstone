# Soundness Assumptions

Every "provably safe" verdict this system emits depends on a chain of assumptions
made by the underlying tool. If any assumption is wrong, a real bug can be pruned
(false negative) — which is the worst failure mode for an offensive search. Every
such assumption MUST be recorded here so the claim is auditable.

Format: one row per assumption.
```
- [TOOL]  [PROPERTY]  short statement of the assumption  (where it's enforced)
```

## Stage A — reachability / taint (sound over-approximation)

- [entrypoints]      dispatcher-type coverage  `surface/entrypoints.py` recognises a *fixed* allowlist of kernel dispatcher struct types (nfnl_callback, nft_expr_ops, nft_set_ops, xt_match, xt_target, nf_hook_ops, file_operations, proto_ops, …). Surfaces routed through types not in the list are silently missed — adding a new dispatcher type to `DISPATCHER_TYPES` is the soundness lever. A missed dispatcher class shrinks the entry set, which can leak a real bug → false-negative.
- [entrypoints]      regex anchoring           The detector matches `static [const] struct TYPE NAME …= {…}` at the line start. Initializers that span macros, are declared via `DEFINE_*` helpers, or sit inside `#ifdef` blocks we did not preprocess away may not match. Document any new helper macro by adding a regex alternative.
- [reachability]     indirect-call resolution  `surface/reachability.py` over-approximates: when any reachable function contains indirect-call syntax (`obj->cb()`, `(*fp)()`, …), every function whose address appears as an initializer value is folded into the keep_set. Coarser than SVF/CodeQL's type-aware resolution but the same soundness guarantee (always conservative). Refining this is a Phase-3 SVF integration task; until then the keep ratio is intentionally high.
- [reachability]     callee-graph scope        Only `.c` files under `--scope` are walked; functions defined in headers or other subsystems are *not* in the call graph. A kept function may have an out-of-scope callee that itself reaches a bug — we cannot prune that callee, so the over-approximation stays sound, but the reduction % is bounded by scope choice.
- [reachability]     callee resolver           Regex callee extraction matches `\bIDENT\s*\(` and drops a curated blacklist of macros / control keywords (`CALL_BLACKLIST`). Unknown macros that wrap a real call (e.g. `WRITE_ONCE(p, fn(x))` patterns where the inner call would otherwise be invisible) are still captured because the regex walks the whole body. Macros that *expand to* a call without writing it textually (rare) would be missed; record these in `CALL_BLACKLIST`'s sibling list when found.
- [SVF]              indirect-call resolution  Function-pointer targets are over-approximated by SVF's Andersen-style pointer analysis; precision drops on type-cast / `void*` arithmetic patterns. The over-approximation stays sound (more callees ⇒ more reachable code ⇒ never prunes a real path). *Not yet wired*; SVF is the Phase-3 replacement for the address-taken heuristic above.
- [Smatch/Sparse]    macro expansion           Heavily macro'd kernel code may parse differently across versions; we re-run analysis per kernel `CONFIG_*` matrix.
- [Coccinelle]       semantic patches          SmPL patterns assume the structural shape of the AST; new dialects can silently miss patterns. Track which SmPL rules ran in `surface/tasks/*.json`.
- [static-hints]     non-soundness role        Smatch / Coccinelle / Sparse / CodeQL findings ingested via `surface/static_hints.py` are **priority signals only**, never pruning evidence. A missing hint never causes a function to be pruned; an extra hint never declares a function exploitable.
- [all]              inline asm                Inline assembly is opaque to all C front-ends; bodies containing `__asm__` are treated as worst-case (read/write any memory). Always reachable, never pruned.

## Labeled-corpus soundness gate (Juliet, Phase 1.5)

- [juliet/stageA]    entry-point heuristic     `eval/juliet/run_stage_a.py` treats every non-`static` function whose name matches `CWE\d+_..._(bad|good*|bad_sink|good*_sink|bad_source|good*_source)` as an entry. Juliet builds a single binary where `main_linux.cpp` dispatches by string lookup into the testcase API, so every such extern function is genuinely externally invokable. A missed naming pattern shrinks the entry set → labeled `_bad` could be pruned → soundness-gate failure surfaces in `missed_bug_count`. Re-running `run_stage_a.py` after adding a CWE keeps the gate honest.
- [juliet/stageB]    helper stubs              `eval/juliet/stubs.c` provides no-op definitions of testcasesupport helpers (printLine, printIntLine, …). `printLine`/`printWLine` deliberately dereference their argument (`volatile char c = line[0]`) because Juliet's UAF testcases pass the freed pointer to `printLine` as the sink — a true no-op would mask the deref and CBMC would falsely report `safe`. Any new sink-helper added to the stub must either deref its argument the same way or be replaced by a real Juliet helper if it is the bug-witnessing call. Confirmed by Phase 1.5 run-log: with deref'ing stubs, 12/12 labeled `_bad` reach `unsafe`; without, 1 falsely reached `safe`.
- [juliet/stageB]    unwind bound choice       Phase 1.5 runs CBMC at `--unwind=128`. Two CWE416 testcases contain `for(i=0;i<100;i++)` — `--unwind=32` left them `inconclusive` (not unsafe per the gate's strict reading, but defeats the verification claim). The unwind bound is a *quality* lever, not a soundness one: `inconclusive` is never recorded as a soundness failure, only `safe` on a `_bad` is.

## Stage B — sound proof

- [Frama-C/EVA]      abstract domain           EVA is sound under its chosen domain (interval, congruence, gauges). Pre-/post-conditions assumed at function boundaries MUST themselves be verified or come from the proof cache with matching keys.
- [CBMC/ESBMC]       bounded loops             A verdict is sound only up to the configured `--unwind` bound. To extend to unbounded soundness we attach an LLM-synthesized loop invariant and have CBMC discharge it; without a verified invariant, the verdict is "safe under bound N", not "safe".
- [proof-cache]      callee-contract identity  A cache hit is valid only when the *current* callee contracts equal the assumed ones from cache time. Verified at hit; never trust the body hash alone.

## Oracle Tier 1 — fast crash

- [sanitizers]       coverage of properties    ASan covers heap/stack/global OOB and UAF; MSan covers uninit reads; UBSan covers UB classes. A "no crash" verdict from Tier 1 is NOT a safety claim — it only means the fuzzer didn't reach the bug within the budget. Always escalate inconclusive Tier-1 to Tier 2/3 before pruning.
- [syzkaller]        syscall surface           syzlang descriptions enumerate the surface explicitly; bugs reachable only via unmodeled syscalls / ioctls are unreachable to syzkaller. Track unmodeled surface in `surface/tasks/*.json`.
- [KASAN]            instrumentation gaps      KASAN reports use-after-free / OOB on slab + buddy allocations covered by the shadow map; non-shadowed memory (early-boot, percpu, vmemmap before init, EFI) is invisible. For the kernelCTF sanity boot, KASAN_INLINE + SLUB_DEBUG_ON are enabled (see `eval/kernelctf/configs/config-6.1.72-kasan.txt`).

## Oracle Tier 2 — symbolic

- [KLEE]             environment modeling      KLEE relies on `klee-uclibc` and POSIX models; calls outside the model become `__klee_warning` and are unmodeled (must be treated as "could do anything").
- [S2E]              selective concretization  Concretized arguments mask paths gated on those args; record which arguments stayed symbolic in each S2E task.
- [angr]             SimProcedure coverage     SimProcedures replace library calls with abstract models; unmodeled calls drop precision.

## Oracle Tier 3 — BMC

- (see Stage B / CBMC entries above; engine is shared)

## Build environment

- [kernel CONFIG_*]  every cached proof's key embeds the `CONFIG_*` set, arch, and compiler/sanitizer mode. Any drift = cache miss = re-verify.

---

If you add a new tool, append its assumptions here before relying on its verdict.
