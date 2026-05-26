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

- [SVF]              indirect-call resolution  Function-pointer targets are over-approximated by SVF's Andersen-style pointer analysis; precision drops on type-cast / `void*` arithmetic patterns. The over-approximation stays sound (more callees ⇒ more reachable code ⇒ never prunes a real path).
- [Smatch/Sparse]    macro expansion           Heavily macro'd kernel code may parse differently across versions; we re-run analysis per kernel `CONFIG_*` matrix.
- [Coccinelle]       semantic patches          SmPL patterns assume the structural shape of the AST; new dialects can silently miss patterns. Track which SmPL rules ran in `surface/tasks/*.json`.
- [all]              inline asm                Inline assembly is opaque to all C front-ends; bodies containing `__asm__` are treated as worst-case (read/write any memory). Always reachable, never pruned.

## Stage B — sound proof

- [Frama-C/EVA]      abstract domain           EVA is sound under its chosen domain (interval, congruence, gauges). Pre-/post-conditions assumed at function boundaries MUST themselves be verified or come from the proof cache with matching keys.
- [CBMC/ESBMC]       bounded loops             A verdict is sound only up to the configured `--unwind` bound. To extend to unbounded soundness we attach an LLM-synthesized loop invariant and have CBMC discharge it; without a verified invariant, the verdict is "safe under bound N", not "safe".
- [proof-cache]      callee-contract identity  A cache hit is valid only when the *current* callee contracts equal the assumed ones from cache time. Verified at hit; never trust the body hash alone.

## Oracle Tier 1 — fast crash

- [sanitizers]       coverage of properties    ASan covers heap/stack/global OOB and UAF; MSan covers uninit reads; UBSan covers UB classes. A "no crash" verdict from Tier 1 is NOT a safety claim — it only means the fuzzer didn't reach the bug within the budget. Always escalate inconclusive Tier-1 to Tier 2/3 before pruning.
- [syzkaller]        syscall surface           syzlang descriptions enumerate the surface explicitly; bugs reachable only via unmodeled syscalls / ioctls are unreachable to syzkaller. Track unmodeled surface in `surface/tasks/*.json`.

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
