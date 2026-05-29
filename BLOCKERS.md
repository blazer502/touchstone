# Blockers

## Track 4 / kernelCTF — next deep lever needs a human decision (2026-05-29)

**State:** the cross-fn Smatch DB hunt is conclusive (`run-logs/smatch-xfn-db-hunt.md`).
Recall is solved (3 → 689 candidates); the wall is now **precision** — on a hardened,
well-audited LTS the user-controlled-index candidates are all defeated by guards in
framework dispatch layers (genetlink op-table validation, NFSD COMPOUND, qdisc band
checks) that live in a different TU and so are invisible even to cross-fn Smatch. No
reproduced novel KASAN crash; the kernelCTF milestone is unmet, as expected for a
patched LTS.

**Why blocked (autonomous):** the three ways forward are all expensive and/or a
strategy call, not a mechanical next step:

1. **CodeQL dispatch-aware interprocedural taint** — could follow the dispatch edge
   Smatch misses, but CodeQL is **not installed** (external download) and building a
   kernel CodeQL DB is a multi-hour traced rebuild.
2. **A genuinely less-audited target** — the in-workspace older tree is `6.1.72`
   (also a hardened kernelCTF LTS; same dispatch-guard structure → likely reconfirms
   the wall, and n-days in an old snapshot are not kernelCTF-eligible). A truly
   less-audited target (fresh out-of-tree driver, non-LTS) is an external fetch +
   build + new `surface/entrypoints/` — a scope decision.
3. **Accept the hardened-LTS ceiling** — record that static-candidate → reproduced-
   crash is precision-bound on a patched LTS, and pivot effort elsewhere.

**Decision needed from operator:** which lever (1/2/3), given each deep option is
~hours of compute with structurally diminishing returns on this hardened tree.
I did **not** burn overnight compute on a ~4h rebuild that would most likely just
reconfirm the wall.

**Unblocked work done instead:** built + committed the cross-fn-DB candidate source
(`tools/smatch_candidates.py`, now precision-ranking user-controlled candidates),
validated `hyp_loop` end-to-end on real rich candidates, and updated the forward-plan.
