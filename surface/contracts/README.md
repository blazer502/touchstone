# Fixed Stage-B Contracts (Phase 1.3, no LLM)

Phase-1.3 ships **hand-written** preconditions/postconditions only. Phase 3.1
will plug in LLM-synthesized ACSL on top of the same harness scaffolding.

## CBMC contracts
Fixed preconditions are encoded as `__CPROVER_assume(...)` in the harness's
`main` (see `surface/smoke/contracted_copy.c`). The assumption is part of the
proof-cache key (Phase 1.4) so a cache hit is only valid when the assumed
contract still holds for the current callers.

## Frama-C/EVA contracts
Fixed contracts are ACSL `requires`/`ensures` annotations on the target
function. EVA uses them as call-site preconditions; on a cache hit, the
proof cache must check that the *current* callers still satisfy `requires`.

## Why "fixed" rather than "implied"
Without LLM synthesis, the contract source is one of:
- the function's existing kernel-doc / comment header (when present),
- the obvious caller-site invariant (e.g. "callers always validate len ≤ cap"),
- a pattern-derived default (refcount get/put ordering, RCU read-side bounds).

Any contract that is not provably implied by callers in the slice is
recorded in `assumed_contracts` on the verdict, so Phase 1.5's soundness gate
can distinguish "proved under verified contract" from "proved under
hand-asserted contract".
