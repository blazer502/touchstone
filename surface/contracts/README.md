# Fixed Stage-B Contracts (hand-written)

This directory ships **hand-written** preconditions / postconditions. The
LLM-synthesized ACSL path plugs in on top of the same harness scaffolding via
`surface/contract_synth.py`.

---

## CBMC contracts

Fixed preconditions are encoded as `__CPROVER_assume(...)` in the harness's
`main` (see `surface/smoke/contracted_copy.c`).

The assumption is part of the proof-cache key, so a cache hit is only valid
when the assumed contract still holds for the current callers.

## Frama-C / EVA contracts

Fixed contracts are ACSL `requires` / `ensures` annotations on the target
function. EVA uses them as call-site preconditions; on a cache hit, the proof
cache must check that the *current* callers still satisfy `requires`.

---

## Why "fixed" rather than "implied"

Without LLM synthesis, the contract source is one of:

- the function's existing kernel-doc / comment header (when present),
- the obvious caller-site invariant (e.g. "callers always validate `len ≤ cap`"),
- a pattern-derived default (refcount get/put ordering, RCU read-side bounds).

Any contract not provably implied by callers in the slice is recorded in
`assumed_contracts` on the verdict, so the labeled soundness gate can
distinguish *proved under verified contract* from *proved under
hand-asserted contract*.
