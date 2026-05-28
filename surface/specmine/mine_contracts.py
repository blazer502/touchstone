"""Phase 5.2 — Contract miner + outlier extractor for spec mining (PLAN §3b.2).

Reads per-callee callsite ledgers emitted by 5.1 (`surface/specmine/callsites/
<target>/<callee>.json`) and mines two artifacts:

1. **Mined contracts** — guard clusters that appear at ≥τ fraction of a callee's
   callsites. A mined contract is the *proposer's* conjecture that "callee F
   expects precondition G of its callers". Phase 5.3 forward-verifies each
   contract via Stage B before it is trusted for pruning.

2. **Outliers** — callsites that don't match a mined contract of their callee.
   Each outlier is a *bug lead*: a callsite where the codebase's own near-
   universal convention is missing. Suspicion is scored as

       suspicion = support_pct × (1 − local_establishment)

   where `local_establishment ∈ {0.0, 1.0}` is a one-hop interprocedural check:
   if the outlier's caller F is itself in the mined-contracts dict and G is one
   of F's own mined contracts, then F's callers establish G before invoking F,
   so G is implicit at the C-callsite and the outlier is downgraded.

   Phase 5.3 backward-verifies surviving outliers via the existing Tier-2/3
   sound oracle (KLEE/CBMC). The *bug verdict* always belongs to the sound
   checker (PLAN §8); mining is only the proposer.

Canonicalisation (kind_class, predicate):
  - `lock`: lock_acquire + lock_assert collapse on the established lock-state
    name (rcu_read_lock_held, spin_held, mutex_held, ...). Synonyms mapped:
    `spin_is_locked`/`assert_spin_locked` → `spin_held`; `mutex_is_locked` →
    `mutex_held`; `rcu_read_lock_held()` ↔ `rcu_read_lock_held`. Lock-variable
    specific asserts (`lockdep_assert_held(x)`) keep `x` distinct.
  - `cap`: capability_check, argument preserved (`capable(CAP_NET_ADMIN)` ≠
    `capable(CAP_SYS_ADMIN)`).
  - `neg`, `null`, `early`: predicate whitespace-normalised, kind preserved.
  - `if_true` / `if_false`: split by polarity — the same `if (P)` establishes
    P in the true branch and !P in the false branch, opposite preconditions.

Variable-role normalisation is intentionally NOT implemented in the MVP — most
strong conventions (lock-state, capability, BUG_ON of named macros) are
variable-free at the syntactic level. Variable-role normalisation is queued as
a 5.x.2 hook in `docs/soundness-assumptions.md` and would expand the set of
mineable contracts to e.g. `arg0 != NULL` across differently-named callsite
parameters. Without it, the mining sees fewer variable-bound contracts; that
*shrinks* the leads (fewer outliers) but does not introduce unsoundness.

No LLM (Phase 5.2 rule).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path


# --------------------------------------------------------------------------- #
# Canonicalisation
# --------------------------------------------------------------------------- #

_WS_RE = re.compile(r"\s+")


def _normalise_ws(s: str) -> str:
    return _WS_RE.sub(" ", s).strip()


# Lock-assertion fn → canonical lock-state name (no arg).
_LOCK_ASSERT_FN_TO_STATE: dict[str, str] = {
    "rcu_read_lock_held": "rcu_read_lock_held",
    "rcu_read_lock_bh_held": "rcu_read_lock_bh_held",
    "rcu_read_lock_sched_held": "rcu_read_lock_sched_held",
    "spin_is_locked": "spin_held",
    "assert_spin_locked": "spin_held",
    "mutex_is_locked": "mutex_held",
}


def _canonical_lock_key(predicate: str) -> str:
    """Collapse lock_acquire / lock_assert predicates onto a single key.

    Examples (predicate → canonical key):
        "rcu_read_lock_held"                 → "rcu_read_lock_held"
        "rcu_read_lock_held()"               → "rcu_read_lock_held"
        "rcu_read_lock_held(current)"        → "rcu_read_lock_held"
        "mutex_is_locked(&table->lock)"      → "mutex_held"
        "spin_is_locked(&p->lock)"           → "spin_held"
        "lockdep_assert_held(&net->mutex)"   → "lockdep_assert_held(&net->mutex)"
        "lockdep_is_held(&t->mutex)"         → "lockdep_is_held(&t->mutex)"
        "rcu_dereference_protected(p, cond)" → "rcu_dereference_protected(p, cond)"
    """
    pred = _normalise_ws(predicate)
    # Whole-string match against the lock-state primitives that we want to
    # collapse on their function name regardless of argument.
    for fn, state in _LOCK_ASSERT_FN_TO_STATE.items():
        if pred == fn:
            return state
        if pred.startswith(fn) and pred[len(fn):].startswith("("):
            return state
    return pred


def canonical_guard_key(g: dict) -> tuple[str, str]:
    kind = g["kind"]
    pred = _normalise_ws(g.get("predicate", ""))
    if kind in ("lock_acquire", "lock_assert"):
        return ("lock", _canonical_lock_key(pred))
    if kind == "capability_check":
        return ("cap", pred)
    if kind == "assert_neg":
        return ("neg", pred)
    if kind == "null_check":
        return ("null", pred)
    if kind == "early_return":
        return ("early", pred)
    if kind == "enclosing_if":
        polarity = g.get("polarity", "in_true_branch")
        side = "if_true" if polarity == "in_true_branch" else "if_false"
        return (side, pred)
    if kind == "enclosing_while":
        return ("while", pred)
    if kind == "enclosing_for":
        return ("for", pred)
    if kind == "enclosing_switch":
        return ("switch", pred)
    return (kind, pred)


def display_kind_class(key_class: str) -> str:
    """Human-readable kind label for the contracts/outliers output."""
    return {
        "lock": "lock_held",
        "cap": "capability_check",
        "neg": "assert_neg",
        "null": "null_check",
        "early": "early_return",
        "if_true": "enclosing_if[true]",
        "if_false": "enclosing_if[false]",
        "while": "enclosing_while",
        "for": "enclosing_for",
        "switch": "enclosing_switch",
    }.get(key_class, key_class)


# --------------------------------------------------------------------------- #
# Loading 5.1 output
# --------------------------------------------------------------------------- #

def load_callee_ledger(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def iter_callee_ledgers(callsites_dir: Path):
    for p in sorted(callsites_dir.glob("*.json")):
        if p.name == "_index.json":
            continue
        d = load_callee_ledger(p)
        if d is None:
            continue
        yield p, d


# --------------------------------------------------------------------------- #
# Mining
# --------------------------------------------------------------------------- #

def mine_one_callee(
    ledger: dict, tau: float, min_support: int
) -> list[dict]:
    """Return the list of mined contracts for one callee."""
    callsites = ledger["callsites"]
    n = len(callsites)
    if n == 0:
        return []
    # Per-callsite canonical-key set (a key counts once per callsite even if the
    # same guard fires multiple times — we mine *presence*, not multiplicity).
    per_callsite_keys: list[set[tuple[str, str]]] = []
    for cs in callsites:
        keys: set[tuple[str, str]] = set()
        for g in cs.get("guards", []):
            keys.add(canonical_guard_key(g))
        per_callsite_keys.append(keys)
    support: Counter[tuple[str, str]] = Counter()
    for keys in per_callsite_keys:
        for k in keys:
            support[k] += 1
    contracts: list[dict] = []
    for key, count in support.items():
        if count < min_support:
            continue
        pct = count / n
        if pct < tau:
            continue
        # Outlier callsites for this contract: those whose key set doesn't
        # contain `key`.
        outlier_indices = [
            i for i, keys in enumerate(per_callsite_keys) if key not in keys
        ]
        contracts.append({
            "kind_class": key[0],
            "kind_label": display_kind_class(key[0]),
            "predicate": key[1],
            "support_count": count,
            "callsite_count": n,
            "support_pct": round(pct, 4),
            "outlier_callsite_indices": outlier_indices,
        })
    # Determinism: sort by support_pct desc, then by kind/predicate.
    contracts.sort(
        key=lambda c: (-c["support_pct"], c["kind_class"], c["predicate"])
    )
    return contracts


# --------------------------------------------------------------------------- #
# Driver
# --------------------------------------------------------------------------- #

def mine(
    callsites_dir: Path,
    target: str,
    tau: float,
    min_support: int,
) -> tuple[dict, dict]:
    """Mine every callee's ledger; return (contracts_doc, outliers_doc)."""
    # First pass: mine per-callee contracts. We collect the *mined-contract set
    # per function* so that step 2 (one-hop establishment) can check whether
    # the outlier's caller carries the same contract.
    per_callee_contracts: dict[str, list[dict]] = {}
    # callsite_records keyed by callee:
    #   callee -> [ {caller, file, line, guards}, ... ] (same order as ledger)
    per_callee_callsites: dict[str, list[dict]] = {}
    # Total callsite counts per callee.
    total_callsites = 0
    total_callees_examined = 0

    for path, ledger in iter_callee_ledgers(callsites_dir):
        callee = ledger.get("callee") or path.stem
        callsites = ledger.get("callsites", [])
        contracts = mine_one_callee(ledger, tau, min_support)
        per_callee_contracts[callee] = contracts
        per_callee_callsites[callee] = callsites
        total_callees_examined += 1
        total_callsites += len(callsites)

    # Build a fast lookup: function name -> set of (kind_class, predicate) keys
    # that are mined contracts of that callee. Used for the one-hop check.
    contract_keys_of: dict[str, set[tuple[str, str]]] = {
        c: {(ct["kind_class"], ct["predicate"]) for ct in cts}
        for c, cts in per_callee_contracts.items()
    }

    # Second pass: emit outliers, applying the one-hop establishment check.
    outliers: list[dict] = []
    mined_contracts_flat: list[dict] = []
    callees_with_contracts = 0
    for callee, contracts in per_callee_contracts.items():
        if not contracts:
            continue
        callees_with_contracts += 1
        callsites = per_callee_callsites[callee]
        for ct in contracts:
            outlier_records: list[dict] = []
            key = (ct["kind_class"], ct["predicate"])
            for idx in ct["outlier_callsite_indices"]:
                cs = callsites[idx]
                caller = cs.get("caller")
                local_est = (
                    1.0
                    if caller in contract_keys_of and key in contract_keys_of[caller]
                    else 0.0
                )
                suspicion = round(ct["support_pct"] * (1.0 - local_est), 4)
                # Strip exit_kind etc. from guards for the outlier dump's
                # `guards_present` field — keep it tight.
                guards_present = [
                    {k: v for k, v in g.items() if k in ("kind", "predicate", "polarity", "source_line")}
                    for g in cs.get("guards", [])
                ]
                outlier_records.append({
                    "callee": callee,
                    "missing_contract": ct["predicate"],
                    "contract_kind_class": ct["kind_class"],
                    "contract_kind_label": ct["kind_label"],
                    "caller": caller,
                    "file": cs.get("file"),
                    "line": cs.get("line"),
                    "support_pct": ct["support_pct"],
                    "support_count": ct["support_count"],
                    "callsite_count": ct["callsite_count"],
                    "local_establishment": local_est,
                    "suspicion": suspicion,
                    "guards_present": guards_present,
                })
            outliers.extend(outlier_records)
            # Flatten contract list (drop the per-index outlier reference, keep
            # the outlier count for cheap rollup).
            mined_contracts_flat.append({
                "callee": callee,
                "kind_class": ct["kind_class"],
                "kind_label": ct["kind_label"],
                "predicate": ct["predicate"],
                "support_count": ct["support_count"],
                "callsite_count": ct["callsite_count"],
                "support_pct": ct["support_pct"],
                "outlier_count": len(outlier_records),
            })

    # Deterministic ordering.
    mined_contracts_flat.sort(key=lambda c: (
        -c["support_pct"], -c["support_count"], c["callee"], c["kind_class"], c["predicate"]
    ))
    outliers.sort(key=lambda o: (
        -o["suspicion"], -o["support_pct"], o["callee"],
        o["contract_kind_class"], o["predicate"] if False else o["missing_contract"],
        o["file"] or "", o["line"] or 0,
    ))

    # Per-kind-class rollup for outliers.
    by_class: Counter[str] = Counter(o["contract_kind_class"] for o in outliers)
    contracts_by_class: Counter[str] = Counter(c["kind_class"] for c in mined_contracts_flat)

    contracts_doc = {
        "target": target,
        "generated_at": int(time.time()),
        "tau": tau,
        "min_support": min_support,
        "stats": {
            "callees_examined": total_callees_examined,
            "callees_with_contracts": callees_with_contracts,
            "mined_contracts": len(mined_contracts_flat),
            "by_kind_class": dict(contracts_by_class),
            "total_callsites": total_callsites,
        },
        "contracts": mined_contracts_flat,
    }
    outliers_doc = {
        "target": target,
        "generated_at": contracts_doc["generated_at"],
        "tau": tau,
        "min_support": min_support,
        "stats": {
            "total_outliers": len(outliers),
            "by_kind_class": dict(by_class),
            "outliers_with_local_establishment": sum(
                1 for o in outliers if o["local_establishment"] > 0
            ),
        },
        "outliers": outliers,
    }
    return contracts_doc, outliers_doc


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Phase 5.2 contract miner.")
    ap.add_argument("--callsites-dir", type=Path,
                    help="Path to surface/specmine/callsites/<target>/ "
                         "(default: derived from --target).")
    ap.add_argument("--target", required=True, type=str)
    ap.add_argument("--tau", type=float, default=0.85,
                    help="Support threshold for mined contracts (default: 0.85).")
    ap.add_argument("--min-support", type=int, default=3,
                    help="Minimum absolute support count to mine a contract "
                         "(default: 3 — guards against tiny callsite sets).")
    ap.add_argument("--out-contracts", type=Path,
                    help="Output path for mined contracts JSON.")
    ap.add_argument("--out-outliers", type=Path,
                    help="Output path for outliers JSON.")
    args = ap.parse_args(argv)

    here = Path(__file__).resolve().parent
    callsites_dir = (
        args.callsites_dir or here / "callsites" / args.target
    )
    if not callsites_dir.is_dir():
        ap.error(f"callsites dir not found: {callsites_dir}")

    contracts_dir = here / "contracts"
    outliers_dir = here / "outliers"
    contracts_dir.mkdir(parents=True, exist_ok=True)
    outliers_dir.mkdir(parents=True, exist_ok=True)
    out_contracts = args.out_contracts or contracts_dir / f"{args.target}.json"
    out_outliers = args.out_outliers or outliers_dir / f"{args.target}.json"

    t0 = time.time()
    contracts_doc, outliers_doc = mine(
        callsites_dir=callsites_dir,
        target=args.target,
        tau=args.tau,
        min_support=args.min_support,
    )
    wall = time.time() - t0
    contracts_doc["stats"]["wall_seconds"] = round(wall, 2)
    outliers_doc["stats"]["wall_seconds"] = round(wall, 2)

    out_contracts.write_text(json.dumps(contracts_doc, indent=2, sort_keys=True) + "\n")
    out_outliers.write_text(json.dumps(outliers_doc, indent=2, sort_keys=True) + "\n")

    cs = contracts_doc["stats"]
    os_ = outliers_doc["stats"]
    print(f"[specmine] tau={args.tau} mined_contracts={cs['mined_contracts']} "
          f"(callees_with_contracts={cs['callees_with_contracts']}/"
          f"{cs['callees_examined']}) outliers={os_['total_outliers']} "
          f"(local_est={os_['outliers_with_local_establishment']}) "
          f"wall={wall:.2f}s")
    print(f"[specmine] contracts -> {out_contracts}")
    print(f"[specmine] outliers  -> {out_outliers}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
