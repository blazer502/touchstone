"""Phase 6.5 — Frequent guard-itemset mining + variable-role normalization (APP-Miner).

Phase 5.2 mines *single* guards (one canonical key per contract). APP-Miner
(IEEE S&P'24) mines API *path patterns* via frequent-subgraph mining — i.e. it
discovers that a callee is conventionally preceded by a *combination* of
operations, not just one. This module is the APP-Miner-lite version: it mines
frequent guard *itemsets* (co-occurring guard sets of size ≥2) per callee, so a
callsite missing the full conjunction is flagged even when each individual guard
is below the single-guard τ.

It also adds **variable-role normalization** (the deferred 5.x.2 hook): caller
parameter names in guard predicates are rewritten to positional roles
(`$arg0`, `$arg1`, …) so `lockdep_assert_held(net->mutex)` and
`lockdep_assert_held(other->mutex)` cluster when `net`/`other` are the
respective callers' first parameters — expanding the set of mineable
variable-bound contracts that 5.2 (which kept predicates verbatim) couldn't
cluster.

Output: `surface/specmine/itemsets/<target>.json` — frequent guard itemsets +
the callsites that violate them (multi-guard outliers). These are *proposer*
leads exactly like 5.2's; the sound checker (5.3) still decides. The headline
deliverable is a multi-statement (conjunction) pattern the single-guard regex
miner cannot express.

No LLM (Phase 6.5 rule).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from collections import Counter, defaultdict
from itertools import combinations
from pathlib import Path

_HERE = Path(__file__).resolve()
sys.path.insert(0, str(_HERE.parents[2]))

from surface.specmine.mine_contracts import (  # noqa: E402
    canonical_guard_key, iter_callee_ledgers,
)


# --------------------------------------------------------------------------- #
# Variable-role normalization
# --------------------------------------------------------------------------- #

_CALLER_PARAM_CACHE: dict[tuple[str, str], list[str]] = {}


def _caller_params(source_root: Path, rel_file: str, caller: str) -> list[str]:
    """Best-effort: parse the caller's parameter identifier list from source."""
    key = (rel_file, caller)
    if key in _CALLER_PARAM_CACHE:
        return _CALLER_PARAM_CACHE[key]
    params: list[str] = []
    path = source_root / rel_file
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        _CALLER_PARAM_CACHE[key] = params
        return params
    m = re.search(rf"\b{re.escape(caller)}\s*\(([^;{{]*)\)\s*\{{", text)
    if m:
        raw = m.group(1).strip()
        if raw and raw != "void":
            for part in raw.split(","):
                # last identifier token in the declarator is the param name
                ids = re.findall(r"[A-Za-z_]\w*", part)
                if ids:
                    params.append(ids[-1])
    _CALLER_PARAM_CACHE[key] = params
    return params


def normalize_roles(predicate: str, params: list[str]) -> str:
    """Rewrite caller param identifiers in `predicate` to $arg0/$arg1/..."""
    if not params:
        return predicate
    out = predicate
    # Longest names first so substrings don't clobber.
    for i, p in sorted(enumerate(params), key=lambda ip: -len(ip[1])):
        out = re.sub(rf"\b{re.escape(p)}\b", f"$arg{i}", out)
    return out


def _normalized_keys(
    guards: list[dict], params: list[str]
) -> frozenset[tuple[str, str]]:
    keys = set()
    for g in guards:
        kc, pred = canonical_guard_key(g)
        keys.add((kc, normalize_roles(pred, params)))
    return frozenset(keys)


# --------------------------------------------------------------------------- #
# Frequent-itemset mining
# --------------------------------------------------------------------------- #

def mine_itemsets_for_callee(
    ledger: dict, source_root: Path, tau: float, min_support: int,
    max_itemset: int = 3,
) -> list[dict]:
    """Mine frequent guard itemsets (size 2..max_itemset) for one callee."""
    callsites = ledger.get("callsites", [])
    n = len(callsites)
    if n < min_support:
        return []
    per_cs_keys: list[frozenset[tuple[str, str]]] = []
    for cs in callsites:
        params = _caller_params(source_root, cs.get("file", ""), cs.get("caller", ""))
        per_cs_keys.append(_normalized_keys(cs.get("guards", []), params))

    # Candidate items = guards appearing in ≥min_support callsites.
    item_support: Counter[tuple[str, str]] = Counter()
    for ks in per_cs_keys:
        for k in ks:
            item_support[k] += 1
    frequent_items = {k for k, c in item_support.items() if c >= min_support}

    results: list[dict] = []
    for size in range(2, max_itemset + 1):
        seen_sets: Counter[frozenset] = Counter()
        for ks in per_cs_keys:
            present = sorted(ks & frequent_items)
            if len(present) < size:
                continue
            for combo in combinations(present, size):
                seen_sets[frozenset(combo)] += 1
        for itemset, count in seen_sets.items():
            pct = count / n
            if count < min_support or pct < tau:
                continue
            outliers = [
                i for i, ks in enumerate(per_cs_keys) if not itemset <= ks
            ]
            results.append({
                "itemset": sorted([list(k) for k in itemset]),
                "size": size,
                "support_count": count,
                "callsite_count": n,
                "support_pct": round(pct, 4),
                "outlier_callsite_indices": outliers,
            })
    # Keep only maximal-ish: drop a smaller itemset fully covered by a larger
    # one with identical support (the larger conjunction subsumes it).
    results.sort(key=lambda r: (-r["size"], -r["support_pct"]))
    return results


def mine(
    callsites_dir: Path, source_root: Path, target: str,
    tau: float, min_support: int,
) -> dict:
    contracts: list[dict] = []
    multi_outliers: list[dict] = []
    callees_examined = 0
    for path, ledger in iter_callee_ledgers(callsites_dir):
        callee = ledger.get("callee") or path.stem
        callees_examined += 1
        itemsets = mine_itemsets_for_callee(ledger, source_root, tau, min_support)
        callsites = ledger.get("callsites", [])
        for it in itemsets:
            contracts.append({
                "callee": callee,
                "itemset": it["itemset"],
                "size": it["size"],
                "support_count": it["support_count"],
                "callsite_count": it["callsite_count"],
                "support_pct": it["support_pct"],
                "outlier_count": len(it["outlier_callsite_indices"]),
            })
            for idx in it["outlier_callsite_indices"]:
                cs = callsites[idx]
                multi_outliers.append({
                    "callee": callee,
                    "caller": cs.get("caller"),
                    "file": cs.get("file"),
                    "line": cs.get("line"),
                    "missing_itemset": it["itemset"],
                    "itemset_size": it["size"],
                    "support_pct": it["support_pct"],
                    "suspicion": round(it["support_pct"], 4),
                })
    contracts.sort(key=lambda c: (-c["size"], -c["support_pct"], c["callee"]))
    multi_outliers.sort(key=lambda o: (-o["suspicion"], -o["itemset_size"], o["callee"]))
    return {
        "target": target,
        "generated_at": int(time.time()),
        "tau": tau,
        "min_support": min_support,
        "stats": {
            "callees_examined": callees_examined,
            "frequent_itemsets": len(contracts),
            "by_size": dict(Counter(c["size"] for c in contracts)),
            "multi_guard_outliers": len(multi_outliers),
        },
        "itemsets": contracts,
        "multi_guard_outliers": multi_outliers,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Phase 6.5 frequent guard-itemset mining.")
    ap.add_argument("--target", required=True, type=str)
    ap.add_argument("--callsites-dir", type=Path, default=None)
    ap.add_argument("--source-root", required=True, type=Path)
    ap.add_argument("--tau", type=float, default=0.85)
    ap.add_argument("--min-support", type=int, default=3)
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args(argv)

    here = Path(__file__).resolve().parent
    callsites_dir = args.callsites_dir or here / "callsites" / args.target
    if not callsites_dir.is_dir():
        ap.error(f"callsites dir not found: {callsites_dir}")

    out_dir = here / "itemsets"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = args.out or out_dir / f"{args.target}.json"

    doc = mine(callsites_dir, args.source_root.resolve(), args.target,
               args.tau, args.min_support)
    out_path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
    s = doc["stats"]
    print(f"[graph-mine] frequent_itemsets={s['frequent_itemsets']} "
          f"by_size={s['by_size']} multi_guard_outliers={s['multi_guard_outliers']} "
          f"-> {out_path}")
    for c in doc["itemsets"][:6]:
        items = " ∧ ".join(f"{k[0]}:{k[1]}" for k in c["itemset"])
        print(f"  {c['support_pct']*100:.0f}% ({c['support_count']}/{c['callsite_count']}) "
              f"{c['callee']} requires [{items}]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
