"""Phase 6.3 — Directed-fuzzing reachability / distance scorer (BEACON / SelectFuzz).

Directed greybox fuzzing (AFLGo, BEACON, SelectFuzz) aims execution at a
specific *target location* by (a) computing each function's call-graph distance
to the target and (b) prioritising seeds/paths that reduce that distance, and
pruning code that provably can't reach the target. This module computes the
static ingredients a directed fuzzer needs, over the call graph we already
extract in `surface/reachability.py`:

  * `distance_to_target`  — per-function shortest call-graph distance to the
    target function (reverse-BFS from the target). Unreachable functions get
    ∞ and are the "SelectFuzz prune set" (no instrumentation / seed-distance
    needed — they can't reach the target).
  * `reachable_callers`   — the set of functions that CAN reach the target
    (finite distance); the BEACON "feasible-path" frontier.
  * `entry_distances`     — distance from each attacker entry-point to the
    target; an entry with finite distance is a viable fuzzing seed surface.

The output is consumed by Phase 6.3's syzlang synthesis (pick the entry
surface closest to the outlier) and, when the syzkaller image is built, by a
distance-guided seed scheduler. No fuzzer is run here — this is the static
scoping a directed fuzzer needs. No LLM.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import defaultdict, deque
from pathlib import Path

_HERE = Path(__file__).resolve()
sys.path.insert(0, str(_HERE.parents[2]))

from surface.reachability import (  # noqa: E402
    list_c_sources, build_call_graph,
)
from surface.indirect_calls import (  # noqa: E402
    build_fp_tables, resolve_indirect_calls,
)


def reverse_graph(cg: dict[str, set[str]]) -> dict[str, set[str]]:
    rev: dict[str, set[str]] = defaultdict(set)
    for caller, callees in cg.items():
        for c in callees:
            rev[c].add(caller)
    return rev


def distance_to_target(
    cg: dict[str, set[str]], target: str
) -> dict[str, int]:
    """Shortest call-graph distance from each function to `target`.

    Reverse-BFS from `target`: distance[target]=0, a direct caller=1, etc.
    Functions with no path to target are absent (treated as ∞).
    """
    rev = reverse_graph(cg)
    dist: dict[str, int] = {target: 0}
    q = deque([target])
    while q:
        n = q.popleft()
        for caller in rev.get(n, ()):
            if caller not in dist:
                dist[caller] = dist[n] + 1
                q.append(caller)
    return dist


def score_target(
    source_root: Path,
    scope: str,
    target_func: str,
    entrypoints_path: Path | None,
    *,
    use_mlta: bool = True,
) -> dict:
    """Compute the directed-fuzzing scoping for one target function.

    `use_mlta=True` augments the direct call graph with Phase-6.2 MLTA-resolved
    indirect-call edges, so indirectly-dispatched targets (kernel callbacks like
    `nft_immediate_init` registered at `nft_expr_ops.init`) become reachable in
    the distance metric — without it the direct graph shows 0 callers.
    """
    scope_root = (source_root / scope).resolve()
    files = list_c_sources(scope_root)
    cg, fn_to_file, _fns_indirect, _addr = build_call_graph(files, source_root)
    defined = set(fn_to_file)

    if target_func not in defined:
        return {
            "target_func": target_func,
            "error": f"target not defined in scope {scope}",
            "defined_functions": len(defined),
        }

    mlta_edges_added = 0
    if use_mlta:
        f2f, tf2f, _ = build_fp_tables(files, source_root, defined=defined)
        resolved, _counts = resolve_indirect_calls(files, source_root, f2f, tf2f)
        for caller, callees in resolved.items():
            tgt = {c for c in callees if c in defined}
            if tgt:
                cg.setdefault(caller, set())
                before = len(cg[caller])
                cg[caller] |= tgt
                mlta_edges_added += len(cg[caller]) - before

    dist = distance_to_target(cg, target_func)
    reachable_callers = sorted(f for f in dist if f != target_func)

    # Entry-point distances (attacker surface → target).
    entry_dists: dict[str, int] = {}
    if entrypoints_path and entrypoints_path.exists():
        catalog = json.loads(entrypoints_path.read_text())
        for e in catalog.get("entries", []):
            f = e["func"]
            if f in dist:
                entry_dists[f] = dist[f]
    # Closest entry surfaces (the best fuzzing seeds).
    closest_entries = sorted(entry_dists.items(), key=lambda kv: kv[1])[:15]

    prune_set_size = len(defined) - len(dist)  # SelectFuzz prune set (∞ dist)

    return {
        "target_func": target_func,
        "scope": scope,
        "defined_functions": len(defined),
        "use_mlta": use_mlta,
        "mlta_edges_added": mlta_edges_added,
        "reachable_callers_count": len(reachable_callers),
        "selectfuzz_prune_set": prune_set_size,
        "selectfuzz_prune_pct": round(100 * prune_set_size / (len(defined) or 1), 2),
        "entry_surfaces_reaching_target": len(entry_dists),
        "closest_entry_surfaces": [
            {"entry": f, "distance": d} for f, d in closest_entries
        ],
        "max_distance": max(dist.values()) if dist else 0,
        "_distance_to_target": dict(sorted(dist.items(), key=lambda kv: kv[1])),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Phase 6.3 directed-fuzzing scorer.")
    ap.add_argument("--source-root", required=True, type=Path)
    ap.add_argument("--scope", required=True, type=str)
    ap.add_argument("--target", required=True, type=str, help="metrics target id")
    ap.add_argument("--target-func", required=True, type=str,
                    help="the callee/site the fuzzer should reach")
    ap.add_argument("--entrypoints", type=Path, default=None)
    ap.add_argument("--no-mlta", action="store_true",
                    help="Disable Phase-6.2 MLTA edge augmentation (direct graph only).")
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args(argv)

    source_root = args.source_root.resolve()
    here = Path(__file__).resolve().parent
    repo = here.parents[1]
    entrypoints_path = args.entrypoints or (
        repo / "surface" / "entrypoints" / f"{args.target}.json"
    )

    t0 = time.time()
    res = score_target(source_root, args.scope, args.target_func, entrypoints_path,
                       use_mlta=not args.no_mlta)
    res["wall_seconds"] = round(time.time() - t0, 2)

    out_dir = here / "directed"
    out_dir.mkdir(parents=True, exist_ok=True)
    safe = "".join(c if c.isalnum() or c in "_-." else "_" for c in args.target_func)
    out_path = args.out or out_dir / f"{args.target}.{safe}.json"
    out_path.write_text(json.dumps(res, indent=2) + "\n")

    if "error" in res:
        print(f"[directed] {res['error']}")
        return 1
    print(f"[directed] target_func={res['target_func']}: "
          f"{res['reachable_callers_count']} reachable callers, "
          f"SelectFuzz prune {res['selectfuzz_prune_pct']}% "
          f"({res['selectfuzz_prune_set']}/{res['defined_functions']}), "
          f"{res['entry_surfaces_reaching_target']} entry surfaces reach it.")
    for e in res["closest_entry_surfaces"][:5]:
        print(f"    seed entry: {e['entry']}  (distance {e['distance']})")
    print(f"[directed] -> {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
