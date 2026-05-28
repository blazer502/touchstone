"""Phase 7 / 6.x — Lock-order mining (static lockdep over the source).

Phase 5/6 spec mining finds "callee F is preceded by guard G" — a *missing
pre-call guard*. It cannot express a lock-*ordering* bug: "lock A is acquired
before lock B almost everywhere, but here B is taken before A" (a circular
lock dependency, the class kernelctf-latest Candidate A landed in). This module
adds that capability — it is lockdep's idea, run statically over source:

  1. Per function, scan lock acquire/release in order, maintaining an ordered
     *held-stack*. Acquiring lock L while H is held emits the ordered pair
     H -> L ("H is acquired before L"). Releases pop the stack.
  2. Aggregate ordered pairs across the whole scope into a weighted
     **lock-order graph**: node = lock class, edge A->B weighted by the number
     of distinct call-sites that establish that order, with provenance.
  3. A **cycle** in this graph (A->B->...->A) is a potential deadlock — exactly
     what lockdep reports at runtime. We find 2-cycles directly and larger
     cycles via Tarjan SCCs.
  4. For each cycle, the **inversion lead** is the minority-weight edge: if 40
     sites take A before B and 1 takes B before A, the lone B->A site is the
     deviant that closes the cycle — the bug lead.

Lock-class identity (approximating lockdep classes from source):
  `&mm->mmap_lock`        -> `mmap_lock`
  `&cpuctx->ctx.mutex`    -> `ctx.mutex`
  `&pmus_lock`            -> `pmus_lock`
  `rcu_read_lock()`       -> `rcu` (no arg)
Receiver before the first `->` is dropped so different *instances* of the same
field merge into one class (over-approximation — see soundness note).

Soundness (docs/soundness-assumptions.md):
  * This is a PROPOSER, like all spec mining. An inversion is a *lead*, not a
    confirmed deadlock. The verdict authority for a deadlock is **lockdep at
    runtime** (or a human auditor) — CBMC/symbolic execution cannot practically
    prove a lock-ordering deadlock from source, so for this bug class lockdep
    *is* the §8 sound checker, and the closed-loop "confirmation" is a lockdep
    splat under directed fuzzing (Phase 6.3).
  * Class-merge over-approximation can fuse two genuinely-distinct lock
    instances of the same field into one node and report a FALSE cycle. That is
    a precision cost on the *lead* side (extra leads to triage), never a missed
    real ordering — and the runtime lockdep adjudication filters it. Macro-
    hidden acquires (NF_HOOK, scoped_guard) are missed the same way 5.1 misses
    macro guards — a soft limit, documented.

No LLM (mining is structural).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from collections import defaultdict, Counter
from pathlib import Path

_HERE = Path(__file__).resolve()
sys.path.insert(0, str(_HERE.parents[2]))

from surface.reachability import list_c_sources, ctags_function_starts, parse_function_bodies  # noqa: E402


# --------------------------------------------------------------------------- #
# Lock acquire/release recognition (argument-capturing)
# --------------------------------------------------------------------------- #

# Each acquire: regex with a capture group for the lock argument (or None for
# arg-less locks like rcu_read_lock). The "kind" tags the lock family.
_ACQUIRE = [
    ("rcu",   re.compile(r"\brcu_read_lock(?:_bh|_sched)?\s*\(\s*\)")),
    ("mutex", re.compile(r"\bmutex_lock(?:_nested|_interruptible|_killable)?\s*\(\s*([^,)]+)")),
    ("spin",  re.compile(r"\b(?:raw_)?spin_lock(?:_bh|_irq|_irqsave|_nested)?\s*\(\s*([^,)]+)")),
    ("read",  re.compile(r"\bread_lock(?:_bh|_irq|_irqsave)?\s*\(\s*([^,)]+)")),
    ("write", re.compile(r"\bwrite_lock(?:_bh|_irq|_irqsave)?\s*\(\s*([^,)]+)")),
    ("rwsem_r", re.compile(r"\bdown_read(?:_interruptible|_killable)?\s*\(\s*([^,)]+)")),
    ("rwsem_w", re.compile(r"\bdown_write(?:_interruptible|_killable)?\s*\(\s*([^,)]+)")),
]
_RELEASE = [
    ("rcu",   re.compile(r"\brcu_read_unlock(?:_bh|_sched)?\s*\(\s*\)")),
    ("mutex", re.compile(r"\bmutex_unlock\s*\(\s*([^,)]+)")),
    ("spin",  re.compile(r"\b(?:raw_)?spin_unlock(?:_bh|_irq|_irqrestore)?\s*\(\s*([^,)]+)")),
    ("read",  re.compile(r"\bread_unlock(?:_bh|_irq|_irqrestore)?\s*\(\s*([^,)]+)")),
    ("write", re.compile(r"\bwrite_unlock(?:_bh|_irq|_irqrestore)?\s*\(\s*([^,)]+)")),
    ("rwsem_r", re.compile(r"\bup_read\s*\(\s*([^,)]+)")),
    ("rwsem_w", re.compile(r"\bup_write\s*\(\s*([^,)]+)")),
]

_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_LINE_COMMENT = re.compile(r"//[^\n]*")


def _strip_comments(text: str) -> str:
    def blank(m):
        return "".join(c if c == "\n" else " " for c in m.group(0))
    return _LINE_COMMENT.sub(blank, _BLOCK_COMMENT.sub(blank, text))


def canonical_lock(kind: str, arg: str | None) -> str:
    """Lock-class id approximating a lockdep class."""
    if arg is None:
        return f"rcu" if kind == "rcu" else kind
    a = arg.strip()
    a = a.lstrip("&").strip()
    a = re.sub(r"^\*+", "", a)            # deref
    a = re.sub(r"\[[^\]]*\]", "", a)      # array subscripts
    a = a.strip()
    # Drop the receiver before the first `->` so instances of the same field
    # merge into one class:  cpuctx->ctx.mutex -> ctx.mutex ; mm->mmap_lock -> mmap_lock
    if "->" in a:
        a = a.split("->", 1)[1]
    a = a.strip()
    # Keep it identifier-ish.
    if not re.match(r"^[A-Za-z_][\w.]*$", a):
        return f"{kind}:{a[:32]}"
    return a


def _scan_events(line: str) -> list[tuple[str, str | None, bool]]:
    """Return ordered [(kind, arg, is_acquire), ...] events on one line."""
    events: list[tuple[int, str, str | None, bool]] = []
    for kind, rx in _ACQUIRE:
        for m in rx.finditer(line):
            arg = m.group(1) if m.groups() else None
            events.append((m.start(), kind, arg, True))
    for kind, rx in _RELEASE:
        for m in rx.finditer(line):
            arg = m.group(1) if m.groups() else None
            events.append((m.start(), kind, arg, False))
    events.sort()
    return [(k, a, acq) for _, k, a, acq in events]


# --------------------------------------------------------------------------- #
# Per-function ordered-pair extraction
# --------------------------------------------------------------------------- #

def extract_pairs_from_function(
    caller: str, body: str, body_start: int, rel_file: str,
) -> list[dict]:
    """Return ordered-pair records [{outer, inner, line}] for one function."""
    body = _strip_comments(body)
    held: list[tuple[str, int]] = []   # ordered held-stack: (lock_id, line)
    pairs: list[dict] = []
    for i, line in enumerate(body.split("\n")):
        abs_line = body_start + i
        for kind, arg, is_acquire in _scan_events(line):
            lock_id = canonical_lock(kind, arg)
            if is_acquire:
                # Each currently-held lock is acquired BEFORE this one.
                for (h, _hl) in held:
                    if h != lock_id:
                        pairs.append({
                            "outer": h, "inner": lock_id,
                            "caller": caller, "file": rel_file, "line": abs_line,
                        })
                held.append((lock_id, abs_line))
            else:
                # Release: pop the most recent matching hold.
                for j in range(len(held) - 1, -1, -1):
                    if held[j][0] == lock_id:
                        held.pop(j)
                        break
    return pairs


# --------------------------------------------------------------------------- #
# Lock-order graph + cycle detection
# --------------------------------------------------------------------------- #

def build_graph(all_pairs: list[dict]):
    """Return (edges, provenance): edges[(a,b)] = weight; prov[(a,b)] = [sites]."""
    edges: Counter[tuple[str, str]] = Counter()
    prov: dict[tuple[str, str], list[dict]] = defaultdict(list)
    seen_site: set[tuple[str, str, str, int]] = set()
    for p in all_pairs:
        key = (p["outer"], p["inner"])
        site = (p["outer"], p["inner"], p["file"], p["line"])
        if site in seen_site:
            continue
        seen_site.add(site)
        edges[key] += 1
        prov[key].append({"caller": p["caller"], "file": p["file"], "line": p["line"]})
    return edges, prov


def _tarjan_sccs(nodes: set[str], adj: dict[str, set[str]]) -> list[list[str]]:
    index_counter = [0]
    stack: list[str] = []
    lowlink: dict[str, int] = {}
    index: dict[str, int] = {}
    on_stack: dict[str, bool] = {}
    result: list[list[str]] = []

    sys.setrecursionlimit(10000)

    def strongconnect(v: str):
        index[v] = index_counter[0]
        lowlink[v] = index_counter[0]
        index_counter[0] += 1
        stack.append(v)
        on_stack[v] = True
        for w in adj.get(v, ()):  # successors
            if w not in index:
                strongconnect(w)
                lowlink[v] = min(lowlink[v], lowlink[w])
            elif on_stack.get(w):
                lowlink[v] = min(lowlink[v], index[w])
        if lowlink[v] == index[v]:
            comp = []
            while True:
                w = stack.pop()
                on_stack[w] = False
                comp.append(w)
                if w == v:
                    break
            result.append(comp)

    for v in nodes:
        if v not in index:
            strongconnect(v)
    return result


def find_cycles(edges: Counter) -> dict:
    """Return 2-cycles + SCCs (size>=2 or self-loop) from the edge set."""
    adj: dict[str, set[str]] = defaultdict(set)
    nodes: set[str] = set()
    for (a, b) in edges:
        adj[a].add(b)
        nodes.add(a); nodes.add(b)
    # 2-cycles: A->B and B->A both present.
    two_cycles = []
    for (a, b) in edges:
        if a < b and (b, a) in edges:
            two_cycles.append({
                "locks": [a, b],
                "weight_ab": edges[(a, b)], "weight_ba": edges[(b, a)],
            })
    # SCCs with a real cycle (size>=2, or a self-loop).
    sccs = _tarjan_sccs(nodes, adj)
    cyclic_sccs = []
    for comp in sccs:
        if len(comp) >= 2 or (len(comp) == 1 and comp[0] in adj.get(comp[0], set())):
            # edges internal to this SCC
            cs = set(comp)
            internal = [
                {"outer": a, "inner": b, "weight": edges[(a, b)]}
                for (a, b) in edges if a in cs and b in cs
            ]
            cyclic_sccs.append({"locks": sorted(comp), "size": len(comp),
                                "internal_edges": sorted(internal,
                                                          key=lambda e: e["weight"])})
    return {"two_cycles": two_cycles, "cyclic_sccs": cyclic_sccs}


def rank_inversions(
    cycles: dict, edges: Counter, prov: dict, *, min_dominant_weight: int = 2,
) -> list[dict]:
    """For each 2-cycle, the minority-weight edge is the inversion lead.

    `min_dominant_weight` suppresses low-confidence 1-vs-1 cycles: an inversion
    is only interesting if it deviates from a *strongly-established* order, so we
    require the dominant edge to have ≥ this many independent sites. A 1-vs-1
    cycle (susp 0.50 floor) is almost always a scanner artifact (a macro-hidden
    acquire or a branch-insensitive false nesting), not a real ordering bug.
    """
    leads: list[dict] = []
    suppressed = 0
    for tc in cycles["two_cycles"]:
        a, b = tc["locks"]
        wab, wba = tc["weight_ab"], tc["weight_ba"]
        if wab == wba:
            minority, majority = (a, b), (b, a)  # arbitrary tiebreak
            min_w, maj_w = wab, wba
        elif wab < wba:
            minority, majority, min_w, maj_w = (a, b), (b, a), wab, wba
        else:
            minority, majority, min_w, maj_w = (b, a), (a, b), wba, wab
        if maj_w < min_dominant_weight:
            suppressed += 1
            continue
        total = min_w + maj_w
        leads.append({
            "kind": "2-cycle",
            "dominant_order": f"{majority[0]} -> {majority[1]}",
            "dominant_weight": maj_w,
            "inversion_order": f"{minority[0]} -> {minority[1]}",
            "inversion_weight": min_w,
            "suspicion": round(1 - (min_w / total), 4) if total else 0.0,
            "inversion_sites": prov.get(minority, []),
        })
    leads.sort(key=lambda l: -l["suspicion"])
    return leads, suppressed


# --------------------------------------------------------------------------- #
# Driver
# --------------------------------------------------------------------------- #

def mine_lock_order(source_root: Path, scope: str, target: str,
                    min_dominant_weight: int = 2) -> dict:
    scope_root = (source_root / scope).resolve()
    files = list_c_sources(scope_root)
    fn_starts = ctags_function_starts(files, source_root)
    all_pairs: list[dict] = []
    funcs_with_nesting = 0
    for relpath, starts in fn_starts.items():
        try:
            text = (source_root / relpath).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        bodies = parse_function_bodies(text, starts)
        for caller, body in bodies.items():
            start_line = next((sl for (nm, sl) in starts if nm == caller), 1)
            pairs = extract_pairs_from_function(caller, body, start_line, relpath)
            if pairs:
                funcs_with_nesting += 1
            all_pairs.extend(pairs)

    edges, prov = build_graph(all_pairs)
    cycles = find_cycles(edges)
    leads, suppressed = rank_inversions(
        cycles, edges, prov, min_dominant_weight=min_dominant_weight)
    # Top lock-order edges by weight (the established conventions).
    top_edges = sorted(edges.items(), key=lambda kv: -kv[1])[:25]
    return {
        "target": target, "scope": scope,
        "generated_at": int(time.time()),
        "min_dominant_weight": min_dominant_weight,
        "stats": {
            "ordered_pairs": len(all_pairs),
            "distinct_edges": len(edges),
            "lock_classes": len({n for e in edges for n in e}),
            "functions_with_nested_locking": funcs_with_nesting,
            "two_cycles": len(cycles["two_cycles"]),
            "cyclic_sccs": len(cycles["cyclic_sccs"]),
            "inversion_leads": len(leads),
            "low_confidence_cycles_suppressed": suppressed,
        },
        "inversion_leads": leads,
        "cyclic_sccs": cycles["cyclic_sccs"],
        "top_order_edges": [
            {"outer": a, "inner": b, "weight": w} for (a, b), w in top_edges
        ],
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Lock-order mining (static lockdep).")
    ap.add_argument("--source-root", required=True, type=Path)
    ap.add_argument("--scope", required=True, type=str)
    ap.add_argument("--target", required=True, type=str)
    ap.add_argument("--min-dominant-weight", type=int, default=2,
                    help="Require the dominant order to have >= N sites before "
                         "reporting an inversion (suppresses 1-vs-1 artifacts).")
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args(argv)

    src = args.source_root.resolve()
    if not (src / args.scope).is_dir():
        ap.error(f"scope not found: {src / args.scope}")
    doc = mine_lock_order(src, args.scope, args.target,
                          min_dominant_weight=args.min_dominant_weight)

    here = Path(__file__).resolve().parent
    out_dir = here / "lock_order"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = args.out or out_dir / f"{args.target}.json"
    out_path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")

    s = doc["stats"]
    print(f"[lock-order] {s['ordered_pairs']} ordered pairs, {s['distinct_edges']} edges, "
          f"{s['lock_classes']} lock classes; "
          f"{s['two_cycles']} 2-cycles, {s['cyclic_sccs']} cyclic SCCs, "
          f"{s['inversion_leads']} inversion leads")
    for l in doc["inversion_leads"][:6]:
        site = l["inversion_sites"][0] if l["inversion_sites"] else {}
        print(f"  susp={l['suspicion']:.2f} dominant[{l['dominant_order']} x{l['dominant_weight']}] "
              f"INVERSION[{l['inversion_order']} x{l['inversion_weight']}] "
              f"@ {site.get('file','?')}:{site.get('line','?')} ({site.get('caller','?')})")
    for scc in doc["cyclic_sccs"][:3]:
        if scc["size"] >= 3:
            print(f"  SCC (size {scc['size']}): {' '.join(scc['locks'])}")
    print(f"[lock-order] -> {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
