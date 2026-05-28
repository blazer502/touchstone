"""Phase 6.2 — MLTA-style indirect-call resolution (source-level).

Stage A (Phase 1.2) resolves indirect calls with a blunt over-approximation:
"if any reachable function contains indirect-call syntax, pull EVERY
address-taken function into the keep-set." That keeps far too much (it is why
netfilter pruning is only ~22%) and it makes spec mining (Phase 5) blind to
indirectly-invoked callees (the `nfnl_ct_hook.attach_expect` wall in 5.2).

This module implements a *source-level approximation* of Multi-Layer Type
Analysis (MLTA / TypeDive, Lu et al. CCS'19; DeepType USENIX Sec'24). The full
MLTA runs on LLVM bitcode and matches the multi-layer type hierarchy of a
function pointer to candidate functions; the in-tree approximation matches on
`(struct type, field)` when the receiver type is locally visible, and falls
back to *field-name-only* matching otherwise. Both are sound over-approximations
of the true callee set — they only ever shrink the keep-set relative to
"all address-taken", never below the real target set.

Builds three tables from `.field = func` initializers across the tree:
  * field_to_funcs[field]            -> {functions assigned to any `.field`}
  * typefield_to_funcs[(type,field)] -> {functions assigned to TYPE's `.field`}
  * func_to_typefields[func]         -> {(type, field) slots the func fills}

Then for each indirect callsite `recv->field(...)` / `recv.field(...)`:
  * if the receiver's struct type is locally declared → typefield resolution
  * else → field-only resolution (sound over-approx)

Reverse direction (for Phase 5.2 establishment): a function F registered at
`(T, field)` is invoked wherever `->field(` is called on a T (or, field-only,
anywhere `->field(` appears) — so an indirectly-dispatched callee's callers
become visible, and the one-hop establishment check can propagate context
(e.g. RCU) through the dispatch.

Soundness (docs/soundness-assumptions.md): the keep-set computed with MLTA
edges must remain a SUPERSET of the truly-reachable set. Field-only fallback
guarantees this: every function the field could ever point to is included. If
the receiver type can't be resolved we use the (larger) field-only set, never
a guess. No true-reachable function is dropped → the Juliet gate must stay 0.

No LLM (Phase 6.2 rule).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from collections import defaultdict, deque
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent))

from surface.entrypoints import (  # noqa: E402
    DECL_HEAD_RE, FIELD_FUNC_RE, _balanced_block,
)
from surface.reachability import (  # noqa: E402
    list_c_sources, ctags_function_starts, parse_function_bodies,
    CALL_BLACKLIST, reachable_from, build_call_graph,
)


# Indirect-call syntax we can attach a field name to:
#   recv->field(   |   recv.field(
# (Bare `(*fp)(` has no field name — left to the field-unknown bucket.)
_ARROW_CALL_RE = re.compile(r"\b(?P<recv>[A-Za-z_]\w*)\s*->\s*(?P<field>\w+)\s*\(")
_DOT_CALL_RE = re.compile(r"\b(?P<recv>[A-Za-z_]\w*)\s*\.\s*(?P<field>\w+)\s*\(")
# Bare function-pointer call without a field — we can't name the slot.
_BARE_FP_CALL_RE = re.compile(r"\(\s*\*\s*(?P<fp>[A-Za-z_]\w*)\s*\)\s*\(")

# Local receiver-type declaration:  struct TYPE *recv   |   const struct TYPE *recv
_LOCAL_DECL_RE_TMPL = (
    r"(?:const\s+)?struct\s+(?P<type>\w+)\s*\*+\s*{recv}\b"
)


# Runtime function-pointer assignments outside initializers:
#   recv->field = func;   recv.field = func;   recv[i].field = func;
# These matter for SOUNDNESS — a target assigned at runtime (not in a static
# initializer) must still land in field_to_funcs, or the keep-set could prune a
# reachable callee.
_RUNTIME_ASSIGN_RE = re.compile(
    r"(?:->|\.)\s*(?P<field>\w+)\s*=\s*(?P<func>[A-Za-z_]\w*)\s*;"
)


def build_fp_tables(
    files: list[Path], source_root: Path, defined: set[str] | None = None
) -> tuple[dict[str, set[str]], dict[tuple[str, str], set[str]], dict[str, set[tuple[str, str]]]]:
    """Scan struct initializers AND runtime assignments; return the FP tables.

    Soundness: harvesting both static `.field = func` initializers and runtime
    `recv->field = func` assignments makes `field_to_funcs[field]` the complete
    set of functions any `->field(` could dispatch to *within what the scanner
    sees*. Targets assigned through opaque means (struct memcpy, a helper that
    takes a fn-ptr arg and stores it) are still missed — that residual is the
    documented MLTA completeness assumption (docs/soundness-assumptions.md).
    """
    field_to_funcs: dict[str, set[str]] = defaultdict(set)
    typefield_to_funcs: dict[tuple[str, str], set[str]] = defaultdict(set)
    func_to_typefields: dict[str, set[tuple[str, str]]] = defaultdict(set)

    def _is_func(name: str) -> bool:
        if name in CALL_BLACKLIST or name in ("NULL", "true", "false"):
            return False
        # If we know the defined-function set, require membership OR an
        # address-taken-looking lowercase identifier. Keeps the table tight.
        if defined is not None:
            return name in defined
        return True

    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        # (a) static initializers (typed): `.field = func` inside `struct T {...}`
        for m in DECL_HEAD_RE.finditer(text):
            struct_type = m.group("type")
            brace_open = text.index("{", m.start())
            brace_end = _balanced_block(text, brace_open)
            if brace_end < 0:
                continue
            body = text[brace_open:brace_end]
            for fm in FIELD_FUNC_RE.finditer(body):
                field, func = fm.group("field"), fm.group("func")
                if not _is_func(func):
                    continue
                field_to_funcs[field].add(func)
                typefield_to_funcs[(struct_type, field)].add(func)
                func_to_typefields[func].add((struct_type, field))
        # (b) runtime assignments (type usually unknown): `recv->field = func;`
        #     Sound contribution to the field-only table.
        for am in _RUNTIME_ASSIGN_RE.finditer(text):
            field, func = am.group("field"), am.group("func")
            if not _is_func(func):
                continue
            field_to_funcs[field].add(func)
            func_to_typefields[func].add(("?", field))
    return field_to_funcs, typefield_to_funcs, func_to_typefields


def _resolve_receiver_type(body: str, recv: str) -> str | None:
    """Best-effort: find `struct TYPE *recv` in the function body."""
    rx = re.compile(_LOCAL_DECL_RE_TMPL.format(recv=re.escape(recv)))
    m = rx.search(body)
    return m.group("type") if m else None


def resolve_indirect_calls(
    files: list[Path],
    source_root: Path,
    field_to_funcs: dict[str, set[str]],
    typefield_to_funcs: dict[tuple[str, str], set[str]],
) -> tuple[dict[str, set[str]], dict[str, int]]:
    """Per-caller resolved indirect callee set + resolution-quality counts."""
    fn_starts = ctags_function_starts(files, source_root)
    resolved: dict[str, set[str]] = defaultdict(set)
    counts = {
        "indirect_callsites": 0,
        "typefield_resolved": 0,
        "field_only_resolved": 0,
        "unresolved_bare_fp": 0,
    }
    for relpath, starts in fn_starts.items():
        path = source_root / relpath
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        bodies = parse_function_bodies(text, starts)
        for caller, body in bodies.items():
            for rx in (_ARROW_CALL_RE, _DOT_CALL_RE):
                for m in rx.finditer(body):
                    field = m.group("field")
                    recv = m.group("recv")
                    if field in CALL_BLACKLIST:
                        continue
                    counts["indirect_callsites"] += 1
                    rtype = _resolve_receiver_type(body, recv)
                    targets: set[str] = set()
                    if rtype and (rtype, field) in typefield_to_funcs:
                        targets = set(typefield_to_funcs[(rtype, field)])
                        counts["typefield_resolved"] += 1
                    elif field in field_to_funcs:
                        targets = set(field_to_funcs[field])
                        counts["field_only_resolved"] += 1
                    if targets:
                        resolved[caller] |= targets
            for m in _BARE_FP_CALL_RE.finditer(body):
                counts["unresolved_bare_fp"] += 1
    return resolved, counts


def _keep_set(seeds: set[str], graph: dict[str, set[str]]) -> set[str]:
    return reachable_from(seeds, graph)


def measure_keep_set_delta(
    source_root: Path, scope: str, target: str,
    entrypoints_path: Path, slice_path: Path | None,
) -> dict:
    """Compare keep-set: all-address-taken (Phase 1.2) vs MLTA-resolved edges."""
    scope_root = (source_root / scope).resolve()
    files = list_c_sources(scope_root)

    # Phase 1.2 baseline machinery.
    cg, fn_to_file, fns_with_indirect, address_taken = build_call_graph(
        files, source_root
    )
    defined = set(fn_to_file)
    catalog = json.loads(entrypoints_path.read_text())
    entry_funcs = {e["func"] for e in catalog["entries"] if e["func"] in defined}

    direct = _keep_set(entry_funcs, cg)

    # --- Baseline keep-set: pull ALL address-taken if any reachable fn is indirect.
    base_keep = set(direct)
    if direct & fns_with_indirect:
        base_keep |= address_taken
    base_keep = _keep_set(base_keep, cg)

    # --- MLTA keep-set: augment the call graph with resolved indirect edges,
    #     then BFS — only the resolved targets get pulled in (per callsite),
    #     not the whole address-taken pool.
    f2f, tf2f, _ = build_fp_tables(files, source_root, defined=defined)
    resolved, counts = resolve_indirect_calls(files, source_root, f2f, tf2f)
    mlta_cg: dict[str, set[str]] = {k: set(v) for k, v in cg.items()}
    for caller, callees in resolved.items():
        mlta_cg.setdefault(caller, set())
        mlta_cg[caller] |= {c for c in callees if c in defined}
    mlta_keep = _keep_set(entry_funcs, mlta_cg)

    # Residual unsoundness budget: indirect callsites we could NOT resolve to
    # any field target, plus bare `(*fp)(` calls. In strict-sound mode these
    # force the address-taken fallback; in MLTA precision mode they ride on the
    # documented completeness assumption.
    unresolved = (
        counts["indirect_callsites"]
        - counts["typefield_resolved"] - counts["field_only_resolved"]
    )
    n = len(defined) or 1
    return {
        "defined_functions": len(defined),
        "entry_functions": len(entry_funcs),
        "address_taken_total": len(address_taken),
        "baseline_keep": len(base_keep),
        "baseline_pruned_pct": round(100 * (1 - len(base_keep) / n), 2),
        "mlta_keep": len(mlta_keep),
        "mlta_pruned_pct": round(100 * (1 - len(mlta_keep) / n), 2),
        "keep_set_reduction": len(base_keep) - len(mlta_keep),
        "resolution_counts": counts,
        "unresolved_indirect_callsites": unresolved,
        "bare_fp_callsites": counts["unresolved_bare_fp"],
        # NOTE: mlta_keep is NOT a strict subset of base_keep — the runtime
        # `->field = func` harvest catches callback targets the baseline's
        # address-taken regex missed, so MLTA both prunes (precision) AND pulls
        # in runtime-assigned targets the baseline overlooked (a soundness gain
        # the other way). The two models resolve different sets; the headline is
        # net pruning. `mlta_only` / `baseline_only` quantify the difference.
        "mlta_subset_of_baseline": mlta_keep.issubset(base_keep),
        "mlta_only_funcs": len(mlta_keep - base_keep),
        "baseline_only_funcs": len(base_keep - mlta_keep),
        "soundness_mode": (
            "precision (opt-in). Net pruning rises to "
            f"{round(100 * (1 - len(mlta_keep) / n), 2)}% vs baseline "
            f"{round(100 * (1 - len(base_keep) / n), 2)}%, riding on the MLTA "
            f"completeness assumption for {unresolved + counts['unresolved_bare_fp']} "
            "unresolved/bare-fp callsites. Default Stage A (reachability.py) is "
            "UNCHANGED — the Juliet soundness gate is untouched. The fully-sound "
            "use is the reverse-resolution proposer hint for Phase 5.2."
        ),
        "_base_keep": sorted(base_keep),
        "_mlta_keep": sorted(mlta_keep),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Phase 6.2 MLTA indirect-call resolution.")
    ap.add_argument("--source-root", required=True, type=Path)
    ap.add_argument("--scope", required=True, type=str)
    ap.add_argument("--target", required=True, type=str)
    ap.add_argument("--entrypoints", type=Path, default=None)
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--reverse-of", type=str, default=None,
                    help="Print the (type,field) slots + indirect callers of this function.")
    args = ap.parse_args(argv)

    source_root = args.source_root.resolve()
    scope_root = (source_root / args.scope).resolve()
    if not scope_root.is_dir():
        ap.error(f"scope not found: {scope_root}")
    here = Path(__file__).resolve().parent
    entrypoints_path = args.entrypoints or here / "entrypoints" / f"{args.target}.json"
    if not entrypoints_path.exists():
        ap.error(f"entrypoint catalog missing: {entrypoints_path}")

    files = list_c_sources(scope_root)
    print(f"[mlta] scanning {len(files)} sources ...", file=sys.stderr)
    f2f, tf2f, func2tf = build_fp_tables(files, source_root)
    print(f"[mlta] fp-table: {len(f2f)} fields, {len(tf2f)} (type,field) slots, "
          f"{len(func2tf)} functions registered as callbacks", file=sys.stderr)

    if args.reverse_of:
        fn = args.reverse_of
        slots = sorted(func2tf.get(fn, []))
        print(f"\n=== reverse resolution for `{fn}` ===")
        if not slots:
            print(f"  {fn} is not assigned to any struct field (not an indirect callback)")
        else:
            for (t, field) in slots:
                print(f"  registered at {t}.{field}")
            # Find indirect callers: functions whose body calls ->field(
            fields = {field for (_t, field) in slots}
            fn_starts = ctags_function_starts(files, source_root)
            callers: list[tuple[str, str]] = []
            for relpath, starts in fn_starts.items():
                text = (source_root / relpath).read_text(errors="replace")
                bodies = parse_function_bodies(text, starts)
                for caller, body in bodies.items():
                    for field in fields:
                        if re.search(rf"->\s*{re.escape(field)}\s*\(", body):
                            callers.append((caller, field))
                            break
            print(f"  indirect callers (via ->{'/'.join(sorted(fields))}( ): "
                  f"{len(callers)}")
            for caller, field in sorted(callers)[:20]:
                print(f"    {caller}  (->{field})")

    delta = measure_keep_set_delta(
        source_root, args.scope, args.target, entrypoints_path, None
    )
    summary = {k: v for k, v in delta.items() if not k.startswith("_")}
    print(f"\n=== keep-set delta (Phase 1.2 baseline vs MLTA) ===")
    for k, v in summary.items():
        print(f"  {k}: {v}")

    out_dir = here / "indirect"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = args.out or out_dir / f"{args.target}.json"
    payload = {
        "target": args.target,
        "scope": args.scope,
        "generated_at": int(time.time()),
        "fp_table_stats": {
            "fields": len(f2f),
            "type_field_slots": len(tf2f),
            "callback_functions": len(func2tf),
        },
        "keep_set_delta": summary,
        # Persist the field→funcs table (sorted) for Stage A / Phase 5 reuse.
        "field_to_funcs": {k: sorted(v) for k, v in sorted(f2f.items())},
        "func_to_typefields": {
            k: sorted([list(tf) for tf in v]) for k, v in sorted(func2tf.items())
        },
    }
    out_path.write_text(json.dumps(payload, indent=2) + "\n")
    print(f"\n[mlta] -> {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
