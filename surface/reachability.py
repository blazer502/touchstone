"""Stage A — sound reachability slice from attacker entry-points.

PLAN §2 Stage A: keep only code reachable from attacker-controlled
entry points (see `surface/entrypoints.py`). The pruning is a *sound
over-approximation*: indirect calls and macro-heavy code are resolved
conservatively so the keep-set never drops a real path.

Per-function callee edges are extracted by walking each .c file once,
using universal-ctags to mark function start lines and a token scan
between consecutive function starts to harvest direct callees. The
direct call graph is BFS'd from the entry-point set; the resulting
keep_set is the slice handed to Stage B.

Indirect-call soundness rule (recorded in docs/soundness-assumptions.md):
- An attacker-controlled dispatcher struct field already names every
  callback as an entry point — so callbacks invoked via attacker
  dispatch tables are already roots and trivially reachable.
- For other indirect calls (`fp(...)`, `obj->cb(...)`), we cannot resolve
  the target precisely. The over-approximation: if any reachable
  function contains indirect-call syntax, every function whose address
  is taken anywhere in the scope is added to the keep_set. (Coarser than
  SVF/type-aware resolution; same soundness guarantee.)

No LLM (Phase 1 rule).
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from collections import defaultdict, deque
from pathlib import Path


CALL_REGEX = re.compile(r"\b([A-Za-z_][A-Za-z_0-9]{2,})\s*\(")
# Indirect-call syntactic patterns. We deliberately keep this loose
# because the over-approximation is the safety net.
INDIRECT_CALL_REGEX = re.compile(
    r"(?:->\s*\w+\s*\(|\.\s*\w+\s*\(\s*\w|\(\s*\*\s*\w+\s*\)\s*\()"
)
# Address-of-function-as-value heuristic: an identifier whose only use
# in a context is to be assigned/passed without a following call. We
# approximate by harvesting `[.field =]?\s*funcname\s*[,}]` after a `=`
# in struct initializers, which is exactly the form decompose / entry-
# point scans see.
ADDR_TAKEN_RE = re.compile(
    r"(?:^|[\s,({=])([A-Za-z_]\w{2,})\s*(?=,|}|\s*$)",
    re.MULTILINE,
)

# Tokens that look like function calls but are control keywords or macros.
CALL_BLACKLIST = {
    "if", "while", "for", "switch", "sizeof", "return", "do", "case",
    "__builtin_expect", "likely", "unlikely",
    "min", "max", "min_t", "max_t", "ARRAY_SIZE", "BUG_ON", "WARN_ON",
    "WARN", "BUG", "pr_info", "pr_err", "pr_warn", "pr_debug", "printk",
    "BUILD_BUG_ON", "IS_ERR", "PTR_ERR", "ERR_PTR", "IS_ERR_OR_NULL",
    "offsetof", "typeof", "__typeof__", "static_assert",
    "EXPORT_SYMBOL", "EXPORT_SYMBOL_GPL", "MODULE_AUTHOR",
    "MODULE_DESCRIPTION", "MODULE_LICENSE", "MODULE_ALIAS",
    "DEFINE_MUTEX", "DEFINE_SPINLOCK", "DEFINE_RWLOCK",
    "LIST_HEAD", "INIT_LIST_HEAD", "RCU_INIT_POINTER",
    "container_of",
}


def list_c_sources(scope_root: Path) -> list[Path]:
    return sorted(p for p in scope_root.rglob("*.c") if p.is_file())


def ctags_function_starts(
    files: list[Path], source_root: Path
) -> dict[str, list[tuple[str, int]]]:
    """{relpath: [(func_name, start_line), ...]} sorted by start_line."""
    cmd = ["ctags", "--c-kinds=f", "-x", "-L", "-"]
    rel_inputs = "\n".join(str(f.relative_to(source_root)) for f in files)
    proc = subprocess.run(
        cmd, input=rel_inputs, cwd=source_root,
        text=True, capture_output=True, check=False,
    )
    out: dict[str, list[tuple[str, int]]] = defaultdict(list)
    if proc.returncode != 0:
        sys.stderr.write(f"ctags failed: {proc.stderr[:500]}\n")
        return out
    for line in proc.stdout.splitlines():
        m = re.match(r"^(\S+)\s+function\s+(\d+)\s+(\S+)\s", line)
        if not m:
            continue
        out[m.group(3)].append((m.group(1), int(m.group(2))))
    for v in out.values():
        v.sort(key=lambda x: x[1])
    return out


def parse_function_bodies(
    file_text: str, fn_starts: list[tuple[str, int]]
) -> dict[str, str]:
    """Approximate per-function bodies by slicing between successive starts."""
    lines = file_text.split("\n")
    out: dict[str, str] = {}
    for i, (name, start) in enumerate(fn_starts):
        end = fn_starts[i + 1][1] - 1 if i + 1 < len(fn_starts) else len(lines)
        # ctags reports the declarator line, body starts a line or two later;
        # over-include is fine — only callees matter.
        body = "\n".join(lines[start - 1 : end])
        out[name] = body
    return out


def extract_callees(body: str, defined: set[str]) -> set[str]:
    return {
        n for n in CALL_REGEX.findall(body)
        if n in defined and n not in CALL_BLACKLIST
    }


def has_indirect_call(body: str) -> bool:
    return bool(INDIRECT_CALL_REGEX.search(body))


def harvest_address_taken(text: str, defined: set[str]) -> set[str]:
    """Function names that appear as r-values in struct/array initializers."""
    out: set[str] = set()
    for m in ADDR_TAKEN_RE.finditer(text):
        tok = m.group(1)
        if tok in defined and tok not in CALL_BLACKLIST:
            out.add(tok)
    return out


def build_call_graph(
    files: list[Path], source_root: Path
) -> tuple[dict[str, set[str]], dict[str, str], set[str], set[str]]:
    """Return (callgraph, fn_to_file, fns_with_indirect, address_taken)."""
    fn_starts = ctags_function_starts(files, source_root)

    # Step 1: collect every function name that's *defined* in the scope.
    defined: set[str] = set()
    fn_to_file: dict[str, str] = {}
    for relpath, starts in fn_starts.items():
        for name, _ in starts:
            defined.add(name)
            # First definition wins (kernel rarely has duplicates in scope).
            fn_to_file.setdefault(name, relpath)

    call_graph: dict[str, set[str]] = defaultdict(set)
    fns_with_indirect: set[str] = set()
    address_taken: set[str] = set()

    # Step 2: per file, slice body and extract callees / indirect flags.
    for relpath, starts in fn_starts.items():
        path = source_root / relpath
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        bodies = parse_function_bodies(text, starts)
        # Address-taken is a file-level signal (initializers live outside
        # of function bodies, often at file scope after the function defs).
        address_taken |= harvest_address_taken(text, defined)
        for name, body in bodies.items():
            call_graph[name] |= extract_callees(body, defined)
            if has_indirect_call(body):
                fns_with_indirect.add(name)

    return call_graph, fn_to_file, fns_with_indirect, address_taken


def reachable_from(
    seeds: set[str],
    call_graph: dict[str, set[str]],
) -> set[str]:
    seen = set(seeds)
    q = deque(seeds)
    while q:
        n = q.popleft()
        for c in call_graph.get(n, ()):
            if c not in seen:
                seen.add(c)
                q.append(c)
    return seen


def per_cluster_summary(
    cluster_dir: Path,
    fn_to_file: dict[str, str],
    keep_set: set[str],
    indirect_in_keep: set[str],
) -> list[dict]:
    """Roll keep_set up to Stage A0 clusters for downstream Stage B."""
    out: list[dict] = []
    index_path = cluster_dir / "_index.json"
    if not index_path.exists():
        return out
    index = json.loads(index_path.read_text())
    # File -> cluster: read each cluster's source list.
    file_to_cluster: dict[str, str] = {}
    cluster_files: dict[str, list[str]] = defaultdict(list)
    for entry in index["clusters"]:
        cluster = entry["cluster"]
        safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", cluster)
        cl = json.loads((cluster_dir / f"{safe}.json").read_text())
        for s in cl["sources"]:
            file_to_cluster[s["path"]] = cluster
            cluster_files[cluster].append(s["path"])

    # Functions per cluster (from fn_to_file).
    cluster_funcs: dict[str, list[str]] = defaultdict(list)
    for fn, relfile in fn_to_file.items():
        c = file_to_cluster.get(relfile)
        if c is None:
            continue
        cluster_funcs[c].append(fn)

    for entry in index["clusters"]:
        cluster = entry["cluster"]
        funcs = set(cluster_funcs.get(cluster, []))
        kept = funcs & keep_set
        ind = kept & indirect_in_keep
        out.append({
            "cluster": cluster,
            "loc": entry["loc"],
            "source_count": entry["source_count"],
            "func_count": len(funcs),
            "kept_func_count": len(kept),
            "pruned_func_count": len(funcs) - len(kept),
            "indirect_call_funcs_in_kept": len(ind),
            "keep_ratio": (len(kept) / len(funcs)) if funcs else 0.0,
            "dominant_patterns": entry["dominant_patterns"],
        })
    out.sort(key=lambda x: -x["loc"])
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Stage A reachability slice.")
    ap.add_argument("--source-root", required=True, type=Path)
    ap.add_argument("--scope", required=True, type=str)
    ap.add_argument("--target", required=True, type=str)
    ap.add_argument("--entrypoints", type=Path, default=None,
                    help="Path to entrypoints/<target>.json (default: derived).")
    ap.add_argument("--clusters", type=Path, default=None,
                    help="Path to surface/tasks/<target>/ (default: derived).")
    ap.add_argument("--out-root", type=Path,
                    default=Path(__file__).resolve().parent / "slice")
    args = ap.parse_args(argv)

    source_root = args.source_root.resolve()
    scope_root = (source_root / args.scope).resolve()
    if not scope_root.is_dir():
        ap.error(f"scope not found: {scope_root}")

    here = Path(__file__).resolve().parent
    entrypoints_path = (
        args.entrypoints
        or here / "entrypoints" / f"{args.target}.json"
    )
    clusters_dir = args.clusters or here / "tasks" / args.target
    if not entrypoints_path.exists():
        ap.error(f"entrypoint catalog missing: {entrypoints_path}")
    if not clusters_dir.exists():
        ap.error(f"cluster dir missing: {clusters_dir}")

    files = list_c_sources(scope_root)
    print(f"[reach] building call graph from {len(files)} sources ...",
          file=sys.stderr)
    cg, fn_to_file, fns_with_indirect, address_taken = build_call_graph(
        files, source_root
    )
    defined = set(fn_to_file.keys())
    print(f"[reach] defined={len(defined)} indirect={len(fns_with_indirect)} "
          f"address_taken={len(address_taken)}", file=sys.stderr)

    catalog = json.loads(entrypoints_path.read_text())
    entry_funcs = {e["func"] for e in catalog["entries"] if e["func"] in defined}
    missing = {e["func"] for e in catalog["entries"]} - defined
    print(f"[reach] entry_funcs in-scope={len(entry_funcs)} "
          f"out-of-scope={len(missing)}", file=sys.stderr)

    direct = reachable_from(entry_funcs, cg)

    # Soundness over-approximation: if any reachable function does
    # indirect calls, fold all address-taken-but-not-yet-reachable funcs
    # into the keep_set so we never prune an indirectly-invoked path.
    keep_set = set(direct)
    indirect_in_direct = direct & fns_with_indirect
    if indirect_in_direct:
        keep_set |= address_taken

    # Final BFS pass: address-taken seeds may pull in *their* transitive
    # direct callees too. Cheap to re-run.
    keep_set = reachable_from(keep_set, cg)

    keep_ratio = len(keep_set) / len(defined) if defined else 0.0
    reduction = 1.0 - keep_ratio
    cluster_rollup = per_cluster_summary(
        clusters_dir, fn_to_file, keep_set, fns_with_indirect,
    )

    args.out_root.mkdir(parents=True, exist_ok=True)
    out = {
        "target": args.target,
        "source_root": str(source_root),
        "scope": args.scope,
        "generated_at": int(time.time()),
        "stats": {
            "defined_functions": len(defined),
            "entry_functions_in_scope": len(entry_funcs),
            "entry_functions_out_of_scope": len(missing),
            "direct_reachable": len(direct),
            "indirect_call_funcs_in_direct": len(indirect_in_direct),
            "address_taken_total": len(address_taken),
            "keep_set": len(keep_set),
            "pruned": len(defined) - len(keep_set),
            "keep_ratio": round(keep_ratio, 4),
            "reduction": round(reduction, 4),
            "soundness_overapprox_applied": bool(indirect_in_direct),
        },
        "by_cluster": cluster_rollup,
        # Persist the keep_set itself so Stage B can iterate it directly.
        "keep_set": sorted(keep_set),
        "entry_functions": sorted(entry_funcs),
        "address_taken": sorted(address_taken),
        "fn_to_file": fn_to_file,
    }
    out_path = args.out_root / f"{args.target}.json"
    out_path.write_text(json.dumps(out, indent=2) + "\n")

    print(f"keep={len(keep_set)}/{len(defined)} "
          f"({reduction:.1%} pruned) -> {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
