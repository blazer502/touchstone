"""Stage A0 — design-pattern-aligned task decomposition.

PLAN §2 Stage A0: split a C source tree into independent analysis tasks,
cut along subsystem/implementation-pattern boundaries. Each task is a
cluster of related sources analyzed together; clusters become the unit
of compositional verification + proof-cache memoization in Stage B.

Phase 1 rule: NO LLM — clustering and labeling are heuristic-only.
LLM-assisted re-clustering / re-labeling is a Phase 3 extension.

Soundness note: any partition is sound as long as contracts at task
boundaries are themselves verified (PLAN §2). The heuristics here only
affect *quality* of the cuts (how small/clean tasks are), not soundness.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable


PATTERN_REGEX: dict[str, re.Pattern[str]] = {
    "ops_vtable": re.compile(
        r"static\s+(?:const\s+)?struct\s+\w+\s+\w+\s*=\s*\{", re.MULTILINE
    ),
    "container_of": re.compile(r"\bcontainer_of\s*\("),
    "refcount": re.compile(
        r"\b(?:refcount_(?:inc|dec|add|sub|set)|kref_(?:get|put|init)|"
        r"atomic_(?:inc|dec)_(?:and_test|return)|put_net|get_net)\b"
    ),
    "rcu": re.compile(
        r"\b(?:rcu_read_(?:lock|unlock)|rcu_dereference(?:_protected|_check)?|"
        r"rcu_assign_pointer|synchronize_rcu|call_rcu)\b"
    ),
    "allocator": re.compile(
        r"\b(?:k[mz]alloc(?:_node)?|kcalloc|krealloc|kfree(?:_rcu)?|"
        r"kmem_cache_(?:create|alloc|free|destroy)|vmalloc|vfree)\b"
    ),
    "parser_sm": re.compile(
        r"\b(?:nla_parse(?:_nested)?|nlmsg_parse|nla_for_each_\w+|"
        r"netlink_(?:dump_start|rcv)|switch\s*\(\s*\w*state)\b"
    ),
}

# Common false-positive call sites we want to drop from the callee graph.
CALL_REGEX = re.compile(r"\b([a-zA-Z_][a-zA-Z0-9_]{2,})\s*\(")
CALL_BLACKLIST = {
    "if", "while", "for", "switch", "sizeof", "return", "do",
    "__builtin_expect", "likely", "unlikely",
    "min", "max", "min_t", "max_t", "ARRAY_SIZE", "BUG_ON", "WARN_ON",
    "WARN", "BUG", "pr_info", "pr_err", "pr_warn", "pr_debug", "printk",
    "BUILD_BUG_ON", "IS_ERR", "PTR_ERR", "ERR_PTR", "IS_ERR_OR_NULL",
    "offsetof", "typeof", "__typeof__", "static_assert",
}


def list_c_sources(scope_root: Path) -> list[Path]:
    """Return all .c files under scope_root, sorted."""
    return sorted(p for p in scope_root.rglob("*.c") if p.is_file())


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def label_patterns(text: str) -> dict[str, int]:
    """Count occurrences per pattern in a file's text."""
    return {name: len(rx.findall(text)) for name, rx in PATTERN_REGEX.items()}


def cluster_key(rel_path: Path, scope_root_name: str) -> str:
    """Pick a cluster key for a source file.

    Subdirectories under the scope root form their own clusters.
    Files in the scope root itself are grouped by filename prefix
    (first 1-2 underscore-separated tokens, e.g. nft_, nf_conntrack_).
    """
    parts = rel_path.parts
    if len(parts) > 1:
        # Subdirectory-rooted file: cluster by immediate subdir.
        return parts[0]
    stem = rel_path.stem
    tokens = stem.split("_")
    if len(tokens) >= 3 and tokens[0] in {"nf", "nft", "ip", "tcp", "udp"}:
        # Two-token prefix for the chunky kernel families.
        return f"{tokens[0]}_{tokens[1]}"
    if len(tokens) >= 2:
        return tokens[0]
    return stem


def extract_functions(files: list[Path], source_root: Path) -> dict[str, list[str]]:
    """Return {function_name: [relpath, ...]} via universal-ctags."""
    if not files:
        return {}
    cmd = ["ctags", "--c-kinds=f", "-x", "-L", "-"]
    rel_inputs = "\n".join(str(f.relative_to(source_root)) for f in files)
    proc = subprocess.run(
        cmd, input=rel_inputs, cwd=source_root,
        text=True, capture_output=True, check=False,
    )
    if proc.returncode != 0:
        sys.stderr.write(f"ctags failed: {proc.stderr[:500]}\n")
        return {}
    out: dict[str, list[str]] = defaultdict(list)
    for line in proc.stdout.splitlines():
        # Format: NAME KIND LINE FILE SIGNATURE
        m = re.match(r"^(\S+)\s+function\s+\d+\s+(\S+)\s", line)
        if m:
            out[m.group(1)].append(m.group(2))
    return out


def extract_calls(text: str, defined: set[str]) -> set[str]:
    """Return callees found in text that match a known definition."""
    return {
        name for name in CALL_REGEX.findall(text)
        if name in defined and name not in CALL_BLACKLIST
    }


def file_record(path: Path, source_root: Path, text: str) -> dict:
    rel = str(path.relative_to(source_root))
    return {
        "path": rel,
        "loc": text.count("\n") + 1,
        "patterns": label_patterns(text),
    }


def assemble_clusters(
    files: list[Path],
    source_root: Path,
    scope_root: Path,
) -> dict[str, dict]:
    scope_rel = scope_root.relative_to(source_root)
    scope_name = scope_rel.name or str(scope_rel)

    clusters: dict[str, dict] = {}
    file_text: dict[str, str] = {}
    file_pattern: dict[str, dict[str, int]] = {}
    file_cluster: dict[str, str] = {}

    for f in files:
        rel_to_scope = f.relative_to(scope_root)
        key = cluster_key(rel_to_scope, scope_name)
        text = read_text(f)
        file_text[str(f)] = text
        rec = file_record(f, source_root, text)
        file_pattern[str(f)] = rec["patterns"]
        file_cluster[str(f)] = key
        clusters.setdefault(
            key,
            {
                "cluster": key,
                "scope": str(scope_rel),
                "sources": [],
                "loc": 0,
                "pattern_totals": Counter(),
                "exports": [],
                "callees_internal": [],
                "callees_external": defaultdict(int),
            },
        )
        clusters[key]["sources"].append(rec)
        clusters[key]["loc"] += rec["loc"]
        clusters[key]["pattern_totals"].update(rec["patterns"])

    # ctags pass over the whole file set so callees can resolve across clusters.
    fn_to_files = extract_functions(files, source_root)
    defined_names = set(fn_to_files.keys())
    # File -> cluster lookup by relative path (ctags reports relative paths).
    relpath_cluster: dict[str, str] = {}
    for f in files:
        relpath_cluster[str(f.relative_to(source_root))] = file_cluster[str(f)]

    # Tag exports per cluster.
    cluster_exports: dict[str, set[str]] = defaultdict(set)
    fn_cluster: dict[str, set[str]] = defaultdict(set)
    for name, paths in fn_to_files.items():
        for p in paths:
            c = relpath_cluster.get(p)
            if c is None:
                continue
            cluster_exports[c].add(name)
            fn_cluster[name].add(c)

    # Walk each file once more for the callee edges.
    for f in files:
        c = file_cluster[str(f)]
        text = file_text[str(f)]
        calls = extract_calls(text, defined_names)
        for callee in calls:
            target_clusters = fn_cluster.get(callee, ())
            for tc in target_clusters:
                if tc == c:
                    clusters[c]["callees_internal"].append(callee)
                else:
                    clusters[c]["callees_external"][tc] += 1

    # Finalize.
    for key, cl in clusters.items():
        cl["pattern_totals"] = dict(cl["pattern_totals"])
        cl["exports"] = sorted(cluster_exports[key])
        cl["export_count"] = len(cl["exports"])
        cl["callees_internal"] = sorted(set(cl["callees_internal"]))
        cl["callees_external"] = dict(cl["callees_external"])
        cl["dominant_patterns"] = [
            n for n, v in sorted(cl["pattern_totals"].items(),
                                 key=lambda kv: -kv[1]) if v > 0
        ][:3]

    return clusters


def write_outputs(
    clusters: dict[str, dict],
    out_dir: Path,
    target: str,
    source_root: Path,
    scope: str,
) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    for key, cl in clusters.items():
        safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", key)
        (out_dir / f"{safe}.json").write_text(json.dumps(cl, indent=2) + "\n")

    index = {
        "target": target,
        "source_root": str(source_root),
        "scope": scope,
        "generated_at": int(time.time()),
        "cluster_count": len(clusters),
        "source_count": sum(len(c["sources"]) for c in clusters.values()),
        "total_loc": sum(c["loc"] for c in clusters.values()),
        "clusters": [
            {
                "cluster": c["cluster"],
                "source_count": len(c["sources"]),
                "loc": c["loc"],
                "export_count": c["export_count"],
                "dominant_patterns": c["dominant_patterns"],
                "fanout_external": sum(c["callees_external"].values()),
                "depends_on": sorted(c["callees_external"].keys()),
            }
            for c in sorted(clusters.values(), key=lambda x: -x["loc"])
        ],
    }
    index_path = out_dir / "_index.json"
    index_path.write_text(json.dumps(index, indent=2) + "\n")
    return index_path


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Stage A0 decomposer.")
    ap.add_argument("--source-root", required=True, type=Path,
                    help="Top of the source tree (e.g. linux/source).")
    ap.add_argument("--scope", required=True, type=str,
                    help="Subpath inside source-root to decompose "
                         "(e.g. net/netfilter).")
    ap.add_argument("--target", required=True, type=str,
                    help="Output directory name under surface/tasks/.")
    ap.add_argument("--out-root", type=Path,
                    default=Path(__file__).resolve().parent / "tasks",
                    help="Where {target}/ goes. Default: surface/tasks/.")
    args = ap.parse_args(argv)

    source_root = args.source_root.resolve()
    scope_root = (source_root / args.scope).resolve()
    if not scope_root.is_dir():
        ap.error(f"scope not found: {scope_root}")

    files = list_c_sources(scope_root)
    if not files:
        ap.error(f"no .c files under {scope_root}")

    clusters = assemble_clusters(files, source_root, scope_root)
    out_dir = args.out_root / args.target
    index_path = write_outputs(clusters, out_dir, args.target, source_root, args.scope)

    print(f"decomposed {len(files)} sources -> "
          f"{len(clusters)} clusters in {out_dir}")
    print(f"index: {index_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
