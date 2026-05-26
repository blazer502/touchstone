"""Stage A — ingest static-analyzer findings as Stage-B priority hints.

PLAN §2 Stage A lists Smatch / Coccinelle / Sparse as scoping tools — they
generate *candidate sites* but never make a final exploitability call (PLAN
§8). Here we parse the Phase-0.4 scoping outputs and attach per-function
hints to the slice so Stage B and the agent can rank work by suspect
density. Hints are **priority signals, not soundness levers** — a missing
hint never causes pruning, an extra hint never confirms a bug.

No LLM (Phase 1 rule).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path


# Smatch line: "<path>:<lineno> <func>() warn: <message>"  (also "error:" / "info:")
SMATCH_RE = re.compile(
    r"^(?P<path>[^:\s]+):(?P<line>\d+)\s+(?P<func>[A-Za-z_]\w*)\(\)\s+"
    r"(?P<sev>warn|error|info):\s+(?P<msg>.+)$"
)
# Sparse line: "<path>:<line>:<col>: warning: <message>"
SPARSE_RE = re.compile(
    r"^(?P<path>\.?[A-Za-z_./0-9-]+):(?P<line>\d+):\d+:\s+"
    r"(?P<sev>warning|error):\s+(?P<msg>.+)$"
)


def _strip_leading_dotslash(p: str) -> str:
    return p[2:] if p.startswith("./") else p


def parse_smatch(text: str) -> list[dict]:
    out: list[dict] = []
    for line in text.splitlines():
        m = SMATCH_RE.match(line)
        if not m:
            continue
        out.append({
            "tool": "smatch",
            "path": _strip_leading_dotslash(m.group("path")),
            "line": int(m.group("line")),
            "func": m.group("func"),
            "sev": m.group("sev"),
            "msg": m.group("msg").strip(),
        })
    return out


def parse_sparse(text: str, scope_filter: str | None = None) -> list[dict]:
    out: list[dict] = []
    for line in text.splitlines():
        m = SPARSE_RE.match(line)
        if not m:
            continue
        path = _strip_leading_dotslash(m.group("path"))
        if scope_filter and not path.startswith(scope_filter):
            continue
        out.append({
            "tool": "sparse",
            "path": path,
            "line": int(m.group("line")),
            "func": None,
            "sev": m.group("sev"),
            "msg": m.group("msg").strip(),
        })
    return out


def attach_to_slice(
    slice_doc: dict,
    findings: list[dict],
) -> dict:
    """Aggregate findings per function (where known) and per file."""
    keep = set(slice_doc.get("keep_set", []))
    fn_to_file: dict[str, str] = slice_doc.get("fn_to_file", {})

    per_func: dict[str, Counter] = defaultdict(Counter)
    per_file: dict[str, Counter] = defaultdict(Counter)
    in_keep = 0
    out_of_keep = 0
    by_tool: Counter = Counter()
    by_sev: Counter = Counter()
    skipped_out_of_scope = 0
    fn_files_set = set(fn_to_file.values())
    for f in findings:
        by_tool[f["tool"]] += 1
        by_sev[f["sev"]] += 1
        path = f["path"]
        if path in fn_files_set:
            per_file[path][f["tool"]] += 1
        else:
            skipped_out_of_scope += 1
            continue
        func = f.get("func")
        if func:
            per_func[func][f["tool"]] += 1
            if func in keep:
                in_keep += 1
            else:
                out_of_keep += 1

    slice_doc["static_hints"] = {
        "tools_seen": dict(by_tool),
        "severities": dict(by_sev),
        "total_findings_in_scope": sum(sum(c.values()) for c in per_file.values()),
        "findings_skipped_out_of_scope": skipped_out_of_scope,
        "findings_attached_to_kept_funcs": in_keep,
        "findings_attached_to_pruned_funcs": out_of_keep,
        "per_function_top20": [
            {"func": fn, "counts": dict(c),
             "in_keep_set": fn in keep,
             "file": fn_to_file.get(fn)}
            for fn, c in sorted(per_func.items(),
                                key=lambda kv: -sum(kv[1].values()))[:20]
        ],
        "per_file_top20": [
            {"file": fp, "counts": dict(c)}
            for fp, c in sorted(per_file.items(),
                                key=lambda kv: -sum(kv[1].values()))[:20]
        ],
    }
    return slice_doc


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Stage A static-analyzer hint ingester."
    )
    ap.add_argument("--slice", required=True, type=Path,
                    help="Path to surface/slice/<target>.json (modified in-place).")
    ap.add_argument("--smatch", type=Path, default=None)
    ap.add_argument("--sparse", type=Path, default=None)
    ap.add_argument("--scope", type=str, default=None,
                    help="Restrict sparse findings to paths starting with this.")
    args = ap.parse_args(argv)

    if not args.slice.exists():
        ap.error(f"slice missing: {args.slice}")
    doc = json.loads(args.slice.read_text())

    findings: list[dict] = []
    if args.smatch and args.smatch.exists():
        findings.extend(parse_smatch(args.smatch.read_text()))
    if args.sparse and args.sparse.exists():
        findings.extend(parse_sparse(args.sparse.read_text(),
                                     scope_filter=args.scope))
    if not findings:
        ap.error("no findings parsed")

    doc = attach_to_slice(doc, findings)
    args.slice.write_text(json.dumps(doc, indent=2) + "\n")
    hints = doc["static_hints"]
    print(f"attached {hints['total_findings_in_scope']} findings "
          f"(in-keep={hints['findings_attached_to_kept_funcs']}, "
          f"out-of-keep={hints['findings_attached_to_pruned_funcs']}, "
          f"skipped-out-of-scope={hints['findings_skipped_out_of_scope']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
