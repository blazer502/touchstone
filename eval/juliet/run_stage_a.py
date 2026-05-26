#!/usr/bin/env python3
"""Phase 1.5 — Stage A reachability soundness gate on Juliet C/C++ v1.3.

For each .c file in the subset:
  * Identify Juliet's "extern" testcase entry-points: every non-static function
    whose name matches CWE\d+_..._{bad,good,bad_sink,good*_sink,bad_source,
    good*_source}. These are the externally-invoked test API; main_linux.cpp
    dispatches to them by name and they collectively define the attacker
    interface for the labeled corpus.
  * Each `_bad`, `_bad_sink`, `_bad_source` is a labeled-bug entry — the bug
    lives at or below it in the call graph.

We then reuse surface.reachability.{build_call_graph, reachable_from} to BFS
from the entry set and apply the same indirect-call over-approximation as the
kernel Stage A. Soundness gate (PLAN §2 acceptance):
  * missed_bug_count = number of labeled-bug entries NOT in keep_set.
  * Must be 0 for Phase 1.5 to pass.

Reduction% is also reported: kept = keep_set, total = defined.
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
import time
from pathlib import Path

# Make surface.* importable when run from the repo root.
REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from surface.reachability import (  # noqa: E402
    build_call_graph,
    reachable_from,
)

JULIET_ROOT = REPO / "eval" / "juliet" / "extracted" / "C" / "testcases"
SUBSET_JSON = REPO / "eval" / "juliet" / "subset.json"
OUT_JSON = REPO / "eval" / "juliet" / "stage_a.json"

# Juliet testcase function naming (deliberately permissive — false positives
# only widen the entry set, which is safe for soundness).
#   CWE<num>_<descr>_<suffix>
# Suffix is one of: bad | good | good\w+ | bad_sink | good\w*_sink |
# bad_source | good\w*_source
TESTCASE_FUNC_RE = re.compile(
    r"^(?P<name>CWE\d+_[A-Za-z0-9_]+_("
    r"bad|good[A-Za-z0-9_]*|bad_sink|good[A-Za-z0-9_]*_sink|"
    r"bad_source|good[A-Za-z0-9_]*_source))$"
)
BAD_SUFFIX_RE = re.compile(r"_(bad|bad_sink|bad_source)$")

# Function definition pattern: optional leading specifiers, return type tokens,
# then name(args). We don't need to be type-perfect — only "is this a non-static
# function definition?". Matches things like:
#   void CWE476_..._01_bad()
#   void CWE476_..._01_bad(int n)
#   static void goodG2B(void)  -> excluded by the leading "static"
FUNC_DEF_RE = re.compile(
    r"(?m)^(?P<prefix>(?:[A-Za-z_]\w*\s+)+)"
    r"(?P<name>[A-Za-z_]\w*)\s*\([^;{]*\)\s*\{?\s*$"
)


def scan_juliet_entrypoints(c_files: list[Path], scope_root: Path) -> dict:
    """Return {entries: [{func, file, kind}], all_bad_funcs: set[str]}."""
    entries: list[dict] = []
    seen: set[str] = set()
    bad: set[str] = set()
    for f in c_files:
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in FUNC_DEF_RE.finditer(text):
            prefix = m.group("prefix") or ""
            name = m.group("name")
            if "static" in prefix.split():
                continue
            tm = TESTCASE_FUNC_RE.match(name)
            if not tm:
                continue
            if name in seen:
                continue
            seen.add(name)
            kind = "good" if name.startswith(name.split("__")[0]) and (
                "good" in name and "bad" not in name
            ) else None
            # Simpler classification:
            if BAD_SUFFIX_RE.search(name):
                kind = "bad"
                bad.add(name)
            elif "_good" in name or name.endswith("_good"):
                kind = "good"
            else:
                kind = "other"
            entries.append({
                "func": name,
                "file": str(f.relative_to(scope_root)),
                "kind": kind,
            })
    return {"entries": entries, "bad_funcs": sorted(bad)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--subset", type=Path, default=SUBSET_JSON)
    ap.add_argument("--out", type=Path, default=OUT_JSON)
    args = ap.parse_args()

    if not JULIET_ROOT.is_dir():
        sys.stderr.write(f"juliet not extracted at {JULIET_ROOT}\n")
        return 2
    if shutil.which("ctags") is None:
        sys.stderr.write("ctags not on PATH\n")
        return 2

    subset = json.loads(args.subset.read_text())
    scope_dirs = [JULIET_ROOT / s for s in subset["stage_a_scope"]]
    for d in scope_dirs:
        if not d.is_dir():
            sys.stderr.write(f"scope dir missing: {d}\n")
            return 2

    files: list[Path] = []
    for d in scope_dirs:
        files.extend(sorted(p for p in d.rglob("*.c") if p.is_file()))
    print(f"[juliet/stageA] {len(files)} .c files across {len(scope_dirs)} CWE scopes",
          file=sys.stderr)

    t0 = time.time()
    cat = scan_juliet_entrypoints(files, JULIET_ROOT)
    entry_funcs = {e["func"] for e in cat["entries"]}
    bad_funcs = set(cat["bad_funcs"])
    print(f"[juliet/stageA] entries={len(entry_funcs)} "
          f"(of which bad={len(bad_funcs)})", file=sys.stderr)

    cg, fn_to_file, fns_with_indirect, address_taken = build_call_graph(
        files, JULIET_ROOT,
    )
    defined = set(fn_to_file.keys())
    print(f"[juliet/stageA] defined={len(defined)} indirect={len(fns_with_indirect)} "
          f"address_taken={len(address_taken)}", file=sys.stderr)

    # In-scope entries: those that actually have a definition in this scope.
    entries_in_scope = entry_funcs & defined
    direct = reachable_from(entries_in_scope, cg)
    keep_set = set(direct)
    indirect_in_direct = direct & fns_with_indirect
    if indirect_in_direct:
        keep_set |= address_taken
    keep_set = reachable_from(keep_set, cg)

    # Soundness gate: every labeled-bug entry must be in keep_set.
    bad_in_scope = bad_funcs & defined
    bad_missed = sorted(bad_in_scope - keep_set)
    missed_bug_count = len(bad_missed)

    reduction = 1.0 - (len(keep_set) / len(defined) if defined else 0.0)
    elapsed_ms = int((time.time() - t0) * 1000)

    out = {
        "phase": "1.5",
        "stage": "A",
        "generated_at": int(time.time()),
        "scope": subset["stage_a_scope"],
        "stats": {
            "c_files": len(files),
            "defined_functions": len(defined),
            "entry_functions": len(entries_in_scope),
            "labeled_bug_functions": len(bad_in_scope),
            "indirect_call_funcs_in_direct": len(indirect_in_direct),
            "address_taken_total": len(address_taken),
            "keep_set": len(keep_set),
            "pruned": len(defined) - len(keep_set),
            "reduction": round(reduction, 4),
            "soundness_overapprox_applied": bool(indirect_in_direct),
            "missed_bug_count": missed_bug_count,
            "elapsed_ms": elapsed_ms,
        },
        "missed_bugs": bad_missed,
    }
    args.out.write_text(json.dumps(out, indent=2) + "\n")
    s = out["stats"]
    print(
        f"keep={s['keep_set']}/{s['defined_functions']} "
        f"({reduction:.1%} pruned) "
        f"bad_in_scope={s['labeled_bug_functions']} missed={missed_bug_count} "
        f"-> {args.out}"
    )
    return 0 if missed_bug_count == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
