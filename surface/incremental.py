"""Incremental analysis driver (P5).

Given a set of changed files (e.g. from `git diff`), compute the minimal
re-verification work required: which clusters contain the changes, then which
clusters transitively depend on them. Use that to:

  - print the set of units the caller must re-verify
  - mark prior cache rows for those units `stale` (with a reason that
    references the changed file list — auditable)

The cluster index produced in Phase 1.1 (`surface/tasks/<target>/_index.json`)
is the dependency oracle; the proof_cache `transitive_dependents` helper does
the BFS. This module wraps that plumbing into a runnable driver and adds the
file → cluster mapping piece that wasn't needed for Phase 1.4 (which keyed by
explicit unit names).

CLI:

    # list units that need re-verification when these files change
    python3 -m surface.incremental impacted \\
        --target linux-6.1.72-netfilter \\
        --changed net/netfilter/nft_immediate.c net/netfilter/nf_tables_core.c

    # against the actual git diff (HEAD~1..HEAD)
    python3 -m surface.incremental impacted-git \\
        --target linux-6.1.72-netfilter \\
        --from HEAD~1 --to HEAD \\
        --strip-prefix linux/source/

    # mark cached rows stale for the impacted units
    python3 -m surface.incremental invalidate \\
        --target linux-6.1.72-netfilter \\
        --changed net/netfilter/nft_immediate.c
"""
from __future__ import annotations

import argparse
import json
import logging
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable, List, Optional

from surface import proof_cache as pc


REPO_ROOT = Path(__file__).resolve().parents[1]
log = logging.getLogger("incremental")


# --- model -------------------------------------------------------------------

@dataclass
class ImpactReport:
    target: str
    changed_files: List[str]
    matched_clusters: List[str]      # clusters that directly contain a changed file
    dependent_clusters: List[str]    # clusters that transitively depend
    impacted_units: List[str]        # exports of {matched ∪ dependent}
    unmatched_files: List[str]       # changed files not mapped to any cluster
    source_root_hint: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


# --- core --------------------------------------------------------------------

def _load_target(target: str) -> dict:
    """Read `surface/tasks/<target>/_index.json` + every cluster's full file list.

    Returns:
        {
            "source_root": str,
            "clusters_by_name": {name: cluster_json},
            "clusters_by_file": {file_path: cluster_name},
            "graph": pc.load_dep_graph(target)  # for transitive_dependents
        }
    """
    base = REPO_ROOT / "surface" / "tasks" / target
    idx_path = base / "_index.json"
    if not idx_path.exists():
        raise FileNotFoundError(f"no cluster index at {idx_path}")
    idx = json.loads(idx_path.read_text())

    by_name: dict[str, dict] = {}
    by_file: dict[str, str] = {}
    for summary in idx.get("clusters", []):
        cname = summary["cluster"]
        cluster_path = base / f"{cname}.json"
        if not cluster_path.exists():
            continue
        cdata = json.loads(cluster_path.read_text())
        by_name[cname] = cdata
        for src in cdata.get("sources", []):
            path = src.get("path") if isinstance(src, dict) else src
            if path:
                by_file[path] = cname

    return {
        "source_root": idx.get("source_root", ""),
        "clusters_by_name": by_name,
        "clusters_by_file": by_file,
        "graph": pc.load_dep_graph(target),
    }


def _normalise_changed(changed: Iterable[str], strip_prefix: str = "") -> List[str]:
    out: List[str] = []
    for c in changed:
        c = c.strip()
        if not c:
            continue
        if strip_prefix and c.startswith(strip_prefix):
            c = c[len(strip_prefix):]
        out.append(c)
    return out


def impacted(target: str, changed_files: Iterable[str], *,
             strip_prefix: str = "") -> ImpactReport:
    """Compute the cluster + unit impact of a set of changed source files."""
    info = _load_target(target)
    changed = _normalise_changed(changed_files, strip_prefix)

    matched: set[str] = set()
    unmatched: list[str] = []
    for f in changed:
        c = info["clusters_by_file"].get(f)
        if c:
            matched.add(c)
        else:
            unmatched.append(f)

    # Transitive cluster dependents.
    g = info["graph"] or {"clusters": []}
    clusters = {c["cluster"]: c for c in g.get("clusters", [])}
    rev: dict[str, set[str]] = {}
    for c in clusters.values():
        for dep in c.get("depends_on", []):
            rev.setdefault(dep, set()).add(c["cluster"])
    dependent: set[str] = set()
    front = set(matched)
    while front:
        nxt: set[str] = set()
        for cl in front:
            for parent in rev.get(cl, ()):
                if parent not in dependent and parent not in matched:
                    dependent.add(parent)
                    nxt.add(parent)
        front = nxt

    impacted_units: set[str] = set()
    for cl in matched | dependent:
        for u in clusters.get(cl, {}).get("exports", []):
            impacted_units.add(u)

    return ImpactReport(
        target=target,
        changed_files=list(changed),
        matched_clusters=sorted(matched),
        dependent_clusters=sorted(dependent),
        impacted_units=sorted(impacted_units),
        unmatched_files=sorted(unmatched),
        source_root_hint=info["source_root"],
    )


def invalidate_cache_for(report: ImpactReport, *, root: Path = pc.CACHE_ROOT) -> dict:
    """Mark every cache row whose `verdict["unit"]` appears in `impacted_units` as stale.

    Conservative — relies on units appearing in verdict dicts. We don't rebuild
    a unit→key index because cache rows already record the unit in the verdict,
    so a scan-and-mark pass is cheap relative to re-verification cost.
    """
    units = set(report.impacted_units)
    if not units:
        return {"scanned": 0, "marked_stale": 0}
    scanned = marked = 0
    for p in root.rglob("*.json"):
        scanned += 1
        try:
            row = json.loads(p.read_text())
        except Exception:
            continue
        if row.get("stale"):
            continue
        unit = row.get("verdict", {}).get("unit") or row.get("key", {}).get("unit")
        if unit in units:
            row["stale"] = True
            row["stale_reason"] = (
                f"incremental: file change in {report.target}; "
                f"impacted_units include {unit}"
            )
            p.write_text(json.dumps(row, indent=2))
            marked += 1
    return {"scanned": scanned, "marked_stale": marked}


# --- git integration --------------------------------------------------------

def changed_files_from_git(git_from: str = "HEAD~1", git_to: str = "HEAD",
                           git_dir: Optional[Path] = None) -> List[str]:
    cmd = ["git", "diff", "--name-only", f"{git_from}..{git_to}"]
    git_dir = git_dir or REPO_ROOT
    r = subprocess.run(cmd, capture_output=True, text=True, cwd=git_dir, check=False)
    if r.returncode != 0:
        raise RuntimeError(f"git diff failed: {r.stderr.strip()}")
    return [l for l in r.stdout.splitlines() if l.strip()]


# --- CLI --------------------------------------------------------------------

def _cmd_impacted(args) -> int:
    report = impacted(args.target, args.changed, strip_prefix=args.strip_prefix)
    out = json.dumps(report.to_dict(), indent=2)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(out)
    print(out)
    return 0


def _cmd_impacted_git(args) -> int:
    changed = changed_files_from_git(args.git_from, args.git_to)
    report = impacted(args.target, changed, strip_prefix=args.strip_prefix)
    out = json.dumps(report.to_dict(), indent=2)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(out)
    print(out)
    return 0


def _cmd_invalidate(args) -> int:
    if args.changed:
        report = impacted(args.target, args.changed, strip_prefix=args.strip_prefix)
    else:
        changed = changed_files_from_git(args.git_from, args.git_to)
        report = impacted(args.target, changed, strip_prefix=args.strip_prefix)
    res = invalidate_cache_for(report, root=args.cache_root)
    out = {**res, "impact": report.to_dict()}
    print(json.dumps(out, indent=2))
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Incremental analysis driver (P5)")
    ap.add_argument("--target", required=True,
                    help="surface/tasks/<target> cluster index name")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("impacted")
    sp.add_argument("--changed", nargs="+", required=True)
    sp.add_argument("--strip-prefix", default="")
    sp.add_argument("--out", default=None)
    sp.set_defaults(func=_cmd_impacted)

    sp = sub.add_parser("impacted-git")
    sp.add_argument("--git-from", default="HEAD~1")
    sp.add_argument("--git-to", default="HEAD")
    sp.add_argument("--strip-prefix", default="")
    sp.add_argument("--out", default=None)
    sp.set_defaults(func=_cmd_impacted_git)

    sp = sub.add_parser("invalidate", help="mark impacted units' cache rows stale")
    sp.add_argument("--changed", nargs="*", default=None,
                    help="optional explicit file list; omit to use git diff")
    sp.add_argument("--git-from", default="HEAD~1")
    sp.add_argument("--git-to", default="HEAD")
    sp.add_argument("--strip-prefix", default="")
    sp.add_argument("--cache-root", type=Path, default=pc.CACHE_ROOT)
    sp.set_defaults(func=_cmd_invalidate)

    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
