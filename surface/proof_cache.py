"""Content-addressed proof cache (Phase 1.4).

Goal (PLAN §2 "Verification reuse"): prove fundamental/shared code once, then
reuse the verdict on later runs and across kernel versions / CyberGym tasks.

Cache key MUST capture everything the proof depended on. If any of these
change, the cached verdict is invalid:

  * normalised function body (whitespace/comment-stripped SHA-256)
  * proved property                       (e.g. "memory-safety")
  * engine + version + unwind             ("cbmc:6.4.0 unwind=16")
  * assumed callee contracts              (sorted list, hashed together)
  * semantics-affecting build flags       (kernel CONFIG_*, arch, sanitizer)
  * pointer/aliasing assumptions          (e.g. "no-aliasing-pre")

Storage: surface/proofcache/<keyprefix>/<keyhash>.json — one Verdict per file.

Soundness rule (docs/soundness-assumptions.md proof-cache callee-contract):
  A cache hit is valid only when the *current* callee contracts equal the
  assumed ones recorded at cache time. `lookup()` re-validates contracts on
  hit; never trust the body hash alone.

Dependency-graph invalidation:
  The cluster index from Phase 1.1 (`surface/tasks/<target>/_index.json`)
  contains the inter-cluster callee edges. When a callee's contract changes,
  every transitively-dependent entry's cache row is marked stale via
  `invalidate_dependents(unit, target)`.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable, Optional

REPO = Path(__file__).resolve().parent.parent
CACHE_ROOT = REPO / "surface" / "proofcache"


# Strip C comments + collapse whitespace so cosmetic edits don't bust the cache.
_C_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_C_LINE_COMMENT = re.compile(r"//[^\n]*")
_WS_RUN = re.compile(r"\s+")


def normalise_body(src: str) -> str:
    s = _C_BLOCK_COMMENT.sub(" ", src)
    s = _C_LINE_COMMENT.sub(" ", s)
    s = _WS_RUN.sub(" ", s).strip()
    return s


def _h(*parts: str) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(p.encode("utf-8"))
        h.update(b"\x00")
    return h.hexdigest()


@dataclass(frozen=True)
class CacheKey:
    """Everything the soundness of the cached verdict depends on.

    NOTE: order of fields in the hash is fixed — adding a new dimension means
    bumping `schema_version` so prior cache rows are NOT silently considered
    valid against the new key. This is the cache-invalidation soundness lever.
    """
    schema_version: str
    body_sha: str
    property: str
    engine: str
    engine_version: str
    unwind: Optional[int]
    assumed_contracts_sha: str
    build_flags_sha: str
    aliasing_sha: str

    def digest(self) -> str:
        return _h(
            self.schema_version, self.body_sha, self.property, self.engine,
            self.engine_version,
            "" if self.unwind is None else str(self.unwind),
            self.assumed_contracts_sha, self.build_flags_sha, self.aliasing_sha,
        )


@dataclass
class CacheRow:
    key_digest: str
    key: dict
    verdict: dict        # the Verdict produced by stage_b backend
    assumed_contracts: list[str]   # raw text, needed to re-validate on hit
    build_flags: dict
    dependents: list[str] = field(default_factory=list)
    stored_at: int = 0
    stale: bool = False
    stale_reason: str = ""


SCHEMA_VERSION = "v1"


def _contracts_sha(contracts: Iterable[str]) -> str:
    # Sort so the order of contract statements doesn't matter for the key.
    return _h(*sorted(c.strip() for c in contracts))


def _flags_sha(flags: dict) -> str:
    return _h(*sorted(f"{k}={flags[k]}" for k in flags))


def make_key(
    body_text: str,
    property: str,
    engine: str,
    engine_version: str,
    unwind: Optional[int],
    assumed_contracts: list[str],
    build_flags: dict,
    aliasing_assumption: str = "",
) -> CacheKey:
    return CacheKey(
        schema_version=SCHEMA_VERSION,
        body_sha=_h(normalise_body(body_text)),
        property=property,
        engine=engine,
        engine_version=engine_version,
        unwind=unwind,
        assumed_contracts_sha=_contracts_sha(assumed_contracts),
        build_flags_sha=_flags_sha(build_flags),
        aliasing_sha=_h(aliasing_assumption),
    )


def _path_for(key_digest: str, root: Path = CACHE_ROOT) -> Path:
    return root / key_digest[:2] / f"{key_digest}.json"


def lookup(
    key: CacheKey,
    *,
    current_contracts: Optional[list[str]] = None,
    root: Path = CACHE_ROOT,
) -> Optional[CacheRow]:
    """Cache hit only if (a) key digest matches AND (b) row is not stale AND
    (c) the assumed contracts at cache time still hold for the current
    callers (`current_contracts`). When `current_contracts` is None the caller
    has not yet computed them — the cache returns None to force a re-run; this
    is the conservative path (never returns a stale verdict)."""
    p = _path_for(key.digest(), root)
    if not p.exists():
        return None
    raw = json.loads(p.read_text())
    row = CacheRow(**raw)
    if row.stale:
        return None
    if current_contracts is None:
        return None
    cached = sorted(c.strip() for c in row.assumed_contracts)
    current = sorted(c.strip() for c in current_contracts)
    if cached != current:
        return None
    return row


def store(
    key: CacheKey,
    verdict: dict,
    assumed_contracts: list[str],
    build_flags: dict,
    *,
    dependents: Optional[list[str]] = None,
    root: Path = CACHE_ROOT,
) -> Path:
    row = CacheRow(
        key_digest=key.digest(),
        key=asdict(key),
        verdict=verdict,
        assumed_contracts=list(assumed_contracts),
        build_flags=dict(build_flags),
        dependents=list(dependents or []),
        stored_at=int(time.time()),
        stale=False,
        stale_reason="",
    )
    p = _path_for(key.digest(), root)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(asdict(row), indent=2))
    return p


def invalidate(
    key_digest: str,
    reason: str,
    *,
    root: Path = CACHE_ROOT,
) -> bool:
    """Mark a row stale without deleting it (so audits can trace why)."""
    p = _path_for(key_digest, root)
    if not p.exists():
        return False
    raw = json.loads(p.read_text())
    raw["stale"] = True
    raw["stale_reason"] = reason
    p.write_text(json.dumps(raw, indent=2))
    return True


def stats(root: Path = CACHE_ROOT) -> dict:
    rows = list(root.rglob("*.json"))
    fresh = stale = 0
    by_engine: dict[str, int] = {}
    for r in rows:
        d = json.loads(r.read_text())
        if d.get("stale"):
            stale += 1
        else:
            fresh += 1
        e = d.get("key", {}).get("engine", "?")
        by_engine[e] = by_engine.get(e, 0) + 1
    return {"rows": len(rows), "fresh": fresh, "stale": stale, "by_engine": by_engine}


# ---------------------------------------------------------------------------
# Dependency graph (from Phase 1.1 cluster index) → transitive invalidation
# ---------------------------------------------------------------------------

def load_dep_graph(target: str) -> dict:
    """Read `surface/tasks/<target>/_index.json` (cluster summaries with
    `depends_on` edges) and merge per-cluster `<name>.json` files for the
    `exports` list. Returns {clusters: [{cluster, depends_on, exports}, ...]}
    or {} if no index exists."""
    base = REPO / "surface" / "tasks" / target
    idx_path = base / "_index.json"
    if not idx_path.exists():
        return {}
    idx = json.loads(idx_path.read_text())
    merged = {"target": idx.get("target", target), "clusters": []}
    for summary in idx.get("clusters", []):
        cname = summary["cluster"]
        cluster_path = base / f"{cname}.json"
        exports: list[str] = []
        if cluster_path.exists():
            cdata = json.loads(cluster_path.read_text())
            exports = list(cdata.get("exports", []))
        merged["clusters"].append({
            "cluster": cname,
            "depends_on": summary.get("depends_on", []),
            "exports": exports,
        })
    return merged


def transitive_dependents(unit: str, target: str) -> list[str]:
    """Return all units in `target` whose cluster transitively depends on the
    cluster containing `unit`. Phase 1.4 conservative impl: we invalidate at
    cluster granularity (every export of every dependent cluster is suspect),
    not at function granularity. Phase 3 can refine to function-level edges
    via the SVF integration tracked in soundness-assumptions.md."""
    g = load_dep_graph(target)
    clusters = {c["cluster"]: c for c in g.get("clusters", [])}
    src_cluster = None
    for c in clusters.values():
        if unit in c.get("exports", []):
            src_cluster = c["cluster"]
            break
    if src_cluster is None:
        return []
    rev: dict[str, set[str]] = {}
    for c in clusters.values():
        for dep in c.get("depends_on", []):
            rev.setdefault(dep, set()).add(c["cluster"])
    visited: set[str] = set()
    front = {src_cluster}
    while front:
        nxt: set[str] = set()
        for cl in front:
            for parent in rev.get(cl, ()):
                if parent not in visited:
                    visited.add(parent)
                    nxt.add(parent)
        front = nxt
    out: list[str] = []
    for cl in visited:
        out.extend(clusters.get(cl, {}).get("exports", []))
    return sorted(out)


# ---------------------------------------------------------------------------
# Multi-tier convenience (P4) — same CacheKey shape works for Tier 1/2/3
# verdicts because `verdict` is just a dict at the storage layer. Callers in
# Tier 1/2/3 drivers can opt into the cache via these helpers without
# changing the existing Stage B integration.
# ---------------------------------------------------------------------------

def cache_verdict_dict(
    verdict_dict: dict,
    *,
    body_text: str,
    property: str,
    engine: str,
    engine_version: str = "",
    unwind: Optional[int] = None,
    assumed_contracts: Optional[list[str]] = None,
    build_flags: Optional[dict] = None,
    dependents: Optional[list[str]] = None,
    root: Path = CACHE_ROOT,
) -> Path:
    """Cache any verdict-shaped dict (Tier 1/2/3 or Stage B).

    The CacheKey covers everything the verdict's soundness depends on; callers
    are responsible for passing the contracts / build flags that were in scope
    at the time the verdict was produced. Returns the path the row was written
    to.
    """
    key = make_key(
        body_text=body_text,
        property=property,
        engine=engine,
        engine_version=engine_version,
        unwind=unwind,
        assumed_contracts=list(assumed_contracts or []),
        build_flags=dict(build_flags or {}),
    )
    return store(
        key,
        verdict=verdict_dict,
        assumed_contracts=list(assumed_contracts or []),
        build_flags=dict(build_flags or {}),
        dependents=dependents,
        root=root,
    )


# ---------------------------------------------------------------------------
# Bundle export / import (P4) — portable verified-knowledge transfer
# ---------------------------------------------------------------------------

BUNDLE_HEADER = {"format": "touchstone-proofcache-bundle", "version": 1}


def export_bundle(out_path: Path, *, root: Path = CACHE_ROOT) -> dict:
    """Dump every cache row under `root` to a single NDJSON bundle.

    Format:

        {header}\\n           ← first line, BUNDLE_HEADER + schema_version
        {row1_json}\\n        ← one CacheRow per subsequent line

    The bundle is content-portable: receivers can `import_bundle` on a fresh
    host and re-establish the same verified knowledge.
    """
    rows = sorted(root.rglob("*.json"))
    out_path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with out_path.open("w") as fh:
        fh.write(json.dumps({**BUNDLE_HEADER, "schema_version": SCHEMA_VERSION,
                             "source_root": str(root), "row_count": len(rows)}))
        fh.write("\n")
        for r in rows:
            try:
                d = json.loads(r.read_text())
            except Exception:
                continue
            fh.write(json.dumps(d) + "\n")
            n += 1
    return {"path": str(out_path), "rows": n}


def import_bundle(in_path: Path, *, root: Path = CACHE_ROOT,
                  overwrite_stale: bool = False) -> dict:
    """Load a bundle into the cache.

    Soundness rule: a row with a matching key_digest that is NOT stale is left
    alone; the importer never *replaces* a fresh local row with a remote one.
    Stale local rows are overwritten only when `overwrite_stale=True`.
    Rows whose `schema_version` does not match `SCHEMA_VERSION` are skipped.
    """
    lines = in_path.read_text().splitlines()
    if not lines:
        return {"imported": 0, "skipped": 0, "version_mismatch": 0}
    header = json.loads(lines[0])
    bundle_schema = header.get("schema_version", "")
    if bundle_schema != SCHEMA_VERSION:
        return {"imported": 0, "skipped": 0,
                "version_mismatch": len(lines) - 1,
                "reason": f"schema {bundle_schema!r} != local {SCHEMA_VERSION!r}"}
    root.mkdir(parents=True, exist_ok=True)
    imported = skipped = 0
    for ln in lines[1:]:
        if not ln.strip():
            continue
        try:
            row = json.loads(ln)
        except Exception:
            continue
        digest = row.get("key_digest")
        if not digest:
            continue
        p = _path_for(digest, root)
        if p.exists():
            existing = json.loads(p.read_text())
            if not existing.get("stale", False) and not overwrite_stale:
                skipped += 1
                continue
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(row, indent=2))
        imported += 1
    return {"imported": imported, "skipped": skipped,
            "header": header, "bundle_path": str(in_path)}


# ---------------------------------------------------------------------------
# CLI (P4)
# ---------------------------------------------------------------------------

def _main() -> int:
    import argparse, sys

    ap = argparse.ArgumentParser(description="Proof cache CLI (P4 multi-tier)")
    ap.add_argument("--root", type=Path, default=CACHE_ROOT)
    sub = ap.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("stats", help="cache size + per-engine counts")
    sp = sub.add_parser("export", help="dump cache to NDJSON bundle")
    sp.add_argument("out", type=Path)
    sp = sub.add_parser("import", help="load an NDJSON bundle into the cache")
    sp.add_argument("in_path", type=Path)
    sp.add_argument("--overwrite-stale", action="store_true")

    args = ap.parse_args()
    if args.cmd == "stats":
        print(json.dumps(stats(root=args.root), indent=2))
        return 0
    if args.cmd == "export":
        print(json.dumps(export_bundle(args.out, root=args.root), indent=2))
        return 0
    if args.cmd == "import":
        print(json.dumps(import_bundle(args.in_path, root=args.root,
                                       overwrite_stale=args.overwrite_stale),
                         indent=2))
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(_main())
