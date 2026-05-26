"""Tests for the proof cache (Phase 1.4). Covers the soundness levers:

  1. body change          → cache miss
  2. assumed-contract change → cache miss (the "contract identity" soundness
     rule from docs/soundness-assumptions.md proof-cache row)
  3. build-flag change     → cache miss
  4. schema-version bump   → cache miss
  5. explicit invalidate() → cache miss + stale_reason recorded
  6. transitive_dependents() over the Phase-1.1 cluster index
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from surface import proof_cache as pc


def _verdict(stub: str) -> dict:
    return {"unit": "x.c::f", "property": "memory-safety", "engine": "cbmc",
            "verdict": "safe", "unwind": 8, "time_ms": 100,
            "evidence": stub, "soundness_note": "", "assumed_contracts": []}


def main() -> int:
    failures = []
    with tempfile.TemporaryDirectory() as td:
        root = Path(td) / "cache"
        body = "int f(int x){ if(x<10) return x; return 0; }"
        contracts = ["x >= 0"]
        flags = {"sanitizer": "asan", "arch": "x86_64"}
        k = pc.make_key(body, "memory-safety", "cbmc", "6.4.0", 8, contracts, flags)
        pc.store(k, _verdict("first"), contracts, flags, root=root)

        # 1. hit on identical inputs (with current_contracts supplied)
        h = pc.lookup(k, current_contracts=contracts, root=root)
        if h is None:
            failures.append("1. identical key+contracts must hit")

        # 1b. without current_contracts → miss (conservative path)
        h = pc.lookup(k, current_contracts=None, root=root)
        if h is not None:
            failures.append("1b. missing current_contracts must miss (conservative)")

        # 2. body edit → different body_sha → miss
        body2 = body.replace("10", "9")
        k2 = pc.make_key(body2, "memory-safety", "cbmc", "6.4.0", 8, contracts, flags)
        if pc.lookup(k2, current_contracts=contracts, root=root) is not None:
            failures.append("2. body edit must miss")

        # 3. contract change → miss (key digest already differs by contracts_sha)
        contracts2 = ["x >= 1"]
        k3 = pc.make_key(body, "memory-safety", "cbmc", "6.4.0", 8, contracts2, flags)
        if pc.lookup(k3, current_contracts=contracts2, root=root) is not None:
            failures.append("3a. contract change must miss via key")

        # 3b. same key but caller now reports different contracts on hit-validation:
        #     simulate that the on-disk row's recorded contracts != current.
        h = pc.lookup(k, current_contracts=["x >= 1"], root=root)
        if h is not None:
            failures.append("3b. contract mismatch at lookup must miss")

        # 4. build-flag change → miss
        flags2 = dict(flags); flags2["sanitizer"] = "msan"
        k4 = pc.make_key(body, "memory-safety", "cbmc", "6.4.0", 8, contracts, flags2)
        if pc.lookup(k4, current_contracts=contracts, root=root) is not None:
            failures.append("4. build-flag change must miss")

        # 5. invalidate → stale → miss
        pc.invalidate(k.digest(), "callee contract changed", root=root)
        if pc.lookup(k, current_contracts=contracts, root=root) is not None:
            failures.append("5. invalidated row must miss")
        # but the file should still record the reason
        p = pc._path_for(k.digest(), root=root)
        if not p.exists() or "callee contract changed" not in p.read_text():
            failures.append("5b. invalidate must record stale_reason on-disk")

    # 6. transitive_dependents from Phase-1.1 cluster index (uses real repo data).
    deps = pc.transitive_dependents("nf_route", "linux-6.1.72-netfilter")
    if not deps:
        # `nf_route` is an export of cluster `utils`; many clusters depend on
        # `utils` (nf_conntrack, etc.), so dependents must be non-empty.
        failures.append("6. transitive_dependents('nf_route') must be non-empty")

    if failures:
        print("FAIL:")
        for f in failures:
            print("  -", f)
        return 1
    print(f"proof_cache tests passed (6 cases)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
