"""Smoke for P4 — multi-tier verdict caching + bundle export/import.

Verifies:
1. Tier-1 + Tier-2 + Tier-3 verdict dicts cache + roundtrip via the existing
   key/store/lookup machinery (no schema change needed).
2. `export_bundle` produces NDJSON usable by `import_bundle` on a fresh root.
3. Schema-version mismatch on import is rejected cleanly.

Run: `python3 -m surface.test_proof_cache_multitier`
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

from surface import proof_cache as pc


def _t1_dict() -> dict:
    """A representative Tier-1 verdict dict (would be Tier1Verdict.to_dict())."""
    return {
        "unit": "arvo:1065",
        "engine": "libfuzzer",
        "sanitizer": "MSan",
        "verdict": "crash",
        "wall_ms": 370,
        "crash_class": "use-of-uninitialized-value",
        "location": "softmagic.c:365",
        "pov_path": "/tmp/poc.bin",
    }


def _t2_dict() -> dict:
    return {
        "unit": "klee:div_by_zero",
        "engine": "klee",
        "verdict": "sat",
        "wall_ms": 44,
        "property": "divide-by-zero",
        "target_location": "klee_sat_div_by_zero.c:10",
    }


def _t3_dict() -> dict:
    return {
        "unit": "cbmc:off_by_one",
        "engine": "cbmc",
        "property": "no-oob",
        "verdict": "unsafe",
        "unwind": 4,
        "wall_ms": 580,
    }


def main() -> int:
    root = Path(tempfile.mkdtemp(prefix="pc-multitier-"))

    # 1) cache + lookup roundtrip for every tier
    paths = {
        "t1": pc.cache_verdict_dict(_t1_dict(),
                                    body_text="// libfuzzer harness body",
                                    property="memory-safety",
                                    engine="libfuzzer", engine_version="14.0",
                                    assumed_contracts=[],
                                    build_flags={"san": "MSan", "O": "0"},
                                    root=root),
        "t2": pc.cache_verdict_dict(_t2_dict(),
                                    body_text="int main() { int d = 0; return 1/d; }",
                                    property="divide-by-zero",
                                    engine="klee", engine_version="3.2-pre",
                                    assumed_contracts=[],
                                    build_flags={"klee-uclibc": "yes"},
                                    root=root),
        "t3": pc.cache_verdict_dict(_t3_dict(),
                                    body_text="int foo(int i){int b[16];return b[i];}",
                                    property="no-oob",
                                    engine="cbmc", engine_version="6.4.0",
                                    unwind=4,
                                    assumed_contracts=[],
                                    build_flags={},
                                    root=root),
    }
    assert all(p.exists() for p in paths.values()), "store failed"
    print(f"[t1/t2/t3] stored at {root}")

    # 2) lookup hits
    for tier, body, prop, eng, ver, uw, flags in [
        ("t1", "// libfuzzer harness body", "memory-safety", "libfuzzer", "14.0", None,
         {"san": "MSan", "O": "0"}),
        ("t2", "int main() { int d = 0; return 1/d; }", "divide-by-zero", "klee", "3.2-pre", None,
         {"klee-uclibc": "yes"}),
        ("t3", "int foo(int i){int b[16];return b[i];}", "no-oob", "cbmc", "6.4.0", 4,
         {}),
    ]:
        key = pc.make_key(body, prop, eng, ver, uw, [], flags)
        row = pc.lookup(key, current_contracts=[], root=root)
        assert row is not None, f"{tier} lookup miss"
        assert row.verdict["engine"] == eng
    print("[hits] tier-1/2/3 lookups all return the cached verdict")

    # 3) bundle export + import on a fresh root
    bundle = root / "bundle.ndjson"
    res = pc.export_bundle(bundle, root=root)
    assert res["rows"] == 3, res
    assert bundle.exists() and bundle.stat().st_size > 0
    print(f"[export] {bundle} rows={res['rows']}")

    fresh_root = Path(tempfile.mkdtemp(prefix="pc-multitier-fresh-"))
    iret = pc.import_bundle(bundle, root=fresh_root)
    assert iret["imported"] == 3 and iret["skipped"] == 0, iret
    print(f"[import] fresh root, imported={iret['imported']}, skipped={iret['skipped']}")

    # re-import is a no-op (all rows already fresh on the receiver)
    iret2 = pc.import_bundle(bundle, root=fresh_root)
    assert iret2["imported"] == 0 and iret2["skipped"] == 3, iret2
    print(f"[import-idempotent] re-import skipped={iret2['skipped']}")

    # 4) schema-version mismatch is rejected
    bad = root / "bad-bundle.ndjson"
    lines = bundle.read_text().splitlines()
    header = json.loads(lines[0]); header["schema_version"] = "vBOGUS"
    bad.write_text(json.dumps(header) + "\n" + "\n".join(lines[1:]))
    iret3 = pc.import_bundle(bad, root=Path(tempfile.mkdtemp(prefix="pc-bad-")))
    assert iret3["imported"] == 0 and iret3.get("version_mismatch", 0) > 0, iret3
    print(f"[import-version-mismatch] rejected cleanly, msg={iret3.get('reason')}")

    print("all multi-tier cache smokes pass")
    return 0


if __name__ == "__main__":
    sys.exit(main())
