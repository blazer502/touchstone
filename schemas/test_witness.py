"""Smoke tests for schemas.cex — every tier round-trips, reducers produce
non-empty artifacts.

Run: `python3 -m schemas.test_cex`
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path


def _t1():
    from oracle.tier1_fuzz.verdict import Tier1Verdict
    from schemas.witness import from_tier1

    pov_bytes = bytes.fromhex("4d5a90ff")
    v = Tier1Verdict(
        unit="arvo:1065",
        engine="libfuzzer",
        sanitizer="MSan",
        verdict="crash",
        wall_ms=370,
        crash_class="use-of-uninitialized-value",
        location="softmagic.c:365",
        pov_path="/tmp/poc-sample.bin",
        evidence_excerpt="MemorySanitizer: use-of-uninitialized-value",
        soundness_note="local replay; rc != 0 + sanitizer banner = crash",
        assumed=["image=n132/arvo:1065-vul", "cmd=/bin/arvo", "poc_mount=/tmp/poc"],
    )
    cex = from_tier1(v, pov_bytes=pov_bytes)
    assert cex.to_bytes() == pov_bytes, "tier-1 byte round-trip failed"
    assert cex.provenance.tier == "1"
    assert cex.violated.kind == "sanitizer"
    assert cex.violated.name == "use-of-uninitialized-value"
    repro = cex.to_regression_test()
    assert repro.startswith("#!/usr/bin/env bash")
    assert "4d5a90ff" in repro
    blob = cex.to_disclosure_blob()
    json.dumps(blob)               # must be json-safe
    print("[t1] OK", len(repro), "byte reproducer,", len(json.dumps(blob)), "json")


def _t2():
    from oracle.tier2_symbolic.verdict import Tier2Verdict
    from schemas.witness import from_tier2

    v = Tier2Verdict(
        unit="klee:div_by_zero",
        engine="klee",
        verdict="sat",
        wall_ms=44,
        property="divide by zero",
        paths_explored=1,
        paths_completed=0,
        target_location="klee_sat_div_by_zero.c:10",
        evidence_excerpt="KLEE: test*.div.err",
        soundness_note="symbolic SAT — candidate, Tier-1 reconfirm required",
        assumed=["klee-uclibc-env"],
    )
    cex = from_tier2(v, variable_bindings={"d": "0"})
    assert cex.to_bytes() is None or isinstance(cex.to_bytes(), bytes)
    assert cex.input.variable_bindings == {"d": "0"}
    assert cex.provenance.tier == "2"
    assert "BINDINGS" in cex.to_regression_test()
    print("[t2] OK variable-bindings + python reproducer")


def _t3():
    from oracle.tier3_bmc.verdict import Tier3Verdict
    from schemas.witness import from_tier3

    # Write a fake cbmc PoV file with assignments.
    pov_dir = tempfile.mkdtemp(prefix="cex-smoke-")
    pov_path = Path(pov_dir) / "main.c.cbmc-pov.json"
    pov_path.write_text(json.dumps({"i": "8u", "v": "0"}))
    v = Tier3Verdict(
        unit="cbmc:unsafe:off_by_one",
        engine="cbmc",
        property="memory-safety",
        verdict="unsafe",
        unwind=16,
        wall_ms=579,
        pov_path=str(pov_path),
        target_location="off_by_one.c:26",
        evidence_excerpt="[main.assertion.1] Failure ...",
        soundness_note="cex extracted from --trace",
        assumed_contracts=["__CPROVER_assume(N > 0)"],
    )
    cex = from_tier3(v)
    assert cex.input.variable_bindings == {"i": "8u", "v": "0"}
    assert cex.provenance.tier == "3"
    assert cex.violated.location == "off_by_one.c:26"
    c_repro = cex.to_regression_test()
    assert c_repro.lstrip().startswith("/*")
    assert "int main(void)" in c_repro
    blob = cex.to_disclosure_blob()
    assert blob["provenance"]["engine"] == "cbmc"
    print("[t3] OK cbmc bindings parsed, C reproducer", len(c_repro), "B")


def main() -> int:
    _t1(); _t2(); _t3()
    print("all cex smokes pass")
    return 0


if __name__ == "__main__":
    sys.exit(main())
