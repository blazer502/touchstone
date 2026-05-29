#!/usr/bin/env python3
"""Phase 1.5 — Stage B sound-proof-engine soundness gate on Juliet (CBMC).

For each Stage B target (a Juliet *_01.c baseline file with a known labeled
bug), run CBMC's verifier with the relevant property checks against the
testcase's `_bad` function. The soundness gate (PLAN §2 acceptance,
"missed-bug = 0 on labeled set") applied to Stage B is:

    CBMC must NEVER report `safe` on a labeled `_bad` function.

`unsafe`  = CBMC caught the bug — expected.
`inconclusive` = CBMC couldn't decide (e.g. unwind limit) — acceptable, not a
                 soundness failure (the verdict authority stays the tool).
`safe` on a `_bad` function = soundness violation — the proof engine "proved"
                              a known bug doesn't exist. THIS MUST BE 0.

Each testcase is compiled together with eval/juliet/stubs.c (no-op
implementations of printLine / printIntLine / globalReturnsTrueOrFalse /
GLOBAL_CONST_* etc.) so CBMC's parser is satisfied. The bug body is in the
testcase itself — the stubs only kick in for unrelated helpers.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
JULIET_TESTCASES = REPO / "eval" / "juliet" / "extracted" / "C" / "testcases"
JULIET_SUPPORT = REPO / "eval" / "juliet" / "extracted" / "C" / "testcasesupport"
STUBS_C = REPO / "eval" / "juliet" / "stubs.c"
SUBSET_JSON = REPO / "eval" / "juliet" / "subset.json"
OUT_JSON = REPO / "eval" / "juliet" / "stage_b.json"
TOOLCHAIN_LOCK = REPO / "docs" / "toolchain.lock"


def _read_lock() -> dict[str, str]:
    out: dict[str, str] = {}
    if not TOOLCHAIN_LOCK.exists():
        return out
    for line in TOOLCHAIN_LOCK.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        out[k.strip()] = v.strip()
    return out


LOCK = _read_lock()
CBMC_IMG = f"touchstone/cbmc:{LOCK.get('CBMC_VERSION', '6.4.0')}"
DOCKER = os.environ.get("DOCKER", "sudo docker")

# CBMC text-output patterns (same as surface/stage_b.py).
_CBMC_OK = re.compile(r"VERIFICATION SUCCESSFUL")
_CBMC_FAILED = re.compile(r"VERIFICATION FAILED")
_CBMC_UNWIND_FAIL = re.compile(
    r"unwinding assertion.*: FAILURE", re.IGNORECASE
)

# Per-CWE property selection.
CWE_PROPERTY = {
    "CWE476": "no-uaf",       # NULL deref shows up as pointer-check failure
    "CWE415": "memory-safety",  # double-free → memory-leak / pointer-check
    "CWE416": "memory-safety",  # UAF
    "CWE121": "no-oob",         # stack buffer overflow
}
CWE_FLAGS = {
    "memory-safety": [
        "--bounds-check", "--pointer-check", "--pointer-overflow-check",
        "--memory-leak-check",
    ],
    "no-oob": ["--bounds-check", "--pointer-check"],
    "no-uaf": ["--pointer-check"],
    "no-overflow": ["--signed-overflow-check", "--unsigned-overflow-check"],
}


@dataclass
class JulietVerdict:
    testcase: str
    function: str
    cwe: str
    property: str
    verdict: str           # safe | unsafe | inconclusive
    expected: str          # always "unsafe" — labeled _bad
    is_soundness_failure: bool
    time_ms: int
    unwind: int
    cbmc_image: str
    evidence: str


def _cwe_of(path: str) -> str:
    m = re.match(r"(CWE\d+)_", Path(path).name)
    return m.group(1) if m else "CWE?"


def _bad_function_name(testcase_path: Path) -> str | None:
    """Extract the `<basename without _01.c>_<NN>_bad` declaration in the file."""
    text = testcase_path.read_text(encoding="utf-8", errors="replace")
    m = re.search(
        r"^\s*[A-Za-z_]\w*\s+([A-Za-z_][A-Za-z_0-9]+_bad)\s*\(",
        text, re.MULTILINE,
    )
    return m.group(1) if m else None


def run_one(testcase_rel: str, unwind: int = 32, timeout_s: int = 180) -> JulietVerdict:
    src = (JULIET_TESTCASES / testcase_rel).resolve()
    if not src.exists():
        return JulietVerdict(
            testcase=testcase_rel, function="?", cwe=_cwe_of(testcase_rel),
            property="?", verdict="inconclusive", expected="unsafe",
            is_soundness_failure=False, time_ms=0, unwind=unwind,
            cbmc_image=CBMC_IMG, evidence=f"source missing: {src}",
        )
    fn = _bad_function_name(src)
    if not fn:
        return JulietVerdict(
            testcase=testcase_rel, function="?", cwe=_cwe_of(testcase_rel),
            property="?", verdict="inconclusive", expected="unsafe",
            is_soundness_failure=False, time_ms=0, unwind=unwind,
            cbmc_image=CBMC_IMG, evidence="no _bad function found",
        )
    cwe = _cwe_of(testcase_rel)
    prop = CWE_PROPERTY.get(cwe, "memory-safety")
    flags = CWE_FLAGS[prop]

    # Mount the testcase file, the stub file, the support include dir, into /work.
    # CBMC needs to find std_testcase.h; we use -I to point at testcasesupport,
    # and pass both .c files so the stub symbols satisfy the parse/link.
    mount_root = src.parent  # the per-CWE dir
    # We mount three things via separate -v entries: the testcase dir, the
    # support headers, and the stubs file.
    cmd = (
        shlex.split(DOCKER)
        + [
            "run", "--rm",
            "-v", f"{src.parent}:/tc:ro",
            "-v", f"{JULIET_SUPPORT}:/support:ro",
            "-v", f"{STUBS_C.parent}:/stubs:ro",
            "-w", "/tc",
            CBMC_IMG, "cbmc",
            f"/tc/{src.name}", "/stubs/stubs.c",
            "-I", "/support",
            "--function", fn,
            "--unwind", str(unwind), "--unwinding-assertions",
            "-DOMITGOOD",
        ]
        + flags
    )
    t0 = time.time()
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s)
    except subprocess.TimeoutExpired:
        return JulietVerdict(
            testcase=testcase_rel, function=fn, cwe=cwe, property=prop,
            verdict="inconclusive", expected="unsafe",
            is_soundness_failure=False,
            time_ms=int((time.time() - t0) * 1000), unwind=unwind,
            cbmc_image=CBMC_IMG, evidence="timeout",
        )
    dt_ms = int((time.time() - t0) * 1000)
    out = (r.stdout or "") + (r.stderr or "")

    if _CBMC_OK.search(out):
        verdict = "safe"
    elif _CBMC_UNWIND_FAIL.search(out):
        verdict = "inconclusive"
    elif _CBMC_FAILED.search(out):
        verdict = "unsafe"
    else:
        verdict = "inconclusive"

    tail = [ln for ln in out.splitlines() if ln.strip()][-14:]
    evidence = "\n".join(tail)[-2400:]
    soundness_failure = (verdict == "safe")
    return JulietVerdict(
        testcase=testcase_rel, function=fn, cwe=cwe, property=prop,
        verdict=verdict, expected="unsafe",
        is_soundness_failure=soundness_failure,
        time_ms=dt_ms, unwind=unwind, cbmc_image=CBMC_IMG,
        evidence=evidence,
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--subset", type=Path, default=SUBSET_JSON)
    ap.add_argument("--out", type=Path, default=OUT_JSON)
    ap.add_argument("--unwind", type=int, default=128)
    ap.add_argument("--timeout", type=int, default=180)
    args = ap.parse_args()

    subset = json.loads(args.subset.read_text())
    targets = subset["stage_b_targets"]

    results: list[dict] = []
    counts = {"safe": 0, "unsafe": 0, "inconclusive": 0}
    soundness_failures: list[dict] = []
    print(f"[juliet/stageB] running CBMC on {len(targets)} _bad functions ...",
          file=sys.stderr)
    for t in targets:
        v = run_one(t, unwind=args.unwind, timeout_s=args.timeout)
        results.append(asdict(v))
        counts[v.verdict] = counts.get(v.verdict, 0) + 1
        if v.is_soundness_failure:
            soundness_failures.append({"testcase": v.testcase, "function": v.function})
        sys.stderr.write(
            f"  {v.cwe} {v.testcase.split('/')[-1]:60s} -> "
            f"{v.verdict:12s} ({v.time_ms:5d} ms)\n"
        )

    summary = {
        "phase": "1.5",
        "stage": "B",
        "engine": "cbmc",
        "engine_image": CBMC_IMG,
        "generated_at": int(time.time()),
        "counts": counts,
        "soundness_failures": soundness_failures,
        "missed_bug_count": len(soundness_failures),
        "results": results,
    }
    args.out.write_text(json.dumps(summary, indent=2) + "\n")
    print(
        f"stage_b(juliet): safe={counts['safe']} unsafe={counts['unsafe']} "
        f"inconclusive={counts['inconclusive']} "
        f"soundness_failures={len(soundness_failures)} -> {args.out}"
    )
    return 0 if not soundness_failures else 1


if __name__ == "__main__":
    sys.exit(main())
