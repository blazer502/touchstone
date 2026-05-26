"""Tier-3 CBMC driver.

Wraps `surface.stage_b.run_cbmc` so the oracle pipeline gets a Tier3Verdict
shape and a PoV artifact extracted from CBMC's counterexample trace.

CBMC's text output for a violated property includes lines of the form
``State <n> file <f> line <l> ...    var=value (type)``. We grab the
assignments to symbolic inputs (variables declared in the harness as
``__CPROVER_nondet_*`` or that appear in counterexample trace lines under the
harness function) and serialize them as JSON next to the verdict. The full
trace is also kept in the evidence excerpt so a reviewer can audit.

No LLM in this module (Phase 2 rule). The harness + assertion are caller-
provided plain C; LLM-synthesized harnesses are Phase 3.2.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Optional

# Reuse Stage B's CBMC backend to keep one source of truth.
_REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO))
from surface import stage_b as _stage_b  # noqa: E402

from .verdict import Tier3Verdict  # noqa: E402


# CBMC 6.x prints one or more "Trace for <prop-id>:" blocks under --trace.
# (CBMC 5.x used "Counterexample:" — we accept both.)
_CEX_HEADER = re.compile(r"^(Counterexample:|Trace for .*:)\s*$", re.MULTILINE)
# CBMC text trace assignment line, e.g.:
#   State 12 file harness.c line 7 function main thread 0
#   ----------------------------------------------------
#     i=8u (00000000 00000000 00000000 00001000)
#     buf[3l]=0 (00000000 ...)
_ASSIGN = re.compile(
    r"^\s*([A-Za-z_][A-Za-z_0-9]*(?:\.[A-Za-z_][A-Za-z_0-9]*|\[[^\]]+\])*)"
    r"\s*=\s*([^\(\n]+?)"          # value (decimal / hex / string / "8u")
    r"(?:\s*\(([^)]*)\))?\s*$",    # optional bitvector annotation
    re.MULTILINE,
)
# Top failed property: "[main.assertion.1] line 11 ...: FAILURE"
_FAIL_LINE = re.compile(
    r"\[([\w.]+)\][^\n]*line\s+(\d+)[^\n]*:\s*FAILURE", re.IGNORECASE
)


def _extract_pov(stdout: str) -> dict:
    """Pull a {var: value} dict out of the first counterexample trace block."""
    m = _CEX_HEADER.search(stdout)
    if not m:
        return {}
    tail = stdout[m.end():]
    # Stop at the next "** Results" / "VERIFICATION" / next "Trace for" block.
    end = re.search(
        r"^\*\* Results|^VERIFICATION |^Trace for ", tail, re.MULTILINE
    )
    if end:
        tail = tail[: end.start()]
    pov: dict[str, str] = {}
    for am in _ASSIGN.finditer(tail):
        var, val = am.group(1).strip(), am.group(2).strip()
        # Only the first assignment to each variable is the input value;
        # later assignments are intermediate computations.
        pov.setdefault(var, val)
    return pov


def _extract_target_location(stdout: str) -> Optional[str]:
    m = _FAIL_LINE.search(stdout)
    if m:
        return f"line {m.group(2)} [{m.group(1)}]"
    return None


def _docker_image_present(image: str) -> bool:
    try:
        r = subprocess.run(
            shlex.split(_stage_b.DOCKER) + ["image", "inspect", image],
            capture_output=True, timeout=30,
        )
        return r.returncode == 0
    except Exception:
        return False


def run_cbmc_oracle(
    source: Path,
    function: str = "main",
    property: str = "memory-safety",
    unwind: int = 16,
    extra_flags: Optional[list[str]] = None,
    assumed_contracts: Optional[list[str]] = None,
    out_dir: Optional[Path] = None,
    timeout_s: int = 120,
    unit: Optional[str] = None,
) -> Tier3Verdict:
    """Run CBMC on `source` checking `function`; return a Tier3Verdict.

    On `verdict=unsafe` a PoV JSON is written under `out_dir/` (or a temp dir)
    with the input-variable assignments extracted from the cex trace, and the
    path is recorded in the verdict.
    """
    unit = unit or f"{source.name}::{function}"
    out_dir = out_dir or Path(tempfile.mkdtemp(prefix="tier3-cbmc-"))
    out_dir.mkdir(parents=True, exist_ok=True)
    assumed_contracts = list(assumed_contracts or [])

    if not _docker_image_present(_stage_b.CBMC_IMG):
        return Tier3Verdict(
            unit=unit, engine="cbmc", property=property,
            verdict="inconclusive", unwind=unwind, wall_ms=0,
            evidence_excerpt=f"image-missing:{_stage_b.CBMC_IMG}",
            soundness_note="CBMC container not built; cannot verify.",
            assumed_contracts=assumed_contracts,
        )

    # We need the full CBMC stdout including the cex trace, so call CBMC
    # directly here (Stage B's helper compresses to the last 12 lines).
    flag_map = {
        "memory-safety": [
            "--bounds-check", "--pointer-check", "--pointer-overflow-check",
            "--memory-leak-check", "--memory-cleanup-check",
        ],
        "no-overflow": [
            "--signed-overflow-check", "--unsigned-overflow-check",
            "--conversion-check",
        ],
        "no-oob": ["--bounds-check"],
        "no-uaf": ["--pointer-check"],
        "assertion": [],  # rely on user-written __CPROVER_assert
    }
    flags = flag_map.get(property, flag_map["memory-safety"])

    src_abs = source.resolve()
    src_dir = src_abs.parent
    cmd = (
        shlex.split(_stage_b.DOCKER)
        + ["run", "--rm", "-v", f"{src_dir}:/work:ro", "-w", "/work",
           _stage_b.CBMC_IMG, "cbmc",
           src_abs.name, "--function", function,
           "--unwind", str(unwind), "--unwinding-assertions",
           "--trace", "-DCBMC_HARNESS=1"]
        + flags + (extra_flags or [])
    )

    t0 = time.monotonic()
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s)
        timed_out = False
    except subprocess.TimeoutExpired as e:
        timed_out = True
        class _R:
            returncode = -1
            stdout = (e.stdout.decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or ""))
            stderr = (e.stderr.decode(errors="replace") if isinstance(e.stderr, bytes) else (e.stderr or ""))
        r = _R()
    wall_ms = int((time.monotonic() - t0) * 1000)

    out = (r.stdout or "") + "\n" + (r.stderr or "")

    if timed_out:
        verdict = "inconclusive"
        note = ("CBMC wall budget exhausted; bounded BMC didn't decide within "
                f"timeout={timeout_s}s. Re-run with larger budget or higher unwind.")
        target_loc = None
        pov_path: Optional[str] = None
    elif _stage_b._CBMC_OK.search(out):
        verdict = "safe"
        note = (
            f"Bounded-sound up to --unwind={unwind} with --unwinding-assertions ON. "
            "Without a verified loop invariant this is NOT an unbounded-safety claim."
        )
        target_loc = None
        pov_path = None
    elif _stage_b._CBMC_UNWIND_FAIL.search(out):
        verdict = "inconclusive"
        note = (
            f"Unwinding assertion failed at --unwind={unwind}: reachable behaviour "
            "exceeds the bound. Phase 3.1 will synthesize a loop invariant; "
            "until then this property cannot be bounded-sound proved."
        )
        target_loc = None
        pov_path = None
    elif _stage_b._CBMC_VIOLATED.search(out):
        verdict = "unsafe"
        note = (
            "CBMC produced a counterexample within the unwind bound. The cex "
            "assignment is a sound witness *for the harness as specified*; "
            "wrap it through the Tier-1 harness/replay path to obtain a "
            "runtime PoV."
        )
        target_loc = _extract_target_location(out)
        pov = _extract_pov(out)
        pov_file = out_dir / f"{Path(source).stem}.cbmc-pov.json"
        pov_file.write_text(json.dumps({
            "engine": "cbmc",
            "source": str(src_abs),
            "function": function,
            "property": property,
            "unwind": unwind,
            "target_location": target_loc,
            "assignment": pov,
        }, indent=2))
        pov_path = str(pov_file)
    else:
        verdict = "inconclusive"
        note = ("CBMC produced no decisive VERIFICATION line; treat as inconclusive "
                "(possible solver error / OOM / unsupported construct).")
        target_loc = None
        pov_path = None

    # Keep last ~80 non-empty lines of output as evidence, plenty to read a cex tail.
    tail = [ln for ln in out.splitlines() if ln.strip()][-80:]
    evidence = "\n".join(tail)[-8000:]

    return Tier3Verdict(
        unit=unit, engine="cbmc", property=property,
        verdict=verdict, unwind=unwind, wall_ms=wall_ms,
        pov_path=pov_path, target_location=target_loc,
        evidence_excerpt=evidence, soundness_note=note,
        assumed_contracts=assumed_contracts,
    )


def _cli() -> int:
    ap = argparse.ArgumentParser(description="Tier-3 CBMC driver.")
    ap.add_argument("--source", required=True)
    ap.add_argument("--function", default="main")
    ap.add_argument("--property", default="memory-safety")
    ap.add_argument("--unwind", type=int, default=16)
    ap.add_argument("--out", required=True, help="Where to write the verdict JSON")
    ap.add_argument("--out-dir", default=None,
                    help="Where to write the PoV artifact (kept after run)")
    ap.add_argument("--timeout-s", type=int, default=120)
    ap.add_argument("--unit", default=None)
    args = ap.parse_args()

    v = run_cbmc_oracle(
        Path(args.source), function=args.function, property=args.property,
        unwind=args.unwind, out_dir=Path(args.out_dir) if args.out_dir else None,
        timeout_s=args.timeout_s, unit=args.unit,
    )
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(v.to_dict(), indent=2))
    print(json.dumps(v.to_dict(), indent=2))
    return 0 if v.verdict in {"safe", "unsafe"} else 1


if __name__ == "__main__":
    sys.exit(_cli())
