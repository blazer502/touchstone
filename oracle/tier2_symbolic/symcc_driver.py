"""SymCC driver (Tier-2 concolic compile-time instrumentation).

PLAN §3 Tier-2: SymCC / SymQEMU is the faster concolic alternative to KLEE
for medium-sized C/C++ targets. The container build (~1.5 GB) is deferred
until KLEE proves insufficient on a real Phase-2.5 / Phase-3 target — the
driver below is the *interface stub* so the router (Phase 2.4) can dispatch
to SymCC the same way it dispatches to KLEE/angr, and we get a clean
"image-missing → inconclusive" instead of a Python exception.

When the image becomes available, swap `_run_symcc` to do:
    docker run --rm -v <work>:/work veri-agent/symcc symcc <args>

No LLM in this module.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

from .verdict import Tier2Verdict


SYMCC_IMAGE = os.environ.get("SYMCC_IMAGE", "veri-agent/symcc:14")


def _image_present(image: str) -> bool:
    docker = os.environ.get("DOCKER", "sudo docker").split()
    r = subprocess.run([*docker, "image", "inspect", image],
                       capture_output=True, text=True)
    return r.returncode == 0


def run(source: Path, target_property: str = "klee-style-assert",
        wall_seconds: int = 60, unit: Optional[str] = None) -> Tier2Verdict:
    unit = unit or source.stem
    t0 = time.monotonic()
    if not _image_present(SYMCC_IMAGE):
        wall_ms = int((time.monotonic() - t0) * 1000)
        return Tier2Verdict(
            unit=unit, engine="symcc", verdict="inconclusive", wall_ms=wall_ms,
            property=target_property,
            evidence_excerpt=f"image-missing: {SYMCC_IMAGE}",
            soundness_note="SymCC image not built on this host; engine wired but inactive.",
            assumed=[f"image={SYMCC_IMAGE}", "image-missing path"],
        )
    # Phase 6.4: real concolic run path (active once the image is built).
    # SymCC compiles the source into a binary that performs concolic execution
    # at runtime, emitting new inputs that flip branches. We seed empty, run
    # under a wall budget, and inspect the output for a sanitizer/assertion trip.
    docker = os.environ.get("DOCKER", "sudo docker").split()
    src_abs = source.resolve()
    work = src_abs.parent
    out_corpus = work / f".symcc-out-{src_abs.stem}"
    out_corpus.mkdir(exist_ok=True)
    compile_cmd = [
        *docker, "run", "--rm", "-v", f"{work}:/work", "-w", "/work",
        SYMCC_IMAGE, "sh", "-c",
        f"symcc {src_abs.name} -o /work/{src_abs.stem}.symcc 2>&1",
    ]
    run_cmd = [
        *docker, "run", "--rm", "-v", f"{work}:/work", "-w", "/work",
        "-e", f"SYMCC_OUTPUT_DIR=/work/{out_corpus.name}",
        SYMCC_IMAGE, "sh", "-c",
        f"timeout {wall_seconds} ./{src_abs.stem}.symcc < /dev/null 2>&1; echo EXIT=$?",
    ]
    try:
        cr = subprocess.run(compile_cmd, capture_output=True, text=True, timeout=120)
        if cr.returncode != 0:
            wall_ms = int((time.monotonic() - t0) * 1000)
            return Tier2Verdict(
                unit=unit, engine="symcc", verdict="inconclusive", wall_ms=wall_ms,
                property=target_property,
                evidence_excerpt=f"symcc compile failed: {cr.stdout[-300:]}",
                soundness_note="compile error → no verdict.",
                assumed=[f"image={SYMCC_IMAGE}"],
            )
        rr = subprocess.run(run_cmd, capture_output=True, text=True,
                            timeout=wall_seconds + 30)
        out = (rr.stdout or "") + (rr.stderr or "")
        wall_ms = int((time.monotonic() - t0) * 1000)
        if re.search(r"(ERROR: AddressSanitizer|runtime error:|SUMMARY: )", out):
            return Tier2Verdict(
                unit=unit, engine="symcc", verdict="sat", wall_ms=wall_ms,
                property=target_property,
                evidence_excerpt=out[-400:],
                soundness_note=("SymCC reached a sanitizer trip under concolic "
                                "exploration — candidate PoV, re-confirm in Tier-1."),
                assumed=[f"image={SYMCC_IMAGE}", "under-approx concolic env"],
            )
        n_inputs = len(list(out_corpus.glob("*"))) if out_corpus.exists() else 0
        return Tier2Verdict(
            unit=unit, engine="symcc", verdict="inconclusive", wall_ms=wall_ms,
            property=target_property,
            evidence_excerpt=f"no sanitizer trip in {wall_seconds}s; "
                             f"{n_inputs} inputs explored.",
            soundness_note=("SymCC explored without tripping the property in the "
                            "wall budget — inconclusive, not a safety proof."),
            assumed=[f"image={SYMCC_IMAGE}"],
        )
    except subprocess.TimeoutExpired:
        wall_ms = int((time.monotonic() - t0) * 1000)
        return Tier2Verdict(
            unit=unit, engine="symcc", verdict="inconclusive", wall_ms=wall_ms,
            property=target_property,
            evidence_excerpt="symcc wall budget exhausted.",
            soundness_note="timeout → no verdict.",
            assumed=[f"image={SYMCC_IMAGE}"],
        )


def _cli() -> int:
    ap = argparse.ArgumentParser(description="Tier-2 SymCC driver (stub).")
    ap.add_argument("--source", required=True)
    ap.add_argument("--wall-seconds", type=int, default=60)
    ap.add_argument("--out", required=True)
    ap.add_argument("--unit", default=None)
    args = ap.parse_args()
    v = run(Path(args.source), wall_seconds=args.wall_seconds, unit=args.unit)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(v.to_dict(), indent=2))
    print(json.dumps(v.to_dict(), indent=2))
    return 0 if v.verdict in {"sat", "unsat"} else 1


if __name__ == "__main__":
    sys.exit(_cli())
