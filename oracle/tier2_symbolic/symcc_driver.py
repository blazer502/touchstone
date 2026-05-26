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
    raise NotImplementedError(
        "SymCC runner stub — image build is deferred to Phase 2.5 / 4 if KLEE+angr are insufficient."
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
