"""Tier-3 ESBMC driver — image-presence stub.

ESBMC is the alternative BMC engine to CBMC (PLAN §3 Tier-3). At Phase 2.3 we
ship the same dispatch surface as CBMC so the router (Phase 2.4) can pick
either engine uniformly, but the heavy `touchstone/esbmc` image is not built
yet — it activates when CBMC's encoding is too slow on a specific Magma /
Phase-2.5 case (the same reason ESBMC sits next to CBMC in `PLAN §9`).

Until the image is built this driver returns a clean `inconclusive` with
`image-missing:<tag>` evidence so the rest of the pipeline runs.
"""
from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

from .verdict import Tier3Verdict


_REPO = Path(__file__).resolve().parents[2]
_LOCK_PATH = _REPO / "docs" / "toolchain.lock"


def _read_lock() -> dict[str, str]:
    out: dict[str, str] = {}
    if not _LOCK_PATH.exists():
        return out
    for line in _LOCK_PATH.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        out[k.strip()] = v.strip()
    return out


_LOCK = _read_lock()
ESBMC_IMG = f"touchstone/esbmc:{_LOCK.get('ESBMC_VERSION', 'v7.6.1')}"
DOCKER = os.environ.get("DOCKER", "sudo docker")


def _docker_image_present(image: str) -> bool:
    try:
        r = subprocess.run(
            shlex.split(DOCKER) + ["image", "inspect", image],
            capture_output=True, timeout=30,
        )
        return r.returncode == 0
    except Exception:
        return False


def run_esbmc_oracle(
    source: Path,
    function: str = "main",
    property: str = "memory-safety",
    unwind: int = 16,
    timeout_s: int = 120,
    unit: Optional[str] = None,
) -> Tier3Verdict:
    unit = unit or f"{source.name}::{function}"
    t0 = time.monotonic()
    if not _docker_image_present(ESBMC_IMG):
        return Tier3Verdict(
            unit=unit, engine="esbmc", property=property,
            verdict="inconclusive", unwind=unwind,
            wall_ms=int((time.monotonic() - t0) * 1000),
            evidence_excerpt=f"image-missing:{ESBMC_IMG}",
            soundness_note=(
                "ESBMC container not built — Phase 2.3 ships ESBMC as a "
                "dispatch-uniform stub. CBMC covers all Phase 2.3 obligations; "
                "ESBMC activates when CBMC's encoding is too slow on a Magma "
                "case in Phase 2.5."
            ),
            assumed_contracts=[],
        )

    # When the image is built, populate this branch the same way cbmc_driver
    # does — ESBMC's CLI is largely compatible (`--unwind`, `--bounds-check`,
    # `--pointer-check`, etc.) and its text output also carries
    # "VERIFICATION SUCCESSFUL" / "VERIFICATION FAILED".
    raise NotImplementedError(
        "ESBMC backend image is built but the run path is unimplemented; "
        "wire when Phase 2.5 demands the alternate engine."
    )


def _cli() -> int:
    ap = argparse.ArgumentParser(description="Tier-3 ESBMC driver (stub).")
    ap.add_argument("--source", required=True)
    ap.add_argument("--function", default="main")
    ap.add_argument("--property", default="memory-safety")
    ap.add_argument("--unwind", type=int, default=16)
    ap.add_argument("--out", required=True)
    ap.add_argument("--unit", default=None)
    args = ap.parse_args()
    v = run_esbmc_oracle(Path(args.source), function=args.function,
                         property=args.property, unwind=args.unwind, unit=args.unit)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(v.to_dict(), indent=2))
    print(json.dumps(v.to_dict(), indent=2))
    return 0 if v.verdict in {"safe", "unsafe"} else 1


if __name__ == "__main__":
    sys.exit(_cli())
