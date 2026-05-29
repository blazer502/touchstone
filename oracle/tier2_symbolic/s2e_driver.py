"""S2E driver (Tier-2 kernel selective symbolic execution).

PLAN §3 Tier-2 (kernel): S2E runs selective symbolic execution on QEMU and
works on real kernels. Full provisioning via `s2e-env init` fetches QEMU,
KLEE, libs2e and rebuilds them (~10 GB, ~30 minutes wall). That cost is only
worth paying when Phase 4.2 (kernelCTF live LTS hunt) demands it, so this
module is a *wired interface stub*:

- If the `touchstone/s2e:<ver>` image is built AND a project directory has
  been provisioned by `s2e-env init`, dispatch to S2E (TODO when image lands).
- Otherwise return a clean "image-missing" inconclusive verdict so the router
  can fall back to syzkaller (Tier-1) / hand-crafted KASAN replay.

Soundness (recorded in ``docs/soundness-assumptions.md``):
- S2E concretizes arguments selectively; concretized inputs mask paths gated
  on them. The verdict's ``assumed`` list will record which arguments stayed
  symbolic when the engine actually runs.

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


S2E_IMAGE = os.environ.get("S2E_IMAGE", "touchstone/s2e:2.0.0")


def _image_present(image: str) -> bool:
    docker = os.environ.get("DOCKER", "sudo docker").split()
    r = subprocess.run([*docker, "image", "inspect", image],
                       capture_output=True, text=True)
    return r.returncode == 0


def run(project_dir: Optional[Path] = None, target_property: str = "kernel-path-reach",
        wall_seconds: int = 600, unit: Optional[str] = None) -> Tier2Verdict:
    unit = unit or (project_dir.name if project_dir else "s2e")
    t0 = time.monotonic()
    if not _image_present(S2E_IMAGE):
        wall_ms = int((time.monotonic() - t0) * 1000)
        return Tier2Verdict(
            unit=unit, engine="s2e", verdict="inconclusive", wall_ms=wall_ms,
            property=target_property,
            evidence_excerpt=f"image-missing: {S2E_IMAGE}",
            soundness_note="S2E image not built on this host; engine wired but inactive.",
            assumed=[f"image={S2E_IMAGE}", "image-missing path"],
        )
    raise NotImplementedError(
        "S2E runner stub — full provisioning (~10 GB) is deferred to Phase 4.2 (kernelCTF live)."
    )


def _cli() -> int:
    ap = argparse.ArgumentParser(description="Tier-2 S2E driver (stub).")
    ap.add_argument("--project-dir", default=None)
    ap.add_argument("--wall-seconds", type=int, default=600)
    ap.add_argument("--unit", default=None)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    v = run(Path(args.project_dir) if args.project_dir else None,
            wall_seconds=args.wall_seconds, unit=args.unit)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(v.to_dict(), indent=2))
    print(json.dumps(v.to_dict(), indent=2))
    return 0 if v.verdict in {"sat", "unsat"} else 1


if __name__ == "__main__":
    sys.exit(_cli())
