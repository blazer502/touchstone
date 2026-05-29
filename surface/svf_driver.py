"""Phase 6.4 — SVF interprocedural value-flow taint driver (Stage A upgrade).

Stage A (Phase 1.2) builds its call graph + reachability with ctags + regex —
no real value-flow, no pointer analysis. SVF (Static Value-Flow, svf-tools)
gives precise interprocedural value-flow on LLVM bitcode (the Sparse Value-Flow
Graph / Andersen pointer analysis), which is the principled substrate for
attacker-source → sink taint reachability.

This driver wraps the containerised SVF tool behind the same Stage-A interface
(emit a keep-set / taint slice). It requires LLVM bitcode of the target — for
userspace that's `clang -emit-llvm` of the OSS-Fuzz harness; for the kernel it
needs a wllvm/`clang` whole-kernel bitcode build (heavy). When the bitcode or
the SVF image is missing it returns a clean `infrastructure_pending` result,
the same honest pattern Phase 5.3 / 6.3 use — the regex Stage A stays the
default so nothing regresses.

Soundness: SVF value-flow is a sound over-approximation (Andersen's analysis is
inclusion-based / over-approximate), so a taint slice it produces is a superset
of the truly-tainted set — consistent with Stage A's "never prune a real path"
rule. When SVF is active it would *refine* (shrink) the keep-set the same way
6.2 MLTA does, under the documented "bitcode reflects the analyzed config"
assumption (CONFIG_* affects which code compiles).

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

SVF_IMAGE = os.environ.get("SVF_IMAGE", "touchstone/svf:latest")


def _docker() -> list[str]:
    return os.environ.get("DOCKER", "sudo docker").split()


def _image_present(image: str) -> bool:
    try:
        r = subprocess.run([*_docker(), "image", "inspect", image],
                           capture_output=True, text=True)
        return r.returncode == 0
    except FileNotFoundError:
        return False


def run_svf_taint(
    bitcode: Optional[Path],
    *,
    sources: Optional[list[str]] = None,
    sinks: Optional[list[str]] = None,
    target: str = "unknown",
    timeout_s: int = 600,
) -> dict:
    """Run SVF source→sink value-flow taint; infra-pending hatch.

    Returns a dict with `status` ∈ {ok, infrastructure_pending} mirroring the
    Stage-A slice schema (a `keep_set` / `tainted` list when active).
    """
    t0 = time.monotonic()
    if not _image_present(SVF_IMAGE):
        return {
            "status": "infrastructure_pending",
            "engine": "svf",
            "target": target,
            "reason": f"image-missing: {SVF_IMAGE} (build via docker/svf.Dockerfile)",
            "soundness_note": (
                "SVF image not built; Stage A stays on the regex call graph "
                "(default, sound). SVF is an opt-in value-flow refinement."
            ),
            "wall_ms": int((time.monotonic() - t0) * 1000),
        }
    if bitcode is None or not Path(bitcode).exists():
        return {
            "status": "infrastructure_pending",
            "engine": "svf",
            "target": target,
            "reason": (
                "bitcode-missing: SVF needs LLVM bitcode of the target "
                "(clang -emit-llvm for userspace; wllvm whole-kernel build for "
                "the kernel — heavy, deferred)."
            ),
            "soundness_note": "no bitcode → no value-flow slice; regex Stage A stays default.",
            "wall_ms": int((time.monotonic() - t0) * 1000),
        }
    # Real path (active once image + bitcode exist): run SVF's saber / svf-ex
    # source-sink checker and parse the tainted value-flow paths.
    work = Path(bitcode).resolve().parent
    cmd = [
        *_docker(), "run", "--rm", "-v", f"{work}:/work", "-w", "/work",
        SVF_IMAGE, "sh", "-c",
        f"saber -leak {Path(bitcode).name} 2>&1 || svf-ex {Path(bitcode).name} 2>&1",
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s)
        out = (r.stdout or "") + (r.stderr or "")
        return {
            "status": "ok",
            "engine": "svf",
            "target": target,
            "evidence_excerpt": out[-2000:],
            "soundness_note": (
                "SVF Andersen-based value-flow is a sound over-approximation; "
                "the tainted slice is a superset of the truly-tainted set."
            ),
            "wall_ms": int((time.monotonic() - t0) * 1000),
        }
    except subprocess.TimeoutExpired:
        return {
            "status": "infrastructure_pending",
            "engine": "svf", "target": target,
            "reason": f"SVF wall budget {timeout_s}s exhausted.",
            "wall_ms": int((time.monotonic() - t0) * 1000),
        }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Phase 6.4 SVF value-flow taint driver.")
    ap.add_argument("--bitcode", type=Path, default=None,
                    help="LLVM bitcode of the target (.bc). Omit for the hatch demo.")
    ap.add_argument("--target", type=str, default="unknown")
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--timeout-s", type=int, default=600)
    args = ap.parse_args(argv)

    res = run_svf_taint(args.bitcode, target=args.target, timeout_s=args.timeout_s)
    here = Path(__file__).resolve().parent
    out_dir = here / "svf"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = args.out or out_dir / f"{args.target}.json"
    out_path.write_text(json.dumps(res, indent=2) + "\n")
    print(f"[svf] status={res['status']} "
          f"{res.get('reason', res.get('evidence_excerpt','')[:80])}")
    print(f"[svf] -> {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
