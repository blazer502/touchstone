"""KLEE driver (Tier-2 userspace symbolic).

Build a C source file to LLVM bitcode under our pinned ``LLVM_VERSION=14``,
run KLEE, parse its output into a Tier2Verdict.

Soundness (recorded in ``docs/soundness-assumptions.md``):
- KLEE's environment is ``klee-uclibc`` + POSIX models. Calls outside the model
  are unmodeled; we surface this in the verdict's ``soundness_note`` whenever
  ``klee_warning_once: calling external`` shows up in the run log.
- A SAT path (``.ktest`` produced for a reachable error or marked target)
  becomes ``sat`` and triggers Tier-1 re-confirmation in the router.
- "Halt: no more states" with zero errors AND zero externals = ``unsat`` for
  the encoded property (the property is e.g. ``klee_assert(false)`` at the
  target). If unmodeled externals appear, we downgrade to ``inconclusive``.
- Timeout/OOM = ``inconclusive``.

No LLM in this module (Phase 2 rule). The harness/property is provided by the
caller as plain C; LLM contract/driver synthesis is Phase 3.2.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Optional

from .verdict import Tier2Verdict


CLANG = os.environ.get("CLANG", "clang-14")
KLEE = os.environ.get("KLEE", "klee")
KLEE_INCLUDE = os.environ.get("KLEE_INCLUDE", "/usr/local/include")


def _truncate(text: str, limit: int = 4000) -> str:
    return text if len(text) <= limit else text[:limit] + f"\n…[truncated {len(text)-limit} bytes]"


def build_bitcode(source: Path, out_bc: Path, extra_cflags: Optional[list[str]] = None) -> None:
    """Compile a C source to LLVM bitcode for KLEE.

    -O0, -g, -Xclang -disable-O0-optnone so KLEE's intrinsics pass can still
    transform the IR; include klee.h from the host install.
    """
    cmd = [
        CLANG, "-emit-llvm", "-c", "-g", "-O0",
        "-Xclang", "-disable-O0-optnone",
        f"-I{KLEE_INCLUDE}",
        *(extra_cflags or []),
        str(source), "-o", str(out_bc),
    ]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"bitcode build failed:\nCMD: {' '.join(cmd)}\nSTDERR:\n{r.stderr}")


def _parse_klee_stats(klee_dir: Path, stderr_blob: str) -> tuple[int, int, int, list[Path]]:
    """Returns (paths_completed, paths_partial, generated_tests, error_ktests).

    KLEE's `--max-time`-bounded run reports:
      "KLEE: done: completed paths = N"
      "KLEE: done: partially completed paths = N"   (forks that hit the budget)
      "KLEE: done: generated tests = N"
    """
    completed = 0
    partial = 0
    generated = 0
    m = re.search(r"KLEE: done: completed paths = (\d+)", stderr_blob)
    if m:
        completed = int(m.group(1))
    m = re.search(r"KLEE: done: partially completed paths = (\d+)", stderr_blob)
    if m:
        partial = int(m.group(1))
    m = re.search(r"KLEE: done: generated tests = (\d+)", stderr_blob)
    if m:
        generated = int(m.group(1))
    err_ktests = sorted(klee_dir.glob("test*.ktest")) if klee_dir.exists() else []
    # Only the ktests that have a sibling .err file are interesting
    err_ktests = [k for k in err_ktests if any(k.with_suffix(s).exists() for s in
                  (".abort.err", ".ptr.err", ".free.err", ".overflow.err", ".div.err", ".assert.err", ".user.err"))]
    return completed, partial, generated, err_ktests


def _has_unmodeled_external(stderr_blob: str) -> bool:
    """Returns True if KLEE logged any external (unmodeled) calls."""
    return bool(re.search(r"klee_warning_once:.*calling external", stderr_blob) or
                re.search(r"KLEE: WARNING.*calling external", stderr_blob))


def run_klee(bitcode: Path, wall_seconds: int = 60, max_memory_mb: int = 2048,
             out_dir: Optional[Path] = None,
             max_forks: int = 4096,
             extra_klee_args: Optional[list[str]] = None,
             unit: Optional[str] = None) -> Tier2Verdict:
    """Run KLEE on a bitcode file with a wall + memory budget."""
    unit = unit or bitcode.stem
    out_dir = out_dir or Path(tempfile.mkdtemp(prefix="tier2-klee-"))
    out_dir.mkdir(parents=True, exist_ok=True)
    klee_out = out_dir / "klee-out"
    if klee_out.exists():
        shutil.rmtree(klee_out)

    cmd = [
        KLEE,
        f"--output-dir={klee_out}",
        f"--max-time={wall_seconds}",
        f"--max-memory={max_memory_mb}",
        f"--max-forks={max_forks}",
        "--exit-on-error-type=Assert",
        "--exit-on-error-type=Ptr",
        "--exit-on-error-type=Free",
        "--exit-on-error-type=Overflow",
        *(extra_klee_args or []),
        str(bitcode),
    ]

    t0 = time.monotonic()
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=wall_seconds + 30)
        timed_out = False
    except subprocess.TimeoutExpired as e:
        timed_out = True
        class _R:  # tiny stand-in matching subprocess.CompletedProcess shape
            returncode = -1
            stdout = (e.stdout.decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or ""))
            stderr = (e.stderr.decode(errors="replace") if isinstance(e.stderr, bytes) else (e.stderr or ""))
        r = _R()
    wall_ms = int((time.monotonic() - t0) * 1000)

    blob = (r.stdout or "") + "\n" + (r.stderr or "")
    completed, partial, _generated, err_ktests = _parse_klee_stats(klee_out, blob)
    unmodeled = _has_unmodeled_external(blob)

    pov_path: Optional[str] = None
    target_location: Optional[str] = None
    if err_ktests:
        pov_path = str(err_ktests[0])
        # First .err file gives location: "File: <path>\nLine: <n>"
        err_file = next((err_ktests[0].with_suffix(s) for s in
                         (".abort.err", ".ptr.err", ".free.err", ".overflow.err",
                          ".div.err", ".assert.err", ".user.err")
                         if err_ktests[0].with_suffix(s).exists()), None)
        if err_file:
            text = err_file.read_text(errors="replace")
            f = re.search(r"^File: (\S+)", text, re.M)
            l = re.search(r"^Line: (\d+)", text, re.M)
            if f and l:
                target_location = f"{f.group(1)}:{l.group(1)}"

    if err_ktests:
        verdict = "sat"
        note = ("KLEE produced an error-ktest; candidate PoV. Re-confirm with Tier-1 "
                "before declaring an exploit. Symbolic SAT alone is not a final verdict.")
    elif timed_out:
        verdict = "inconclusive"
        note = "KLEE wall budget exhausted; no decisive verdict within time."
    elif unmodeled:
        verdict = "inconclusive"
        note = ("KLEE encountered unmodeled external calls (klee-uclibc/POSIX model gap); "
                "unsat under such a model is unsound for pruning, so we report inconclusive.")
    elif completed > 0 and partial == 0:
        # Every explored path completed (no fork exhausted the budget) and no error
        # ktests were produced ⇒ the encoded property is unreachable under the
        # symbolic model. UNSAT is sound only relative to that model.
        verdict = "unsat"
        note = ("All explored paths completed without hitting the encoded property; "
                "unsat is sound only under the klee-uclibc + POSIX environment model.")
    else:
        verdict = "inconclusive"
        note = (f"KLEE returned no error; completed={completed} partial={partial}. "
                "Partial paths or zero completion means exhaustion / budget hit ⇒ inconclusive.")

    return Tier2Verdict(
        unit=unit,
        engine="klee",
        verdict=verdict,
        wall_ms=wall_ms,
        property="klee-encoded-assertions",
        paths_explored=completed + partial,
        paths_completed=completed,
        pov_path=pov_path,
        target_location=target_location,
        evidence_excerpt=_truncate(blob),
        soundness_note=note,
        assumed=[f"wall_seconds={wall_seconds}",
                 f"max_memory_mb={max_memory_mb}",
                 f"max_forks={max_forks}",
                 "klee-uclibc + POSIX environment model"],
    )


def fuzz(source: Path, wall_seconds: int = 60, unit: Optional[str] = None,
         out_dir: Optional[Path] = None, extra_cflags: Optional[list[str]] = None,
         extra_klee_args: Optional[list[str]] = None) -> Tier2Verdict:
    """Build C source to bitcode + run KLEE in one call."""
    unit = unit or source.stem
    out_dir = out_dir or Path(tempfile.mkdtemp(prefix="tier2-klee-"))
    out_dir.mkdir(parents=True, exist_ok=True)
    bc = out_dir / f"{unit}.bc"
    build_bitcode(source, bc, extra_cflags=extra_cflags)
    return run_klee(bc, wall_seconds=wall_seconds, out_dir=out_dir,
                    extra_klee_args=extra_klee_args, unit=unit)


def _cli() -> int:
    ap = argparse.ArgumentParser(description="Tier-2 KLEE driver.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_run = sub.add_parser("run", help="Compile a C source + run KLEE.")
    p_run.add_argument("--source", required=True)
    p_run.add_argument("--wall-seconds", type=int, default=60)
    p_run.add_argument("--out", required=True, help="Where to write the verdict JSON")
    p_run.add_argument("--out-dir", default=None, help="Working directory (kept after run)")
    p_run.add_argument("--unit", default=None)

    p_bc = sub.add_parser("run-bc", help="Run KLEE on existing bitcode.")
    p_bc.add_argument("--bitcode", required=True)
    p_bc.add_argument("--wall-seconds", type=int, default=60)
    p_bc.add_argument("--out", required=True)
    p_bc.add_argument("--out-dir", default=None)
    p_bc.add_argument("--unit", default=None)

    args = ap.parse_args()
    if args.cmd == "run":
        v = fuzz(Path(args.source), wall_seconds=args.wall_seconds,
                 unit=args.unit,
                 out_dir=Path(args.out_dir) if args.out_dir else None)
    else:
        v = run_klee(Path(args.bitcode), wall_seconds=args.wall_seconds,
                     out_dir=Path(args.out_dir) if args.out_dir else None,
                     unit=args.unit)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(v.to_dict(), indent=2))
    print(json.dumps(v.to_dict(), indent=2))
    return 0 if v.verdict in {"sat", "unsat"} else 1


if __name__ == "__main__":
    sys.exit(_cli())
