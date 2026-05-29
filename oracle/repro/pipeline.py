"""Crash-reproducer pipeline orchestrator (R1: userspace).

Given a crashing input + a harness (local libFuzzer binary or in-container
OSS-Fuzz harness), produce a ``ReproVerdict`` carrying a minimized,
reproducibility-scored ``Reproducer``.

Stages (PLAN R-track):
  1. characterize  — replay the candidate N times, find the majority crash
                     bucket (``crash_signature``); that's the *target* bug.
  2. minimize      — libFuzzer ``-minimize_crash`` (best-effort), then confirm
                     the minimized input still fires the SAME signature.
  3. measure       — re-run the chosen trigger N times -> ``repro_rate``.
  4. package       — emit ``Reproducer`` + ``ReproVerdict``.

The re-run is the verdict authority (PLAN §8); no LLM here.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from collections import Counter
from pathlib import Path
from typing import List, Optional, Tuple

from schemas.reproducer import (
    DEFAULT_REPRO_THRESHOLD,
    DOMAIN_USERSPACE,
    Reproducer,
    ReproVerdict,
    classify_repro,
)

from . import userspace as us

_HEX_INLINE_MAX = 64        # inline the trigger bytes into the artifact when this small


def _sha12(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()[:12]


def _majority(samples: List[str]) -> Tuple[str, int]:
    c = Counter(s for s in samples if s)
    if not c:
        return "", 0
    sig, n = c.most_common(1)[0]
    return sig, n


def _maybe_hex(p: Path) -> Optional[str]:
    try:
        b = p.read_bytes()
    except OSError:
        return None
    return b.hex() if len(b) <= _HEX_INLINE_MAX else None


def _build_verdict(unit: str, repro_rate: float, runs: int, signature: str,
                   threshold: float, reproducer: Optional[Reproducer],
                   wall_ms: int, assumed: List[str]) -> ReproVerdict:
    verdict = classify_repro(repro_rate, threshold)
    note = ("repro_rate is a finite-N frequency estimate; 'unreproducible' = "
            "not reproduced within N runs under this build, NOT 'safe'. "
            "Re-run (sanitizer) is the verdict authority.")
    return ReproVerdict(
        unit=unit, domain=DOMAIN_USERSPACE, verdict=verdict,
        repro_rate=round(repro_rate, 4), runs=runs, signature=signature,
        threshold=threshold, reproducer=reproducer, wall_ms=wall_ms,
        soundness_note=note, assumed=assumed,
    )


def run_userspace_local(harness_bin: Path, poc: Path, *, sanitizer: str = "auto",
                        runs: int = 10, threshold: float = DEFAULT_REPRO_THRESHOLD,
                        minimize: bool = True, unit: Optional[str] = None,
                        out_dir: Optional[Path] = None,
                        timeout_seconds: int = 60) -> ReproVerdict:
    t0 = time.monotonic()
    unit = unit or harness_bin.stem
    out_dir = out_dir or poc.resolve().parent
    build_id = _sha12(harness_bin)
    assumed = [f"backend=local", f"harness={harness_bin.name}", f"build_id={build_id}",
               f"runs={runs}", f"sanitizer={sanitizer}"]

    # 1. characterize
    _, _, samples = us.measure_local(harness_bin, poc, target_signature="",
                                     sanitizer=sanitizer, runs=runs,
                                     timeout_seconds=timeout_seconds)
    target_sig, hits = _majority(samples)
    if not target_sig:
        return _build_verdict(unit, 0.0, runs, "", threshold, None,
                              int((time.monotonic() - t0) * 1000),
                              assumed + ["never crashed in characterization"])

    trigger = poc
    minimized = False
    orig_size = poc.stat().st_size
    repro_rate = hits / runs

    # 2. minimize (best-effort) + confirm same signature
    if minimize:
        cand = us.minimize_local(harness_bin, poc, out_dir / f"{unit}.min")
        if cand is not None and cand.stat().st_size < orig_size:
            ch, cr, _ = us.measure_local(harness_bin, poc=cand, target_signature=target_sig,
                                         sanitizer=sanitizer, runs=max(3, runs // 3),
                                         timeout_seconds=timeout_seconds)
            if cr > 0 and ch == cr:           # every confirm run reproduced the SAME bug
                trigger = cand
                minimized = True

    # 3. measure on the chosen trigger
    if minimized:
        hits, runs, _ = us.measure_local(harness_bin, trigger, target_signature=target_sig,
                                         sanitizer=sanitizer, runs=runs,
                                         timeout_seconds=timeout_seconds)
        repro_rate = hits / runs

    san, cls, loc = target_sig.split("|", 2)
    reproducer = Reproducer(
        signature=target_sig, domain=DOMAIN_USERSPACE, repro_rate=round(repro_rate, 4),
        runs=runs, build_id=build_id, engine="libfuzzer",
        replay_cmd=f"{harness_bin} {trigger}", minimized=minimized,
        minimized_trigger_path=str(trigger) if minimized else None,
        minimized_trigger_hex=_maybe_hex(trigger),
        original_trigger_path=str(poc), original_size_bytes=orig_size,
        minimized_size_bytes=trigger.stat().st_size,
        crash_class=(cls if cls != "?" else None),
        location=(loc if loc != "?" else None),
        wall_ms=int((time.monotonic() - t0) * 1000),
    )
    return _build_verdict(unit, repro_rate, runs, target_sig, threshold, reproducer,
                          int((time.monotonic() - t0) * 1000), assumed)


def run_userspace_docker(image: str, harness_path: str, poc: Path, *,
                         sanitizer: str = "auto", runs: int = 10,
                         threshold: float = DEFAULT_REPRO_THRESHOLD,
                         minimize: bool = True, unit: Optional[str] = None,
                         out_dir: Optional[Path] = None,
                         timeout_seconds: int = 60) -> ReproVerdict:
    t0 = time.monotonic()
    unit = unit or f"{image}:{Path(harness_path).name}"
    out_dir = out_dir or poc.resolve().parent
    build_id = image
    assumed = [f"backend=docker", f"image={image}", f"harness={harness_path}",
               f"runs={runs}", f"sanitizer={sanitizer}"]

    _, _, samples = us.measure_docker(image, harness_path, poc, target_signature="",
                                      sanitizer=sanitizer, runs=runs,
                                      timeout_seconds=timeout_seconds)
    target_sig, hits = _majority(samples)
    if not target_sig:
        return _build_verdict(unit, 0.0, runs, "", threshold, None,
                              int((time.monotonic() - t0) * 1000),
                              assumed + ["never crashed in characterization"])

    trigger = poc
    minimized = False
    orig_size = poc.stat().st_size
    repro_rate = hits / runs

    if minimize:
        cand = us.minimize_docker(image, harness_path, poc, out_dir / f"{Path(harness_path).name}.min")
        if cand is not None and cand.stat().st_size < orig_size:
            ch, cr, _ = us.measure_docker(image, harness_path, cand, target_signature=target_sig,
                                          sanitizer=sanitizer, runs=max(3, runs // 3),
                                          timeout_seconds=timeout_seconds)
            if cr > 0 and ch == cr:
                trigger = cand
                minimized = True
                hits, runs, _ = us.measure_docker(image, harness_path, trigger,
                                                  target_signature=target_sig,
                                                  sanitizer=sanitizer, runs=runs,
                                                  timeout_seconds=timeout_seconds)
                repro_rate = hits / runs

    san, cls, loc = target_sig.split("|", 2)
    reproducer = Reproducer(
        signature=target_sig, domain=DOMAIN_USERSPACE, repro_rate=round(repro_rate, 4),
        runs=runs, build_id=build_id, engine="libfuzzer",
        replay_cmd=(f"docker run --rm --network=none -v {trigger}:/poc:ro "
                    f"{image} {harness_path} /poc"),
        minimized=minimized,
        minimized_trigger_path=str(trigger) if minimized else None,
        minimized_trigger_hex=_maybe_hex(trigger),
        original_trigger_path=str(poc), original_size_bytes=orig_size,
        minimized_size_bytes=trigger.stat().st_size,
        crash_class=(cls if cls != "?" else None),
        location=(loc if loc != "?" else None),
        wall_ms=int((time.monotonic() - t0) * 1000),
    )
    return _build_verdict(unit, repro_rate, runs, target_sig, threshold, reproducer,
                          int((time.monotonic() - t0) * 1000), assumed)


def _cli() -> int:
    ap = argparse.ArgumentParser(description="Crash-reproducer pipeline (R1 userspace).")
    sub = ap.add_subparsers(dest="cmd", required=True)

    pl = sub.add_parser("userspace-local", help="Score+minimize against a local libFuzzer binary.")
    pl.add_argument("--harness-bin", required=True)
    pl.add_argument("--poc", required=True)
    pl.add_argument("--sanitizer", default="auto")
    pl.add_argument("--runs", type=int, default=10)
    pl.add_argument("--threshold", type=float, default=DEFAULT_REPRO_THRESHOLD)
    pl.add_argument("--no-minimize", action="store_true")
    pl.add_argument("--unit", default=None)
    pl.add_argument("--out", required=True)

    pd = sub.add_parser("userspace-docker", help="Score+minimize against an OSS-Fuzz image harness.")
    pd.add_argument("--image", required=True)
    pd.add_argument("--harness-path", required=True)
    pd.add_argument("--poc", required=True)
    pd.add_argument("--sanitizer", default="auto")
    pd.add_argument("--runs", type=int, default=10)
    pd.add_argument("--threshold", type=float, default=DEFAULT_REPRO_THRESHOLD)
    pd.add_argument("--no-minimize", action="store_true")
    pd.add_argument("--unit", default=None)
    pd.add_argument("--out", required=True)

    args = ap.parse_args()
    if args.cmd == "userspace-local":
        v = run_userspace_local(Path(args.harness_bin), Path(args.poc), sanitizer=args.sanitizer,
                                runs=args.runs, threshold=args.threshold,
                                minimize=not args.no_minimize, unit=args.unit)
    else:
        v = run_userspace_docker(args.image, args.harness_path, Path(args.poc),
                                 sanitizer=args.sanitizer, runs=args.runs,
                                 threshold=args.threshold, minimize=not args.no_minimize,
                                 unit=args.unit)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(v.to_dict(), indent=2))
    print(json.dumps(v.to_dict(), indent=2))
    return 0 if v.verdict == "reproducible" else 1


if __name__ == "__main__":
    sys.exit(_cli())
