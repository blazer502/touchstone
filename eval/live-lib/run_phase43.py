"""Phase 4.3 driver: build + fuzz live SQLite via libFuzzer + ASan and emit
per-harness Tier1Verdict JSONs that the agent loop / metrics harness consume.

Two harnesses (paired control, mirrors Phase 4.2's k1/k2 pattern):

  L1 = live target — host libsqlite3 3.37.2 driven by sqlite3_ossfuzz.c
       Expected outcome: ``inconclusive`` (no crash within short budget,
       which is the *realistic* field-target result — sqlite3 has been
       continuously fuzzed by OSS-Fuzz since 2016).
  L2 = positive control — sqlite3_synth_oob.c links sqlite3 (so the live
       toolchain is exercised end-to-end) and ALSO contains a deterministic
       stack-OOB when input starts with "OOB!". Pre-seeded corpus carries
       that trigger so libFuzzer hits the crash in <1 s.

A green Phase-4.3 run is: L2 confirmed AND L1 inconclusive (no crash, no
toolchain failure). If L2 fails the toolchain is degraded; if L1 silently
``crash``-es we've potentially found a novel bug and the JSONL row records
the PoC artifact path.

Reuses ``oracle.tier1_fuzz.userspace.build_libfuzzer`` so the build flags
match the Phase-2.1 Tier-1 pin exactly (clang-14, -O0, ASan+libFuzzer).
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict
from pathlib import Path
from typing import Optional

from oracle.tier1_fuzz.userspace import build_libfuzzer, _truncate
from oracle.tier1_fuzz.verdict import Tier1Verdict, from_libfuzzer_log


REPO = Path(__file__).resolve().parents[2]
LIVE_DIR = REPO / "eval" / "live-lib"
HARNESS_DIR = LIVE_DIR / "harnesses"
ARTIFACTS_DIR = LIVE_DIR / "artifacts"


def _seed_corpus(corpus_dir: Path, positive_control: bool) -> None:
    """Drop deterministic seeds. For the positive control, the very first
    seed is the "OOB!" trigger so libFuzzer flips it to a crash immediately.
    For the live harness, seeds are plausible SQL bytes — they don't matter
    for soundness, only for time-to-coverage.
    """
    corpus_dir.mkdir(parents=True, exist_ok=True)
    if positive_control:
        (corpus_dir / "trigger.bin").write_bytes(b"OOB!" + b"A" * 64)
    else:
        for i, seed in enumerate([
            b"CREATE TABLE t(x);",
            b"SELECT 1;",
            b"PRAGMA integrity_check;",
            b"INSERT INTO t VALUES(json('[1,2,3]'));",
            b"WITH RECURSIVE c(x) AS (VALUES(1) UNION SELECT x+1 FROM c WHERE x<10) SELECT * FROM c;",
        ]):
            (corpus_dir / f"seed-{i:02d}.bin").write_bytes(seed)


def fuzz_live(harness_src: Path, unit: str, sanitizer: str, wall_seconds: int,
              extra_cflags: list[str], positive_control: bool,
              out_dir: Path) -> Tier1Verdict:
    out_dir.mkdir(parents=True, exist_ok=True)
    bin_path = out_dir / f"{unit}.bin"
    crash_dir = out_dir / "crashes"
    crash_dir.mkdir(exist_ok=True)
    corpus_dir = out_dir / "corpus"
    _seed_corpus(corpus_dir, positive_control=positive_control)

    build_libfuzzer(harness_src, bin_path, sanitizer, extra_cflags=extra_cflags)

    argv = [str(bin_path),
            f"-max_total_time={wall_seconds}",
            "-max_len=4096",
            f"-artifact_prefix={crash_dir}/",
            "-print_final_stats=1",
            str(corpus_dir)]
    t0 = time.monotonic()
    try:
        r = subprocess.run(argv, capture_output=True, text=True,
                           timeout=wall_seconds + 30)
        stdout, stderr, rc = r.stdout or "", r.stderr or "", r.returncode
    except subprocess.TimeoutExpired as e:
        stdout, stderr, rc = e.stdout or "", e.stderr or "", -1
    wall_ms = int((time.monotonic() - t0) * 1000)

    blob = (stdout if isinstance(stdout, str) else stdout.decode("utf-8", "replace")) + "\n" + \
           (stderr if isinstance(stderr, str) else stderr.decode("utf-8", "replace"))
    cls, loc = from_libfuzzer_log(blob)

    pov: Optional[str] = None
    for pat in ("crash-*", "leak-*", "oom-*", "timeout-*"):
        for art in sorted(crash_dir.glob(pat)):
            pov = str(art); break
        if pov: break

    verdict = "crash" if (cls or pov) else "inconclusive"

    return Tier1Verdict(
        unit=unit,
        engine="libfuzzer",
        sanitizer=sanitizer,
        verdict=verdict,
        wall_ms=wall_ms,
        crash_class=cls,
        location=loc,
        pov_path=pov,
        evidence_excerpt=_truncate(blob),
        soundness_note=("Tier-1 sanitizer hit = high-precision crash. "
                        "Absence of crash within wall budget is inconclusive, not safe."),
        assumed=[f"libFuzzer wall_seconds={wall_seconds}",
                 f"sanitizer={sanitizer}",
                 "max_len=4096",
                 "linked: -lsqlite3 (host libsqlite3 3.37.2)"],
    )


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--wall-live", type=int, default=20,
                   help="seconds for the live SQLite harness")
    p.add_argument("--wall-control", type=int, default=5,
                   help="seconds for the positive-control harness")
    p.add_argument("--out", type=Path,
                   default=REPO / "run-logs" / "phase4.3-live-lib.jsonl")
    p.add_argument("--summary", type=Path,
                   default=REPO / "run-logs" / "phase4.3-summary.json")
    args = p.parse_args(argv)

    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    args.out.parent.mkdir(parents=True, exist_ok=True)

    rows: list[dict] = []

    # L2 — positive control first; cheap and confirms the toolchain.
    v_ctrl = fuzz_live(
        harness_src=HARNESS_DIR / "sqlite3_synth_oob.c",
        unit="sqlite3-synth-oob",
        sanitizer="ASan",
        wall_seconds=args.wall_control,
        extra_cflags=["-lsqlite3"],
        positive_control=True,
        out_dir=ARTIFACTS_DIR / "sqlite3_synth_oob",
    )
    rows.append({"role": "positive_control", **v_ctrl.to_dict()})

    # L1 — live target.
    v_live = fuzz_live(
        harness_src=HARNESS_DIR / "sqlite3_ossfuzz.c",
        unit="sqlite3-live-3.37.2",
        sanitizer="ASan",
        wall_seconds=args.wall_live,
        extra_cflags=["-lsqlite3"],
        positive_control=False,
        out_dir=ARTIFACTS_DIR / "sqlite3_live",
    )
    rows.append({"role": "live_target", **v_live.to_dict()})

    with args.out.open("w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")

    # Phase-4.3 acceptance gate (the paired-control invariant).
    pass_ctrl = (v_ctrl.verdict == "crash")
    pass_live = (v_live.verdict in ("inconclusive", "crash"))  # crash on live = novel finding, also success
    gate_ok = pass_ctrl and pass_live
    novel_pov = (v_live.verdict == "crash")

    summary = {
        "target": "sqlite3-live-3.37.2",
        "wall_live_seconds": args.wall_live,
        "wall_control_seconds": args.wall_control,
        "control_verdict": v_ctrl.verdict,
        "control_class": v_ctrl.crash_class,
        "control_location": v_ctrl.location,
        "live_verdict": v_live.verdict,
        "live_class": v_live.crash_class,
        "live_pov_path": v_live.pov_path,
        "gate": "pass" if gate_ok else "fail",
        "novel_pov": novel_pov,
        "out": str(args.out.relative_to(REPO)),
    }
    args.summary.write_text(json.dumps(summary, indent=2))

    print(json.dumps(summary, indent=2))
    return 0 if gate_ok else 1


if __name__ == "__main__":
    sys.exit(main())
