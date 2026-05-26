"""Kernel Tier-1 driver: KASAN-replay (deterministic) + syzkaller wiring.

Two modes share the same Tier1Verdict shape:

- ``kasan-replay``: re-run a recorded reproducer (PoC binary baked into an
  initramfs) under QEMU+KASAN, parse the serial log for a KASAN BUG banner.
  This is the path Phase 0.4 stood up; here we wrap it behind the unified
  verdict schema so the router/metrics layer treats it like any Tier-1 result.

- ``syzkaller``: thin wrapper over the pinned syzkaller manager image. In
  Phase 2.1 this only validates the image builds + ``syz-manager -version``
  responds; coverage-guided fuzz runs against a live kernel are Phase 4.2.

The hand-written syzlang descriptor for nf_tables (CVE-2024-1086 surface)
lives at ``oracle/tier1_fuzz/syzlang/nf_tables_cve_2024_1086.txt`` so a future
fuzz-mode call can feed it to syz-manager.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

from .verdict import Tier1Verdict, from_kasan_log


def _truncate(text: str, limit: int = 6000) -> str:
    return text if len(text) <= limit else text[:limit] + f"\n…[truncated {len(text)-limit} bytes]"


def kasan_replay(qemu_script: Path, log_path: Optional[Path] = None,
                 unit: str = "kernelctf-historical", timeout_seconds: int = 120) -> Tier1Verdict:
    """Run a QEMU+KASAN replay script and parse its log for a KASAN BUG."""
    t0 = time.monotonic()
    try:
        r = subprocess.run(["bash", str(qemu_script)], capture_output=True, text=True,
                           timeout=timeout_seconds)
        rc = r.returncode
        blob = (r.stdout or "") + "\n" + (r.stderr or "")
    except subprocess.TimeoutExpired as e:
        rc = -1
        blob = ((e.stdout.decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or ""))
                + "\n"
                + (e.stderr.decode(errors="replace") if isinstance(e.stderr, bytes) else (e.stderr or "")))
    wall_ms = int((time.monotonic() - t0) * 1000)

    # Prefer the on-disk log if the script wrote one — captures full dmesg even
    # if we time out on the wrapper.
    text = blob
    if log_path and log_path.exists():
        text = log_path.read_text(errors="replace")

    cls, loc = from_kasan_log(text)
    has_bug = bool(re.search(r"BUG:\s+KASAN:", text))
    verdict = "crash" if has_bug else ("no_crash" if rc == 0 else "inconclusive")

    return Tier1Verdict(
        unit=unit, engine="kasan_replay", sanitizer="KASAN", verdict=verdict, wall_ms=wall_ms,
        crash_class=cls, location=loc,
        pov_path=str(qemu_script),
        evidence_excerpt=_truncate(text),
        soundness_note="KASAN BUG banner in serial log = crash. Tier-1 'no_crash' is precision, not soundness.",
        assumed=[f"qemu_timeout={timeout_seconds}s", "kernel=KASAN+KCOV"],
    )


def kasan_replay_from_log(log_path: Path, unit: str = "kernelctf-historical") -> Tier1Verdict:
    """Parse a previously-captured dmesg log for a KASAN BUG banner.

    Used by the metrics harness to avoid re-booting QEMU on every baseline
    run (≈90s per boot). The serial log produced by ``scripts/run_qemu.sh``
    is the authoritative evidence; this is a pure parser over that file.
    """
    text = log_path.read_text(errors="replace")
    cls, loc = from_kasan_log(text)
    has_bug = bool(re.search(r"BUG:\s+KASAN:", text))
    verdict = "crash" if has_bug else "inconclusive"
    return Tier1Verdict(
        unit=unit, engine="kasan_replay", sanitizer="KASAN", verdict=verdict, wall_ms=0,
        crash_class=cls, location=loc,
        pov_path=str(log_path),
        evidence_excerpt=_truncate(text),
        soundness_note=("Replay from captured log. KASAN BUG banner is the verdict — "
                        "the wall_ms=0 here is bookkeeping (the boot happened in 0.4)."),
        assumed=["log=parsed-only", "no fresh qemu boot"],
    )


def syzkaller_smoke(image: str = "veri-agent/syzkaller:master",
                    unit: str = "syzkaller-version-stamp") -> Tier1Verdict:
    """Stamp the pinned syzkaller image's version. Wired-but-not-fuzzed in 2.1."""
    docker = os.environ.get("DOCKER", "sudo docker").split()
    # Image may not be built yet — that's expected (heavy build). Return inconclusive cleanly.
    t0 = time.monotonic()
    has_image = subprocess.run([*docker, "image", "inspect", image], capture_output=True).returncode == 0
    if not has_image:
        wall_ms = int((time.monotonic() - t0) * 1000)
        return Tier1Verdict(
            unit=unit, engine="syzkaller_fuzz", sanitizer="KASAN", verdict="inconclusive",
            wall_ms=wall_ms,
            evidence_excerpt=(f"docker image {image} not present. "
                              "Build with: docker build -f docker/syzkaller.Dockerfile -t " + image + " docker/"),
            soundness_note=("Syzkaller-as-fuzzer is Phase 4.2; in 2.1 we only require the path "
                            "be wired. Falls through to KASAN-replay for the 2.1 acceptance row."),
            assumed=["image not built"],
        )
    r = subprocess.run([*docker, "run", "--rm", image, "syz-manager", "-version"],
                       capture_output=True, text=True, timeout=60)
    wall_ms = int((time.monotonic() - t0) * 1000)
    blob = (r.stdout or "") + "\n" + (r.stderr or "")
    return Tier1Verdict(
        unit=unit, engine="syzkaller_fuzz", sanitizer="KASAN",
        verdict="no_crash" if r.returncode == 0 else "inconclusive",
        wall_ms=wall_ms,
        evidence_excerpt=_truncate(blob),
        soundness_note="Smoke only — version stamp. Fuzz-driven runs are Phase 4.2.",
        assumed=[f"image={image}"],
    )


def _cli() -> int:
    ap = argparse.ArgumentParser(description="Tier-1 kernel driver (KASAN replay + syzkaller).")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_rep = sub.add_parser("kasan-replay", help="Run QEMU+KASAN replay, parse for BUG banner.")
    p_rep.add_argument("--qemu-script", required=True)
    p_rep.add_argument("--log-path", default=None)
    p_rep.add_argument("--unit", default="kernelctf-historical")
    p_rep.add_argument("--timeout-seconds", type=int, default=120)
    p_rep.add_argument("--out", required=True)

    p_log = sub.add_parser("kasan-from-log", help="Parse an existing dmesg/serial log for a KASAN BUG.")
    p_log.add_argument("--log-path", required=True)
    p_log.add_argument("--unit", default="kernelctf-historical")
    p_log.add_argument("--out", required=True)

    p_syz = sub.add_parser("syzkaller-smoke", help="Stamp syzkaller image version.")
    p_syz.add_argument("--image", default="veri-agent/syzkaller:master")
    p_syz.add_argument("--unit", default="syzkaller-version-stamp")
    p_syz.add_argument("--out", required=True)

    args = ap.parse_args()
    if args.cmd == "kasan-replay":
        v = kasan_replay(Path(args.qemu_script),
                         log_path=Path(args.log_path) if args.log_path else None,
                         unit=args.unit, timeout_seconds=args.timeout_seconds)
    elif args.cmd == "kasan-from-log":
        v = kasan_replay_from_log(Path(args.log_path), unit=args.unit)
    else:
        v = syzkaller_smoke(image=args.image, unit=args.unit)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(v.to_dict(), indent=2))
    print(json.dumps({k: v.to_dict()[k] for k in v.to_dict() if k != "evidence_excerpt"}, indent=2))
    return 0 if v.verdict == "crash" else 1


if __name__ == "__main__":
    sys.exit(_cli())
