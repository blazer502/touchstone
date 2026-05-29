"""Userspace Tier-1 driver: libFuzzer (+ AFL++ optional) with ASan/MSan/UBSan.

Modes:
- ``fuzz``  : build a hand-written harness, run libFuzzer up to ``wall_seconds``,
              parse sanitizer output → Tier1Verdict.
- ``replay``: run an *existing* harness binary (e.g. from a CyberGym OSS-Fuzz
              Docker image) against a recorded PoC; parse sanitizer output → verdict.

Host clang-14 is used directly — it matches ``LLVM_VERSION=14`` in
``docs/toolchain.lock`` exactly, so we avoid the multi-GB clang image.

No LLM in this module (Phase 2 explicitly hand-written; LLM harness generation
is Phase 3.2).
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Optional

from .verdict import Tier1Verdict, from_libfuzzer_log


CLANG = os.environ.get("CLANG", "clang")
SANITIZER_FLAGS = {
    "ASan":  ["-fsanitize=address,fuzzer", "-fno-omit-frame-pointer"],
    "MSan":  ["-fsanitize=memory,fuzzer", "-fsanitize-memory-track-origins=2", "-fno-omit-frame-pointer"],
    "UBSan": ["-fsanitize=undefined,fuzzer", "-fno-omit-frame-pointer", "-fno-sanitize-recover=undefined"],
}
# Sanitizer banner → canonical name (used for verdict.sanitizer when parsing replay logs)
BANNER_TO_SAN = {
    "AddressSanitizer": "ASan",
    "MemorySanitizer": "MSan",
    "UndefinedBehaviorSanitizer": "UBSan",
    "ThreadSanitizer": "TSan",
    "LeakSanitizer": "ASan",
}


def _truncate(text: str, limit: int = 4000) -> str:
    return text if len(text) <= limit else text[:limit] + f"\n…[truncated {len(text)-limit} bytes]"


def _gcc_libdir() -> Optional[str]:
    """Locate libstdc++.so for the linker.

    On host Ubuntu 22.04 with clang-14, the `libstdc++-NN-dev` packages put the
    .so symlink inside /usr/lib/gcc/x86_64-linux-gnu/<gccver>/, which the linker
    doesn't search by default — clang's libFuzzer runtime links C++, so without
    this we get "cannot find -lstdc++". The containerized clang image has its
    own gcc layer with the symlink in /usr/lib, so this is a no-op there.
    """
    import glob
    candidates = sorted(glob.glob("/usr/lib/gcc/x86_64-linux-gnu/*/libstdc++.so"), reverse=True)
    return os.path.dirname(candidates[0]) if candidates else None


def build_libfuzzer(source: Path, out_bin: Path, sanitizer: str, extra_cflags: Optional[list[str]] = None) -> None:
    if sanitizer not in SANITIZER_FLAGS:
        raise ValueError(f"unknown sanitizer {sanitizer}")
    libdir = _gcc_libdir()
    extra_ldflags = [f"-L{libdir}"] if libdir else []
    # -O0 by default: at -O1+ clang folds short if-ladders in tiny hand-written
    # harnesses, which collapses libFuzzer's coverage feedback to a single edge.
    # Real OSS-Fuzz targets are large enough that -O1 keeps useful structure;
    # override via extra_cflags=["-O1"] when needed.
    cmd = [CLANG, "-O0", "-g", *SANITIZER_FLAGS[sanitizer], *(extra_cflags or []),
           str(source), "-o", str(out_bin), *extra_ldflags]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"clang build failed:\nCMD: {' '.join(cmd)}\nSTDERR:\n{r.stderr}")


def fuzz(harness_src: Path, sanitizer: str = "ASan", wall_seconds: int = 60,
         corpus: Optional[Path] = None, max_len: int = 4096, unit: Optional[str] = None,
         out_dir: Optional[Path] = None,
         extra_cflags: Optional[list[str]] = None) -> Tier1Verdict:
    """Build harness with sanitizer+libFuzzer and fuzz for ``wall_seconds``.

    ``extra_cflags`` is forwarded to the build step — used by live-library
    harnesses that need ``-lsqlite3`` / ``-lssl -lcrypto`` / ``-lxml2`` etc.
    """
    unit = unit or harness_src.stem
    out_dir = out_dir or Path(tempfile.mkdtemp(prefix="tier1-"))
    out_dir.mkdir(parents=True, exist_ok=True)
    bin_path = out_dir / f"{unit}.bin"
    crash_dir = out_dir / "crashes"
    crash_dir.mkdir(exist_ok=True)
    corpus_dir = corpus or (out_dir / "corpus")
    corpus_dir.mkdir(exist_ok=True)

    build_libfuzzer(harness_src, bin_path, sanitizer, extra_cflags=extra_cflags)

    argv = [str(bin_path),
            f"-max_total_time={wall_seconds}",
            f"-max_len={max_len}",
            f"-artifact_prefix={crash_dir}/",
            "-print_final_stats=1",
            str(corpus_dir)]
    t0 = time.monotonic()
    r = subprocess.run(argv, capture_output=True, text=True, timeout=wall_seconds + 30)
    wall_ms = int((time.monotonic() - t0) * 1000)

    blob = (r.stdout or "") + "\n" + (r.stderr or "")
    cls, loc = from_libfuzzer_log(blob)

    # libFuzzer writes the offending input as crash-<hash>; the artifact_prefix sends it to crash_dir.
    pov = None
    artifacts = sorted(crash_dir.glob("crash-*")) + sorted(crash_dir.glob("oom-*")) + sorted(crash_dir.glob("timeout-*"))
    if artifacts:
        pov = str(artifacts[0])

    if cls is not None or pov is not None:
        verdict = "crash"
    else:
        verdict = "inconclusive"   # PLAN §3 Tier-1: no-crash within budget is NOT "safe"

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
                 f"max_len={max_len}"],
    )


def replay(harness_bin: Path, poc: Path, sanitizer: str = "ASan",
           unit: Optional[str] = None, timeout_seconds: int = 60) -> Tier1Verdict:
    """Run an existing harness binary against a recorded PoC; parse sanitizer output.

    Used for CyberGym-style validation: the OSS-Fuzz pre-patch binary + the
    reference PoC. No build performed.
    """
    unit = unit or harness_bin.stem
    t0 = time.monotonic()
    try:
        r = subprocess.run([str(harness_bin), str(poc)],
                           capture_output=True, text=True, timeout=timeout_seconds)
        timed_out = False
        rc = r.returncode
        blob = (r.stdout or "") + "\n" + (r.stderr or "")
    except subprocess.TimeoutExpired as e:
        timed_out = True
        rc = -1
        blob = ((e.stdout.decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or ""))
                + "\n"
                + (e.stderr.decode(errors="replace") if isinstance(e.stderr, bytes) else (e.stderr or "")))
    wall_ms = int((time.monotonic() - t0) * 1000)

    cls, loc = from_libfuzzer_log(blob)
    # Detect sanitizer from banner if caller asked for "auto".
    san = sanitizer
    if sanitizer == "auto":
        san = "none"
        for banner, name in BANNER_TO_SAN.items():
            if banner in blob:
                san = name
                break

    # rc != 0 + sanitizer banner ⇒ crash.
    if cls is not None or (rc != 0 and not timed_out):
        verdict = "crash"
    elif timed_out:
        verdict = "inconclusive"
    else:
        verdict = "no_crash"

    return Tier1Verdict(
        unit=unit,
        engine="libfuzzer",
        sanitizer=san,
        verdict=verdict,
        wall_ms=wall_ms,
        crash_class=cls,
        location=loc,
        pov_path=str(poc),
        evidence_excerpt=_truncate(blob),
        soundness_note=("Replay: rc != 0 with sanitizer banner = crash. "
                        "rc == 0 = no_crash. Timeout = inconclusive."),
        assumed=[f"timeout={timeout_seconds}s",
                 f"sanitizer={sanitizer}"],
    )


def replay_docker(image: str, harness_path: str, poc: Path, sanitizer: str = "auto",
                  unit: Optional[str] = None, timeout_seconds: int = 60,
                  extra_args: Optional[list[str]] = None) -> Tier1Verdict:
    """Replay PoC against a harness *inside a Docker image* (CyberGym OSS-Fuzz path).

    The harness binary often depends on paths inside the build image (e.g. magic.mgc
    for libmagic); running it from the image preserves that ABI without us having to
    reconstruct the loader env.
    """
    unit = unit or f"{image}:{Path(harness_path).name}"
    docker = os.environ.get("DOCKER", "sudo docker").split()
    poc = poc.resolve()
    cmd = [*docker, "run", "--rm", "-v", f"{poc}:/poc:ro", image, harness_path, "/poc",
           *(extra_args or [])]
    t0 = time.monotonic()
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_seconds)
        timed_out = False; rc = r.returncode
        blob = (r.stdout or "") + "\n" + (r.stderr or "")
    except subprocess.TimeoutExpired as e:
        timed_out = True; rc = -1
        blob = ((e.stdout.decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or ""))
                + "\n"
                + (e.stderr.decode(errors="replace") if isinstance(e.stderr, bytes) else (e.stderr or "")))
    wall_ms = int((time.monotonic() - t0) * 1000)

    cls, loc = from_libfuzzer_log(blob)
    san = sanitizer
    if sanitizer == "auto":
        san = "none"
        for banner, name in BANNER_TO_SAN.items():
            if banner in blob:
                san = name
                break

    if cls is not None or (rc != 0 and not timed_out):
        verdict = "crash"
    elif timed_out:
        verdict = "inconclusive"
    else:
        verdict = "no_crash"

    return Tier1Verdict(
        unit=unit, engine="libfuzzer", sanitizer=san, verdict=verdict, wall_ms=wall_ms,
        crash_class=cls, location=loc, pov_path=str(poc),
        evidence_excerpt=_truncate(blob),
        soundness_note="Replay (in-container): rc != 0 + sanitizer banner = crash.",
        assumed=[f"image={image}", f"harness={harness_path}", f"timeout={timeout_seconds}s"],
    )


# --- AFL++ (used when libFuzzer's interface isn't available; not the default in 2.1) ---
def fuzz_aflpp(harness_src: Path, sanitizer: str = "ASan", wall_seconds: int = 60,
               corpus: Optional[Path] = None, unit: Optional[str] = None,
               out_dir: Optional[Path] = None) -> Tier1Verdict:
    """AFL++ fuzz; requires `afl-clang-fast`/`afl-fuzz` in PATH (containerized image)."""
    if shutil.which("afl-clang-fast") is None or shutil.which("afl-fuzz") is None:
        return Tier1Verdict(
            unit=unit or harness_src.stem, engine="aflpp", sanitizer=sanitizer,
            verdict="inconclusive", wall_ms=0,
            evidence_excerpt="afl-clang-fast/afl-fuzz not in PATH; build touchstone/aflpp image to enable.",
            soundness_note="AFL++ engine wired but image not built — Tier-1 default is libFuzzer.",
        )
    raise NotImplementedError("AFL++ runner stub — wired but not exercised in 2.1; libFuzzer is the default.")


def _cli() -> int:
    ap = argparse.ArgumentParser(description="Tier-1 userspace driver (libFuzzer + sanitizers).")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_fuzz = sub.add_parser("fuzz", help="Build harness, fuzz for wall_seconds, emit verdict.")
    p_fuzz.add_argument("--harness", required=True)
    p_fuzz.add_argument("--sanitizer", default="ASan", choices=list(SANITIZER_FLAGS.keys()))
    p_fuzz.add_argument("--wall-seconds", type=int, default=60)
    p_fuzz.add_argument("--corpus", default=None)
    p_fuzz.add_argument("--unit", default=None)
    p_fuzz.add_argument("--out", required=True)
    p_fuzz.add_argument("--out-dir", default=None)

    p_repl = sub.add_parser("replay", help="Replay existing harness binary against a PoC.")
    p_repl.add_argument("--harness-bin", required=True)
    p_repl.add_argument("--poc", required=True)
    p_repl.add_argument("--sanitizer", default="auto")
    p_repl.add_argument("--unit", default=None)
    p_repl.add_argument("--timeout-seconds", type=int, default=60)
    p_repl.add_argument("--out", required=True)

    p_dock = sub.add_parser("replay-docker", help="Replay PoC against harness inside a docker image.")
    p_dock.add_argument("--image", required=True)
    p_dock.add_argument("--harness-path", required=True, help="In-container path to harness (e.g. /out/magic_fuzzer)")
    p_dock.add_argument("--poc", required=True)
    p_dock.add_argument("--sanitizer", default="auto")
    p_dock.add_argument("--unit", default=None)
    p_dock.add_argument("--timeout-seconds", type=int, default=60)
    p_dock.add_argument("--out", required=True)

    args = ap.parse_args()
    if args.cmd == "fuzz":
        v = fuzz(Path(args.harness), sanitizer=args.sanitizer, wall_seconds=args.wall_seconds,
                 corpus=Path(args.corpus) if args.corpus else None, unit=args.unit,
                 out_dir=Path(args.out_dir) if args.out_dir else None)
    elif args.cmd == "replay-docker":
        v = replay_docker(args.image, args.harness_path, Path(args.poc), sanitizer=args.sanitizer,
                          unit=args.unit, timeout_seconds=args.timeout_seconds)
    else:
        v = replay(Path(args.harness_bin), Path(args.poc), sanitizer=args.sanitizer,
                   unit=args.unit, timeout_seconds=args.timeout_seconds)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(v.to_dict(), indent=2))
    print(json.dumps(v.to_dict(), indent=2))
    return 0 if v.verdict == "crash" else 1


if __name__ == "__main__":
    sys.exit(_cli())
