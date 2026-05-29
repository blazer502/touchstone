"""Userspace reproducer backend: re-run determinism + libFuzzer minimization.

Reuses the Tier-1 replay primitives (``oracle.tier1_fuzz.userspace.replay`` /
``replay_docker``) so a reproducibility measurement is byte-for-byte the same
execution path the oracle already trusts. Two backends, selected by the caller:

- *local*  : a libFuzzer harness binary on the host (e.g. built from
             ``oracle/tier1_fuzz/harnesses/*.c`` via ``build_libfuzzer``).
- *docker* : an OSS-Fuzz harness inside a CyberGym ``n132/arvo:*-vul`` image.

A "hit" is a run that (a) crashes AND (b) crashes with the SAME
``crash_signature`` as the target — re-firing a *different* bug does not count
toward ``repro_rate``. This is what makes the rate a measure of *this* bug's
determinism, not of "the harness crashes sometimes".

No LLM in this module — execution is the verdict authority (PLAN §8).
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Callable, List, Optional, Tuple

from oracle.tier1_fuzz.userspace import replay, replay_docker
from schemas.reproducer import crash_signature


def _verdict_signature(v) -> str:
    """Project a Tier1Verdict onto a crash_signature (only when it crashed)."""
    if v.verdict != "crash":
        return ""
    return crash_signature(v.sanitizer, v.crash_class, v.location)


def measure_local(harness_bin: Path, poc: Path, target_signature: str,
                  sanitizer: str = "auto", runs: int = 10,
                  timeout_seconds: int = 60) -> Tuple[int, int, List[str]]:
    """Replay ``poc`` against a local libFuzzer binary ``runs`` times.

    Returns ``(hits, runs, sample_signatures)`` where ``hits`` = runs whose
    crash signature == ``target_signature``.
    """
    hits = 0
    samples: List[str] = []
    for _ in range(runs):
        v = replay(harness_bin, poc, sanitizer=sanitizer, timeout_seconds=timeout_seconds)
        sig = _verdict_signature(v)
        samples.append(sig)
        if sig and sig == target_signature:
            hits += 1
    return hits, runs, samples


def measure_docker(image: str, harness_path: str, poc: Path, target_signature: str,
                   sanitizer: str = "auto", runs: int = 10,
                   timeout_seconds: int = 60) -> Tuple[int, int, List[str]]:
    """Replay ``poc`` against an in-container OSS-Fuzz harness ``runs`` times."""
    hits = 0
    samples: List[str] = []
    for _ in range(runs):
        v = replay_docker(image, harness_path, poc, sanitizer=sanitizer,
                          timeout_seconds=timeout_seconds)
        sig = _verdict_signature(v)
        samples.append(sig)
        if sig and sig == target_signature:
            hits += 1
    return hits, runs, samples


def minimize_local(harness_bin: Path, poc: Path, out_path: Path,
                   minimize_runs: int = 5000, timeout_seconds: int = 120) -> Optional[Path]:
    """libFuzzer crash minimization on a local binary.

    Runs ``harness_bin -minimize_crash=1 -runs=N -exact_artifact_path=out poc``.
    libFuzzer writes the smallest still-crashing input to ``out_path``. Returns
    the path on success (file exists and is non-empty), else ``None`` (caller
    keeps the original — minimization is best-effort, never required).
    """
    out_path.parent.mkdir(parents=True, exist_ok=True)
    cmd = [str(harness_bin), "-minimize_crash=1", f"-runs={minimize_runs}",
           f"-exact_artifact_path={out_path}", str(poc)]
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        pass
    if out_path.exists() and out_path.stat().st_size > 0:
        return out_path
    return None


def minimize_docker(image: str, harness_path: str, poc: Path, out_path: Path,
                    minimize_runs: int = 5000, timeout_seconds: int = 300) -> Optional[Path]:
    """libFuzzer crash minimization inside an OSS-Fuzz image.

    Mounts an rw scratch dir, runs the in-container libFuzzer harness in
    minimize mode writing to ``/work/min``, copies the result back to
    ``out_path``. Best-effort: returns ``None`` if the image won't minimize
    (e.g. MSan uninit-value bugs that don't shrink) so the caller keeps the
    original trigger.
    """
    import os
    docker = os.environ.get("DOCKER", "sudo docker").split()
    poc = poc.resolve()
    work = Path(tempfile.mkdtemp(prefix="repro-min-"))
    try:
        cmd = [*docker, "run", "--rm", "--network=none",
               "-v", f"{poc}:/poc:ro", "-v", f"{work}:/work",
               image, harness_path, "-minimize_crash=1",
               f"-runs={minimize_runs}", "-exact_artifact_path=/work/min", "/poc"]
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            pass
        produced = work / "min"
        if produced.exists() and produced.stat().st_size > 0:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(produced, out_path)
            return out_path
        return None
    finally:
        shutil.rmtree(work, ignore_errors=True)
