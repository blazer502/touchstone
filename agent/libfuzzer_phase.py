"""libFuzzer mutation phase — fuzz around a seed corpus, collect crashes.

The cybergym-server-data binary IS a libFuzzer harness. libFuzzer is a
bytes-mutation engine designed for exactly the task we were (badly)
asking the LLM to do: take a seed corpus, mutate it, score against the
target. Running it in mutation mode for a few seconds beats burning
minutes of 70B reasoning to ask "what byte sequence might crash this?".

API:

    crashes = fuzz_collect(harness, seeds, budget_seconds=10)

Returns a list of raw byte payloads — one per `crash-<sha>` artifact
libFuzzer wrote during mutation. The caller (cybergym_agent) submits
each through `adapter.score_local` to apply the (vul=crash ∧ fix=no_crash)
scoring rule.
"""
from __future__ import annotations

import logging
import os
import re
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

from agent.local_oracle import LocalHarness, _SAN_ENV


log = logging.getLogger("libfuzzer_phase")


@dataclass
class FuzzResult:
    crash_payloads: list[bytes]
    execs_total: int
    wall_ms: int
    timed_out: bool
    error: Optional[str] = None


_EXECS_RE = re.compile(r"#(\d+)\s+(?:DONE|REDUCE|INITED|NEW|cov:)")
_FINAL_STATS_RE = re.compile(r"stat::number_of_executed_units:\s*(\d+)")


def fuzz_collect(harness: LocalHarness,
                 seeds: Iterable[bytes],
                 *,
                 budget_seconds: int = 10,
                 max_seed_bytes: int = 4096,
                 corpus_dir: Optional[Path] = None,
                 artifact_dir: Optional[Path] = None) -> FuzzResult:
    """Mutate around `seeds` for `budget_seconds`, return any crash payloads.

    libFuzzer writes one `crash-<sha>` file per crashing input it finds. We
    collect those files at the end and return their byte contents. The
    caller scores them through the usual `adapter.score_local` path so the
    server's binary scoring rule (vul=crash ∧ fix=no_crash) is what's
    counted, not just "libFuzzer found *something* that crashes".
    """
    if corpus_dir is None:
        corpus_dir = Path(tempfile.mkdtemp(prefix="libfuzz-corp-"))
    if artifact_dir is None:
        artifact_dir = Path(tempfile.mkdtemp(prefix="libfuzz-art-"))
    corpus_dir.mkdir(parents=True, exist_ok=True)
    artifact_dir.mkdir(parents=True, exist_ok=True)

    # Seed the corpus. Skip blobs over max_seed_bytes (libFuzzer ignores huge
    # initial inputs anyway).
    seeded = 0
    for i, blob in enumerate(seeds):
        if len(blob) > max_seed_bytes:
            continue
        (corpus_dir / f"seed-{i:04d}").write_bytes(blob)
        seeded += 1
    if seeded == 0:
        # libFuzzer needs at least one input — give it an empty file.
        (corpus_dir / "seed-empty").write_bytes(b"")

    env = dict(os.environ)
    env.update(_SAN_ENV)
    env.update(harness.env_extra)
    if harness.libs_dir is not None:
        existing = env.get("LD_LIBRARY_PATH", "")
        env["LD_LIBRARY_PATH"] = (str(harness.libs_dir) +
                                  (":" + existing if existing else ""))

    cmd = [
        str(harness.binary),
        str(corpus_dir),
        f"-max_total_time={budget_seconds}",
        f"-artifact_prefix={str(artifact_dir)}/",
        # Keep libFuzzer printable but quiet
        "-print_final_stats=1",
        "-rss_limit_mb=2048",
        # Bound each input's runtime so a stuck mutation can't burn the wall.
        "-timeout=5",
        # libFuzzer kills itself on the first crash by default; we want that —
        # one crash per fuzz_collect call is enough, then the caller can
        # decide whether to score / iterate / move on.
    ]
    t0 = time.monotonic()
    timed_out = False
    err_msg = None
    try:
        r = subprocess.run(cmd, env=env, capture_output=True, text=False,
                           timeout=budget_seconds + 30, check=False)
        stderr = r.stderr.decode("utf-8", errors="replace")
    except subprocess.TimeoutExpired as e:
        timed_out = True
        stderr = (e.stderr.decode("utf-8", errors="replace")
                  if isinstance(e.stderr, bytes) else (e.stderr or ""))
    except Exception as e:
        err_msg = f"libfuzzer-exec-error: {e}"
        stderr = ""
    wall_ms = int((time.monotonic() - t0) * 1000)

    # Parse the last "#N <state>" line for an exec count, or the final-stats
    # block if printed.
    execs_total = 0
    m_final = _FINAL_STATS_RE.search(stderr)
    if m_final:
        execs_total = int(m_final.group(1))
    else:
        last = 0
        for m in _EXECS_RE.finditer(stderr):
            last = int(m.group(1))
        execs_total = last

    crash_payloads: list[bytes] = []
    for p in sorted(artifact_dir.iterdir()):
        if not p.is_file():
            continue
        name = p.name
        if not (name.startswith("crash-") or name.startswith("oom-")
                or name.startswith("timeout-")):
            continue
        try:
            payload = p.read_bytes()
        except Exception:
            continue
        if 0 < len(payload) <= max_seed_bytes:
            crash_payloads.append(payload)

    return FuzzResult(
        crash_payloads=crash_payloads,
        execs_total=execs_total,
        wall_ms=wall_ms,
        timed_out=timed_out,
        error=err_msg,
    )
