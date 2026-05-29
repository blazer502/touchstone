"""libFuzzer mutation phase — fuzz around a seed corpus, collect crashes.

The cybergym-server-data binary IS a libFuzzer harness. libFuzzer is a
bytes-mutation engine designed for exactly the task we were (badly)
asking the LLM to do: take a seed corpus, mutate it, score against the
target. Running it in mutation mode for a few seconds beats burning
minutes of 70B reasoning to ask "what byte sequence might crash this?".

Two APIs:

    fuzz_collect(harness, seeds, budget_seconds=10)
        Fixed-budget run. Easy to reason about; wall = budget_seconds.

    fuzz_collect_adaptive(harness, seeds,
                          budget_min=3, budget_max=30,
                          stagnation_window=4)
        F1 coverage-driven scheduling: terminate the child as soon as
        libFuzzer hasn't reported new coverage in `stagnation_window`
        seconds (after `budget_min`); never run past `budget_max`. On a
        large run, easy tasks free their leftover budget for the next
        task; hard tasks get the headroom they actually need.

Both return a list of raw byte payloads — one per `crash-<sha>` artifact
libFuzzer wrote during the run. The caller scores them through
`score_cached` so the `vul=crash ∧ fix=no_crash` rule keeps verdict
authority.
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
                 artifact_dir: Optional[Path] = None,
                 dict_path: Optional[Path] = None) -> FuzzResult:
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
    if dict_path is not None and Path(dict_path).exists():
        cmd.append(f"-dict={dict_path}")
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


# --- F1: coverage-driven adaptive scheduling -------------------------------

_COV_RE = re.compile(rb"cov:\s*(\d+)\s+ft:\s*(\d+)")


def fuzz_collect_adaptive(harness: LocalHarness,
                          seeds: Iterable[bytes],
                          *,
                          budget_min: int = 3,
                          budget_max: int = 30,
                          stagnation_window: int = 4,
                          max_seed_bytes: int = 4096,
                          corpus_dir: Optional[Path] = None,
                          artifact_dir: Optional[Path] = None,
                          dict_path: Optional[Path] = None,
                          extra_corpus_dirs: Optional[list] = None) -> FuzzResult:
    """Adaptive-budget libFuzzer run.

    Streams libFuzzer's stderr and tracks `cov: N ft: M` updates. Behaviour:

    - Always runs at least `budget_min` seconds.
    - Past `budget_min`, terminates if no new coverage / features for
      `stagnation_window` seconds.
    - Hard ceiling at `budget_max`. libFuzzer also exits on its own when
      it hits a crash (default behaviour); we let that path return early.

    Same `FuzzResult` shape as `fuzz_collect`, so callers can swap freely.
    """
    if corpus_dir is None:
        corpus_dir = Path(tempfile.mkdtemp(prefix="libfuzz-corp-"))
    if artifact_dir is None:
        artifact_dir = Path(tempfile.mkdtemp(prefix="libfuzz-art-"))
    corpus_dir.mkdir(parents=True, exist_ok=True)
    artifact_dir.mkdir(parents=True, exist_ok=True)

    seeded = 0
    for i, blob in enumerate(seeds):
        if len(blob) > max_seed_bytes:
            continue
        (corpus_dir / f"seed-{i:04d}").write_bytes(blob)
        seeded += 1
    if seeded == 0:
        (corpus_dir / "seed-empty").write_bytes(b"")

    env = dict(os.environ)
    env.update(_SAN_ENV)
    env.update(harness.env_extra)
    if harness.libs_dir is not None:
        existing = env.get("LD_LIBRARY_PATH", "")
        env["LD_LIBRARY_PATH"] = (str(harness.libs_dir) +
                                  (":" + existing if existing else ""))

    cmd = [str(harness.binary), str(corpus_dir)]
    # Additional read corpora (e.g. the upstream OSS-Fuzz public corpus).
    # libFuzzer reads all positional dirs and writes new finds to the first.
    for d in (extra_corpus_dirs or []):
        if d is not None and Path(d).exists():
            cmd.append(str(d))
    cmd += [
        f"-max_total_time={budget_max}",        # hard cap
        f"-artifact_prefix={str(artifact_dir)}/",
        "-print_final_stats=1",
        "-rss_limit_mb=4096",
        "-timeout=5",
        # Value-profile uses the trace-cmp instrumentation already compiled
        # into -fsanitize=fuzzer binaries — the built-in cmplog/redqueen
        # equivalent for cracking magic-byte / checksum / length gates. No
        # rebuild required (the OSS-Fuzz build env is unavailable to us).
        "-use_value_profile=1",
    ]
    if dict_path is not None and Path(dict_path).exists():
        cmd.append(f"-dict={dict_path}")
    t0 = time.monotonic()
    last_cov_update = t0
    last_cov_summary: tuple[Optional[int], Optional[int]] = (None, None)
    stderr_buf: list[bytes] = []
    timed_out = False
    err_msg: Optional[str] = None
    early_terminated = False

    import select  # local import — only adaptive path needs it
    try:
        proc = subprocess.Popen(cmd, env=env,
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.PIPE,
                                bufsize=0)
    except Exception as e:
        return FuzzResult(crash_payloads=[], execs_total=0,
                          wall_ms=0, timed_out=False,
                          error=f"libfuzzer-spawn-error: {e}")

    poll_dt = 0.5
    try:
        while True:
            now = time.monotonic()
            elapsed = now - t0

            # Hard cap.
            if elapsed >= budget_max:
                proc.terminate()
                break

            rc = proc.poll()
            if rc is not None:
                # libFuzzer exited (typically on a crash or natural end).
                break

            # Stagnation check (only after the minimum budget).
            if (elapsed > budget_min
                    and (now - last_cov_update) > stagnation_window):
                proc.terminate()
                early_terminated = True
                break

            # Pull whatever stderr is available without blocking.
            ready, _, _ = select.select([proc.stderr], [], [], poll_dt)
            if not ready:
                continue
            chunk = proc.stderr.read(4096)
            if not chunk:
                # EOF on stderr → process is wrapping up
                continue
            stderr_buf.append(chunk)
            for m in _COV_RE.finditer(chunk):
                summary = (int(m.group(1)), int(m.group(2)))
                if summary != last_cov_summary:
                    last_cov_summary = summary
                    last_cov_update = time.monotonic()
    except Exception as e:
        err_msg = f"libfuzzer-stream-error: {e}"
        try:
            proc.terminate()
        except Exception:
            pass

    # Drain remaining output.
    try:
        rest, _ = proc.communicate(timeout=5)
        if rest:
            stderr_buf.append(rest)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            proc.kill()
            proc.communicate(timeout=5)
        except Exception:
            pass

    wall_ms = int((time.monotonic() - t0) * 1000)
    stderr = b"".join(stderr_buf).decode("utf-8", errors="replace")

    # Stats + crash collection — same shape as fuzz_collect.
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
    if artifact_dir.exists():
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

    log.debug("[adaptive] wall=%dms execs=%d crashes=%d early_term=%s cov=%s",
              wall_ms, execs_total, len(crash_payloads),
              early_terminated, last_cov_summary)

    return FuzzResult(
        crash_payloads=crash_payloads,
        execs_total=execs_total,
        wall_ms=wall_ms,
        timed_out=timed_out,
        error=err_msg,
    )
