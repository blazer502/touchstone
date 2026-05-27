"""F2 + V4 — score-result caching, crash dedup, parallel scoring.

`task.score(poc)` is deterministic on `(harness_binary_content, poc_bytes)`
under the standard `vul=crash ∧ fix=no_crash` rule, so the result is
content-addressed:

    score_cached(task, poc) → ScoreResult           (cache hit → 0 wall)

`dedup_crashes(...)` collapses crash payloads that share a libFuzzer
DEDUP_TOKEN or top sanitizer frame, so we score one representative per
root cause instead of all of them.

`score_many(...)` runs many `score()` calls in parallel via a thread pool;
threads are fine because the work is dominated by external Docker / HTTP.

All three are benchmark-agnostic: they operate against the abstract
`BenchmarkTask` Protocol (`agent.task_interface`), not against any
benchmark-specific shape.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict
from functools import lru_cache
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

from agent.task_interface import BenchmarkTask, ScoreResult

REPO_ROOT = Path(__file__).resolve().parents[1]
CACHE_ROOT = REPO_ROOT / "run-logs" / "score-cache"
log = logging.getLogger("score_cache")


# --- key derivation ---------------------------------------------------------

@lru_cache(maxsize=4096)
def _binary_sha(path_str: str, size: int) -> str:
    """Cache file-content sha by (path, size) so re-reading a 1 GB binary
    every score call doesn't dominate wall.

    Size-keyed (not mtime-keyed) — the OSS-Fuzz binaries on disk don't
    change inside a session; if they do, the file size will too. For
    paranoia, include the first 4 KB of the file too.
    """
    p = Path(path_str)
    h = hashlib.sha256()
    h.update(str(size).encode())
    try:
        with open(p, "rb") as fh:
            h.update(fh.read(4096))
    except FileNotFoundError:
        h.update(b"<missing>")
    return h.hexdigest()[:16]


def _task_signature(task: BenchmarkTask) -> str:
    bp = task.harness_binary_path()
    if bp is None:
        return f"noharness:{task.task_id}"
    try:
        sz = bp.stat().st_size
    except (FileNotFoundError, OSError):
        return f"missingbinary:{task.task_id}"
    return f"{task.task_id}::{_binary_sha(str(bp), sz)}"


def cache_key(task: BenchmarkTask, poc_bytes: bytes) -> str:
    sig = _task_signature(task)
    poc = hashlib.sha256(poc_bytes).hexdigest()[:16]
    safe_id = task.task_id.replace(":", "_").replace("/", "_")
    return f"{safe_id}.{poc}"


def _cache_path(task: BenchmarkTask, poc_bytes: bytes,
                root: Path = CACHE_ROOT) -> Path:
    key = cache_key(task, poc_bytes)
    return root / key[:2] / f"{key}.json"


# --- cache get/put ----------------------------------------------------------

def get(task: BenchmarkTask, poc_bytes: bytes,
        *, root: Path = CACHE_ROOT) -> Optional[ScoreResult]:
    p = _cache_path(task, poc_bytes, root)
    if not p.exists():
        return None
    try:
        d = json.loads(p.read_text())
    except Exception:
        return None
    # Validate the binary signature still matches — if the harness was
    # rebuilt, invalidate (return None).
    cached_sig = d.pop("_task_signature", None)
    if cached_sig and cached_sig != _task_signature(task):
        log.debug("[%s] cache stale (signature mismatch)", task.task_id)
        return None
    try:
        return ScoreResult(**d)
    except TypeError:
        return None


def put(task: BenchmarkTask, poc_bytes: bytes, score: ScoreResult,
        *, root: Path = CACHE_ROOT) -> None:
    p = _cache_path(task, poc_bytes, root)
    p.parent.mkdir(parents=True, exist_ok=True)
    d = asdict(score)
    d["_task_signature"] = _task_signature(task)
    p.write_text(json.dumps(d, indent=2))


def score_cached(task: BenchmarkTask, poc_bytes: bytes, *,
                 root: Path = CACHE_ROOT,
                 vul_timeout: int = 30, fix_timeout: int = 30) -> ScoreResult:
    """Score with content-addressed cache. Identical contract to `task.score()`."""
    hit = get(task, poc_bytes, root=root)
    if hit is not None:
        return hit
    res = task.score(poc_bytes, vul_timeout=vul_timeout, fix_timeout=fix_timeout)
    put(task, poc_bytes, res, root=root)
    return res


# --- crash deduplication ---------------------------------------------------

_DEDUP_RE = re.compile(r"DEDUP_TOKEN:\s*([^\s\n]+)")
_TOP_FRAME_RE = re.compile(
    r"#0\s+0x[0-9a-f]+\s+in\s+(?P<sym>\S+)\s+(?P<file>[^\s:]+):(?P<line>\d+)",
    re.MULTILINE,
)
_SUMMARY_RE = re.compile(
    r"SUMMARY:\s+\w+Sanitizer:\s+(?P<class>\S+)\s+(?P<loc>\S+)",
    re.MULTILINE,
)


def signature(excerpt: str) -> str:
    """Compute a content signature for a sanitizer/libFuzzer crash blob.

    Priority order: DEDUP_TOKEN > SUMMARY (class+loc) > top frame > sha of
    first 200 bytes. All produce a short string; equal signatures are
    treated as the same root cause.
    """
    if not excerpt:
        return "empty"
    m = _DEDUP_RE.search(excerpt)
    if m:
        return f"dedup:{m.group(1)}"
    m2 = _SUMMARY_RE.search(excerpt)
    if m2:
        return f"summary:{m2.group('class')}@{m2.group('loc')}"
    m3 = _TOP_FRAME_RE.search(excerpt)
    if m3:
        return f"frame:{m3.group('sym')}@{m3.group('file')}:{m3.group('line')}"
    return f"sha:{hashlib.sha256(excerpt[:200].encode()).hexdigest()[:12]}"


def dedup_crashes(crashes: Iterable[Tuple[bytes, str]]) -> List[Tuple[bytes, str]]:
    """Keep one representative crash per signature.

    Input: iterable of `(poc_bytes, sanitizer_excerpt)` tuples.
    Output: deduplicated list preserving first-seen order.
    """
    seen: set[str] = set()
    out: List[Tuple[bytes, str]] = []
    for blob, excerpt in crashes:
        sig = signature(excerpt or "")
        if sig in seen:
            continue
        seen.add(sig)
        out.append((blob, excerpt))
    return out


# --- parallel scoring ------------------------------------------------------

def score_many(task: BenchmarkTask, poc_blobs: Iterable[bytes], *,
               workers: int = 4, root: Path = CACHE_ROOT,
               vul_timeout: int = 30,
               fix_timeout: int = 30) -> List[ScoreResult]:
    """Score multiple PoCs against the same task in parallel.

    Threads are fine here — each `score()` is dominated by external Docker
    or HTTP wait (GIL release). `workers` defaults conservatively to 4 to
    avoid hammering the CyberGym server's container pool; bump if the
    oracle is local and not rate-limited.
    """
    blobs = list(poc_blobs)
    if not blobs:
        return []
    if len(blobs) == 1 or workers <= 1:
        return [score_cached(task, b, root=root,
                             vul_timeout=vul_timeout,
                             fix_timeout=fix_timeout)
                for b in blobs]
    results: List[Optional[ScoreResult]] = [None] * len(blobs)
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(score_cached, task, b,
                          root=root, vul_timeout=vul_timeout,
                          fix_timeout=fix_timeout): i
                for i, b in enumerate(blobs)}
        for fut in as_completed(futs):
            i = futs[fut]
            try:
                results[i] = fut.result()
            except Exception as e:
                log.warning("[%s] score failed in worker: %s", task.task_id, e)
                results[i] = ScoreResult(False, False, False, False,
                                         vul_evidence=f"runner-error: {e}")
    return [r for r in results if r is not None]


# --- stats / CLI -----------------------------------------------------------

def stats(root: Path = CACHE_ROOT) -> dict:
    if not root.exists():
        return {"rows": 0, "task_ids": 0}
    rows = list(root.rglob("*.json"))
    by_task: dict[str, int] = {}
    for p in rows:
        prefix = p.stem.split(".", 1)[0]
        by_task[prefix] = by_task.get(prefix, 0) + 1
    return {"rows": len(rows), "task_ids": len(by_task)}


__all__ = [
    "ScoreResult",
    "BenchmarkTask",
    "score_cached", "score_many",
    "get", "put",
    "signature", "dedup_crashes",
    "cache_key", "stats",
    "CACHE_ROOT",
]


if __name__ == "__main__":
    import sys
    print(json.dumps(stats(), indent=2))
    sys.exit(0)
