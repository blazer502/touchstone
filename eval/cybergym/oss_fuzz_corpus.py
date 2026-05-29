"""Fetch a project's public OSS-Fuzz seed corpus (ClusterFuzz public.zip).

CyberGym targets are OSS-Fuzz fuzzers; OSS-Fuzz publishes each fuzz target's
accumulated public corpus at:

    https://storage.googleapis.com/<project>-backup.clusterfuzz-external
        .appspot.com/corpus/libFuzzer/<fuzz_target>/public.zip

Seeding libFuzzer with that corpus (and mutating around it) is the standard,
benchmark-agnostic way these bugs were originally found — it is the project's
own test corpus, not the benchmark's hidden reference PoC. The fuzz-target
name is usually `<project>_<binary>`, but when the binary name already starts
with the project it can be just `<binary>`; we try a few candidates.

This module is OSS-Fuzz-specific on purpose and lives in the adapter layer
(not in `agent/`), exposed to agent code only through
`BenchmarkTask.upstream_corpus_dir()`.
"""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
import zipfile
from pathlib import Path
from typing import Optional

log = logging.getLogger("oss_fuzz_corpus")

CACHE_ROOT = Path(os.environ.get(
    "OSS_FUZZ_CORPUS_CACHE",
    "/mnt/data/chanyoung/cybergym/oss-fuzz-corpus-cache"))
_BASE = "https://storage.googleapis.com"
_MAX_ZIP_BYTES = int(os.environ.get("OSS_FUZZ_CORPUS_MAX_ZIP", str(250 * 1024 * 1024)))
_MAX_FILES = int(os.environ.get("OSS_FUZZ_CORPUS_MAX_FILES", "20000"))


def _candidates(project: str, fuzzer: str) -> list[str]:
    cands = [f"{project}_{fuzzer}", fuzzer]
    # some targets are registered with a doubled or prefixed name
    if not fuzzer.startswith(project):
        cands.append(f"{project}_{project}_{fuzzer}")
    seen, out = set(), []
    for c in cands:
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out


def _url(project: str, target: str) -> str:
    return (f"{_BASE}/{project}-backup.clusterfuzz-external.appspot.com/"
            f"corpus/libFuzzer/{target}/public.zip")


def _content_length(url: str) -> Optional[int]:
    try:
        r = subprocess.run(["curl", "-sI", "--max-time", "25", url],
                           capture_output=True, text=True, timeout=40)
        for line in r.stdout.splitlines():
            if line.lower().startswith("content-length:"):
                return int(line.split(":", 1)[1].strip())
    except Exception:
        return None
    return None


def corpus_dir(project: Optional[str], fuzzer: Optional[str], *,
               max_zip_bytes: int = _MAX_ZIP_BYTES,
               cache_root: Path = CACHE_ROOT) -> Optional[Path]:
    """Return a local directory of seed files for `<project>/<fuzzer>`.

    Downloads + caches the public corpus on first use. Returns None if no
    public corpus exists or it exceeds `max_zip_bytes`. Idempotent: a
    `.done` marker means the cache is populated.
    """
    if not project or not fuzzer:
        return None
    safe = f"{project}__{fuzzer}".replace("/", "_")
    out_dir = cache_root / safe
    done = out_dir / ".done"
    if done.exists():
        return out_dir if any(out_dir.iterdir()) else None
    empty = out_dir / ".empty"
    if empty.exists():
        return None

    out_dir.mkdir(parents=True, exist_ok=True)
    for target in _candidates(project, fuzzer):
        url = _url(project, target)
        cl = _content_length(url)
        if cl is None:
            continue
        if cl > max_zip_bytes:
            log.info("corpus %s too large (%d bytes); skipping", target, cl)
            continue
        zip_path = out_dir / "public.zip"
        try:
            r = subprocess.run(
                ["curl", "-sf", "--max-time", "600", "-o", str(zip_path), url],
                capture_output=True, timeout=620)
            if r.returncode != 0 or not zip_path.exists():
                continue
            n = 0
            with zipfile.ZipFile(zip_path) as zf:
                for info in zf.infolist():
                    if info.is_dir() or n >= _MAX_FILES:
                        continue
                    # flatten names; corpus entries are content-hashed files
                    name = Path(info.filename).name or f"seed{n}"
                    try:
                        data = zf.read(info)
                    except Exception:
                        continue
                    if 0 < len(data) <= 4 * 1024 * 1024:
                        (out_dir / f"c{n:06d}").write_bytes(data)
                        n += 1
            zip_path.unlink(missing_ok=True)
            if n > 0:
                done.write_text(f"{target}\n{n}\n")
                log.info("corpus %s: %d seeds cached", target, n)
                return out_dir
        except Exception as e:
            log.warning("corpus fetch %s failed: %s", target, e)
            continue

    # No corpus found — mark so we don't retry every task.
    empty.write_text("no public corpus")
    return None


def corpus_seed_sample(project: Optional[str], fuzzer: Optional[str], *,
                       max_files: int = 3000) -> list[bytes]:
    """Load up to `max_files` corpus seeds as bytes (smallest first)."""
    d = corpus_dir(project, fuzzer)
    if d is None:
        return []
    files = [p for p in d.iterdir() if p.is_file() and not p.name.startswith(".")]
    files.sort(key=lambda p: p.stat().st_size)
    out = []
    for p in files[:max_files]:
        try:
            out.append(p.read_bytes())
        except Exception:
            continue
    return out
