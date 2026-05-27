"""Smokes for agent.score_cache — cache roundtrip, dedup, parallel."""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

from agent.score_cache import (cache_key, dedup_crashes, get, put,
                               score_cached, signature, stats)
from agent.task_interface import BenchmarkTask, ScoreResult


# A tiny stub task that produces deterministic ScoreResults so we can
# verify the cache without involving Docker or HTTP.
class StubTask:
    def __init__(self, task_id: str, binary: Path):
        self.task_id = task_id
        self._binary = binary
        self.score_calls = 0

    def description(self):
        return ""

    def harness_binary_path(self):
        return self._binary

    def harness_libs_dir(self):
        return None

    def harness_env(self):
        return {}

    def disclosed_error_text(self):
        return None

    def bug_class_hint(self):
        return None

    def disclosed_patch_diff(self):
        return None

    def project_group(self):
        return "stub"

    def score(self, poc_bytes, *, vul_timeout=30, fix_timeout=30):
        self.score_calls += 1
        crashed = poc_bytes.startswith(b"CRASH")
        return ScoreResult.from_vul_fix(
            vul_crashed=crashed, fix_crashed=False,
            wall_ms=10, oracle_name="stub",
        )


def t_cache_roundtrip():
    root = Path(tempfile.mkdtemp(prefix="score-cache-test-"))
    bin_path = root / "fake-binary"
    bin_path.write_bytes(b"fake binary content")
    task = StubTask("test:1", bin_path)
    assert isinstance(task, BenchmarkTask), "stub must satisfy BenchmarkTask"

    poc = b"CRASH-1"
    a = score_cached(task, poc, root=root)
    b = score_cached(task, poc, root=root)
    assert a == b
    assert task.score_calls == 1, "second call must hit cache"
    print(f"[t-cache] OK calls={task.score_calls} verdict={a.reproduces_target}")
    return root


def t_cache_invalidate_on_binary_change():
    root = Path(tempfile.mkdtemp(prefix="score-cache-test-"))
    bin_path = root / "fake-binary"
    bin_path.write_bytes(b"v1 content")
    task = StubTask("test:2", bin_path)
    poc = b"CRASH-2"
    score_cached(task, poc, root=root)
    assert task.score_calls == 1
    # Simulate rebuild: write new content. Cache must invalidate.
    bin_path.write_bytes(b"v2 content but different length")
    score_cached(task, poc, root=root)
    assert task.score_calls == 2, "rebuild must trigger cache miss"
    print(f"[t-invalidate] OK calls={task.score_calls}")


def t_dedup():
    excerpts = [
        ("aaaa", "DEDUP_TOKEN: foo--bar--baz\nrest"),
        ("bbbb", "DEDUP_TOKEN: foo--bar--baz\nother"),   # dup of #1
        ("cccc", "DEDUP_TOKEN: other_sig"),
        ("dddd", "DEDUP_TOKEN: foo--bar--baz"),           # dup again
        ("eeee", "SUMMARY: AddressSanitizer: heap-buffer-overflow file.c:42 in fn"),
        ("ffff", "SUMMARY: AddressSanitizer: heap-buffer-overflow file.c:42 in fn"),  # dup
        ("gggg", "no signature here at all"),
    ]
    crashes = [(b.encode(), e) for b, e in excerpts]
    out = dedup_crashes(crashes)
    sigs = [signature(e) for _, e in out]
    print(f"[t-dedup] {len(crashes)} in, {len(out)} out: {sigs}")
    assert len(out) == 4, f"expected 4 unique groups, got {len(out)}"


def t_stats():
    root = t_cache_roundtrip()
    s = stats(root=root)
    assert s["rows"] >= 1, s
    print(f"[t-stats] OK rows={s['rows']} task_ids={s['task_ids']}")


def main():
    t_cache_roundtrip()
    t_cache_invalidate_on_binary_change()
    t_dedup()
    t_stats()
    print("all score_cache smokes pass")
    return 0


if __name__ == "__main__":
    sys.exit(main())
