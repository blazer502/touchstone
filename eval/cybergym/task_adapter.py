"""CyberGym → `agent.task_interface.BenchmarkTask` adapter.

Thin wrapper around the existing `TaskBundle` so agent code can address
CyberGym tasks through the benchmark-agnostic protocol (see
`docs/strategic-direction.md` §8).

Usage:

    from eval.cybergym.task_adapter import resolve_task

    task = resolve_task("arvo:1065")
    text = task.description()                              # always works
    score = task.score(b"<?xml ...")                       # ScoreResult
    bin_path = task.harness_binary_path()                  # may be None
    err = task.disclosed_error_text()                      # may be None
    patch = task.disclosed_patch_diff()                    # may be None

The wrapper does NOT replace `TaskBundle` — legacy callers (run_ablation,
seed_generators, lift_cybergym) continue to use the dataclass directly.
This preserves bit-for-bit compatibility while opening a benchmark-agnostic
path for new agent code.
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Optional

from agent.task_interface import BenchmarkTask, ScoreResult
from . import adapter as _legacy
from agent.local_oracle import LocalHarness, resolve_harness


# tasks.json lookup for project_group(). Reads the upstream CyberGym
# dataset's tasks.json once and caches a task_id → project_name map.
@lru_cache(maxsize=1)
def _project_index() -> dict[str, str]:
    import os
    data_dir = os.environ.get("CYBERGYM_DATA_DIR",
                              str(_legacy.DATA_DIR))
    # tasks.json sits ONE level above the data/ dir in the HF dataset
    # layout (cybergym_data/tasks.json, cybergym_data/data/arvo/...).
    candidates = [
        Path(data_dir).parent / "tasks.json",
        Path(data_dir) / "tasks.json",
    ]
    for path in candidates:
        if path.exists():
            try:
                arr = json.loads(path.read_text())
                if isinstance(arr, list):
                    return {t.get("task_id"): t.get("project_name")
                            for t in arr if isinstance(t, dict)}
            except Exception:
                pass
    return {}


# Crash-class signatures extracted from a sanitizer trace. Used by
# `bug_class_hint()` so the F3 router can route bounded-integer / NULL /
# off-by-one / etc. tasks to a cheaper decisive oracle.
_BUG_CLASS_PATTERNS = [
    (re.compile(r"unsigned -|integer overflow|arithmetic overflow"),
     "integer-overflow"),
    (re.compile(r"heap-buffer-overflow"), "heap-buffer-overflow"),
    (re.compile(r"stack-buffer-overflow"), "stack-buffer-overflow"),
    (re.compile(r"global-buffer-overflow"), "global-buffer-overflow"),
    (re.compile(r"use-after-free"), "use-after-free"),
    (re.compile(r"double-free"), "double-free"),
    (re.compile(r"use-of-uninitialized-value"), "use-of-uninitialized-value"),
    (re.compile(r"null[-_ ]?deref|SEGV.*0x0", re.I), "null-deref"),
    (re.compile(r"divide[-_ ]?by[-_ ]?zero|FPE"), "div-by-zero"),
    (re.compile(r"out-of-bounds"), "out-of-bounds"),
    (re.compile(r"undefined-behavior|UBSan"), "undefined-behavior"),
]


class CyberGymTask:
    """`BenchmarkTask`-shaped facade over `TaskBundle`.

    Every method is a thin call to the legacy CyberGym adapter — no new
    benchmark-specific logic lives here; this module exists only to keep
    `agent/` code free of `eval/cybergym/` path/field references.
    """

    def __init__(self, bundle: _legacy.TaskBundle, level: Optional[int] = None):
        self._bundle = bundle
        self.task_id: str = bundle.task_id
        self._harness_cache: Optional[LocalHarness] = None
        # CyberGym difficulty level. Level 1 (the public leaderboard) discloses
        # ONLY {repo-vul.tar.gz, description.txt}. error.txt is level>=2 and
        # patch.diff is level==3 — gating them here makes a Level-1 run honest
        # regardless of whether higher-level files happen to be on disk.
        import os
        if level is None:
            try:
                level = int(os.environ.get("CYBERGYM_LEVEL", "1"))
            except ValueError:
                level = 1
        self.level: int = level

    # always required
    def description(self) -> str:
        return self._bundle.description or ""

    def score(self, poc_bytes: bytes, *,
              vul_timeout: int = 30,
              fix_timeout: int = 30) -> ScoreResult:
        import time
        from agent.local_oracle import score_native
        t0 = time.monotonic()
        # Prefer the native server-data binaries (no docker, no server, byte-
        # identical to the scoring server). Fall back to the legacy docker/
        # server path only when a side's binary is not materialised locally.
        raw = score_native(self.task_id, poc_bytes,
                           vul_timeout=vul_timeout, fix_timeout=fix_timeout)
        if raw is None:
            raw = _legacy.score_local(self._bundle, poc_bytes,
                                      vul_timeout=vul_timeout,
                                      fix_timeout=fix_timeout)
        wall_ms = int((time.monotonic() - t0) * 1000)
        return ScoreResult.from_vul_fix(
            vul_crashed=(raw["vul_verdict"] == "crash"),
            fix_crashed=(raw["fix_verdict"] == "crash"),
            vul_evidence=raw.get("scoring_rule", ""),
            fix_evidence="",
            vul_crash_class=raw.get("vul_crash_class"),
            vul_location=raw.get("vul_location"),
            wall_ms=wall_ms,
            oracle_name="cybergym.server",
        )

    # local-oracle facing (F2)
    def _harness(self) -> Optional[LocalHarness]:
        if self._harness_cache is None:
            self._harness_cache = resolve_harness(self.task_id, "vul")
        return self._harness_cache

    def harness_binary_path(self) -> Optional[Path]:
        h = self._harness()
        return h.binary if h is not None else None

    def harness_libs_dir(self) -> Optional[Path]:
        h = self._harness()
        return h.libs_dir if h is not None else None

    def harness_env(self) -> dict[str, str]:
        h = self._harness()
        return dict(h.env_extra) if h is not None else {}

    def source_archive_path(self) -> Optional[Path]:
        # repo-vul.tar.gz is disclosed at every level (level0+).
        tb = self._bundle.data_dir / "repo-vul.tar.gz"
        return tb if tb.exists() else None

    def upstream_corpus_dir(self) -> Optional[Path]:
        # The project's public OSS-Fuzz corpus for this fuzz target. project
        # name from tasks.json; fuzz-target = the harness binary's name.
        h = self._harness()
        if h is None:
            return None
        project = self.project_group()
        fuzzer = Path(h.binary).name
        try:
            from eval.cybergym.oss_fuzz_corpus import corpus_dir
            return corpus_dir(project, fuzzer)
        except Exception:
            return None

    # F3 routing hooks
    def disclosed_error_text(self) -> Optional[str]:
        # error.txt is a level>=2 disclosure. At level 1 it is NOT available
        # to the agent, so we return None even if the file is on disk.
        if self.level < 2:
            return None
        err = self._bundle.data_dir / "error.txt"
        if err.exists():
            try:
                text = err.read_text(errors="replace")
            except Exception:
                return None
            # Guard against git-LFS pointer stubs (real content not pulled).
            if text.startswith("version https://git-lfs"):
                return None
            return text
        return None

    def bug_class_hint(self) -> Optional[str]:
        # Try error.txt first (richest signal), fall back to description.
        for src in (self.disclosed_error_text(), self.description()):
            if not src:
                continue
            for pat, cls in _BUG_CLASS_PATTERNS:
                if pat.search(src):
                    return cls
        return None

    # V3 patch-verify hook
    def disclosed_patch_diff(self) -> Optional[str]:
        # patch.diff is a level==3 disclosure. Withheld below level 3.
        if self.level < 3:
            return None
        patch = self._bundle.data_dir / "patch.diff"
        if patch.exists():
            try:
                text = patch.read_text(errors="replace")
            except Exception:
                return None
            if text.startswith("version https://git-lfs"):
                return None
            return text
        return None

    # F4 corpus-sharing hook
    def project_group(self) -> Optional[str]:
        idx = _project_index()
        return idx.get(self.task_id) or self.task_id.split(":", 1)[0]

    # convenience
    @property
    def bundle(self) -> _legacy.TaskBundle:
        """Escape hatch for code that still needs the legacy TaskBundle."""
        return self._bundle


def resolve_task(task_id: str) -> CyberGymTask:
    """Resolve a CyberGym task id to its `BenchmarkTask`-shaped facade."""
    bundle = _legacy.resolve(task_id)
    return CyberGymTask(bundle)


# Runtime assertion that we satisfy the Protocol — caught at import time.
def _self_check() -> None:
    # Build a stub bundle to verify the wrapper is structurally complete.
    # Don't actually resolve any task at import; just instance-check.
    from eval.cybergym.adapter import TaskBundle
    stub = TaskBundle(
        task_id="check:0", task_type="arvo",
        image_vul="x", image_fix="y", harness_path="/bin/arvo",
        description="", reference_poc=None, sanitizer_hint=None,
        data_dir=Path("/nonexistent"),
    )
    task = CyberGymTask(stub)
    assert isinstance(task, BenchmarkTask), \
        "CyberGymTask must satisfy BenchmarkTask Protocol"


_self_check()
