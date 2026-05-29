"""Abstract task interface — keeps agent code benchmark-agnostic.

Rule (docs/strategic-direction.md §8): agent improvements must not hard-code
fields, paths, or scoring quirks of a single benchmark. Every benchmark
(CyberGym, Magma, Juliet, kernelCTF, SV-COMP, ...) implements a thin
adapter on top of this protocol; agent code goes through the protocol.

Surface:

    BenchmarkTask  — the task object the agent sees (Protocol)
    ScoreResult    — verdict of submitting a PoC against the benchmark's
                     scoring oracle (typically vul=crash ∧ fix=no_crash)
    BenchmarkOracle — alternative shape if scoring is decoupled from the
                     task object (most adapters just put `score()` on the
                     task itself; this Protocol is exposed for adapters
                     that prefer separation)

Adapters add methods piecewise: F2/V4/V1 only need `harness_binary_path`,
`harness_libs_dir`, and `score`. F3 adds `disclosed_error_text` +
`bug_class_hint`. V3 adds `disclosed_patch_diff`. F4 adds `project_group`.
Methods that an adapter cannot supply return `None` rather than throwing,
so agent code can gracefully degrade.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Protocol, runtime_checkable


@dataclass
class ScoreResult:
    """The verdict of a benchmark's scoring oracle on a single PoC.

    `reproduces_target = vul_crashed ∧ ¬fix_crashed` is the standard
    leaderboard scoring rule (the bug fires pre-patch, the disclosed
    patch closes it). `finds_post_patch = fix_crashed` is a secondary
    "regression / new bug" metric.

    `vul_evidence` / `fix_evidence` carry sanitizer banners and stack
    traces — these feed the Witness disclosure blob downstream.
    """
    vul_crashed: bool
    fix_crashed: bool
    reproduces_target: bool
    finds_post_patch: bool
    vul_evidence: str = ""
    fix_evidence: str = ""
    vul_crash_class: Optional[str] = None
    vul_location: Optional[str] = None
    wall_ms: int = 0
    oracle_name: str = ""

    @classmethod
    def from_vul_fix(cls, vul_crashed: bool, fix_crashed: bool,
                     **kw) -> "ScoreResult":
        """Convenience constructor — derives both leaderboard rules."""
        return cls(
            vul_crashed=vul_crashed,
            fix_crashed=fix_crashed,
            reproduces_target=(vul_crashed and not fix_crashed),
            finds_post_patch=fix_crashed,
            **kw,
        )


@runtime_checkable
class BenchmarkTask(Protocol):
    """A task the agent can analyze.

    Every CyberGym / Magma / Juliet / ... task implements this. Methods
    return `None` when the benchmark doesn't expose that field — agents
    must tolerate optional surfaces.
    """
    task_id: str

    # --- always required ---------------------------------------------------

    def description(self) -> str:
        """Free-text description of the bug, if disclosed."""
        ...

    def score(self, poc_bytes: bytes, *,
              vul_timeout: int = 30,
              fix_timeout: int = 30) -> ScoreResult:
        """Run the benchmark's scoring oracle on this PoC.

        For CyberGym this runs the vul + fix images and returns the
        `vul=crash ∧ fix=no_crash` verdict. For benchmarks without a
        post-patch image, `fix_crashed = False` by convention.
        """
        ...

    # --- local-oracle facing (F2 / fast iteration) ------------------------

    def harness_binary_path(self) -> Optional[Path]:
        """Path to the pre-built libFuzzer / OSS-Fuzz harness binary, if any.

        When present, the agent can run candidates locally (no docker,
        no HTTP, no rate limit) before submitting to the scoring oracle.
        Returns None when only a remote / containerised oracle is available.
        """
        return None

    def harness_libs_dir(self) -> Optional[Path]:
        """Directory of shared libraries the harness binary depends on."""
        return None

    def harness_env(self) -> dict[str, str]:
        """Extra environment variables required for the local harness run
        (e.g. MAGIC for libmagic, dictionary paths). Default: empty."""
        return {}

    def source_archive_path(self) -> Optional[Path]:
        """Path to an archive (tar/zip) of the target's vulnerable source, if
        the benchmark discloses one. Program-analysis steps (harness shape,
        magic-constant dictionary, reachability slice) read from it. Returns
        None when no source is disclosed."""
        return None

    def upstream_corpus_dir(self) -> Optional[Path]:
        """Directory of the upstream project's own public test/seed corpus
        for this fuzz target (e.g. the OSS-Fuzz public corpus), if available.
        Seeding the fuzzer with it is standard practice and benchmark-agnostic
        (it is the project's corpus, not the benchmark's hidden PoC). Returns
        None when no upstream corpus is available."""
        return None

    # --- F3 routing hooks (bug-class triage) -------------------------------

    def disclosed_error_text(self) -> Optional[str]:
        """Sanitizer stack trace / disclosure note, when the benchmark
        exposes one (CyberGym `error.txt`, kernelCTF dmesg, ...)."""
        return None

    def bug_class_hint(self) -> Optional[str]:
        """Free-text bug-class label (e.g. `heap-buffer-overflow`,
        `unsigned-underflow`, `use-of-uninitialized-value`) used by the
        router (F3) to dispatch to the cheapest decisive oracle."""
        return None

    # --- V3 patch-verify hook ----------------------------------------------

    def disclosed_patch_diff(self) -> Optional[str]:
        """The upstream patch as a unified diff, when disclosed.
        Enables auto-patch_verify on every confirm."""
        return None

    # --- F4 corpus-sharing hook -------------------------------------------

    def project_group(self) -> Optional[str]:
        """Identifier for the project this task belongs to (e.g. `libpng`,
        `openssl`, kernel subsystem name). Tasks with the same project
        share libFuzzer corpora — finding a new crashing input on one
        task seeds the others."""
        return None


@runtime_checkable
class BenchmarkOracle(Protocol):
    """Optional separation: a scoring oracle decoupled from the task object.

    Most adapters won't use this — they put `score()` directly on the
    `BenchmarkTask`. Exposed for adapters where scoring is a centralised
    service (e.g. one server endpoint scores every task in a benchmark).
    """
    def score(self, task: BenchmarkTask, poc_bytes: bytes, *,
              vul_timeout: int = 30,
              fix_timeout: int = 30) -> ScoreResult: ...


__all__ = ["BenchmarkTask", "BenchmarkOracle", "ScoreResult"]
