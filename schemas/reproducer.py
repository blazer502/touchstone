"""Crash-reproducer pipeline schema (R-track: crash -> reproducer).

Turns a raw crash *signal* into a reproducibility-scored, minimized, portable
reproducer artifact. This is the missing bridge between "a sanitizer/KASAN
fired once" (what the Tier-1 oracle produces) and everything downstream
(exploitability triage, weaponization, kernelCTF's ~90 %-reproducible bar).

Mirrors the verdict-dataclass pattern used across the oracle tiers
(``Tier1Verdict`` / ``Tier2Verdict`` / ``Tier3Verdict``) so the router /
metrics / loop layers treat a reproducibility result like any other verdict.

Benchmark-agnostic (``docs/strategic-direction.md`` §8): a ``CrashRecord`` is
source-agnostic; kernel vs userspace differ only in the re-run *backend*, not
in agent logic.

Soundness rules (recorded in ``docs/soundness-assumptions.md``; mirror the
PLAN §3 Tier-1 "no-crash is inconclusive, never safe" rule):

- ``repro_rate`` is a FINITE-N frequency estimate. ``verdict='unreproducible'``
  means "not reproduced within N runs under this build/config", NEVER
  "safe / no bug". Only a sound engine (Stage B / Tier-3 BMC) may say safe.
- The re-run (sanitizer / KASAN / lockdep) is the verdict authority. An LLM may
  only *propose* a candidate trigger (kernel synthesis fallback); the actual
  execution decides reproducibility (PLAN §8).
- A ``Reproducer`` is bound to ``build_id``: replaying against a different
  kernel/harness build is a miss, the same discipline as the proof cache
  (PLAN §2 cache key).
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import List, Optional


# --- domains -----------------------------------------------------------------
DOMAIN_KERNEL = "kernel"
DOMAIN_USERSPACE = "userspace"

# --- verdict vocabulary ------------------------------------------------------
REPRO_REPRODUCIBLE = "reproducible"      # repro_rate >= threshold
REPRO_FLAKY = "flaky"                     # 0 < repro_rate < threshold
REPRO_UNREPRODUCIBLE = "unreproducible"   # repro_rate == 0 over N runs

# kernelCTF wants ~0.9; default high so "reproducible" is a strong claim.
DEFAULT_REPRO_THRESHOLD = 0.9


def crash_signature(sanitizer: Optional[str], crash_class: Optional[str],
                    location: Optional[str]) -> str:
    """Stable, cross-run bucket key for a crash.

    Strips run-varying noise so two firings of the SAME bug match across
    re-runs (and so dedup collapses duplicates):

    - ASLR addresses (``0x...``) anywhere in the location are removed,
    - kernel frame offsets (``ip_rcv+0x6b1/0x730`` -> ``ip_rcv``) are removed,
    - a trailing column on ``file.c:line:col`` -> ``file.c:line``.

    Returns ``"<san>|<class>|<loc>"`` with ``None`` rendered as ``"?"``.
    """
    san = (sanitizer or "?").strip()
    cls = (crash_class or "?").strip()
    loc = (location or "?").strip()
    # kernel offset:  ip_rcv+0x6b1/0x730 -> ip_rcv
    loc = re.sub(r"\+0x[0-9a-f]+(?:/0x[0-9a-f]+)?", "", loc)
    # bare hex addresses -> drop
    loc = re.sub(r"0x[0-9a-f]+", "", loc)
    # file.c:line:col -> file.c:line
    m = re.match(r"(.+:\d+):\d+$", loc)
    if m:
        loc = m.group(1)
    loc = loc.strip() or "?"
    return f"{san}|{cls}|{loc}"


def classify_repro(repro_rate: float, threshold: float = DEFAULT_REPRO_THRESHOLD) -> str:
    """(repro_rate) -> reproducible | flaky | unreproducible."""
    if repro_rate <= 0.0:
        return REPRO_UNREPRODUCIBLE
    if repro_rate >= threshold:
        return REPRO_REPRODUCIBLE
    return REPRO_FLAKY


# --- the data model ----------------------------------------------------------

@dataclass
class CrashRecord:
    """A normalized crash from ANY oracle source (kernel dmesg | userspace
    sanitizer | cybergym server output).

    ``candidate_trigger_path`` is the input that (allegedly) produces the
    crash: raw bytes file (userspace) or a syz program / executor log (kernel).
    """
    domain: str                                  # DOMAIN_KERNEL | DOMAIN_USERSPACE
    signature: str                               # crash_signature(...)
    sanitizer: Optional[str] = None
    crash_class: Optional[str] = None
    location: Optional[str] = None
    severity: str = "crash"                      # kernel: crash|warn|dos|unknown; userspace: crash
    candidate_trigger_path: Optional[str] = None
    build_id: str = ""                           # harness-bin hash | image tag | bzImage hash
    unit: str = ""                               # task/bucket id for logs
    evidence_excerpt: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_libfuzzer_log(cls, text: str, *, trigger_path: Optional[str],
                           build_id: str, unit: str,
                           sanitizer: Optional[str] = None) -> "CrashRecord":
        """Build a userspace CrashRecord from a libFuzzer/ASan/MSan/UBSan blob."""
        from oracle.tier1_fuzz.verdict import from_libfuzzer_log
        crash_class, location = from_libfuzzer_log(text)
        return cls(
            domain=DOMAIN_USERSPACE,
            signature=crash_signature(sanitizer, crash_class, location),
            sanitizer=sanitizer,
            crash_class=crash_class,
            location=location,
            severity="crash",
            candidate_trigger_path=trigger_path,
            build_id=build_id,
            unit=unit,
            evidence_excerpt=text[:6000],
        )

    @classmethod
    def from_kernel_log(cls, text: str, *, trigger_path: Optional[str],
                        build_id: str, unit: str) -> "CrashRecord":
        """Build a kernel CrashRecord from a dmesg/serial blob."""
        from oracle.tier1_fuzz.verdict import classify_kernel_bug, from_kernel_bug_log
        san, crash_class, location = from_kernel_bug_log(text)
        severity = classify_kernel_bug(san, crash_class)
        return cls(
            domain=DOMAIN_KERNEL,
            signature=crash_signature(san, crash_class, location),
            sanitizer=san,
            crash_class=crash_class,
            location=location,
            severity=severity,
            candidate_trigger_path=trigger_path,
            build_id=build_id,
            unit=unit,
            evidence_excerpt=text[:6000],
        )


@dataclass
class Reproducer:
    """The deliverable artifact: a minimized, reproducibility-scored trigger
    bound to a specific build, plus the exact command that re-fires it."""
    signature: str
    domain: str
    repro_rate: float
    runs: int
    build_id: str
    engine: str
    replay_cmd: str
    minimized: bool = False
    minimized_trigger_path: Optional[str] = None
    minimized_trigger_hex: Optional[str] = None     # inlined when small
    original_trigger_path: Optional[str] = None
    original_size_bytes: Optional[int] = None
    minimized_size_bytes: Optional[int] = None
    crash_class: Optional[str] = None
    location: Optional[str] = None
    wall_ms: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ReproVerdict:
    """Reproducibility verdict — mirrors Tier1Verdict shape for uniform
    router/metrics/loop handling."""
    unit: str
    domain: str
    verdict: str                                 # reproducible | flaky | unreproducible
    repro_rate: float
    runs: int
    signature: str
    threshold: float = DEFAULT_REPRO_THRESHOLD
    reproducer: Optional[Reproducer] = None
    wall_ms: int = 0
    soundness_note: str = ""
    assumed: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        return d
