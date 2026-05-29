"""Falsifiable kernel-bug hypothesis — the object an LLM proposes and PA tests.

The LLM is a PROPOSER: it turns a program-analysis finding (a static-analyzer
warning sitting in a reachable slice) into a concrete, falsifiable claim about a
memory-corruption bug. Every hypothesis MUST cite its grounding evidence and
name a falsifier (a check a PA leg runs) — a hypothesis with neither is rejected
at intake (the anti-hallucination gate). The sound oracle (KASAN / syz-repro)
is the only thing that confirms; this schema never asserts a verdict.

Distinct from `agent.router.Hypothesis` (per-tier verification *spec*); this is
the *bug claim*.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Optional

# Memory-corruption classes worth weaponizing (LPE-capable), vs DoS-only.
BUG_CLASSES = (
    "uaf", "double-free", "refcount-underflow", "oob-write", "oob-read",
    "uninit", "type-confusion", "lock-order-inversion",
)
# Classes that can yield a write/control primitive (kernelCTF-relevant).
WRITE_CAPABLE = {"uaf", "double-free", "refcount-underflow", "oob-write", "type-confusion"}


@dataclass
class Site:
    file: str
    line: Optional[int] = None
    fn: Optional[str] = None


@dataclass
class Evidence:
    tool: str                 # smatch | coccinelle | codeql | cve | directed
    path: str
    line: Optional[int]
    msg: str


@dataclass
class KernelBugHypothesis:
    hid: str
    bug_class: str                                  # one of BUG_CLASSES
    site: Site
    falsifier: str                                  # REQUIRED: a concrete PA check
    evidence: list[Evidence] = field(default_factory=list)   # REQUIRED grounding
    # Lifetime / trigger claims (LLM-filled, refined by PA).
    object: dict = field(default_factory=dict)      # {struct, alloc_site, free_site, field}
    trigger_sketch: list[str] = field(default_factory=list)  # syscall/ioctl steps
    spray_hint: dict = field(default_factory=dict)  # {slab_cache, size_class}
    # Reachability (filled by directed.py / reach.py).
    reachability: dict = field(default_factory=dict)   # {unprivileged, distance, entry_surfaces}
    # Bookkeeping.
    provenance: dict = field(default_factory=dict)   # {proposer_model, source_sha, cve_refs}
    score: float = 0.0
    status: str = "proposed"        # proposed|reachable|triggerable|reproduced|refuted
    refutation: str = ""            # which leg said no + why

    def write_capable(self) -> bool:
        return self.bug_class in WRITE_CAPABLE

    def is_valid_intake(self) -> bool:
        """Anti-hallucination gate: must cite grounding evidence AND name a
        falsifier AND a recognised bug class. Free-form invented bugs fail."""
        return (self.bug_class in BUG_CLASSES
                and bool(self.falsifier.strip())
                and len(self.evidence) > 0)

    def to_dict(self) -> dict:
        return asdict(self)


def classify_warning(msg: str) -> Optional[str]:
    """Map a static-analyzer warning message to a memory-corruption bug class,
    or None if it's not memory-corruption-relevant (style/indent/etc.)."""
    m = msg.lower()
    if "use after free" in m or "used after free" in m or "freed" in m and "use" in m:
        return "uaf"
    if "double free" in m or "double-free" in m:
        return "double-free"
    if "underflow" in m and ("ref" in m or "count" in m):
        return "refcount-underflow"
    if "out-of-bounds" in m or "buffer overflow" in m or "array overflow" in m \
            or "out of bounds" in m:
        return "oob-write"
    if "uninitial" in m or "uninit" in m:
        return "uninit"
    if "could be null" in m or "null deref" in m or "dereferenc" in m and "null" in m:
        # null-deref is usually DoS, but track as oob-read candidate for triage.
        return "oob-read"
    if "type mismatch" in m or "type confusion" in m:
        return "type-confusion"
    return None


__all__ = ["KernelBugHypothesis", "Site", "Evidence", "BUG_CLASSES",
           "WRITE_CAPABLE", "classify_warning"]
