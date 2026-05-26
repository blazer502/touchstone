"""Tier-3 (BMC) verdict schema.

Mirrors Stage B (`surface/stage_b.py`) since the engine is shared, and matches
the Tier-1/Tier-2 verdict shape so the router (Phase 2.4) treats all tiers
uniformly.

Soundness rules (PLAN §3 Tier-3):

- ``safe``        — verified by the BMC engine up to the chosen unwind bound,
                    with `--unwinding-assertions` ON so any loop that exceeds
                    the bound surfaces as `inconclusive` instead of silently
                    `safe`. Unbounded safety requires a verified loop invariant
                    (Phase 3.1 LLM hook). Stage B's `docs/soundness-assumptions.md`
                    Stage B / CBMC bounded-loops entry applies.
- ``unsafe``      — engine produced a counterexample. The Tier-3 wrapper
                    extracts the cex assignment into a PoV artifact (concrete
                    inputs for the harness's nondeterministic variables). This
                    is the *definitive* BMC verdict — it is a sound finding of
                    a real bug for the harness as specified.
- ``inconclusive`` — timeout, unwinding-assertion failure (loop exceeds bound),
                    image missing, or the engine could not decide. NEVER
                    silently "safe".
"""
from __future__ import annotations

from dataclasses import dataclass, asdict, field
from typing import Optional, List


VERDICT_SAFE = "safe"
VERDICT_UNSAFE = "unsafe"
VERDICT_INCONCLUSIVE = "inconclusive"

ENGINES = {"cbmc", "esbmc"}


@dataclass
class Tier3Verdict:
    unit: str                            # harness id / "<source>::<function>"
    engine: str                          # one of ENGINES
    property: str                        # memory-safety | no-overflow | no-oob | no-uaf | assertion
    verdict: str                         # safe | unsafe | inconclusive
    unwind: Optional[int]
    wall_ms: int
    pov_path: Optional[str] = None       # cex assignment as JSON, when verdict=unsafe
    target_location: Optional[str] = None
    evidence_excerpt: str = ""
    soundness_note: str = ""
    assumed_contracts: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)
