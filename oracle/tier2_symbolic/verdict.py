"""Tier-2 (symbolic / concolic feasibility) verdict schema.

Mirrors `oracle/tier1_fuzz/verdict.py` and `surface/stage_b.py` so the router
(Phase 2.4) treats all tiers uniformly.

Soundness rules (PLAN §3 Tier-2):

- ``sat``       — solver returned a model + concrete input that drives the
                  target path/property; this is a *candidate* PoV, to be
                  re-checked with the Tier-1 oracle. Symbolic SAT alone is
                  NOT a final exploit verdict (KLEE/angr environment models
                  may under-approximate the runtime).
- ``unsat``     — solver proved the property/path infeasible *under the
                  symbolic model in use*. This becomes "refute" / prune ONLY
                  when the environment model covers everything reachable
                  (see ``docs/soundness-assumptions.md`` Tier-2 entries).
- ``inconclusive`` — timeout, unmodeled external call, fork-bomb, OOM, or
                  any case where the solver did not return a decisive answer
                  within budget. NEVER "safe".
"""
from __future__ import annotations

from dataclasses import dataclass, asdict, field
from typing import Optional, List


VERDICT_SAT = "sat"
VERDICT_UNSAT = "unsat"
VERDICT_INCONCLUSIVE = "inconclusive"

ENGINES = {"klee", "symcc", "angr", "s2e"}


@dataclass
class Tier2Verdict:
    unit: str                            # function / harness / binary id
    engine: str                          # one of ENGINES
    verdict: str                         # sat | unsat | inconclusive
    wall_ms: int
    property: str = ""                   # e.g. "reach(target_addr)", "div_by_zero"
    paths_explored: int = 0
    paths_completed: int = 0
    pov_path: Optional[str] = None       # concrete input artifact (ktest / bytes)
    target_location: Optional[str] = None
    evidence_excerpt: str = ""           # stdout/stderr tail
    soundness_note: str = ""
    assumed: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)
