"""Budget helpers — read config/budget.yaml and expose simple caps.

Phase 0.2 wires the *fields*; the actual enforcer (a counter incremented per
request that aborts at the per-phase cap) turns on in Phase 2 when there are
real LLM calls to throttle. Until then this module exists so downstream code
can already depend on a stable surface.
"""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PATH = REPO_ROOT / "config" / "budget.yaml"


@dataclass
class TierBudget:
    cost_weight: int
    wall_seconds: int


@dataclass
class Budget:
    per_phase_tokens: dict[str, int]
    proposal_max_tokens: int
    refinement_max_tokens: int
    tiers: dict[str, TierBudget]
    cybergym_per_task_wall_seconds: int
    cybergym_per_task_tokens: int

    @classmethod
    def load(cls, path: Path | None = None) -> "Budget":
        path = path or DEFAULT_PATH
        raw = yaml.safe_load(path.read_text())
        return cls(
            per_phase_tokens={k: int(v) for k, v in raw["tokens"]["per_phase"].items()},
            proposal_max_tokens=int(raw["tokens"]["per_hypothesis"]["proposal_max"]),
            refinement_max_tokens=int(raw["tokens"]["per_hypothesis"]["refinement_max"]),
            tiers={
                name: TierBudget(int(t["cost_weight"]), int(t["wall_seconds"]))
                for name, t in raw["tiers"].items()
            },
            cybergym_per_task_wall_seconds=int(raw["cybergym"]["per_task_wall_seconds"]),
            cybergym_per_task_tokens=int(raw["cybergym"]["per_task_tokens"]),
        )


if __name__ == "__main__":
    import json
    b = Budget.load()
    print(json.dumps({
        "per_phase_tokens": b.per_phase_tokens,
        "proposal_max": b.proposal_max_tokens,
        "tiers": {k: vars(v) for k, v in b.tiers.items()},
        "cybergym_task_tokens": b.cybergym_per_task_tokens,
    }, indent=2))
