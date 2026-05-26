"""Tier-2 oracle adapter — reports symbolic / concolic feasibility verdicts.

Reads Tier2Verdict JSON files emitted by:
- oracle/tier2_symbolic/klee_driver.py    (KLEE userspace, sat/unsat smokes)
- oracle/tier2_symbolic/angr_driver.py    (angr binary feasibility, sat/unsat smokes)
- oracle/tier2_symbolic/symcc_driver.py   (image-missing inconclusive stub)
- oracle/tier2_symbolic/s2e_driver.py     (image-missing inconclusive stub)

Phase 2.2 success criterion is *deterministic engine wiring*: each driver
returns the correct verdict on a labeled smoke. Magma-level precision /
false-confirmation measurement is the Phase 2.5 step.
"""
from __future__ import annotations

import json
from pathlib import Path

from ..metrics import MetricRow, make_row, REPO_ROOT

RUN_LOGS = REPO_ROOT / "run-logs"

# (target_label, file path relative to run-logs, expected verdict for "success")
SOURCES: list[tuple[str, str, str]] = [
    ("klee:sat:div_by_zero",  "phase2.2/klee_sat.json",   "sat"),
    ("klee:unsat:clamped",    "phase2.2/klee_unsat.json", "unsat"),
    ("angr:sat:magic",        "phase2.2/angr_magic.json", "sat"),
    ("angr:unsat:dead_code",  "phase2.2/angr_dead.json",  "unsat"),
    ("symcc:stub",            "phase2.2/symcc_stub.json", "inconclusive"),
    ("s2e:stub",              "phase2.2/s2e_stub.json",   "inconclusive"),
]


def _row_from_verdict(target: str, expected: str, path: Path) -> MetricRow:
    if not path.exists():
        return make_row(
            adapter="tier2_oracle", target=target, status="not_setup", phase="2.2",
            success=False, notes=f"missing {path.relative_to(REPO_ROOT)}",
        )
    v = json.loads(path.read_text())
    verdict = v.get("verdict")
    # The smoke is correct when verdict matches expected.
    # For image-missing stubs, "inconclusive" is the expected verdict and is
    # reported as "not_setup" (visually distinct from a successful sat/unsat).
    if expected == "inconclusive":
        status = "not_setup" if verdict == "inconclusive" else "fail"
        success = False
    else:
        status = "success" if verdict == expected else "fail"
        success = (verdict == expected)
    note = (
        f"engine={v.get('engine')} verdict={verdict} expected={expected} "
        f"paths={v.get('paths_completed')}/{v.get('paths_explored')} "
        f"loc={v.get('target_location')} wall_ms={v.get('wall_ms')}"
    )
    return make_row(
        adapter="tier2_oracle", target=target,
        status=status, phase="2.2",
        success=success, verdict=verdict,
        notes=note,
        per_tier_latency_s={
            "tier1": None,
            "tier2": (v.get("wall_ms", 0) / 1000.0) if v.get("wall_ms") else None,
            "tier3": None,
        },
        evidence_paths=[str(path.relative_to(REPO_ROOT))],
    )


def baseline_rows() -> list[MetricRow]:
    return [_row_from_verdict(target, exp, RUN_LOGS / rel)
            for target, rel, exp in SOURCES]
