"""Tier-3 oracle adapter — reports BMC verdicts.

Reads Tier3Verdict JSON files emitted by:
- oracle/tier3_bmc/cbmc_driver.py    (CBMC safe/unsafe/inconclusive smokes)
- oracle/tier3_bmc/esbmc_driver.py   (image-missing inconclusive stub)

Phase 2.3 success criterion is *deterministic engine wiring*: each driver
returns the correct verdict on a labeled smoke. Magma-level precision /
false-confirmation measurement is the Phase 2.5 step.
"""
from __future__ import annotations

import json
from pathlib import Path

from ..metrics import MetricRow, make_row, REPO_ROOT

RUN_LOGS = REPO_ROOT / "run-logs"

# (target_label, file path relative to run-logs, expected verdict)
SOURCES: list[tuple[str, str, str]] = [
    ("cbmc:safe:bounded",         "phase2.3/cbmc_safe.json",         "safe"),
    ("cbmc:unsafe:off_by_one",    "phase2.3/cbmc_unsafe.json",       "unsafe"),
    ("cbmc:inconclusive:unwind",  "phase2.3/cbmc_inconclusive.json", "inconclusive"),
    ("esbmc:stub",                "phase2.3/esbmc_stub.json",        "inconclusive"),
]


def _row_from_verdict(target: str, expected: str, path: Path) -> MetricRow:
    if not path.exists():
        return make_row(
            adapter="tier3_oracle", target=target, status="not_setup", phase="2.3",
            success=False, notes=f"missing {path.relative_to(REPO_ROOT)}",
        )
    v = json.loads(path.read_text())
    verdict = v.get("verdict")
    # For the ESBMC stub, "inconclusive" is the expected verdict and reported
    # as "not_setup" (visually distinct from a real safe/unsafe). The
    # CBMC inconclusive smoke is a genuine *engine-correctness* check — the
    # driver MUST report inconclusive when the unwind bound is exceeded —
    # so it counts as a success.
    if target == "esbmc:stub":
        status = "not_setup" if verdict == "inconclusive" else "fail"
        success = False
    else:
        status = "success" if verdict == expected else "fail"
        success = (verdict == expected)
    note = (
        f"engine={v.get('engine')} verdict={verdict} expected={expected} "
        f"unwind={v.get('unwind')} pov={v.get('pov_path')} "
        f"loc={v.get('target_location')} wall_ms={v.get('wall_ms')}"
    )
    return make_row(
        adapter="tier3_oracle", target=target,
        status=status, phase="2.3",
        success=success, verdict=verdict,
        notes=note,
        per_tier_latency_s={
            "tier1": None,
            "tier2": None,
            "tier3": (v.get("wall_ms", 0) / 1000.0) if v.get("wall_ms") else None,
        },
        evidence_paths=[str(path.relative_to(REPO_ROOT))],
    )


def baseline_rows() -> list[MetricRow]:
    return [_row_from_verdict(target, exp, RUN_LOGS / rel)
            for target, rel, exp in SOURCES]
