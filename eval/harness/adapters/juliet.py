"""Juliet adapter — labeled C/C++ test cases, used with Magma for the Phase 1
soundness gate (PLAN §2 acceptance). Stub for Phase 0.5.
"""
from __future__ import annotations

from ..metrics import MetricRow, make_row, REPO_ROOT

JULIET_DIR = REPO_ROOT / "eval" / "juliet"


def baseline_rows() -> list[MetricRow]:
    setup = any(JULIET_DIR.iterdir()) if JULIET_DIR.exists() else False
    return [make_row(
        adapter="juliet", target="-", status="not_setup",
        success=False,
        notes="Juliet corpus not ingested; needed for Phase 1.5 soundness gate",
        evidence_paths=[str(JULIET_DIR.relative_to(REPO_ROOT))] if setup else [],
    )]
