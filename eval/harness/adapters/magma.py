"""Magma adapter — Phase 1 soundness gate + Phase 2 false-confirmation check.

Stubbed for Phase 0.5: Magma drops in Phase 1.5 and Phase 2.5. Returns
not_setup so the row exists in the baseline schema.
"""
from __future__ import annotations

from ..metrics import MetricRow, make_row, REPO_ROOT

MAGMA_DIR = REPO_ROOT / "eval" / "magma"


def baseline_rows() -> list[MetricRow]:
    setup = any(MAGMA_DIR.iterdir()) if MAGMA_DIR.exists() else False
    return [make_row(
        adapter="magma", target="-", status="not_setup",
        success=False,
        notes="Magma corpus not ingested; needed for Phase 1.5 soundness gate",
        evidence_paths=[str(MAGMA_DIR.relative_to(REPO_ROOT))] if setup else [],
    )]
