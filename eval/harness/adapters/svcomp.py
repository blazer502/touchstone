"""SV-COMP adapter — secondary, validates Component (1) proof engine.

Stubbed for Phase 0.5: the SV-COMP benchmarks have not been ingested yet (the
official set is multi-GB; not in the 0.5 done-when). Returns a not_setup row so
the schema stays present and Phase 1 can fill it in.
"""
from __future__ import annotations

from ..metrics import MetricRow, make_row, REPO_ROOT

SVCOMP_DIR = REPO_ROOT / "eval" / "sv-comp"


def baseline_rows() -> list[MetricRow]:
    setup = any(SVCOMP_DIR.iterdir()) if SVCOMP_DIR.exists() else False
    return [make_row(
        adapter="sv-comp", target="-", status="not_setup",
        success=False,
        notes="benchmark set not ingested; Phase 1 task (Frama-C/CBMC verification correctness)",
        evidence_paths=[str(SVCOMP_DIR.relative_to(REPO_ROOT))] if setup else [],
    )]
