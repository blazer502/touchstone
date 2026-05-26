"""Live-library field-target adapter (PLAN §5b.B.5).

The live SQLite/OpenSSL/libxml2 hunt is a Phase 4 field run. PLAN §0.3 lists
the SQLite OSS-Fuzz simple-smoke as "an even simpler smoke" — explicitly
deferred to Phase 4 in PROGRESS.md. Stub here.
"""
from __future__ import annotations

from ..metrics import MetricRow, make_row, REPO_ROOT

LIVE_DIR = REPO_ROOT / "eval" / "live-lib"


def baseline_rows() -> list[MetricRow]:
    setup = any(LIVE_DIR.iterdir()) if LIVE_DIR.exists() else False
    return [make_row(
        adapter="live-lib", target="-", status="not_setup",
        success=False,
        notes="live SQLite/OpenSSL/libxml2 hunt deferred to Phase 4.3",
        evidence_paths=[str(LIVE_DIR.relative_to(REPO_ROOT))] if setup else [],
    )]
