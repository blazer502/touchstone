"""CyberGym adapter — primary scoring backend (PLAN §5c).

In Phase 0.5 we only need to read existing Phase 0.3 evidence (the reference-PoC
end-to-end run on arvo:1065) and convert it into a MetricRow. The submit-loop
itself is `eval/cybergym/run_phase03_smoke.sh` and stays where it is. Later
phases will call into this adapter to run new tasks.
"""
from __future__ import annotations

import json
import pathlib

from ..metrics import MetricRow, make_row, REPO_ROOT

PHASE03_RESULT = REPO_ROOT / "run-logs" / "phase0.3-cybergym-arvo1065.json"
SUBSET = REPO_ROOT / "eval" / "cybergym" / "subset.json"


def _read_phase03() -> dict | None:
    if not PHASE03_RESULT.exists():
        return None
    return json.loads(PHASE03_RESULT.read_text())


def baseline_rows() -> list[MetricRow]:
    rows: list[MetricRow] = []
    r = _read_phase03()
    if r is None:
        rows.append(make_row(
            adapter="cybergym", target="arvo:1065", status="not_setup",
            notes="phase0.3 evidence missing",
        ))
        return rows

    success = bool(r.get("verdict") == "success")
    rows.append(make_row(
        adapter="cybergym",
        target=r.get("task_id", "arvo:1065"),
        status="success" if success else "fail",
        success=success,
        verdict=r.get("verdict_rule"),
        notes=r.get("crash_summary"),
        per_tier_latency_s={"tier1": None, "tier2": None, "tier3": None},
        tokens_used=0,
        llm_used=bool(r.get("llm_used", False)),
        evidence_paths=[str(PHASE03_RESULT.relative_to(REPO_ROOT))],
    ))

    # Coverage roll-up: 1/10 of the published subset scored end-to-end so far.
    if SUBSET.exists():
        subset = json.loads(SUBSET.read_text())
        n_total = len(subset.get("tasks", subset) if isinstance(subset, dict) else subset)
        rows.append(make_row(
            adapter="cybergym",
            target="subset_coverage",
            status="success" if success else "fail",
            success=success,
            verdict=f"{1 if success else 0}/{n_total} of 10-subset scored with reference PoC",
            notes="phase0 baseline: only arvo:1065 reproduced; remaining tasks deferred to phase 2+",
            evidence_paths=[str(SUBSET.relative_to(REPO_ROOT))],
        ))
    return rows
