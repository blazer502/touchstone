"""Router adapter — reports Phase-2.4 router smoke verdicts.

Reads `run-logs/phase2.4-router-smoke.jsonl` (emitted by
`python3 -m agent.router --hypotheses agent/smoke/hypotheses.json --out …`)
and converts each trace into a MetricRow so the harness reflects router
behaviour alongside the per-tier rows.

A row is `success` when the trace's final verdict is "decisive" — anything
other than `inconclusive` or `no_dispatch`. The `noop` row is reported as
`not_setup` (it intentionally carries no specs).
"""
from __future__ import annotations

import json
from pathlib import Path

from ..metrics import MetricRow, make_row, REPO_ROOT

RUN_LOGS = REPO_ROOT / "run-logs"
TRACE_PATH = RUN_LOGS / "phase2.4-router-smoke.jsonl"


# Map router final verdict → harness status.
_DECISIVE = {"confirmed", "refuted", "proved_safe", "bmc_unsafe", "candidate"}


def _row_from_trace(trace: dict) -> MetricRow:
    hid = trace["hypothesis_id"]
    final = trace["final_verdict"]
    if final == "no_dispatch":
        status = "not_setup"
        success = False
    elif final in _DECISIVE:
        status = "success"
        success = True
    else:
        status = "fail"
        success = False

    # Aggregate per-tier latency from attempts.
    per_tier: dict[str, float] = {"tier1": None, "tier2": None, "tier3": None}
    for a in trace.get("attempts", []):
        bucket = {"tier1_fuzz": "tier1", "tier2_symbolic": "tier2",
                  "tier3_bmc": "tier3"}.get(a["tier"])
        if bucket is None:
            continue
        wall_s = (a.get("wall_ms") or 0) / 1000.0
        per_tier[bucket] = (per_tier[bucket] or 0.0) + wall_s

    return make_row(
        adapter="router", target=hid, status=status, phase="2.4",
        success=success, verdict=final,
        notes=(f"{trace.get('decision_reason','')} "
               f"(cost={trace.get('total_cost',0)}, wall_ms={trace.get('total_wall_ms',0)}, "
               f"pov={trace.get('pov_path')})"),
        per_tier_latency_s=per_tier,
        evidence_paths=[str(TRACE_PATH.relative_to(REPO_ROOT))],
    )


def baseline_rows() -> list[MetricRow]:
    if not TRACE_PATH.exists():
        return [make_row(
            adapter="router", target="phase2.4-smoke", status="not_setup", phase="2.4",
            success=False,
            notes=("router smoke not run yet — execute "
                   "`python3 -m agent.router --hypotheses agent/smoke/hypotheses.json "
                   "--out run-logs/phase2.4-router-smoke.jsonl`"),
        )]
    rows = []
    for line in TRACE_PATH.read_text().splitlines():
        if not line.strip():
            continue
        rows.append(_row_from_trace(json.loads(line)))
    return rows
