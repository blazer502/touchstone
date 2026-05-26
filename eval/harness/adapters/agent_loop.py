"""Phase 4.1 closed-loop adapter — reports per-candidate dispositions.

Reads `run-logs/phase4.1-loop-smoke.jsonl` (emitted by
`python3 -m agent.loop --candidates agent/smoke/candidates.json --out …`)
and converts each candidate's result into a MetricRow plus a single rollup
row.

A row counts as `success` when the candidate reaches a *decisive*
disposition — anything other than `inconclusive` / `no_dispatch`. The
rule mirrors `eval/harness/adapters/router.py` so the harness's
success-count semantics stay consistent across phases.
"""
from __future__ import annotations

import json
from pathlib import Path

from ..metrics import MetricRow, make_row, REPO_ROOT

RUN_LOGS = REPO_ROOT / "run-logs"
TRACE_PATH = RUN_LOGS / "phase4.1-loop-smoke.jsonl"

_DECISIVE = {"confirmed", "pruned", "candidate"}


def _row_from(result: dict) -> MetricRow:
    cid = result["candidate_id"]
    disp = result["decision"]["disposition"]
    reason = result["decision"]["reason"]
    pov = result["decision"].get("pov_path")
    ref = result.get("refinement", {})
    wall_ms = result.get("total_wall_ms", 0)

    if disp in _DECISIVE:
        status, success = "success", True
    elif disp == "no_dispatch":
        status, success = "not_setup", False
    else:
        status, success = "fail", False

    # Per-tier latency from the underlying route trace.
    per_tier: dict[str, float] = {"tier1": None, "tier2": None, "tier3": None}
    for a in result.get("route_trace", {}).get("attempts", []):
        bucket = {"tier1_fuzz": "tier1", "tier2_symbolic": "tier2",
                  "tier3_bmc": "tier3"}.get(a.get("tier"))
        if bucket is None:
            continue
        s = (a.get("wall_ms") or 0) / 1000.0
        per_tier[bucket] = (per_tier[bucket] or 0.0) + s

    refined = bool(ref.get("invoked"))
    tokens = int(ref.get("tokens_used") or 0)
    notes = (f"{reason}; refine={refined}"
             + (f" (iter={ref.get('iterations',0)} final={ref.get('final_verdict','-')})"
                if refined else "")
             + (f" pov={pov}" if pov else ""))

    return make_row(
        adapter="agent-loop", target=cid, status=status, phase="4.1",
        success=success, verdict=disp, notes=notes,
        per_tier_latency_s=per_tier,
        tokens_used=tokens, llm_used=refined and tokens > 0,
        evidence_paths=[str(TRACE_PATH.relative_to(REPO_ROOT))],
    )


def baseline_rows() -> list[MetricRow]:
    if not TRACE_PATH.exists():
        return [make_row(
            adapter="agent-loop", target="phase4.1-smoke",
            status="not_setup", phase="4.1", success=False,
            notes=("closed-loop smoke not run yet — execute "
                   "`python3 -m agent.loop --candidates agent/smoke/candidates.json "
                   "--out run-logs/phase4.1-loop-smoke.jsonl`"),
        )]
    rows: list[MetricRow] = []
    by_disp: dict[str, int] = {}
    decisive = 0
    for line in TRACE_PATH.read_text().splitlines():
        if not line.strip():
            continue
        r = json.loads(line)
        rows.append(_row_from(r))
        d = r["decision"]["disposition"]
        by_disp[d] = by_disp.get(d, 0) + 1
        if d in _DECISIVE:
            decisive += 1
    total = len(rows)
    rollup = make_row(
        adapter="agent-loop", target="rollup", phase="4.1",
        status="success" if decisive == total and total > 0 else "fail",
        success=decisive == total and total > 0,
        verdict=f"{decisive}/{total} decisive",
        notes=f"by_disposition={by_disp}",
        evidence_paths=[str(TRACE_PATH.relative_to(REPO_ROOT))],
    )
    return [rollup] + rows
