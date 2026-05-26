"""Phase 3.4 CyberGym ablation adapter — rolls up the headline experiment.

Reads `run-logs/phase3.4-ablation.json` (emitted by `eval.cybergym.run_ablation`)
and emits:
  - one rollup row summarizing the baseline vs. accelerated headline numbers
  - one row per task with the per-task delta (confirmed_baseline,
    confirmed_accelerated, first_crash index delta, wall_ms delta, tokens)
"""
from __future__ import annotations

import json

from ..metrics import MetricRow, make_row, REPO_ROOT

ABLATION_JSON = REPO_ROOT / "run-logs" / "phase3.4-ablation.json"


def baseline_rows() -> list[MetricRow]:
    if not ABLATION_JSON.exists():
        return [make_row(
            adapter="cybergym-ablation", target="phase3.4", status="not_setup",
            notes="run `python3 -m eval.cybergym.run_ablation` to populate",
        )]
    data = json.loads(ABLATION_JSON.read_text())
    roll = data.get("rollup", {})
    rows: list[MetricRow] = []

    # Headline rollup.
    n = roll.get("tasks_run", 0)
    base = roll.get("baseline_confirmed", 0)
    acc = roll.get("accelerated_confirmed", 0)
    delta = roll.get("headline_delta_confirmed", acc - base)
    success = (acc > base) and (n > 0)
    rows.append(make_row(
        phase="3.4",
        adapter="cybergym-ablation", target="rollup",
        status="success" if success else ("fail" if n > 0 else "not_setup"),
        success=success,
        verdict=f"accelerated={acc}/{n}, baseline={base}/{n}, delta={delta:+d}",
        notes=(f"budget={data.get('budget_candidates')} per arm; "
               f"baseline_wall_ms={roll.get('baseline_wall_ms_total')}, "
               f"accelerated_wall_ms={roll.get('accelerated_wall_ms_total')}"),
        tokens_used=int(roll.get("accelerated_tokens_used", 0)),
        llm_used=True,
        evidence_paths=[str(ABLATION_JSON.relative_to(REPO_ROOT))],
    ))

    # Per-task rows.
    for t in roll.get("per_task", []):
        rows.append(make_row(
            phase="3.4",
            adapter="cybergym-ablation", target=t["task_id"],
            status="success" if t["accelerated_confirmed"] else "fail",
            success=bool(t["accelerated_confirmed"]),
            verdict=(f"baseline={'crash' if t['baseline_confirmed'] else 'no_crash'} / "
                     f"accelerated={'crash' if t['accelerated_confirmed'] else 'no_crash'}"),
            notes=(f"baseline_first_idx={t['baseline_first_crash_idx']}, "
                   f"accelerated_first_idx={t['accelerated_first_crash_idx']}, "
                   f"wall_ms_baseline={t['wall_ms_baseline']}, "
                   f"wall_ms_accelerated={t['wall_ms_accelerated']}"),
            tokens_used=int(t.get("tokens_used", 0)),
            llm_used=True,
            evidence_paths=[str(ABLATION_JSON.relative_to(REPO_ROOT))],
        ))
    return rows
