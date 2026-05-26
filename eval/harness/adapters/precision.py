"""Phase 2.5 precision / latency / escalation adapter.

Reads `run-logs/phase2.5-precision-summary.json` and emits one harness
roll-up row plus per-target rows (each labeled hypothesis -> one row, so the
JSONL can be sliced per hypothesis the same way the Phase 2.1/2.2/2.3
adapters expose per-engine rows).

If the precision run hasn't been executed yet, a single `not_setup` row is
emitted pointing at the driver to run.
"""
from __future__ import annotations

import json
from pathlib import Path

from ..metrics import MetricRow, make_row, REPO_ROOT

RUN_LOGS = REPO_ROOT / "run-logs"
SUMMARY_PATH = RUN_LOGS / "phase2.5-precision-summary.json"
TRACES_PATH = RUN_LOGS / "phase2.5-precision-traces.jsonl"

CONFIRMATION_SET = {"confirmed", "bmc_unsafe"}


def _rollup_row(s: dict) -> MetricRow:
    fc = s.get("false_confirmations", 0)
    missed = s.get("determinism", {}).get("buggy_missed", 0)
    sv = len(s.get("soundness_violations", []))
    # Soundness gate: false_confirmations + soundness_violations + buggy_missed
    # must all be zero for the row to be 'success' (Phase 2 Done-when).
    ok = (fc == 0 and missed == 0 and sv == 0
          and s.get("mismatches", 0) == 0)
    per_tier = s.get("per_tier_latency", {})
    return make_row(
        adapter="precision", target="phase2.5-rollup",
        status="success" if ok else "fail", phase="2.5",
        success=ok,
        verdict=(f"precision={s.get('precision_of_confirmation')} "
                 f"recall={s.get('recall_of_confirmation')} "
                 f"false_conf={fc} missed={missed} mismatches={s.get('mismatches',0)}"),
        notes=(f"n={s.get('n_hypotheses')} matches={s.get('matches')} "
               f"wall={s.get('corpus_wall_s')}s "
               f"escalation_rate={s.get('escalation',{}).get('escalation_rate',0):.2%} "
               f"no_dispatch={s.get('escalation',{}).get('no_dispatch',0)}"),
        oracle_precision=s.get("precision_of_confirmation"),
        oracle_recall=s.get("recall_of_confirmation"),
        per_tier_latency_s={
            "tier1": (per_tier.get("tier1_fuzz", {}).get("p50_ms", 0) / 1000.0) or None,
            "tier2": (per_tier.get("tier2_symbolic", {}).get("p50_ms", 0) / 1000.0) or None,
            "tier3": (per_tier.get("tier3_bmc", {}).get("p50_ms", 0) / 1000.0) or None,
        },
        missed_bug_count=missed,
        evidence_paths=[
            str(SUMMARY_PATH.relative_to(REPO_ROOT)),
            str(TRACES_PATH.relative_to(REPO_ROOT)),
        ],
    )


def _per_hypothesis_rows() -> list[MetricRow]:
    if not TRACES_PATH.exists():
        return []
    rows: list[MetricRow] = []
    for line in TRACES_PATH.read_text().splitlines():
        if not line.strip():
            continue
        r = json.loads(line)
        match = r["match"]
        # Soundness violation: buggy labeled as proved_safe → mark `fail`.
        gt = r["ground_truth"]
        actual = r["actual"]
        soundness_fail = (gt == "buggy" and actual == "proved_safe")
        if soundness_fail or not match:
            status = "fail"
            success = False
        else:
            status = "success"
            success = True
        # Per-tier latency from attempts (this hypothesis only).
        per_tier = {"tier1": None, "tier2": None, "tier3": None}
        for a in r.get("attempts", []):
            bucket = {"tier1_fuzz": "tier1",
                      "tier2_symbolic": "tier2",
                      "tier3_bmc": "tier3"}.get(a["tier"])
            if bucket is None:
                continue
            wall_s = (a.get("wall_ms") or 0) / 1000.0
            per_tier[bucket] = (per_tier[bucket] or 0.0) + wall_s
        rows.append(make_row(
            adapter="precision", target=r["hid"], status=status, phase="2.5",
            success=success, verdict=actual,
            notes=(f"gt={gt} expected={r['expected']} actual={actual} "
                   f"reason={r.get('decision_reason')!s} "
                   f"attempts={len(r.get('attempts', []))} "
                   f"cost={r.get('total_cost', 0)}"),
            per_tier_latency_s=per_tier,
            evidence_paths=[str(TRACES_PATH.relative_to(REPO_ROOT))],
        ))
    return rows


def baseline_rows() -> list[MetricRow]:
    if not SUMMARY_PATH.exists():
        return [make_row(
            adapter="precision", target="phase2.5-rollup",
            status="not_setup", phase="2.5", success=False,
            notes=("precision run has not been executed yet — run "
                   "`python3 eval/precision/run.py`"),
        )]
    s = json.loads(SUMMARY_PATH.read_text())
    return [_rollup_row(s)] + _per_hypothesis_rows()
