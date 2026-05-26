"""Phase 3.3 LLM-router adapter.

Reads two artifacts emitted by the Phase-3.3 verification runs:

  run-logs/phase3.3-router-llm-multi.jsonl     — RouteTrace rows (LLM dispatcher)
  run-logs/phase3.3-llm-dispatch-multi.jsonl   — per-hypothesis LLM dispatch trace
  run-logs/phase3.3-precision-summary.json     — precision corpus under the LLM router

Emits one rollup row (precision under LLM router) plus per-hypothesis rows for the
multi-tier smoke (so the harness records which proposals the LLM made and the
verdict the engine returned). The rollup row's success criterion mirrors the
Phase-2.5 gate: false_confirmations + soundness_violations + buggy_missed == 0.
"""
from __future__ import annotations

import json
from pathlib import Path

from ..metrics import MetricRow, make_row, REPO_ROOT

RUN_LOGS = REPO_ROOT / "run-logs"
LLM_ROUTE_TRACE = RUN_LOGS / "phase3.3-router-llm-multi.jsonl"
LLM_DISPATCH_TRACE = RUN_LOGS / "phase3.3-llm-dispatch-multi.jsonl"
PRECISION_SUMMARY = RUN_LOGS / "phase3.3-precision-summary.json"

_DECISIVE = {"confirmed", "refuted", "proved_safe", "bmc_unsafe", "candidate"}


def _precision_rollup() -> MetricRow:
    if not PRECISION_SUMMARY.exists():
        return make_row(
            adapter="router_llm", target="precision-rollup", status="not_setup", phase="3.3",
            success=False,
            notes=("LLM-router precision corpus not run yet — execute "
                   "`python3 -m eval.precision.run --dispatcher llm "
                   "--traces run-logs/phase3.3-precision-traces.jsonl "
                   "--summary run-logs/phase3.3-precision-summary.json`"),
        )
    s = json.loads(PRECISION_SUMMARY.read_text())
    fc = s.get("false_confirmations", 0)
    missed = s.get("determinism", {}).get("buggy_missed", 0)
    sv = len(s.get("soundness_violations", []))
    ok = (fc == 0 and missed == 0 and sv == 0)
    notes = (f"matches={s.get('matches')}/{s.get('n_hypotheses')} "
             f"precision={s.get('precision_of_confirmation')} "
             f"recall={s.get('recall_of_confirmation')} "
             f"false_conf={fc} soundness_viol={sv} buggy_missed={missed} "
             f"wall={s.get('corpus_wall_s')}s")
    return make_row(
        adapter="router_llm", target="precision-rollup", phase="3.3",
        status="success" if ok else "fail", success=ok,
        verdict="all-match" if ok else "mismatch",
        notes=notes,
        evidence_paths=[str(PRECISION_SUMMARY.relative_to(REPO_ROOT))],
    )


def _multi_smoke_rows() -> list[MetricRow]:
    if not LLM_ROUTE_TRACE.exists() or not LLM_DISPATCH_TRACE.exists():
        return [make_row(
            adapter="router_llm", target="multi-smoke", status="not_setup", phase="3.3",
            success=False,
            notes=("LLM-router multi-tier smoke not run yet — execute "
                   "`python3 -m agent.router --hypotheses agent/smoke/hypotheses_multi.json "
                   "--out run-logs/phase3.3-router-llm-multi.jsonl --dispatcher llm "
                   "--dispatch-trace run-logs/phase3.3-llm-dispatch-multi.jsonl`"),
        )]
    routes = [json.loads(l) for l in LLM_ROUTE_TRACE.read_text().splitlines() if l.strip()]
    dispatches = {json.loads(l)["hid"]: json.loads(l)
                  for l in LLM_DISPATCH_TRACE.read_text().splitlines() if l.strip()}
    rows: list[MetricRow] = []
    for r in routes:
        hid = r["hypothesis_id"]
        d = dispatches.get(hid, {})
        final = r["final_verdict"]
        ok = final in _DECISIVE
        per_tier: dict[str, float | None] = {"tier1": None, "tier2": None, "tier3": None}
        for a in r.get("attempts", []):
            bucket = {"tier1_fuzz": "tier1", "tier2_symbolic": "tier2",
                      "tier3_bmc": "tier3"}.get(a["tier"])
            if bucket is None:
                continue
            per_tier[bucket] = (per_tier[bucket] or 0.0) + (a.get("wall_ms") or 0) / 1000.0
        notes = (f"used_llm={d.get('used_llm')} proposal={d.get('proposal')} "
                 f"reason={d.get('reason','')!r} verdict={final} "
                 f"cost={r.get('total_cost')} wall_ms={r.get('total_wall_ms')}")
        rows.append(make_row(
            adapter="router_llm", target=hid, phase="3.3",
            status="success" if ok else ("not_setup" if final == "no_dispatch" else "fail"),
            success=ok, verdict=final,
            tokens_used=int(d.get("tokens") or 0),
            per_tier_latency_s=per_tier,
            notes=notes,
            evidence_paths=[str(LLM_ROUTE_TRACE.relative_to(REPO_ROOT)),
                            str(LLM_DISPATCH_TRACE.relative_to(REPO_ROOT))],
        ))
    return rows


def baseline_rows() -> list[MetricRow]:
    return [_precision_rollup()] + _multi_smoke_rows()
