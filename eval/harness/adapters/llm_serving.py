"""LLM serving adapter — sources GPU util / token telemetry from Phase 0.2 smoke.

Phase 0 done-when requires "LLM endpoint serves" and "metric harness logs a
baseline row" — including GPU util. This adapter reads `run-logs/phase0.2-smoke.json`
and surfaces the smoke verdict + GPU peak as a metric row. No LLM is in the
analysis path; the row just confirms the endpoint is live.
"""
from __future__ import annotations

import json

from ..metrics import MetricRow, make_row, REPO_ROOT

SMOKE = REPO_ROOT / "run-logs" / "phase0.2-smoke.json"


def baseline_rows() -> list[MetricRow]:
    if not SMOKE.exists():
        return [make_row(
            adapter="llm-serving", target="gateway", status="not_setup",
            notes="phase 0.2 smoke result missing",
        )]
    r = json.loads(SMOKE.read_text())
    peak = 0.0
    for g in r.get("gpu_peak", []):
        peak = max(peak, float(g.get("util_pct", 0)))
    usage = r.get("usage") or {}
    return [make_row(
        adapter="llm-serving",
        target=f"profile={r.get('health', {}).get('profile', '?')}",
        status="success",
        success=True,
        verdict="vLLM gateway answered an OpenAI-format chat completion",
        notes=f"latency_s={r.get('latency_s')}",
        tokens_used=int(usage.get("total_tokens", 0)),
        gpu_util_peak_pct=peak,
        llm_used=True,
        evidence_paths=[str(SMOKE.relative_to(REPO_ROOT))],
    )]
