"""Phase 3.1 — LLM-synthesized Stage-B contract refinement results.

Reads `run-logs/phase3.1-synth-smoke.json` produced by:
    python3 -m surface.stage_b_refine_cli \
        --manifest surface/smoke/synth_manifest.json \
        --out run-logs/phase3.1-synth-smoke.json

Records one rollup row + one row per refined unit (baseline → final verdict,
contracts accumulated, tokens used). The headline number is `improved_units`:
how many units were *flipped* from unsafe/inconclusive to safe by the
synthesizer, with `soundness_failures==0` as the gate.
"""
from __future__ import annotations

import json
from pathlib import Path

from ..metrics import MetricRow, make_row, REPO_ROOT

RESULT_JSON = REPO_ROOT / "run-logs" / "phase3.1-synth-smoke.json"


def _rollup(d: dict) -> MetricRow:
    counts = d.get("counts", {})
    improved = int(d.get("improved_units", 0))
    sf = len(d.get("soundness_failures", []))
    safe = counts.get("safe", 0)
    unsafe = counts.get("unsafe", 0)
    inconc = counts.get("inconclusive", 0)
    tokens = int(d.get("synth_tokens_total", 0))
    success = sf == 0 and improved >= 1
    return make_row(
        adapter="contract-synth",
        target=d.get("target", "stage_b-phase3.1-synth-smoke"),
        status="success" if success else ("fail" if sf else "partial"),
        phase="3.1",
        success=success,
        verdict="improvement" if improved else "no-change",
        notes=(
            f"refinement-loop: safe={safe} unsafe={unsafe} inconc={inconc} "
            f"improved={improved} soundness_failures={sf} synth_tokens={tokens}"
        ),
        tokens_used=tokens,
        evidence_paths=[str(RESULT_JSON.relative_to(REPO_ROOT))],
    )


def _unit_row(r: dict) -> MetricRow:
    baseline = r.get("baseline_verdict", "?")
    final = r.get("verdict", "?")
    improved = baseline != final and final == "safe"
    contracts = r.get("accumulated_contracts", [])
    tokens = int(r.get("synth_tokens", 0))
    return make_row(
        adapter="contract-synth",
        target=r.get("unit", "?"),
        status="success" if improved else "neutral",
        phase="3.1",
        success=improved,
        verdict=f"{baseline}->{final}",
        notes=(
            f"contracts={contracts} tokens={tokens} "
            f"iters={len(r.get('refinement_history', []))-1}"
        ),
        tokens_used=tokens,
    )


def baseline_rows() -> list[MetricRow]:
    if not RESULT_JSON.exists():
        return [make_row(
            adapter="contract-synth", target="-", status="not_setup",
            phase="3.1", success=False,
            notes=(
                "run: python3 -m surface.stage_b_refine_cli "
                "--manifest surface/smoke/synth_manifest.json "
                "--out run-logs/phase3.1-synth-smoke.json"
            ),
        )]
    d = json.loads(RESULT_JSON.read_text())
    rows: list[MetricRow] = [_rollup(d)]
    for r in d.get("results", []):
        rows.append(_unit_row(r))
    return rows
