"""Phase 3.2 — LLM-synthesized Tier-1/2/3 harness/driver/assertion smokes.

Reads ``run-logs/phase3.2-synth-smoke.json`` produced by:
    python3 oracle/smoke/run_harness_synth.py \
        --out run-logs/phase3.2-synth-smoke.json

Emits one rollup row + one row per tier (Tier-1 libFuzzer / Tier-2 KLEE /
Tier-3 CBMC), capturing which synth_source was used (`llm` vs `rule`) and
whether the verdict matched the expected one.
"""
from __future__ import annotations

import json

from ..metrics import MetricRow, make_row, REPO_ROOT

RESULT_JSON = REPO_ROOT / "run-logs" / "phase3.2-synth-smoke.json"


def _rollup(d: dict) -> MetricRow:
    counts = d.get("counts", {})
    success = int(counts.get("success", 0))
    total = int(counts.get("total", 0))
    tokens = int(d.get("synth_tokens_total", 0))
    ok = total > 0 and success == total
    sources = ",".join(d.get("synth_sources", []) or [])
    return make_row(
        adapter="oracle-synth",
        target="phase3.2-tier1+tier2+tier3-synth",
        status="success" if ok else ("partial" if success else "fail"),
        phase="3.2",
        success=ok,
        verdict=f"{success}/{total}",
        notes=(
            f"synth-smoke: {success}/{total} match expected verdict "
            f"(sources={sources}, synth_tokens={tokens})"
        ),
        tokens_used=tokens,
        evidence_paths=[str(RESULT_JSON.relative_to(REPO_ROOT))],
    )


def _run_row(r: dict) -> MetricRow:
    tier = r.get("tier", "?")
    expected = r.get("expected_verdict", "?")
    got = r.get("verdict", "?")
    ok = bool(r.get("success"))
    src = r.get("synth_source", "?")
    rej = r.get("rejected_reason")
    tokens = int(r.get("synth_tokens") or 0)
    notes_parts = [
        f"synth_source={src}",
        f"expected={expected}",
        f"got={got}",
        f"wall_ms={r.get('wall_ms', 0)}",
        f"synth_tokens={tokens}",
    ]
    if rej:
        notes_parts.append(f"rejected_reason={rej}")
    if r.get("crash_class"):
        notes_parts.append(f"crash_class={r['crash_class']}")
    if r.get("target_location"):
        notes_parts.append(f"loc={r['target_location']}")
    return make_row(
        adapter="oracle-synth",
        target=f"{tier}::phase3.2",
        status="success" if ok else "fail",
        phase="3.2",
        success=ok,
        verdict=f"{expected}->{got}",
        notes=" ".join(notes_parts),
        tokens_used=tokens,
    )


def baseline_rows() -> list[MetricRow]:
    if not RESULT_JSON.exists():
        return [make_row(
            adapter="oracle-synth", target="-", status="not_setup",
            phase="3.2", success=False,
            notes=(
                "run: python3 oracle/smoke/run_harness_synth.py "
                "--out run-logs/phase3.2-synth-smoke.json"
            ),
        )]
    d = json.loads(RESULT_JSON.read_text())
    rows: list[MetricRow] = [_rollup(d)]
    for r in d.get("runs", []):
        rows.append(_run_row(r))
    return rows
