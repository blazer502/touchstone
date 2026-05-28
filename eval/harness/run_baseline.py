#!/usr/bin/env python3
"""Phase 0.5 metrics harness — emits one JSONL row per adapter/target.

Run:  python3 -m eval.harness.run_baseline [--out PATH]

Reads existing Phase 0.2/0.3/0.4 evidence; no LLM and no tool execution. Writes:
  run-logs/phase0.5-baseline.jsonl   (one row per adapter/target)
  run-logs/phase0.5-baseline.json    (single-shot summary)
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys

# Ensure repo root is importable when run as `python3 eval/harness/run_baseline.py`.
_HERE = pathlib.Path(__file__).resolve()
sys.path.insert(0, str(_HERE.parents[2]))

from eval.harness.adapters import (  # noqa: E402
    agent_loop,
    contract_synth,
    cybergym,
    cybergym_ablation,
    end_to_end as e2e_adapter,
    exploit_triage as exploit_triage_adapter,
    juliet,
    kernelctf,
    kernelctf_live,
    live_lib,
    llm_serving,
    magma,
    oracle_synth,
    precision,
    reproducer as reproducer_adapter,
    router as router_adapter,
    router_llm as router_llm_adapter,
    specmine,
    svcomp,
    tier1_oracle,
    tier2_oracle,
    tier3_oracle,
)
from eval.harness.metrics import MetricWriter, REPO_ROOT  # noqa: E402

ADAPTERS = [
    ("cybergym", cybergym.baseline_rows),
    ("kernelctf", kernelctf.baseline_rows),
    ("llm-serving", llm_serving.baseline_rows),
    ("sv-comp", svcomp.baseline_rows),
    ("magma", magma.baseline_rows),
    ("juliet", juliet.baseline_rows),
    ("live-lib", live_lib.baseline_rows),
    ("tier1-oracle", tier1_oracle.baseline_rows),
    ("tier2-oracle", tier2_oracle.baseline_rows),
    ("tier3-oracle", tier3_oracle.baseline_rows),
    ("router", router_adapter.baseline_rows),
    ("router-llm", router_llm_adapter.baseline_rows),
    ("precision", precision.baseline_rows),
    ("contract-synth", contract_synth.baseline_rows),
    ("oracle-synth", oracle_synth.baseline_rows),
    ("cybergym-ablation", cybergym_ablation.baseline_rows),
    ("agent-loop", agent_loop.baseline_rows),
    ("kernelctf-live", kernelctf_live.baseline_rows),
    ("specmine", specmine.baseline_rows),
    ("reproducer", reproducer_adapter.baseline_rows),
    ("exploit-triage", exploit_triage_adapter.baseline_rows),
    ("end-to-end", e2e_adapter.baseline_rows),
]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(REPO_ROOT / "run-logs" / "phase0.5-baseline.jsonl"))
    ap.add_argument("--summary", default=str(REPO_ROOT / "run-logs" / "phase0.5-baseline.json"))
    args = ap.parse_args()

    out_path = pathlib.Path(args.out)
    # Truncate so re-runs don't accumulate stale rows.
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("")

    all_rows = []
    with MetricWriter(out_path) as w:
        for name, fn in ADAPTERS:
            try:
                rows = fn()
            except Exception as e:  # adapter must never break the whole run
                from eval.harness.metrics import make_row
                rows = [make_row(adapter=name, target="-", status="fail",
                                 notes=f"adapter exception: {e!r}")]
            for row in rows:
                w.write(row)
                all_rows.append(row.to_json())

    # Summary
    by_status: dict[str, int] = {}
    for r in all_rows:
        by_status[r["status"]] = by_status.get(r["status"], 0) + 1
    summary = {
        "phase": "0.5",
        "rows": len(all_rows),
        "by_status": by_status,
        "out_jsonl": str(out_path.relative_to(REPO_ROOT)),
        "adapters": sorted({r["adapter"] for r in all_rows}),
    }
    pathlib.Path(args.summary).write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
