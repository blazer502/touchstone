"""Phase 4.3 adapter — live SQLite/OpenSSL/libxml2 hunt (PLAN §5b.B.5).

Reads:
- ``run-logs/phase4.3-summary.json``        — paired-control gate from
  ``eval/live-lib/run_phase43.py`` (libFuzzer+ASan against host libsqlite3
  3.37.2). PASS = control crashes ∧ live verdict ∈ {inconclusive, crash}.
- ``run-logs/phase4.3-live-lib-loop.jsonl`` — closed-loop wiring of the
  same harnesses through ``agent.loop`` (router → Tier-1 → disposition).
  PASS = L2 (positive control) `confirmed` ∧ L1 (live target) `inconclusive`
  (or `confirmed` if we struck a novel finding).

A ``novel_pov=True`` on the live target is reported but does NOT flip the
gate — it's a separate column the operator inspects.
"""
from __future__ import annotations

import json
from pathlib import Path

from ..metrics import MetricRow, make_row, REPO_ROOT

LIVE_DIR = REPO_ROOT / "eval" / "live-lib"
SUMMARY = REPO_ROOT / "run-logs" / "phase4.3-summary.json"
JSONL = REPO_ROOT / "run-logs" / "phase4.3-live-lib.jsonl"
LOOP = REPO_ROOT / "run-logs" / "phase4.3-live-lib-loop.jsonl"


def baseline_rows() -> list[MetricRow]:
    rows: list[MetricRow] = []

    # 1. Phase-4.3 driver gate (direct libFuzzer run, before the agent loop).
    if SUMMARY.exists() and JSONL.exists():
        summ = json.loads(SUMMARY.read_text())
        verdicts = [json.loads(l) for l in JSONL.read_text().splitlines() if l.strip()]
        ctrl = next((v for v in verdicts if v.get("role") == "positive_control"), None)
        live = next((v for v in verdicts if v.get("role") == "live_target"), None)

        if ctrl:
            rows.append(make_row(
                adapter="live-lib", target="sqlite3-synth-oob:positive-control",
                phase="4.3", status="success" if ctrl["verdict"] == "crash" else "fail",
                success=(ctrl["verdict"] == "crash"),
                verdict=ctrl["verdict"],
                notes=(f"libFuzzer+ASan ⇒ {ctrl.get('crash_class')} @ {ctrl.get('location')}; "
                       "harness links host libsqlite3 — toolchain validation."),
                per_tier_latency_s={"tier1": ctrl["wall_ms"] / 1000.0,
                                    "tier2": None, "tier3": None},
                evidence_paths=[str(JSONL.relative_to(REPO_ROOT))]
                                + ([ctrl["pov_path"]] if ctrl.get("pov_path") else []),
            ))
        if live:
            # `inconclusive` in a heavily-fuzzed library is the EXPECTED field outcome,
            # not a failure. Success-flag tracks the *gate*, not bug-presence.
            ok = (live["verdict"] in ("inconclusive", "crash"))
            verdict_note = ("no_crash within budget — realistic field outcome "
                            "(sqlite3 has been continuously fuzzed since 2016)") \
                if live["verdict"] == "inconclusive" \
                else f"NOVEL crash candidate: {live.get('crash_class')} @ {live.get('location')}"
            rows.append(make_row(
                adapter="live-lib", target="sqlite3-live-3.37.2",
                phase="4.3", status="success" if ok else "fail",
                success=ok, verdict=live["verdict"], notes=verdict_note,
                per_tier_latency_s={"tier1": live["wall_ms"] / 1000.0,
                                    "tier2": None, "tier3": None},
                evidence_paths=[str(JSONL.relative_to(REPO_ROOT))]
                                + ([live["pov_path"]] if live.get("pov_path") else []),
            ))
        rows.append(make_row(
            adapter="live-lib", target="phase4.3-gate",
            phase="4.3", status="success" if summ["gate"] == "pass" else "fail",
            success=(summ["gate"] == "pass"),
            verdict=f"ctrl={summ['control_verdict']},live={summ['live_verdict']},novel={summ['novel_pov']}",
            notes=("paired-control gate: control crashes (toolchain OK) AND live "
                   "verdict ∈ {inconclusive, crash}. novel_pov=True is reported "
                   "but does not gate."),
            evidence_paths=[str(SUMMARY.relative_to(REPO_ROOT))],
        ))
    else:
        rows.append(make_row(
            adapter="live-lib", target="-", phase="4.3", status="not_setup",
            success=False,
            notes=("Phase 4.3 not yet exercised — run "
                   "`python3 eval/live-lib/run_phase43.py`"),
        ))

    # 2. Closed-loop wiring (router → Tier-1 → disposition).
    if LOOP.exists():
        seen: dict[str, str] = {}
        for line in LOOP.read_text().splitlines():
            if not line.strip():
                continue
            r = json.loads(line)
            cid = r["candidate_id"]
            disp = r["decision"]["disposition"]
            wall = r.get("total_wall_ms", 0) / 1000.0
            seen[cid] = disp
            rows.append(make_row(
                adapter="live-lib", target=cid, phase="4.3",
                status="success", success=True, verdict=disp,
                notes=r["decision"]["reason"],
                per_tier_latency_s={"tier1": wall, "tier2": None, "tier3": None},
                evidence_paths=[str(LOOP.relative_to(REPO_ROOT))],
            ))
        l2_ok = seen.get("L2-sqlite3-synth-oob-positive-control") == "confirmed"
        l1_ok = seen.get("L1-sqlite3-live-3.37.2-hunt") in ("inconclusive", "confirmed")
        rollup_ok = l2_ok and l1_ok
        rows.append(make_row(
            adapter="live-lib", target="closed-loop-rollup", phase="4.3",
            status="success" if rollup_ok else "fail", success=rollup_ok,
            verdict=("L2=confirmed,L1=" + str(seen.get("L1-sqlite3-live-3.37.2-hunt", "?")))
                     if rollup_ok else f"L2={seen.get('L2-sqlite3-synth-oob-positive-control','?')},"
                                       f"L1={seen.get('L1-sqlite3-live-3.37.2-hunt','?')}",
            notes=("paired-control invariant: positive control confirms (toolchain "
                   "OK end-to-end through router/loop) AND live target remains "
                   "inconclusive (no_crash ≠ safe) or surfaces a novel finding."),
            evidence_paths=[str(LOOP.relative_to(REPO_ROOT))],
        ))
    else:
        rows.append(make_row(
            adapter="live-lib", target="closed-loop-wiring",
            phase="4.3", status="not_setup", success=False,
            notes=("closed-loop wiring not exercised — run "
                   "`python3 -m agent.loop --candidates "
                   "agent/smoke/candidates_live_lib.json --out "
                   "run-logs/phase4.3-live-lib-loop.jsonl`"),
        ))

    return rows
