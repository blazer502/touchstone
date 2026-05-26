#!/usr/bin/env python3
"""Phase 2.5 precision / latency / escalation measurement.

Reads `eval/precision/corpus.json` — a labeled hypothesis set — routes each
hypothesis through `agent.router.route(...)`, and reports:

- confusion: per-(expected_verdict, actual_verdict) counts.
- precision: (# correct "confirmation" verdicts) / (# verdicts in
  CONFIRMATION_SET emitted on ANY case). The CONFIRMATION_SET is
  {confirmed, bmc_unsafe} — verdicts that claim a runtime / bounded-sound
  bug witness. `candidate` is intentionally excluded: it is the explicit
  "symbolic SAT, needs Tier-1 reconfirm" verdict and never counts as a
  confirmation.
- false_confirmations: count of `clean`-labeled hypotheses where the
  router emitted a verdict in CONFIRMATION_SET. This is the Phase 2
  Done-when number — must be 0 for the "near-zero false confirmations"
  acceptance.
- per-tier latency: p50 / p95 / mean wall_ms across the attempts
  recorded in each trace (one tier may run multiple times across the
  corpus — we aggregate per (tier_name)).
- escalation: how often the router took >1 attempt before settling, and
  the most common escalation paths.

Outputs:
  run-logs/phase2.5-precision-traces.jsonl   (one row per hypothesis)
  run-logs/phase2.5-precision-summary.json   (aggregates)

No LLM. Reuses the Phase 2.1/2.2/2.3 drivers and the Phase 2.4 router.
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve()
sys.path.insert(0, str(_HERE.parents[2]))

from agent.router import route, _hyp_from_json, RouteTrace  # noqa: E402
from llm.budget import Budget  # noqa: E402

REPO = _HERE.parents[2]
DEFAULT_CORPUS = REPO / "eval" / "precision" / "corpus.json"
DEFAULT_TRACES = REPO / "run-logs" / "phase2.5-precision-traces.jsonl"
DEFAULT_SUMMARY = REPO / "run-logs" / "phase2.5-precision-summary.json"

# Verdicts that represent a *runtime / bounded-sound* bug witness.
CONFIRMATION_SET = {"confirmed", "bmc_unsafe"}
# `candidate` is explicitly informational — symbolic SAT pending Tier-1
# reconfirm. It is neither a confirmation nor a soundness violation.
INFORMATIONAL = {"candidate"}
NEGATIVE_VERDICTS = {"refuted", "proved_safe", "inconclusive", "no_dispatch"}


def _percentile(xs: list[int], p: float) -> float:
    if not xs:
        return 0.0
    xs = sorted(xs)
    if len(xs) == 1:
        return float(xs[0])
    k = (len(xs) - 1) * p
    f = int(k)
    c = min(f + 1, len(xs) - 1)
    return xs[f] + (xs[c] - xs[f]) * (k - f)


def run_corpus(corpus_path: Path, traces_path: Path, summary_path: Path) -> dict:
    data = json.loads(corpus_path.read_text())
    items = data["hypotheses"]
    budget = Budget.load()

    traces_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, Any]] = []

    print(f"[precision] routing {len(items)} hypotheses ...", file=sys.stderr)
    t_corpus = time.monotonic()
    with traces_path.open("w") as fh:
        for item in items:
            label = item.pop("label")
            hyp = _hyp_from_json(item)
            t0 = time.monotonic()
            try:
                tr: RouteTrace = route(hyp, budget=budget)
                error = None
            except Exception as e:
                tr = None
                error = repr(e)
            wall_ms = int((time.monotonic() - t0) * 1000)

            actual = tr.final_verdict if tr is not None else "error"
            expected = label["expected"]
            row = {
                "hid": item["hid"],
                "ground_truth": label["ground_truth"],
                "expected": expected,
                "actual": actual,
                "match": actual == expected,
                "decision_reason": tr.decision_reason if tr else error,
                "total_cost": tr.total_cost if tr else 0,
                "total_wall_ms": tr.total_wall_ms if tr else wall_ms,
                "wall_ms_outer": wall_ms,
                "pov_path": tr.pov_path if tr else None,
                "attempts": [a.to_dict() for a in tr.attempts] if tr else [],
                "error": error,
            }
            fh.write(json.dumps(row) + "\n")
            fh.flush()
            rows.append(row)

            tag = "OK " if row["match"] else "MIS"
            print(f"  [{tag}] {item['hid']:38s} expected={expected:14s} "
                  f"actual={actual:14s} wall_ms={wall_ms:6d}", file=sys.stderr)
    corpus_wall_s = time.monotonic() - t_corpus

    # --- aggregates -----------------------------------------------------------
    confusion: Counter = Counter()
    for r in rows:
        confusion[(r["expected"], r["actual"])] += 1

    # Precision of confirmation verdicts:
    #   precision = TP / (TP + FP)
    #   TP = ground_truth==buggy AND actual in CONFIRMATION_SET
    #   FP = ground_truth==clean AND actual in CONFIRMATION_SET
    tp = sum(1 for r in rows
             if r["ground_truth"] == "buggy" and r["actual"] in CONFIRMATION_SET)
    fp = sum(1 for r in rows
             if r["ground_truth"] == "clean" and r["actual"] in CONFIRMATION_SET)
    # Recall over the *positive* confirmation set: how many buggy cases
    # whose expected verdict was a confirmation actually got confirmed.
    confirm_expected_pos = sum(1 for r in rows
                               if r["ground_truth"] == "buggy"
                               and r["expected"] in CONFIRMATION_SET)
    confirm_actual_pos = sum(1 for r in rows
                             if r["ground_truth"] == "buggy"
                             and r["expected"] in CONFIRMATION_SET
                             and r["actual"] in CONFIRMATION_SET)
    precision = (tp / (tp + fp)) if (tp + fp) > 0 else None
    recall = (confirm_actual_pos / confirm_expected_pos
              if confirm_expected_pos > 0 else None)

    # Per-tier latency
    latencies: dict[str, list[int]] = defaultdict(list)
    for r in rows:
        for a in r["attempts"]:
            latencies[a["tier"]].append(int(a.get("wall_ms") or 0))
    latency_summary = {
        tier: {
            "n": len(xs),
            "mean_ms": (statistics.mean(xs) if xs else 0.0),
            "p50_ms": _percentile(xs, 0.50),
            "p95_ms": _percentile(xs, 0.95),
            "max_ms": (max(xs) if xs else 0),
        }
        for tier, xs in latencies.items()
    }

    # Escalation analysis
    escalated = sum(1 for r in rows if len(r["attempts"]) > 1)
    escalation_paths = Counter(
        " > ".join(a["tier"] for a in r["attempts"]) for r in rows if r["attempts"]
    )
    no_dispatch = sum(1 for r in rows if r["actual"] == "no_dispatch")

    # Deterministic-confirmation check (Phase 2 Done-when)
    determinism = {
        "buggy_total": sum(1 for r in rows if r["ground_truth"] == "buggy"),
        "buggy_confirmed_or_bmc_unsafe": sum(
            1 for r in rows if r["ground_truth"] == "buggy"
            and r["actual"] in CONFIRMATION_SET
        ),
        "buggy_candidate": sum(
            1 for r in rows if r["ground_truth"] == "buggy"
            and r["actual"] in INFORMATIONAL
        ),
        "buggy_missed": sum(
            1 for r in rows if r["ground_truth"] == "buggy"
            and r["actual"] in NEGATIVE_VERDICTS
        ),
    }
    soundness_violations = [
        {"hid": r["hid"], "expected": r["expected"], "actual": r["actual"]}
        for r in rows
        if r["ground_truth"] == "buggy" and r["actual"] == "proved_safe"
    ]

    summary = {
        "phase": "2.5",
        "corpus": str(corpus_path.relative_to(REPO)),
        "n_hypotheses": len(rows),
        "matches": sum(1 for r in rows if r["match"]),
        "mismatches": sum(1 for r in rows if not r["match"]),
        "corpus_wall_s": round(corpus_wall_s, 2),
        "confusion": [
            {"expected": k[0], "actual": k[1], "count": v}
            for k, v in sorted(confusion.items())
        ],
        "precision_of_confirmation": precision,
        "recall_of_confirmation": recall,
        "true_positives": tp,
        "false_positives": fp,
        "false_confirmations": fp,
        "determinism": determinism,
        "soundness_violations": soundness_violations,
        "per_tier_latency": latency_summary,
        "escalation": {
            "n_with_attempts": sum(1 for r in rows if r["attempts"]),
            "n_escalated": escalated,
            "escalation_rate": (
                escalated / sum(1 for r in rows if r["attempts"])
                if any(r["attempts"] for r in rows) else 0.0
            ),
            "paths": [
                {"path": p, "count": c} for p, c in escalation_paths.most_common()
            ],
            "no_dispatch": no_dispatch,
        },
        "traces": str(traces_path.relative_to(REPO)),
    }
    summary_path.write_text(json.dumps(summary, indent=2) + "\n")
    return summary


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    ap.add_argument("--traces", type=Path, default=DEFAULT_TRACES)
    ap.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    args = ap.parse_args()
    s = run_corpus(args.corpus, args.traces, args.summary)
    # Print headline numbers
    print()
    print(f"  matches              : {s['matches']}/{s['n_hypotheses']}")
    print(f"  precision (conf set) : {s['precision_of_confirmation']}")
    print(f"  recall    (conf set) : {s['recall_of_confirmation']}")
    print(f"  false_confirmations  : {s['false_confirmations']}")
    print(f"  buggy missed         : {s['determinism']['buggy_missed']}")
    print(f"  soundness violations : {len(s['soundness_violations'])}")
    print(f"  escalation rate      : {s['escalation']['escalation_rate']:.2%}")
    print(f"  wall (corpus)        : {s['corpus_wall_s']}s")
    print(f"  summary              : {args.summary}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
