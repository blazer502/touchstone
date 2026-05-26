"""Phase 3.4 — headline CyberGym ablation driver.

Runs the same CyberGym task through two arms (PLAN §5c.D3):

  * **baseline**     : random byte candidates, no scoping, no LLM
  * **accelerated**  : LLM-guided seeds (description + sanitizer hint) on the
                       same submit path; falls back to a deterministic
                       structured-byte bank when the gateway is down

Per arm: generate K candidates, run each against the task's vul image via the
Phase-2.1 `replay_docker` driver (sound oracle, sanitizer-verified), and on
crash, apply CyberGym's binary scoring rule locally (vul crashes ∧ fix clean).
Patch isolation is structural (`adapter.score_local` is the only call site
that opens `image_fix`).

Two artifacts per run:

  run-logs/phase3.4-<task>-<arm>-trace.jsonl   # per-candidate trace
  run-logs/phase3.4-<task>-summary.json        # per-task arm comparison

A roll-up across all tasks is written to run-logs/phase3.4-ablation.json so
the metrics adapter can pick it up.

Usage:
    python3 -m eval.cybergym.run_ablation \\
        --tasks arvo:1065 [arvo:368 ...] \\
        --budget 12 \\
        --out-root run-logs

If --tasks is omitted, runs every task in subset.json whose data dir is on disk.
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

from . import adapter
from . import seed_generators as seeds


REPO_ROOT = Path(__file__).resolve().parents[2]
log = logging.getLogger("ablation")


@dataclass
class CandidateRecord:
    arm: str
    unit_tag: str
    bytes_hex: str
    crashed: bool
    vul_verdict: str
    crash_class: Optional[str]
    location: Optional[str]
    wall_ms: int


@dataclass
class ArmResult:
    arm: str
    task_id: str
    candidates_tried: int
    crashes_local: int
    confirmed: bool
    first_crash_index: Optional[int]
    first_crash_wall_ms_cumulative: Optional[int]
    total_wall_ms: int
    tokens_used: int
    llm_calls: int
    llm_failed: bool
    score_local: Optional[dict] = None
    notes: str = ""
    trace_path: Optional[str] = None
    candidates: list[CandidateRecord] = field(default_factory=list)


def _run_arm(bundle: adapter.TaskBundle, arm: str, budget: int,
             vul_timeout: int, out_trace: Path) -> ArmResult:
    if arm == "baseline":
        gen = seeds.RandomSeedGenerator()
    else:
        gen = seeds.LLMGuidedSeedGenerator(
            description=bundle.description,
            sanitizer_hint=bundle.sanitizer_hint,
        )
    result = ArmResult(
        arm=arm, task_id=bundle.task_id,
        candidates_tried=0, crashes_local=0, confirmed=False,
        first_crash_index=None, first_crash_wall_ms_cumulative=None,
        total_wall_ms=0, tokens_used=0, llm_calls=0, llm_failed=False,
        trace_path=str(out_trace),
    )
    out_trace.parent.mkdir(parents=True, exist_ok=True)
    cumulative_ms = 0
    with out_trace.open("w") as fh:
        for i, (tag, blob) in enumerate(gen.iter_seeds(budget)):
            verdict = adapter.try_candidate(
                bundle, blob, unit_tag=f"{arm}-{tag}",
                timeout_seconds=vul_timeout,
            )
            cumulative_ms += verdict.wall_ms
            rec = CandidateRecord(
                arm=arm, unit_tag=f"{arm}-{tag}",
                bytes_hex=blob.hex()[:512],
                crashed=(verdict.verdict == "crash"),
                vul_verdict=verdict.verdict,
                crash_class=verdict.crash_class,
                location=verdict.location,
                wall_ms=verdict.wall_ms,
            )
            fh.write(json.dumps(asdict(rec)) + "\n")
            fh.flush()
            result.candidates.append(rec)
            result.candidates_tried += 1
            if rec.crashed:
                result.crashes_local += 1
                if result.first_crash_index is None:
                    result.first_crash_index = i
                    result.first_crash_wall_ms_cumulative = cumulative_ms
                # Stop at first crash — score binary, then we're done.
                log.info("[%s/%s] crash on candidate %s (%s @ %s)",
                         bundle.task_id, arm, tag, verdict.crash_class, verdict.location)
                break
            log.info("[%s/%s] cand %d/%d no_crash (%d ms)",
                     bundle.task_id, arm, i + 1, budget, verdict.wall_ms)
    result.total_wall_ms = cumulative_ms
    # Pull token/LLM stats from the generator (only the LLM arm tracks them).
    result.tokens_used = getattr(gen, "tokens_used", 0)
    result.llm_calls = getattr(gen, "llm_calls", 0)
    result.llm_failed = getattr(gen, "llm_failed", False)
    if result.llm_failed:
        result.notes = f"llm-fallback: {getattr(gen, 'last_error', '')}"
    # Binary scoring (vul ∧ ¬fix) only when something crashed locally.
    if result.crashes_local > 0:
        winning = next(c for c in result.candidates if c.crashed)
        winning_bytes = bytes.fromhex(winning.bytes_hex)
        score = adapter.score_local(bundle, winning_bytes,
                                    vul_timeout=vul_timeout, fix_timeout=vul_timeout)
        result.score_local = score
        result.confirmed = score["success"]
    return result


def run_task(task_id: str, budget: int, vul_timeout: int, out_root: Path) -> dict:
    bundle = adapter.resolve(task_id)
    safe_id = task_id.replace(":", "_")
    base_trace = lambda arm: out_root / f"phase3.4-{safe_id}-{arm}-trace.jsonl"
    log.info("=== task %s : budget=%d, sanitizer_hint=%s ===",
             task_id, budget, bundle.sanitizer_hint)
    t0 = time.monotonic()
    baseline = _run_arm(bundle, "baseline", budget, vul_timeout, base_trace("baseline"))
    accelerated = _run_arm(bundle, "accelerated", budget, vul_timeout, base_trace("accelerated"))
    wall_total = int((time.monotonic() - t0) * 1000)
    summary = {
        "task_id": task_id,
        "budget_candidates": budget,
        "sanitizer_hint": bundle.sanitizer_hint,
        "description": bundle.description,
        "image_vul": bundle.image_vul,
        "image_fix": bundle.image_fix,
        "wall_ms_total": wall_total,
        "arms": {
            "baseline": _summarize(baseline),
            "accelerated": _summarize(accelerated),
        },
        "delta": _delta(baseline, accelerated),
    }
    summary_path = out_root / f"phase3.4-{safe_id}-summary.json"
    summary_path.write_text(json.dumps(summary, indent=2))
    log.info("[%s] summary → %s", task_id, summary_path)
    return summary


def _summarize(r: ArmResult) -> dict:
    return {
        "arm": r.arm,
        "candidates_tried": r.candidates_tried,
        "crashes_local": r.crashes_local,
        "confirmed_binary_score": r.confirmed,
        "first_crash_index": r.first_crash_index,
        "first_crash_wall_ms_cumulative": r.first_crash_wall_ms_cumulative,
        "total_wall_ms": r.total_wall_ms,
        "tokens_used": r.tokens_used,
        "llm_calls": r.llm_calls,
        "llm_failed": r.llm_failed,
        "notes": r.notes,
        "trace_path": r.trace_path,
        "score_local": r.score_local,
    }


def _delta(baseline: ArmResult, accelerated: ArmResult) -> dict:
    """Headline deltas — what we report for the Phase 3.4 ablation."""
    def _delta_idx(a, b):
        if a is None and b is None: return None
        if a is None: return -b
        if b is None: return a
        return a - b
    return {
        "confirmed_baseline": baseline.confirmed,
        "confirmed_accelerated": accelerated.confirmed,
        "tokens_cost_accelerated": accelerated.tokens_used,
        "first_crash_cand_delta": _delta_idx(baseline.first_crash_index, accelerated.first_crash_index),
        "wall_ms_delta": baseline.total_wall_ms - accelerated.total_wall_ms,
    }


def _rollup(results: list[dict]) -> dict:
    n = len(results)
    base_conf = sum(1 for r in results if r["arms"]["baseline"]["confirmed_binary_score"])
    acc_conf = sum(1 for r in results if r["arms"]["accelerated"]["confirmed_binary_score"])
    tok = sum(r["arms"]["accelerated"]["tokens_used"] for r in results)
    base_wall = sum(r["arms"]["baseline"]["total_wall_ms"] for r in results)
    acc_wall = sum(r["arms"]["accelerated"]["total_wall_ms"] for r in results)
    return {
        "tasks_run": n,
        "baseline_confirmed": base_conf,
        "accelerated_confirmed": acc_conf,
        "headline_delta_confirmed": acc_conf - base_conf,
        "accelerated_tokens_used": tok,
        "baseline_wall_ms_total": base_wall,
        "accelerated_wall_ms_total": acc_wall,
        "per_task": [
            {
                "task_id": r["task_id"],
                "baseline_confirmed": r["arms"]["baseline"]["confirmed_binary_score"],
                "accelerated_confirmed": r["arms"]["accelerated"]["confirmed_binary_score"],
                "baseline_first_crash_idx": r["arms"]["baseline"]["first_crash_index"],
                "accelerated_first_crash_idx": r["arms"]["accelerated"]["first_crash_index"],
                "tokens_used": r["arms"]["accelerated"]["tokens_used"],
                "wall_ms_baseline": r["arms"]["baseline"]["total_wall_ms"],
                "wall_ms_accelerated": r["arms"]["accelerated"]["total_wall_ms"],
            }
            for r in results
        ],
    }


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Phase 3.4 CyberGym ablation")
    ap.add_argument("--tasks", nargs="*", default=None,
                    help="Task ids (e.g. arvo:1065). Default: all on-disk tasks.")
    ap.add_argument("--budget", type=int, default=12,
                    help="Candidate inputs per arm. Default 12.")
    ap.add_argument("--vul-timeout", type=int, default=30,
                    help="Per-candidate vul-image timeout (seconds). Default 30.")
    ap.add_argument("--out-root", default=str(REPO_ROOT / "run-logs"),
                    help="Where to write per-task and rollup artifacts.")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")

    out_root = Path(args.out_root)
    out_root.mkdir(parents=True, exist_ok=True)
    tasks = args.tasks or adapter.available_tasks()
    if not tasks:
        log.error("no tasks resolvable; populate eval/cybergym/data/<type>/<id>/")
        return 2

    results: list[dict] = []
    for tid in tasks:
        try:
            summary = run_task(tid, args.budget, args.vul_timeout, out_root)
        except Exception as e:
            log.exception("[%s] failed: %s", tid, e)
            summary = {"task_id": tid, "error": str(e)}
        results.append(summary)

    rollup = {
        "ts_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "budget_candidates": args.budget,
        "vul_timeout_s": args.vul_timeout,
        "results": results,
        "rollup": _rollup([r for r in results if "error" not in r]),
    }
    out = out_root / "phase3.4-ablation.json"
    out.write_text(json.dumps(rollup, indent=2))
    log.info("rollup → %s", out)
    print(json.dumps(rollup["rollup"], indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
