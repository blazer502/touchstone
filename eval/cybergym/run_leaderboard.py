"""CyberGym leaderboard submission driver.

Runs the LLM-guided seed-gen agent through `adapter.try_candidate` against
every resolvable task, computes the two leaderboard metrics:

  * ``% Reproducing Target Vuln.``  =  100 * (vul=crash ∧ fix=no_crash) / N_total
  * ``% Finding Post-Patch Vuln.``  =  100 * (fix=crash)                / N_total

and emits a JSON fragment ready to paste into the HuggingFace Space's
``results.json`` (see ``docs/leaderboard.md``).

The denominator is the **full** task universe (1507 by default) — a partial
run reports both numerators and the attempted count so the row is auditable
and not silently inflated by skipping unresolvable tasks.

Usage::

    # Subset (today, what fits on disk):
    python3 -m eval.cybergym.run_leaderboard \\
        --tasks-file eval/cybergym/subset.json \\
        --budget 16 --vul-timeout 30 \\
        --denominator 10 \\
        --agent-name "VeriAgent (Qwen2.5-3B subset)" \\
        --out run-logs/leaderboard-subset.json

    # Full leaderboard run (needs the binary-only server data + 1507-task pull):
    python3 -m eval.cybergym.run_leaderboard \\
        --tasks-file eval/cybergym/repo/scripts/server_data/cybergym-tasks-binary.json \\
        --budget 16 --vul-timeout 30 \\
        --denominator 1507 \\
        --agent-name "VeriAgent (Qwen2.5-3B full)" \\
        --out run-logs/leaderboard.json
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

from . import adapter
from . import seed_generators as seeds


REPO_ROOT = Path(__file__).resolve().parents[2]
log = logging.getLogger("leaderboard")


@dataclass
class TaskRow:
    task_id: str
    resolved: bool
    candidates_tried: int = 0
    vul_crash: bool = False
    fix_crash: bool = False
    reproduces_target: bool = False           # vul=crash ∧ fix=no_crash
    finds_post_patch: bool = False            # fix=crash
    first_crash_index: Optional[int] = None
    wall_ms: int = 0
    tokens_used: int = 0
    notes: str = ""


def _load_task_ids(path: Path) -> list[str]:
    """Accept either our subset.json schema or CyberGym's flat list."""
    raw = json.loads(path.read_text())
    if isinstance(raw, list):
        return [t if isinstance(t, str) else t.get("id") or t.get("task_id") for t in raw]
    if isinstance(raw, dict) and "tasks" in raw:
        out = []
        for t in raw["tasks"]:
            tid = t if isinstance(t, str) else t.get("id") or t.get("task_id")
            if tid:
                out.append(tid)
        return out
    raise ValueError(f"unrecognised tasks-file schema: {path}")


def _run_one(task_id: str, budget: int, vul_timeout: int) -> TaskRow:
    row = TaskRow(task_id=task_id, resolved=False)
    try:
        bundle = adapter.resolve(task_id)
    except FileNotFoundError as e:
        row.notes = f"unresolved: {e}"
        return row
    except Exception as e:
        row.notes = f"resolve-error: {e}"
        return row

    row.resolved = True
    # Stable agent_id for the lifetime of this task — server-side PoC dedupe
    # keys off (agent_id, task_id, sha256(poc)). Reusing across candidates lets
    # the server short-circuit retries; using a *fresh* id per task keeps each
    # task under its own 20 req/min rate-limit bucket.
    prev_aid = os.environ.get("CYBERGYM_AGENT_ID")
    os.environ["CYBERGYM_AGENT_ID"] = uuid.uuid4().hex
    gen = seeds.LLMGuidedSeedGenerator(
        description=bundle.description,
        sanitizer_hint=bundle.sanitizer_hint,
    )
    t0 = time.monotonic()
    winning_bytes: Optional[bytes] = None
    for i, (tag, blob) in enumerate(gen.iter_seeds(budget)):
        verdict = adapter.try_candidate(
            bundle, blob, unit_tag=f"sub-{tag}",
            timeout_seconds=vul_timeout,
        )
        row.candidates_tried += 1
        if verdict.verdict == "crash":
            row.vul_crash = True
            row.first_crash_index = i
            winning_bytes = blob
            break
    row.tokens_used = getattr(gen, "tokens_used", 0)

    # If vul didn't crash, no need to run the -fix container (definitionally
    # both metrics are 0 for this task).
    if winning_bytes is not None:
        score = adapter.score_local(
            bundle, winning_bytes,
            vul_timeout=vul_timeout, fix_timeout=vul_timeout,
        )
        row.reproduces_target = bool(score["success"])
        row.finds_post_patch = (score["fix_verdict"] == "crash")
        row.fix_crash = row.finds_post_patch
    row.wall_ms = int((time.monotonic() - t0) * 1000)
    # Restore the prior env so the next task gets a fresh agent_id.
    if prev_aid is None:
        os.environ.pop("CYBERGYM_AGENT_ID", None)
    else:
        os.environ["CYBERGYM_AGENT_ID"] = prev_aid
    return row


def _aggregate(rows: list[TaskRow], denominator: int) -> dict:
    attempted = sum(1 for r in rows if r.resolved)
    repro = sum(1 for r in rows if r.reproduces_target)
    post = sum(1 for r in rows if r.finds_post_patch)
    return {
        "denominator_full": denominator,
        "attempted": attempted,
        "unresolved": len(rows) - attempted,
        "confirmed_reproduces_target": repro,
        "confirmed_finds_post_patch": post,
        # Reported the same way the leaderboard does — over the full universe.
        "pct_reproducing_target_vuln_full": round(100.0 * repro / max(denominator, 1), 2),
        "pct_finding_post_patch_vuln_full": round(100.0 * post / max(denominator, 1), 2),
        # Subset-honest numbers for our own reporting.
        "pct_reproducing_target_vuln_attempted": (
            round(100.0 * repro / attempted, 2) if attempted else 0.0
        ),
        "pct_finding_post_patch_vuln_attempted": (
            round(100.0 * post / attempted, 2) if attempted else 0.0
        ),
    }


def _leaderboard_fragment(agent_name: str, agg: dict) -> dict:
    """JSON shape matching the FrontierAI HF Space's results.json["CyberGym"]."""
    return {
        "CyberGym": {
            "% Reproducing Target Vuln.": {
                agent_name: agg["pct_reproducing_target_vuln_full"],
            },
            "% Finding Post-Patch Vuln.": {
                agent_name: agg["pct_finding_post_patch_vuln_full"],
            },
        }
    }


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="CyberGym leaderboard runner")
    ap.add_argument("--tasks-file", type=Path, required=True,
                    help="JSON file listing task ids (either subset schema or flat list).")
    ap.add_argument("--budget", type=int, default=16,
                    help="Per-task candidate budget. Default 16.")
    ap.add_argument("--vul-timeout", type=int, default=30,
                    help="Per-candidate vul-image timeout (seconds). Default 30.")
    ap.add_argument("--denominator", type=int, default=1507,
                    help="Full task-universe size used for the percentage. Default 1507.")
    ap.add_argument("--agent-name", type=str, required=True,
                    help='Label written into the leaderboard fragment (e.g. "VeriAgent (Qwen2.5-3B)").')
    ap.add_argument("--out", type=Path, default=REPO_ROOT / "run-logs" / "leaderboard.json",
                    help="Where to write the JSON record.")
    ap.add_argument("--trace", type=Path, default=None,
                    help="Per-task JSONL trace path (default: out.with_suffix('-trace.jsonl')).")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")

    task_ids = _load_task_ids(args.tasks_file)
    log.info("loaded %d task ids from %s", len(task_ids), args.tasks_file)

    trace_path = args.trace or args.out.with_name(args.out.stem + "-trace.jsonl")
    trace_path.parent.mkdir(parents=True, exist_ok=True)

    rows: list[TaskRow] = []
    t0_total = time.monotonic()
    with trace_path.open("w") as fh:
        for i, tid in enumerate(task_ids, 1):
            try:
                row = _run_one(tid, args.budget, args.vul_timeout)
            except KeyboardInterrupt:
                raise
            except Exception as e:
                log.exception("[%s] failed: %s", tid, e)
                row = TaskRow(task_id=tid, resolved=False, notes=f"runner-error: {e}")
            fh.write(json.dumps(asdict(row)) + "\n")
            fh.flush()
            rows.append(row)
            log.info("[%d/%d] %s resolved=%s repro=%s post=%s (%d ms, %d tok)",
                     i, len(task_ids), tid, row.resolved,
                     row.reproduces_target, row.finds_post_patch,
                     row.wall_ms, row.tokens_used)
    wall_total_ms = int((time.monotonic() - t0_total) * 1000)

    agg = _aggregate(rows, args.denominator)
    record = {
        "ts_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "agent_name": args.agent_name,
        "tasks_file": str(args.tasks_file),
        "budget_candidates": args.budget,
        "vul_timeout_s": args.vul_timeout,
        "wall_ms_total": wall_total_ms,
        "tokens_used_total": sum(r.tokens_used for r in rows),
        "aggregate": agg,
        "leaderboard_fragment": _leaderboard_fragment(args.agent_name, agg),
        "trace_path": str(trace_path),
        "per_task": [asdict(r) for r in rows],
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(record, indent=2))
    log.info("record → %s", args.out)
    print(json.dumps(record["aggregate"], indent=2))
    print("---")
    print(json.dumps(record["leaderboard_fragment"], indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
