"""Fast parallel CyberGym Level-1 evaluation harness.

The measurement workhorse for the 88% push. For each task in a subset manifest
it runs the agent (`agent.cybergym_agent.run_agent`) and records whether the
produced PoC reproduces the target vuln, scoring through the NATIVE server-data
binaries (no docker, no server, byte-identical to the scoring server). Tasks
run in a process pool across the host's cores.

Level-1 honesty: sets CYBERGYM_LEVEL=1 so the Task interface withholds
error.txt / patch.diff regardless of what is on disk.

Usage:
    python3 -m eval.cybergym.run_level1 \
        --subset eval/cybergym/subset_l1_100.json \
        --workers 20 --libfuzzer-seconds 10 --libfuzzer-budget-max 30 \
        --max-turns 0 \
        --out run-logs/l1-baseline.json
"""
from __future__ import annotations

import argparse
import json
import os
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import asdict
from pathlib import Path
from typing import Optional

REPO_ROOT = Path(__file__).resolve().parents[2]

# Default data locations (the full 1507-task assets live off-repo on the NVMe).
os.environ.setdefault("CYBERGYM_DATA_DIR",
                      "/mnt/data/chanyoung/cybergym/cybergym_data/data")
os.environ.setdefault("CYBERGYM_SERVER_DATA_DIR",
                      "/mnt/data/chanyoung/cybergym/cybergym-server-data")
os.environ["CYBERGYM_LEVEL"] = "1"


def _load_subset(path: Path) -> list[str]:
    raw = json.loads(path.read_text())
    if isinstance(raw, dict) and "tasks" in raw:
        return [t["id"] if isinstance(t, dict) else t for t in raw["tasks"]]
    if isinstance(raw, list):
        return [t["id"] if isinstance(t, dict) else t for t in raw]
    raise ValueError(f"unrecognised subset schema: {path}")


def _run_one(task_id: str, cfg_kw: dict) -> dict:
    """Worker entry — runs in a child process."""
    # Re-assert env in the child (ProcessPool may not inherit on spawn).
    os.environ.setdefault("CYBERGYM_DATA_DIR",
                          "/mnt/data/chanyoung/cybergym/cybergym_data/data")
    os.environ.setdefault("CYBERGYM_SERVER_DATA_DIR",
                          "/mnt/data/chanyoung/cybergym/cybergym-server-data")
    os.environ["CYBERGYM_LEVEL"] = "1"
    import logging
    logging.disable(logging.WARNING)
    from agent.cybergym_agent import run_agent, AgentConfig
    t0 = time.monotonic()
    try:
        cfg = AgentConfig(**cfg_kw)
        ar = run_agent(task_id, cfg)
        wall = int((time.monotonic() - t0) * 1000)
        if ar.error:
            return {"task_id": task_id, "resolved": False, "error": ar.error,
                    "wall_ms": wall}
        return {
            "task_id": task_id,
            "resolved": True,
            "reproduces_target": ar.confirmed_reproduces_target,
            "finds_post_patch": ar.confirmed_finds_post_patch,
            "winning_source": ar.winning_source,
            "candidates": len(ar.attempts),
            "tokens": ar.total_tokens,
            "wall_ms": ar.total_wall_ms or wall,
        }
    except Exception as e:
        return {"task_id": task_id, "resolved": False,
                "error": f"runner-exc: {e}", "wall_ms": int((time.monotonic()-t0)*1000)}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Parallel CyberGym Level-1 eval")
    ap.add_argument("--subset", type=Path,
                    default=REPO_ROOT / "eval" / "cybergym" / "subset_l1_100.json")
    ap.add_argument("--workers", type=int, default=min(20, (os.cpu_count() or 8)))
    ap.add_argument("--denominator", type=int, default=0,
                    help="Override denominator (default: number of tasks in subset).")
    # Agent config knobs (mapped onto AgentConfig).
    ap.add_argument("--max-turns", type=int, default=0,
                    help="LLM turns after bank+libfuzzer (0 = no LLM).")
    ap.add_argument("--bank-budget", type=int, default=12)
    ap.add_argument("--libfuzzer-seconds", type=int, default=10)
    ap.add_argument("--libfuzzer-adaptive", action="store_true", default=True)
    ap.add_argument("--no-adaptive", dest="libfuzzer_adaptive", action="store_false")
    ap.add_argument("--libfuzzer-budget-max", type=int, default=30)
    ap.add_argument("--libfuzzer-stagnation-window", type=int, default=4)
    ap.add_argument("--local-timeout-s", type=int, default=20)
    # Agentic PoC phase (smolagents open-model code-agent) on libFuzzer misses.
    ap.add_argument("--smol-agent", action="store_true", default=False)
    ap.add_argument("--smol-mode", choices=["agent", "seedgen"], default="agent")
    ap.add_argument("--smol-max-steps", type=int, default=6)
    ap.add_argument("--smol-no-analyst", dest="smol_use_analyst",
                    action="store_false", default=True)
    ap.add_argument("--smol-wall-s", type=int, default=240)
    ap.add_argument("--smol-fuzz-seconds", type=int, default=180)
    ap.add_argument("--oss-fuzz-corpus", dest="use_oss_fuzz_corpus",
                    action="store_true", default=False,
                    help="Seed libFuzzer with the project's public OSS-Fuzz corpus.")
    ap.add_argument("--out", type=Path,
                    default=REPO_ROOT / "run-logs" / "l1-eval.json")
    ap.add_argument("--label", type=str, default="l1-eval")
    args = ap.parse_args(argv)

    task_ids = _load_subset(args.subset)
    denom = args.denominator or len(task_ids)

    cfg_kw = dict(
        max_turns=args.max_turns,
        bank_budget=args.bank_budget,
        libfuzzer_seconds=args.libfuzzer_seconds,
        libfuzzer_adaptive=args.libfuzzer_adaptive,
        libfuzzer_budget_max=args.libfuzzer_budget_max,
        libfuzzer_stagnation_window=args.libfuzzer_stagnation_window,
        local_timeout_s=args.local_timeout_s,
        use_oss_fuzz_corpus=args.use_oss_fuzz_corpus,
        smol_agent=args.smol_agent,
        smol_mode=args.smol_mode,
        smol_max_steps=args.smol_max_steps,
        smol_use_analyst=args.smol_use_analyst,
        smol_wall_s=args.smol_wall_s,
        smol_fuzz_seconds=args.smol_fuzz_seconds,
    )

    print(f"[run_level1] {len(task_ids)} tasks, {args.workers} workers, "
          f"cfg={cfg_kw}")
    t0 = time.monotonic()
    rows: list[dict] = []
    done = 0
    with ProcessPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(_run_one, tid, cfg_kw): tid for tid in task_ids}
        for fut in as_completed(futs):
            row = fut.result()
            rows.append(row)
            done += 1
            mark = "✓" if row.get("reproduces_target") else (
                "·" if row.get("resolved") else "x")
            print(f"[{done}/{len(task_ids)}] {mark} {row['task_id']} "
                  f"repro={row.get('reproduces_target')} "
                  f"src={row.get('winning_source')} "
                  f"({row.get('wall_ms',0)}ms)", flush=True)
    wall_total = int((time.monotonic() - t0) * 1000)

    repro = sum(1 for r in rows if r.get("reproduces_target"))
    post = sum(1 for r in rows if r.get("finds_post_patch"))
    resolved = sum(1 for r in rows if r.get("resolved"))
    rec = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "label": args.label,
        "subset": str(args.subset),
        "level": 1,
        "cfg": cfg_kw,
        "workers": args.workers,
        "count": len(task_ids),
        "resolved": resolved,
        "denominator": denom,
        "reproduces_target": repro,
        "finds_post_patch": post,
        "pct_reproduces_target": round(100.0 * repro / max(denom, 1), 2),
        "pct_finds_post_patch": round(100.0 * post / max(denom, 1), 2),
        "wall_ms_total": wall_total,
        "rows": sorted(rows, key=lambda r: r["task_id"]),
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(rec, indent=2))
    print("=" * 60)
    print(f"REPRODUCE-TARGET: {repro}/{denom} = {rec['pct_reproduces_target']}%")
    print(f"POST-PATCH:       {post}/{denom} = {rec['pct_finds_post_patch']}%")
    print(f"resolved={resolved}/{len(task_ids)}  wall={wall_total/1000:.1f}s")
    print(f"record → {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
