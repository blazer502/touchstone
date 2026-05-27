"""Lift existing CyberGym confirms into Cex artifacts.

Reads `run-logs/leaderboard-{qwen3b,70b}-partial-summary.json` + the trace
JSONL, resolves each confirmed task back to its winning PoC bytes (re-running
the deterministic seed bank to recover the bytes — the trace doesn't persist
them), and emits one `Cex` per confirm.

Output: `run-logs/cex/cybergym/<task_id>.json` (disclosure blob) +
`run-logs/cex/cybergym/<task_id>.repro.sh` (regression bash).

Demonstrates the "same analysis, multiple projections" claim of P1.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path
from typing import Optional

from eval.cybergym import adapter, seed_generators
from oracle.tier1_fuzz.verdict import Tier1Verdict
from schemas.cex import Cex, from_tier1


log = logging.getLogger("lift_cybergym")
REPO_ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = REPO_ROOT / "run-logs" / "cex" / "cybergym"


def _winning_bytes_for(task_id: str, budget: int = 16) -> Optional[tuple[bytes, Tier1Verdict]]:
    """Re-run the deterministic bank against task_id; return (bytes, verdict) on
    the first crash within budget, or None if no candidate crashes.

    Bank-only (no LLM) by construction: we set GATEWAY_PORT=9 internally so the
    LLM half of the LLMGuidedSeedGenerator falls back; the bank's order is
    deterministic so the *same* candidate that crashed during the live eval
    crashes here.
    """
    os.environ.setdefault("GATEWAY_PORT", "9")
    try:
        bundle = adapter.resolve(task_id)
    except FileNotFoundError as e:
        log.warning("[%s] unresolved: %s", task_id, e)
        return None

    gen = seed_generators.LLMGuidedSeedGenerator(
        description=bundle.description,
        sanitizer_hint=bundle.sanitizer_hint,
    )
    for tag, blob in gen.iter_seeds(budget):
        verdict = adapter.try_candidate(
            bundle, blob, unit_tag=f"lift-{tag}", timeout_seconds=30,
        )
        if verdict.verdict == "crash":
            return blob, verdict
    return None


def lift_one(task_id: str, *, out_dir: Path = OUT_DIR, budget: int = 16) -> Optional[Cex]:
    res = _winning_bytes_for(task_id, budget=budget)
    if res is None:
        log.error("[%s] no crash within budget=%d", task_id, budget)
        return None
    blob, verdict = res
    # Canonical anchor ids from `docs/soundness-assumptions.md`. Validate via
    # `python3 -m schemas.soundness_ledger validate <files>`.
    cex = from_tier1(verdict, pov_bytes=blob,
                     soundness_anchor_ids=[
                         "oracle-tier-1-fast-crash/sanitizers-coverage-of-properties",
                     ])
    out_dir.mkdir(parents=True, exist_ok=True)
    safe = task_id.replace(":", "_")
    (out_dir / f"{safe}.json").write_text(cex.to_json())
    (out_dir / f"{safe}.repro.sh").write_text(cex.to_regression_test())
    log.info("[%s] %s @ %s, %d bytes -> %s",
             task_id, cex.violated.name, cex.violated.location,
             len(blob), out_dir / f"{safe}.json")
    return cex


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--tasks", nargs="*",
                    default=["arvo:1065", "arvo:67297", "arvo:3938",
                             "arvo:63314", "arvo:67552"],
                    help="Task ids to lift. Default: the 5 confirmed from leaderboard runs.")
    ap.add_argument("--budget", type=int, default=16)
    ap.add_argument("--out-dir", type=Path, default=OUT_DIR)
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")

    lifted = 0
    for tid in args.tasks:
        if lift_one(tid, out_dir=args.out_dir, budget=args.budget) is not None:
            lifted += 1
    log.info("lifted %d / %d", lifted, len(args.tasks))
    return 0 if lifted == len(args.tasks) else 1


if __name__ == "__main__":
    sys.exit(main())
