#!/usr/bin/env python3
"""Driver for Phase-3.1 contract refinement (LLM + rule fallback).

Usage:
  python3 -m surface.stage_b_refine_cli \\
      --manifest surface/smoke/synth_manifest.json \\
      --out run-logs/phase3.1-synth-smoke.json \\
      [--max-iters N] [--no-rule-fallback]

This is intentionally separate from `surface/stage_b.py`'s `run_manifest` (the
Phase-1.3 batch) so the no-LLM Phase-1 paths stay completely free of LLM
imports. The refinement driver imports the LLM client only here.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from surface import stage_b


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--manifest", required=True, type=Path)
    p.add_argument("--out", required=True, type=Path)
    p.add_argument("--max-iters", type=int, default=3)
    p.add_argument("--no-rule-fallback", action="store_true",
                   help="disable the deterministic rule fallback when the LLM is unreachable")
    args = p.parse_args()
    s = stage_b.refine_manifest(
        args.manifest, args.out,
        max_iters=args.max_iters,
        allow_rule_fallback=not args.no_rule_fallback,
    )
    c = s["counts"]
    print(
        f"refine: safe={c.get('safe',0)} unsafe={c.get('unsafe',0)} "
        f"inconclusive={c.get('inconclusive',0)} "
        f"improved={s['improved_units']} tokens={s['synth_tokens_total']} "
        f"soundness_failures={len(s['soundness_failures'])}"
    )
    return 1 if s["soundness_failures"] else 0


if __name__ == "__main__":
    sys.exit(main())
