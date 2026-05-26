"""Phase 3.2 smoke — synthesize Tier-1/2/3 harnesses with the LLM (rule fallback),
then validate each end-to-end through the real oracle.

Each smoke case:
  1. Builds a `TargetFunction` / `SymbolicTarget` / `BmcTarget` description,
  2. Calls the per-tier synthesizer (`oracle.tier1_fuzz.harness_synth.synthesize`,
     `oracle.tier2_symbolic.driver_synth.synthesize`,
     `oracle.tier3_bmc.harness_synth.synthesize` → `assertions.synthesize`),
  3. Writes the proposed C to a temp file,
  4. Runs the corresponding oracle driver (libFuzzer fuzz / KLEE run / CBMC run),
  5. Asserts the verdict matches the expected one.

Writes a JSON result to ``run-logs/phase3.2-synth-smoke.json``.
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Optional

# Repo root on sys.path so `python3 oracle/smoke/run_harness_synth.py` works.
_REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO))

from oracle.tier1_fuzz import harness_synth as t1_synth
from oracle.tier1_fuzz import userspace as t1_user
from oracle.tier2_symbolic import driver_synth as t2_synth
from oracle.tier2_symbolic import klee_driver as t2_klee
from oracle.tier3_bmc import harness_synth as t3_synth
from oracle.tier3_bmc import assertions as t3_assert
from oracle.tier3_bmc import cbmc_driver as t3_cbmc


# ----------------------------- Tier-1 case -----------------------------------

TIER1_TARGET = t1_synth.TargetFunction(
    name="oob_write",
    signature="void oob_write(const uint8_t *buf, size_t n)",
    source_snippet="""\
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

static void oob_write(const uint8_t *buf, size_t n) {
    /* Triggers heap-buffer-overflow when n > 16. */
    if (n < 17) return;
    char *p = (char *)malloc(16);
    if (!p) return;
    p[n - 1] = (char)buf[0];
    free(p);
}
""",
    bug_class_hint="memory",
    description=(
        "Function is a 1-byte heap write at offset n-1 into a 16-byte malloc. "
        "Bug triggers when caller passes n > 16."
    ),
)


def _run_tier1(out_dir: Path) -> dict:
    t0 = time.monotonic()
    r = t1_synth.synthesize(TIER1_TARGET)
    synth_ms = int((time.monotonic() - t0) * 1000)
    harness_path = out_dir / "tier1_oob_write.c"
    out: dict[str, Any] = {
        "tier": "tier1_fuzz",
        "synth_source": r.source,
        "synth_tokens": r.tokens_used,
        "synth_latency_ms": int(r.latency_s * 1000),
        "synth_total_ms": synth_ms,
        "rejected_reason": r.rejected_reason,
        "error": r.error,
        "harness_path": str(harness_path),
        "expected_verdict": "crash",
    }
    if not r.harness_c:
        out.update({"verdict": "synth_failed", "success": False})
        return out
    harness_path.write_text(r.harness_c)
    v = t1_user.fuzz(harness_path, sanitizer="ASan", wall_seconds=15,
                     unit=f"phase3.2-synth-{r.source}")
    out.update({
        "verdict": v.verdict,
        "crash_class": v.crash_class,
        "location": v.location,
        "wall_ms": v.wall_ms,
        "success": v.verdict == "crash",
    })
    return out


# ----------------------------- Tier-2 case -----------------------------------

TIER2_TARGET = t2_synth.SymbolicTarget(
    name="divide_by_zero",
    signature="int divide(int n, int d)",
    source_snippet="""\
static int divide(int n, int d) {
    /* KLEE: division by zero when d == 0. */
    return n / d;
}
""",
    property="div-by-zero",
    constraint_hints=None,  # let KLEE find d == 0 itself
    must_not_assume=["d"],  # block "helpful" klee_assume(d != 0)
    description="Classic div-by-zero on the second argument.",
)


def _run_tier2(out_dir: Path) -> dict:
    t0 = time.monotonic()
    r = t2_synth.synthesize(TIER2_TARGET)
    synth_ms = int((time.monotonic() - t0) * 1000)
    driver_path = out_dir / "tier2_divide.c"
    out: dict[str, Any] = {
        "tier": "tier2_symbolic",
        "synth_source": r.source,
        "synth_tokens": r.tokens_used,
        "synth_latency_ms": int(r.latency_s * 1000),
        "synth_total_ms": synth_ms,
        "rejected_reason": r.rejected_reason,
        "error": r.error,
        "driver_path": str(driver_path),
        "expected_verdict": "sat",
    }
    if not r.driver_c:
        out.update({"verdict": "synth_failed", "success": False})
        return out
    driver_path.write_text(r.driver_c)
    v = t2_klee.fuzz(driver_path, wall_seconds=30, out_dir=out_dir / "klee-out",
                     unit=f"phase3.2-synth-{r.source}")
    out.update({
        "verdict": v.verdict,
        "target_location": v.target_location,
        "wall_ms": v.wall_ms,
        "pov_path": v.pov_path,
        "success": v.verdict == "sat",
    })
    return out


# ----------------------------- Tier-3 case -----------------------------------

TIER3_TARGET = t3_synth.BmcTarget(
    name="phase3p2_off_by_one",
    includes=["stdint.h"],
    source="""\
#include <stdint.h>
#define N 8
static int buf[N];

static void write_at(unsigned int i, int v) {
    /* Bug: off-by-one — allows i == N. */
    if (i <= N) {
        buf[i] = v;
    }
}
""",
    function_under_test="write_at",
    inputs=[("unsigned int", "i"), ("int", "v")],
    invocation="write_at(i, v);",
    property_description="i must be strictly less than N (= 8)",
    seed_property="i < N",
    seed_preconditions=["i <= N"],
)


def _run_tier3(out_dir: Path) -> dict:
    t0 = time.monotonic()
    r = t3_synth.synthesize(TIER3_TARGET)
    synth_ms = int((time.monotonic() - t0) * 1000)
    out: dict[str, Any] = {
        "tier": "tier3_bmc",
        "synth_source": r.source,
        "synth_tokens": r.tokens_used,
        "synth_latency_ms": int(r.latency_s * 1000),
        "synth_total_ms": synth_ms,
        "rejected_reason": r.rejected_reason,
        "error": r.error,
        "expected_verdict": "unsafe",
    }
    if r.hypothesis is None:
        out.update({"verdict": "synth_failed", "success": False})
        return out
    harness_c = t3_assert.synthesize(r.hypothesis)
    harness_path = out_dir / "tier3_off_by_one.c"
    harness_path.write_text(harness_c)
    out["harness_path"] = str(harness_path)
    v = t3_cbmc.run_cbmc_oracle(
        harness_path, function="main", property="assertion",
        unwind=8, out_dir=out_dir,
        unit=f"phase3.2-synth-{r.source}",
    )
    out.update({
        "verdict": v.verdict,
        "target_location": v.target_location,
        "wall_ms": v.wall_ms,
        "pov_path": v.pov_path,
        "preconditions": r.hypothesis.preconditions,
        "assertion": r.hypothesis.assertion,
        "success": v.verdict == "unsafe",
    })
    return out


# ----------------------------- driver ---------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(_REPO / "run-logs" / "phase3.2-synth-smoke.json"))
    ap.add_argument("--work-dir", default=None,
                    help="Working directory for synthesized harnesses (kept). "
                         "Default: a temp dir under run-logs/phase3.2/")
    ap.add_argument("--skip", nargs="*", default=[],
                    choices=["tier1", "tier2", "tier3"],
                    help="Skip tiers (e.g. when KLEE/CBMC aren't available locally).")
    args = ap.parse_args()

    work = Path(args.work_dir) if args.work_dir else (_REPO / "run-logs" / "phase3.2" / "smoke")
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True, exist_ok=True)

    runs: list[dict] = []
    cases = [("tier1", _run_tier1), ("tier2", _run_tier2), ("tier3", _run_tier3)]
    for label, fn in cases:
        if label in args.skip:
            continue
        sub = work / label
        sub.mkdir(parents=True, exist_ok=True)
        try:
            row = fn(sub)
        except Exception as e:
            row = {"tier": label, "verdict": "exception", "success": False,
                   "error": f"{type(e).__name__}: {e}"}
        runs.append(row)

    counts = {"success": sum(1 for r in runs if r.get("success")),
              "total": len(runs)}
    sources = sorted({r.get("synth_source") for r in runs if r.get("synth_source")})
    tokens_total = sum(int(r.get("synth_tokens") or 0) for r in runs)
    summary = {
        "phase": "3.2",
        "counts": counts,
        "synth_sources": sources,
        "synth_tokens_total": tokens_total,
        "work_dir": str(work),
        "runs": runs,
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    return 0 if counts["success"] == counts["total"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
