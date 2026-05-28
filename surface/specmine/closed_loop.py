"""Phase 5.6 — Closed-loop driver: spec-mining outliers → agent.loop (PLAN §3b, §4).

This module is the integration glue between Component (3) (spec mining) and
the existing PLAN §4 closed loop. Each outlier produced by Phase 5.2 is
converted into an `agent.loop.Candidate` with a Tier-3 CBMC spec wrapping the
5.3 backward harness; `agent.loop.agent_step` then routes through the same
dispatcher Phase 2.4 / 3.3 use, so spec-mining hypotheses flow through the
same oracle stack as Phase 1 surface candidates.

When the router returns `inconclusive`, the loop invokes Phase 5.5
`refine_one` to widen the CBMC bound with LLM-proposed preconditions (live
gateway or deterministic rule-based fallback).

Output: `surface/specmine/closed_loop/<target>.json` — per-outlier record
with router trace summary, agent decision, and (optional) refinement result.

Soundness rule (PLAN §8 carries through): the LLM proposes preconditions /
contract widenings; CBMC remains the verdict authority. The metrics adapter
counts `false_confirmations = 0` as the gate.

No new soundness claims: the loop's `confirmed` disposition still requires
the same Phase-5.3 witness rule (engine UNSAFE + audit-able `.cbmc-pov.json`).
The router maps CBMC UNSAFE → `R_BMC_UNSAFE`, which `agent.loop._maybe_refine`
already handles, and which 5.6 reports as `confirmed` for the spec-mining
class (the BMC witness IS the structural confirmation, same rule as the
verify `--via-router` path).
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Optional

_REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO))
from agent import loop as agent_loop  # noqa: E402
from llm.client import LLMClient, LLMUnavailable  # noqa: E402

from surface.specmine.cbmc_oracle import (  # noqa: E402
    synthesise_harness, is_supported_contract,
)
from surface.specmine.refine import refine_one  # noqa: E402


# Router → spec-mining disposition map.
# We treat both R_CONFIRMED (Tier-1 sanitizer) and R_BMC_UNSAFE (Tier-3 cex
# witness, no runtime replay) as `confirmed` for spec-mining purposes — the
# BMC witness is the structural confirmation. Same rule as
# `surface/specmine/verify.py --via-router`.
_DISPOSITION_MAP = {
    "confirmed":     "confirmed",       # AgentDecision.disposition == "confirmed"
    "candidate":     "confirmed",       # BMC-unsafe witness path
    "pruned":        "refuted",
    "inconclusive":  "inconclusive",
    "no_dispatch":   "infrastructure_pending",
}


def _outliers_dispatchable(
    outliers: list[dict],
    *,
    min_suspicion: float,
) -> tuple[list[dict], dict[str, int]]:
    """Filter outliers to those the 5.3 harness can adjudicate.

    Drops:
      * suspicion < min_suspicion (one-hop deprioritized, funnel rule)
      * kernel-source outliers (CBMC infrastructure-pending; 5.6 will collect
        these into a separate `infrastructure_pending` bucket without invoking
        the router)
      * outliers whose contract_kind_class is not in the lock/null MVP set
        (same set Phase 5.3 honors)
    """
    keep: list[dict] = []
    skipped: Counter[str] = Counter()
    for o in outliers:
        suspicion = float(o.get("suspicion") or 0.0)
        if suspicion < min_suspicion:
            skipped["proposer_deprioritized"] += 1
            continue
        if not is_supported_contract(
            o.get("contract_kind_class", ""),
            o.get("missing_contract", ""),
        ):
            skipped["unsupported_contract_class"] += 1
            continue
        keep.append(o)
    return keep, dict(skipped)


def _candidate_for_outlier(
    outlier: dict,
    source_root: Path,
    out_dir: Path,
    *,
    cid: str,
    unwind: int,
    timeout_s: int,
) -> Optional[agent_loop.Candidate]:
    """Synthesise the 5.3 backward harness and wrap it as a Candidate."""
    synth = synthesise_harness(outlier, source_root)
    if synth is None or synth.get("unsupported"):
        return None
    harness_dir = out_dir / "harnesses"
    harness_dir.mkdir(parents=True, exist_ok=True)
    safe = "".join(
        c if c.isalnum() or c in "_-." else "_"
        for c in f"{outlier.get('callee')}_{outlier.get('caller')}_{outlier.get('contract_kind_class')}"
    )
    harness_path = harness_dir / f"{safe}.c"
    harness_path.write_text(synth["source"])
    return agent_loop.Candidate(
        cid=cid,
        description=(
            f"spec-mine outlier: {outlier.get('callee')} missing "
            f"{outlier.get('missing_contract')} in {outlier.get('caller')}"
        ),
        class_hint="bounded",
        tier3_cbmc={
            "source": str(harness_path),
            "function": "main",
            "property": "assertion",
            "unwind": unwind,
            "timeout_s": timeout_s,
            "unit": f"specmine:{safe}",
        },
    )


def _run_one(
    outlier: dict,
    source_root: Path,
    out_dir: Path,
    *,
    cid: str,
    unwind: int,
    refine_unwind: int,
    timeout_s: int,
    refine_llm: Optional[LLMClient],
) -> dict:
    """Run a single outlier through agent.loop, then 5.5 refine if inconclusive."""
    cand = _candidate_for_outlier(
        outlier, source_root, out_dir,
        cid=cid, unwind=unwind, timeout_s=timeout_s,
    )
    if cand is None:
        return {
            "outlier": _outlier_summary(outlier),
            "disposition": "infrastructure_pending",
            "reason": (
                "harness synthesis returned no source (kernel path, missing "
                "caller body, or unsupported contract class)."
            ),
            "router_verdict": None,
            "post_refine_disposition": "infrastructure_pending",
        }
    # Run the loop — pass refinement=None so agent.loop's own Stage-B contract
    # refinement (Phase 3.1) doesn't fire; we own refinement via Phase 5.5
    # outside the loop, because the spec-mining refinement is about main()-
    # level preconditions, not Stage-B function contracts.
    res = agent_loop.agent_step(cand)
    agent_disp = res.decision.disposition
    sm_disp = _DISPOSITION_MAP.get(agent_disp, "inconclusive")
    # Soundness rule: a confirmed disposition needs a witness path on disk.
    if sm_disp == "confirmed" and not res.decision.pov_path:
        sm_disp = "inconclusive"

    record = {
        "outlier": _outlier_summary(outlier),
        "harness_path": cand.tier3_cbmc.get("source") if cand.tier3_cbmc else None,
        "router_verdict": res.route_trace.get("final_verdict"),
        "agent_disposition": agent_disp,
        "agent_reason": res.decision.reason,
        "witness_path": res.decision.pov_path,
        "total_wall_ms": res.total_wall_ms,
        "disposition": sm_disp,
        "post_refine_disposition": sm_disp,
        "refinement": None,
    }

    # If inconclusive, run Phase 5.5 refinement using the existing verify-style
    # record shape that refine_one expects.
    if sm_disp == "inconclusive":
        cbmc_attempts = [
            a for a in res.route_trace.get("attempts", [])
            if a.get("engine") == "cbmc"
        ]
        last = cbmc_attempts[-1].get("raw_verdict", {}) if cbmc_attempts else {}
        synthetic_verified = {
            **_outlier_summary(outlier),
            "contract_kind_class": outlier.get("contract_kind_class"),
            "missing_contract": outlier.get("missing_contract"),
            "disposition": "inconclusive",
            "engine_verdict": last.get("verdict", "inconclusive"),
            "evidence_excerpt": last.get("evidence_excerpt", ""),
        }
        rr = refine_one(
            synthetic_verified, source_root, out_dir,
            llm=refine_llm, re_unwind=refine_unwind, timeout_s=timeout_s,
        )
        record["refinement"] = rr.__dict__
        if rr.post_refine_disposition == "confirmed":
            record["post_refine_disposition"] = "confirmed"
            # Promote the refined witness to the record so downstream
            # adapters / audits see the auditable cex.
            if rr.refined_witness_path:
                record["witness_path"] = rr.refined_witness_path
        elif rr.post_refine_disposition == "refuted":
            record["post_refine_disposition"] = "refuted"
        # else: still inconclusive
    return record


def _outlier_summary(o: dict) -> dict:
    keys = (
        "callee", "caller", "file", "line", "missing_contract",
        "contract_kind_class", "contract_kind_label",
        "support_pct", "support_count", "callsite_count",
        "suspicion", "local_establishment",
    )
    return {k: o.get(k) for k in keys}


def run(
    outliers_doc: dict,
    source_root: Path,
    out_dir: Path,
    *,
    min_suspicion: float,
    unwind: int,
    refine_unwind: int,
    timeout_s: int,
    use_llm_refine: bool,
    triage: bool = False,
    budget: Optional[int] = None,
) -> dict:
    """Run the closed-loop end-to-end for one target's outliers.

    Phase 6.1 additions:
      * `triage=True` runs the LLM triage layer (`surface.specmine.triage`) and
        reorders dispatch so high-plausibility outliers are verified first. The
        triage layer NEVER drops an outlier — it only reorders.
      * `budget` caps the number of CBMC verifications; outliers beyond the cap
        get disposition `deferred_by_budget` (NOT a verdict — re-run with a
        bigger budget to verify them). With `budget=None` every outlier is
        verified, so the confirmed-bug set is order-independent (zero loss).
    """
    all_outliers = outliers_doc.get("outliers", [])
    dispatchable, skipped = _outliers_dispatchable(
        all_outliers, min_suspicion=min_suspicion
    )

    llm = LLMClient() if use_llm_refine else None
    if llm is not None:
        try:
            llm.healthz()
        except LLMUnavailable:
            llm = None

    # Phase 6.1: triage-driven reordering (scoping only; never drops outliers).
    triage_doc = None
    if triage:
        from surface.specmine import triage as triage_mod
        triage_doc = triage_mod.triage(dispatchable, use_llm=True)
        dispatchable = triage_mod.order_outliers(dispatchable, triage_doc)

    records: list[dict] = []
    deferred: list[dict] = []
    t0 = time.time()
    for i, o in enumerate(dispatchable):
        if budget is not None and i >= budget:
            # Explicit budget deferral — NOT a verdict. Re-run with a larger
            # budget (or no budget) to verify these.
            deferred.append({
                "outlier": _outlier_summary(o),
                "disposition": "deferred_by_budget",
                "post_refine_disposition": "deferred_by_budget",
                "reason": f"beyond --budget={budget} under triage ordering.",
                "router_verdict": None,
                "witness_path": None,
            })
            continue
        cid = f"specmine-{outliers_doc.get('target', 'tgt')}-{i:04d}"
        records.append(_run_one(
            o, source_root, out_dir,
            cid=cid, unwind=unwind, refine_unwind=refine_unwind,
            timeout_s=timeout_s, refine_llm=llm,
        ))
    wall = time.time() - t0
    records.extend(deferred)

    # Roll-ups.
    by_disp: Counter[str] = Counter(r["disposition"] for r in records)
    by_post_disp: Counter[str] = Counter(
        r["post_refine_disposition"] for r in records
    )
    by_class_confirmed: Counter[str] = Counter()
    by_class_postconfirmed: Counter[str] = Counter()
    for r in records:
        cls = (r.get("outlier") or {}).get("contract_kind_class") or "unknown"
        if r["disposition"] == "confirmed":
            by_class_confirmed[cls] += 1
        if r["post_refine_disposition"] == "confirmed":
            by_class_postconfirmed[cls] += 1
    # The soundness gate: confirmed records must carry a witness path.
    false_confirmations = sum(
        1 for r in records
        if r["disposition"] == "confirmed" and not r.get("witness_path")
    )
    refined_flips = sum(
        1 for r in records
        if r.get("refinement")
        and r["refinement"].get("pre_refine_disposition") == "inconclusive"
        and r["refinement"].get("post_refine_disposition")
        in ("confirmed", "refuted")
    )

    verified_count = sum(
        1 for r in records if r["disposition"] != "deferred_by_budget"
    )
    deferred_count = by_disp.get("deferred_by_budget", 0)

    return {
        "target": outliers_doc.get("target"),
        "generated_at": int(time.time()),
        "min_suspicion": min_suspicion,
        "unwind": unwind,
        "refine_unwind": refine_unwind,
        "timeout_s": timeout_s,
        "use_llm_refine": use_llm_refine,
        "triage": triage,
        "budget": budget,
        "triage_stats": (triage_doc or {}).get("stats") if triage_doc else None,
        "stats": {
            "outliers_total": len(all_outliers),
            "outliers_dispatched": len(dispatchable),
            "verifications_run": verified_count,   # CBMC spawns actually done
            "deferred_by_budget": deferred_count,
            "skipped": skipped,
            "wall_seconds": round(wall, 2),
            "by_disposition_pre_refine": dict(by_disp),
            "by_disposition_post_refine": dict(by_post_disp),
            "confirmed_pre_refine": by_disp.get("confirmed", 0),
            "confirmed_post_refine": by_post_disp.get("confirmed", 0),
            "refuted": by_post_disp.get("refuted", 0),
            "inconclusive": by_post_disp.get("inconclusive", 0),
            "refined_flips": refined_flips,
            "false_confirmations": false_confirmations,  # GATE
            "by_class_confirmed": dict(by_class_confirmed),
            "by_class_post_refine_confirmed": dict(by_class_postconfirmed),
            "classes_with_confirmed_leads": len(by_class_postconfirmed),
        },
        "records": records,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Phase 5.6 closed-loop driver.")
    ap.add_argument("--target", required=True, type=str)
    ap.add_argument("--outliers-from", type=Path,
                    help="surface/specmine/outliers/<target>.json (default: derived).")
    ap.add_argument("--source-root", required=True, type=Path)
    ap.add_argument("--out", type=Path)
    ap.add_argument("--min-suspicion", type=float, default=0.5)
    ap.add_argument("--unwind", type=int, default=4)
    ap.add_argument("--refine-unwind", type=int, default=8)
    ap.add_argument("--timeout-s", type=int, default=60)
    ap.add_argument("--no-llm-refine", action="store_true",
                    help="Force rule-based refinement only (gateway-down semantics).")
    ap.add_argument("--triage", action="store_true",
                    help="Phase 6.1: run LLM triage and dispatch in plausibility "
                         "order (scoping only — never drops an outlier).")
    ap.add_argument("--budget", type=int, default=None,
                    help="Phase 6.1: cap CBMC verifications; outliers beyond the "
                         "cap get `deferred_by_budget` (not a verdict).")
    args = ap.parse_args(argv)

    here = Path(__file__).resolve().parent
    outliers_path = (
        args.outliers_from or here / "outliers" / f"{args.target}.json"
    )
    if not outliers_path.exists():
        ap.error(f"outliers not found: {outliers_path}")
    outliers_doc = json.loads(outliers_path.read_text())

    out_dir = here / "closed_loop" / args.target
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = args.out or out_dir / "closed_loop.json"

    doc = run(
        outliers_doc=outliers_doc,
        source_root=args.source_root.resolve(),
        out_dir=out_dir,
        min_suspicion=args.min_suspicion,
        unwind=args.unwind,
        refine_unwind=args.refine_unwind,
        timeout_s=args.timeout_s,
        use_llm_refine=not args.no_llm_refine,
        triage=args.triage,
        budget=args.budget,
    )
    out_path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
    s = doc["stats"]
    print(
        f"[specmine] closed-loop: dispatched={s['outliers_dispatched']}/"
        f"{s['outliers_total']} "
        f"verifications={s['verifications_run']} "
        f"deferred_by_budget={s['deferred_by_budget']} "
        f"confirmed_post={s['confirmed_post_refine']} "
        f"refuted={s['refuted']} inconclusive={s['inconclusive']} "
        f"classes_confirmed={s['classes_with_confirmed_leads']} "
        f"false_confirmations={s['false_confirmations']} "
        f"wall={s['wall_seconds']:.1f}s"
    )
    print(f"[specmine] closed-loop -> {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
