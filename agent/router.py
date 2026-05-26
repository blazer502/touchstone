"""Phase-2.4 router skeleton — hand-coded heuristic, no LLM.

PLAN §3 / §7 mandate a *funnel*: the router routes each hypothesis to the
cheapest tier that can decide it, escalating only on `inconclusive`. The
funnel order is fixed by the per-tier cost weights in `config/budget.yaml`:

    tier1_fuzz (1)  ≺  tier2_symbolic (25)  ≺  tier3_bmc (50)

This skeleton dispatches against the Phase-2.1/2.2/2.3 drivers under their
existing verdict shapes (`Tier1Verdict`, `Tier2Verdict`, `Tier3Verdict`) and
emits a `RouteTrace` capturing every attempt, the tier costs charged, and a
final verdict mapped onto a uniform router vocabulary:

    confirmed | refuted | proved_safe | bmc_unsafe | candidate | inconclusive | no_dispatch

The router never replaces a sound verdict (PLAN §8): a Tier-1 crash that
already reproduces is a confirmed PoV; a Tier-3 `safe` (bounded) is reported
as `proved_safe`; a Tier-2 SAT becomes `confirmed` ONLY if a Tier-1 replay
path is supplied and reproduces the crash — symbolic SAT alone is `candidate`.

Phase 3.3 replaces this heuristic with an LLM-based router; the dispatch
surface (`route()`) stays the same so the LLM router is a drop-in.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Optional

from llm.budget import Budget, TierBudget
from oracle.tier1_fuzz import userspace as t1_userspace
from oracle.tier1_fuzz import kernel as t1_kernel
from oracle.tier1_fuzz.verdict import Tier1Verdict
from oracle.tier2_symbolic import klee_driver as t2_klee
from oracle.tier2_symbolic import angr_driver as t2_angr
from oracle.tier2_symbolic.verdict import Tier2Verdict
from oracle.tier3_bmc import cbmc_driver as t3_cbmc
from oracle.tier3_bmc.verdict import Tier3Verdict


# --- Router-uniform verdict vocabulary ---------------------------------------
R_CONFIRMED = "confirmed"          # PoV reproduces (Tier-1 crash or Tier-2/3 promoted via Tier-1)
R_REFUTED = "refuted"              # symbolic UNSAT under modeled environment
R_PROVED_SAFE = "proved_safe"      # Tier-3 safe (bounded)
R_BMC_UNSAFE = "bmc_unsafe"        # Tier-3 unsafe witness but no runtime replay
R_CANDIDATE = "candidate"          # Tier-2 SAT, no Tier-1 reconfirmation path available
R_INCONCLUSIVE = "inconclusive"    # every dispatched tier returned inconclusive
R_NO_DISPATCH = "no_dispatch"      # hypothesis carried no executable spec for any tier


# --- Hypothesis input shape ---------------------------------------------------
@dataclass
class Tier1FuzzSpec:
    """Hand-written libFuzzer harness to *fuzz* fresh."""
    harness_src: str                # path to .c
    sanitizer: str = "ASan"
    wall_seconds: Optional[int] = None
    unit: Optional[str] = None
    extra_cflags: Optional[list[str]] = None   # e.g. ["-lsqlite3"] for live-lib harnesses


@dataclass
class Tier1ReplaySpec:
    """Replay a recorded PoC against an existing harness binary or docker image."""
    poc_path: str
    harness_bin: Optional[str] = None
    docker_image: Optional[str] = None
    docker_harness_path: Optional[str] = None
    sanitizer: str = "auto"
    timeout_seconds: int = 60
    unit: Optional[str] = None


@dataclass
class Tier1KasanReplaySpec:
    """Replay a captured KASAN dmesg log (no QEMU re-boot)."""
    dmesg_path: str
    unit: Optional[str] = None


@dataclass
class Tier2KleeSpec:
    source: str
    wall_seconds: Optional[int] = None
    unit: Optional[str] = None


@dataclass
class Tier2AngrSpec:
    binary: str
    target: str                     # symbol or 0xADDR
    avoid: Optional[list[str]] = None
    stdin_size: int = 32
    step_budget: int = 200
    wall_seconds: Optional[int] = None
    unit: Optional[str] = None


@dataclass
class Tier3CbmcSpec:
    source: str
    function: str = "main"
    property: str = "memory-safety"
    unwind: int = 16
    timeout_s: Optional[int] = None
    unit: Optional[str] = None


@dataclass
class Hypothesis:
    """A hypothesis = (id, optional class hint, per-tier specs).

    The router prefers cheaper tiers and uses ``class_hint`` to break ties when
    multiple specs are populated. Class hint values follow PLAN §3 vocabulary:

        crash        — sanitizer-detectable runtime bug; favour Tier-1
        feasibility  — "is this path reachable under constraint C"; favour Tier-2
        bounded      — small bounded property; favour Tier-3
        kernel_uaf   — KASAN replay (Tier-1 kernel path)
    """
    hid: str
    description: str = ""
    class_hint: str = "crash"
    tier1_fuzz: Optional[Tier1FuzzSpec] = None
    tier1_replay: Optional[Tier1ReplaySpec] = None
    tier1_kasan: Optional[Tier1KasanReplaySpec] = None
    tier2_klee: Optional[Tier2KleeSpec] = None
    tier2_angr: Optional[Tier2AngrSpec] = None
    tier3_cbmc: Optional[Tier3CbmcSpec] = None


# --- Trace output -------------------------------------------------------------
@dataclass
class Attempt:
    tier: str                       # "tier1_fuzz" | "tier2_symbolic" | "tier3_bmc"
    engine: str
    role: str                       # "primary" | "reconfirm"
    raw_verdict: dict
    cost_weight: int                # router's per-tier cost (PLAN §7 funnel)
    wall_ms: int

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class RouteTrace:
    hypothesis_id: str
    final_verdict: str              # one of R_*
    decision_reason: str
    attempts: list[Attempt] = field(default_factory=list)
    total_cost: int = 0
    total_wall_ms: int = 0
    pov_path: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "hypothesis_id": self.hypothesis_id,
            "final_verdict": self.final_verdict,
            "decision_reason": self.decision_reason,
            "total_cost": self.total_cost,
            "total_wall_ms": self.total_wall_ms,
            "pov_path": self.pov_path,
            "attempts": [a.to_dict() for a in self.attempts],
        }


# --- Tier executors -----------------------------------------------------------
def _run_tier1(hyp: Hypothesis, budget: Budget) -> Optional[tuple[str, Tier1Verdict]]:
    """Run the most-preferred Tier-1 spec attached to the hypothesis.

    Order of preference within Tier-1:
      1. replay  — fastest, deterministic
      2. kasan   — kernel replay, deterministic
      3. fuzz    — explorative
    """
    if hyp.tier1_replay is not None:
        s = hyp.tier1_replay
        if s.docker_image and s.docker_harness_path:
            v = t1_userspace.replay_docker(
                s.docker_image, s.docker_harness_path, Path(s.poc_path),
                sanitizer=s.sanitizer, unit=s.unit, timeout_seconds=s.timeout_seconds,
            )
            return "libfuzzer", v
        if s.harness_bin:
            v = t1_userspace.replay(
                Path(s.harness_bin), Path(s.poc_path),
                sanitizer=s.sanitizer, unit=s.unit, timeout_seconds=s.timeout_seconds,
            )
            return "libfuzzer", v
    if hyp.tier1_kasan is not None:
        s = hyp.tier1_kasan
        v = t1_kernel.kasan_replay_from_log(Path(s.dmesg_path), unit=s.unit or "kernelctf-historical")
        return "kasan_replay", v
    if hyp.tier1_fuzz is not None:
        s = hyp.tier1_fuzz
        wall = s.wall_seconds or budget.tiers["tier1_fuzz"].wall_seconds
        v = t1_userspace.fuzz(
            Path(s.harness_src), sanitizer=s.sanitizer,
            wall_seconds=wall, unit=s.unit,
            extra_cflags=s.extra_cflags,
        )
        return "libfuzzer", v
    return None


def _run_tier2(hyp: Hypothesis, budget: Budget) -> Optional[tuple[str, Tier2Verdict]]:
    """Run a Tier-2 spec; prefer KLEE (C source) over angr (binary)."""
    if hyp.tier2_klee is not None:
        s = hyp.tier2_klee
        wall = s.wall_seconds or budget.tiers["tier2_symbolic"].wall_seconds
        v = t2_klee.fuzz(Path(s.source), wall_seconds=wall, unit=s.unit)
        return "klee", v
    if hyp.tier2_angr is not None:
        s = hyp.tier2_angr
        wall = s.wall_seconds or budget.tiers["tier2_symbolic"].wall_seconds
        v = t2_angr.explore(
            Path(s.binary), s.target, stdin_size=s.stdin_size,
            step_budget=s.step_budget, wall_seconds=wall,
            unit=s.unit, avoid=s.avoid,
        )
        return "angr", v
    return None


def _run_tier3(hyp: Hypothesis, budget: Budget) -> Optional[tuple[str, Tier3Verdict]]:
    if hyp.tier3_cbmc is not None:
        s = hyp.tier3_cbmc
        wall = s.timeout_s or budget.tiers["tier3_bmc"].wall_seconds
        v = t3_cbmc.run_cbmc_oracle(
            Path(s.source), function=s.function, property=s.property,
            unwind=s.unwind, timeout_s=wall, unit=s.unit,
        )
        return "cbmc", v
    return None


# --- Populated-tier inventory -------------------------------------------------
def _populated_tiers(hyp: Hypothesis) -> list[str]:
    have_t1 = (hyp.tier1_replay is not None or hyp.tier1_kasan is not None
               or hyp.tier1_fuzz is not None)
    have_t2 = hyp.tier2_klee is not None or hyp.tier2_angr is not None
    have_t3 = hyp.tier3_cbmc is not None
    out = []
    if have_t1: out.append("tier1_fuzz")
    if have_t2: out.append("tier2_symbolic")
    if have_t3: out.append("tier3_bmc")
    return out


# --- Heuristic dispatch order -------------------------------------------------
def _dispatch_order(hyp: Hypothesis) -> list[str]:
    """Pick the order of tiers to try based on class_hint + populated specs.

    Always falls through cheaper → more expensive. ``class_hint`` only
    re-orders within ties (e.g. "bounded" puts Tier-3 first if both Tier-2
    and Tier-3 are populated).
    """
    available = _populated_tiers(hyp)
    if not available:
        return []
    have_t1 = "tier1_fuzz" in available
    have_t2 = "tier2_symbolic" in available
    have_t3 = "tier3_bmc" in available

    order: list[str] = []
    if hyp.class_hint == "bounded" and have_t3:
        # Caller said "small bounded property" — Tier-3 first is cheaper than
        # waking a fuzzer that won't converge.
        if have_t3: order.append("tier3_bmc")
        if have_t1: order.append("tier1_fuzz")
        if have_t2: order.append("tier2_symbolic")
    elif hyp.class_hint == "feasibility" and have_t2:
        # Path-reachability question — go to the symbolic engine first.
        if have_t2: order.append("tier2_symbolic")
        if have_t1: order.append("tier1_fuzz")
        if have_t3: order.append("tier3_bmc")
    else:
        # Default funnel: Tier-1 → Tier-2 → Tier-3.
        if have_t1: order.append("tier1_fuzz")
        if have_t2: order.append("tier2_symbolic")
        if have_t3: order.append("tier3_bmc")
    return order


def _sanitize_order(
    proposal: Any,
    available: list[str],
    *,
    fallback: list[str],
) -> list[str]:
    """Filter a dispatcher proposal to the set of populated tiers.

    - Non-list / empty / all-foreign proposals fall back to the heuristic order.
    - Foreign tiers (not in ``available``) are dropped silently.
    - Duplicates are removed preserving first occurrence.
    - Any populated tier omitted by the proposer is appended after, so a buggy
      LLM cannot accidentally *exclude* a populated tier (that would lose
      precision: an unfired Tier-3 cex would never surface).
    """
    if not isinstance(proposal, list) or not proposal:
        return fallback
    seen: set[str] = set()
    out: list[str] = []
    for t in proposal:
        if not isinstance(t, str):
            continue
        if t not in available or t in seen:
            continue
        seen.add(t)
        out.append(t)
    if not out:
        return fallback
    for t in available:
        if t not in seen:
            out.append(t)
    return out


# --- Public entrypoint --------------------------------------------------------
def route(
    hyp: Hypothesis,
    budget: Optional[Budget] = None,
    *,
    dispatcher: Optional[Any] = None,
) -> RouteTrace:
    """Run the router on one hypothesis.

    The router executes tiers in order until one produces a *decisive* verdict
    (Tier-1 crash, Tier-2 sat/unsat, Tier-3 safe/unsafe). On Tier-2 SAT a
    Tier-1 replay reconfirmation is attempted iff the hypothesis supplied a
    replay spec — symbolic SAT alone is `candidate`, not `confirmed` (PLAN §8).

    ``dispatcher`` is a callable ``(Hypothesis, list[str] available) -> list[str]``
    returning the tier execution order. Defaults to the hand-coded heuristic
    (Phase 2.4). Pass ``LLMDispatcher()`` to use the Phase-3.3 LLM router.
    The router *always* re-validates the returned order against the populated-
    tier set (filters out fabrications, dedupes) — no dispatcher decision can
    weaken soundness because the engines themselves still hold verdict authority.
    """
    budget = budget or Budget.load()
    tr = RouteTrace(hypothesis_id=hyp.hid, final_verdict=R_NO_DISPATCH,
                    decision_reason="no specs attached")
    available = _populated_tiers(hyp)
    if not available:
        return tr
    if dispatcher is None:
        order = _dispatch_order(hyp)
    else:
        proposal = dispatcher(hyp, list(available))
        order = _sanitize_order(proposal, available, fallback=_dispatch_order(hyp))
    if not order:
        return tr

    decided = False
    for tier in order:
        if tier == "tier1_fuzz":
            res = _run_tier1(hyp, budget)
            if res is None:
                continue
            engine, v = res
            cost = budget.tiers["tier1_fuzz"].cost_weight
            tr.attempts.append(Attempt("tier1_fuzz", engine, "primary",
                                       v.to_dict(), cost, v.wall_ms))
            tr.total_cost += cost
            tr.total_wall_ms += v.wall_ms
            if v.verdict == "crash":
                tr.final_verdict = R_CONFIRMED
                tr.decision_reason = (f"Tier-1 {engine} sanitizer-confirmed crash "
                                      f"({v.crash_class or 'unknown'}) at {v.location or '?'}")
                tr.pov_path = v.pov_path
                decided = True
                break
            # no_crash / inconclusive: escalate.
        elif tier == "tier2_symbolic":
            res = _run_tier2(hyp, budget)
            if res is None:
                continue
            engine, v = res
            cost = budget.tiers["tier2_symbolic"].cost_weight
            tr.attempts.append(Attempt("tier2_symbolic", engine, "primary",
                                       v.to_dict(), cost, v.wall_ms))
            tr.total_cost += cost
            tr.total_wall_ms += v.wall_ms
            if v.verdict == "sat":
                # Symbolic SAT is a *candidate*. Try Tier-1 reconfirm if available.
                tr.pov_path = v.pov_path
                if hyp.tier1_replay is not None and (hyp.tier1_replay.harness_bin
                                                     or hyp.tier1_replay.docker_image):
                    rec = _tier1_reconfirm(hyp, v, budget)
                    if rec is not None:
                        eng2, rv = rec
                        cost1 = budget.tiers["tier1_fuzz"].cost_weight
                        tr.attempts.append(Attempt("tier1_fuzz", eng2, "reconfirm",
                                                   rv.to_dict(), cost1, rv.wall_ms))
                        tr.total_cost += cost1
                        tr.total_wall_ms += rv.wall_ms
                        if rv.verdict == "crash":
                            tr.final_verdict = R_CONFIRMED
                            tr.decision_reason = (f"Tier-2 {engine} SAT → Tier-1 {eng2} "
                                                  f"reconfirmed crash at {rv.location or '?'}")
                            tr.pov_path = rv.pov_path or v.pov_path
                            decided = True
                            break
                        # reconfirm didn't reproduce — degrade to candidate, do NOT prune.
                tr.final_verdict = R_CANDIDATE
                tr.decision_reason = (f"Tier-2 {engine} SAT at {v.target_location or '?'} "
                                      "(symbolic candidate, no runtime reconfirm available)")
                decided = True
                break
            if v.verdict == "unsat":
                tr.final_verdict = R_REFUTED
                tr.decision_reason = (f"Tier-2 {engine} UNSAT under modeled environment "
                                      f"(completed={v.paths_completed})")
                decided = True
                break
            # inconclusive — escalate.
        elif tier == "tier3_bmc":
            res = _run_tier3(hyp, budget)
            if res is None:
                continue
            engine, v = res
            cost = budget.tiers["tier3_bmc"].cost_weight
            tr.attempts.append(Attempt("tier3_bmc", engine, "primary",
                                       v.to_dict(), cost, v.wall_ms))
            tr.total_cost += cost
            tr.total_wall_ms += v.wall_ms
            if v.verdict == "safe":
                tr.final_verdict = R_PROVED_SAFE
                tr.decision_reason = (f"Tier-3 {engine} proved safe up to --unwind={v.unwind} "
                                      f"(property={v.property})")
                decided = True
                break
            if v.verdict == "unsafe":
                # BMC cex is a sound witness for the harness; promote to confirmed
                # only via Tier-1 replay (which requires the runtime harness).
                tr.pov_path = v.pov_path
                tr.final_verdict = R_BMC_UNSAFE
                tr.decision_reason = (f"Tier-3 {engine} unsafe at {v.target_location or '?'} "
                                      "(bounded-sound witness; runtime PoV needs Tier-1 wrap)")
                decided = True
                break
            # inconclusive — escalate (nothing left after Tier-3 unless we re-loop).

    if not decided:
        tr.final_verdict = R_INCONCLUSIVE
        tr.decision_reason = "All dispatched tiers returned inconclusive within budget"

    return tr


def _tier1_reconfirm(hyp: Hypothesis, t2: Tier2Verdict, budget: Budget) -> Optional[tuple[str, Tier1Verdict]]:
    """Re-run Tier-1 against the symbolic PoV.

    Two paths:
    - Docker (CyberGym OSS-Fuzz style): use the recorded harness image.
    - Local binary: replay against the harness_bin in the hypothesis.

    The PoC bytes come from the symbolic engine's pov_path; if absent, we
    reuse the hypothesis's existing tier1_replay.poc_path (handed in by caller).
    """
    s = hyp.tier1_replay
    if s is None:
        return None
    poc = Path(t2.pov_path) if t2.pov_path else Path(s.poc_path)
    if not poc.exists():
        return None
    if s.docker_image and s.docker_harness_path:
        v = t1_userspace.replay_docker(
            s.docker_image, s.docker_harness_path, poc,
            sanitizer=s.sanitizer, unit=(s.unit or "reconfirm") + "+reconfirm",
            timeout_seconds=s.timeout_seconds,
        )
        return "libfuzzer", v
    if s.harness_bin:
        v = t1_userspace.replay(
            Path(s.harness_bin), poc, sanitizer=s.sanitizer,
            unit=(s.unit or "reconfirm") + "+reconfirm",
            timeout_seconds=s.timeout_seconds,
        )
        return "libfuzzer", v
    return None


# --- CLI ----------------------------------------------------------------------
def _hyp_from_json(d: dict) -> Hypothesis:
    """Reconstruct Hypothesis from a JSON blob (matches dataclass field names)."""
    def _opt(cls, k):
        v = d.get(k)
        return cls(**v) if isinstance(v, dict) else None
    return Hypothesis(
        hid=d["hid"],
        description=d.get("description", ""),
        class_hint=d.get("class_hint", "crash"),
        tier1_fuzz=_opt(Tier1FuzzSpec, "tier1_fuzz"),
        tier1_replay=_opt(Tier1ReplaySpec, "tier1_replay"),
        tier1_kasan=_opt(Tier1KasanReplaySpec, "tier1_kasan"),
        tier2_klee=_opt(Tier2KleeSpec, "tier2_klee"),
        tier2_angr=_opt(Tier2AngrSpec, "tier2_angr"),
        tier3_cbmc=_opt(Tier3CbmcSpec, "tier3_cbmc"),
    )


def _cli() -> int:
    import argparse, sys
    ap = argparse.ArgumentParser(description="Phase 2.4 heuristic router.")
    ap.add_argument("--hypotheses", required=True,
                    help="Path to a JSON file: either a single Hypothesis dict or a list of them.")
    ap.add_argument("--out", required=True, help="Write JSONL trace here (one row per hypothesis).")
    ap.add_argument("--dispatcher", default="heuristic", choices=("heuristic", "llm"),
                    help="Tier-ordering policy. 'llm' uses the Phase-3.3 router model.")
    ap.add_argument("--dispatch-trace", default=None,
                    help="If --dispatcher=llm, write per-hypothesis LLM dispatch trace JSONL here.")
    args = ap.parse_args()

    data = json.loads(Path(args.hypotheses).read_text())
    hyps = [data] if isinstance(data, dict) else list(data)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    budget = Budget.load()

    dispatcher = None
    llm_traces = None
    if args.dispatcher == "llm":
        from agent.router_llm import LLMDispatcher
        d = LLMDispatcher()
        dispatcher = d
        llm_traces = d.traces

    rows = []
    with out.open("w") as fh:
        for h in hyps:
            tr = route(_hyp_from_json(h), budget=budget, dispatcher=dispatcher)
            row = tr.to_dict()
            fh.write(json.dumps(row) + "\n")
            rows.append(row)
            print(f"{tr.hypothesis_id}: {tr.final_verdict} — {tr.decision_reason} "
                  f"(cost={tr.total_cost}, wall_ms={tr.total_wall_ms})")
    print(f"\nWrote {len(rows)} trace(s) to {out}")
    if args.dispatch_trace and llm_traces is not None:
        dt_path = Path(args.dispatch_trace)
        dt_path.parent.mkdir(parents=True, exist_ok=True)
        with dt_path.open("w") as fh:
            for hyp_dict, tr in zip(hyps, llm_traces):
                fh.write(json.dumps({
                    "hid": hyp_dict.get("hid"),
                    "used_llm": tr.used_llm,
                    "proposal": tr.proposal,
                    "reason": tr.reason,
                    "tokens": tr.tokens,
                    "latency_s": tr.latency_s,
                    "error": tr.error,
                }) + "\n")
        print(f"Wrote {len(llm_traces)} dispatch trace(s) to {dt_path}")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(_cli())
