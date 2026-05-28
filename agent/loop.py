"""Phase 4.1 — closed agent loop.

PLAN §4 (The Closed Loop):
    propose exploit hypothesis -> ROUTER picks oracle tier ->
    verify -> on confirm emit PoV; on refute prune;
    on inconclusive, refine hypothesis or escalate tier ->
    counterexamples feed back to Stage B (contracts) and to the agent

The router (Phase 2.4 / 3.3) already covers `propose -> route -> verify`.
This module wraps it with two missing pieces for the closed loop:

  1. **Candidate site → Hypothesis assembly.** A ``Candidate`` is a small
     declarative record (source, function, property, class hint, optional
     per-tier specs). The loop assembles the matching ``Hypothesis`` and
     hands it to ``agent.router.route``.

  2. **Counterexample-driven refinement.** When the router returns
     ``inconclusive`` (every tier inconclusive) or ``bmc_unsafe`` (Tier-3
     found a witness but the property may rely on a missing precondition),
     the loop invokes ``surface.stage_b.refine_unit`` to ask the LLM
     (with deterministic rule-based fallback) for stronger contracts. The
     engine then re-decides; the LLM never overrides a sound verdict
     (PLAN §8). If refinement flips ``unsafe`` → ``safe`` the candidate is
     pruned; if it stays unsafe under accepted contracts, the BMC witness
     is preserved as a PoV.

Refinement is bounded by ``max_refine_iters`` (default 3). The full
attempt log + refinement history are returned so the metrics harness can
report tokens/latency/decision per candidate.

For Phase 4 acceptance the loop is exercised on a small smoke set
(``agent/smoke/candidates.json``) and end-to-end on the live targets
(Phase 4.2 kernelCTF + Phase 4.3 live-lib). The smoke set deliberately
uses targets that are deterministic without docker/LLM dependencies so
CI can run the loop offline.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Optional

from agent import router as router_mod
from surface import stage_b
from llm import client as llm_client


# --- Candidate input ---------------------------------------------------------

@dataclass
class RefinementSpec:
    """When the router returns inconclusive/bmc_unsafe, try Stage-B refinement.

    The source/function/property are handed straight to ``stage_b.refine_unit``.
    The source must carry a ``/* @CONTRACTS */`` marker so refinement can
    inject preconditions at the right place (Phase 3.1 convention).
    """
    source: str
    function: str = "main"
    property: str = "memory-safety"
    unwind: int = 16
    max_iters: int = 3
    apply_on: tuple[str, ...] = ("inconclusive", "bmc_unsafe")


@dataclass
class Candidate:
    """A candidate bug site to drive through the closed loop.

    The per-tier specs are the same shape as ``agent.router.Hypothesis``,
    so a Candidate is just a Hypothesis plus refinement metadata.
    """
    cid: str
    description: str = ""
    class_hint: str = "crash"
    tier1_fuzz: Optional[dict] = None
    tier1_replay: Optional[dict] = None
    tier1_kasan: Optional[dict] = None
    tier2_klee: Optional[dict] = None
    tier2_angr: Optional[dict] = None
    tier3_cbmc: Optional[dict] = None
    refine: Optional[dict] = None    # RefinementSpec as a dict
    repro: Optional[dict] = None     # opt-in crash-reproducer spec (R-track)


# --- Result shape ------------------------------------------------------------

@dataclass
class RefinementOutcome:
    invoked: bool = False
    reason: str = ""                 # why refinement ran
    initial_verdict: str = ""        # CBMC verdict before any contract synth
    final_verdict: str = ""          # CBMC verdict after refinement
    accumulated_contracts: list[str] = field(default_factory=list)
    iterations: int = 0
    tokens_used: int = 0
    history: list[dict] = field(default_factory=list)


@dataclass
class AgentDecision:
    """Final disposition emitted by the loop, mapped to PLAN §4 vocabulary.

    confirmed    — sound runtime PoV in hand
    pruned       — proved safe (Stage-B or Tier-3) or refuted by Tier-2 UNSAT
    candidate    — Tier-2 SAT or Tier-3 unsafe with no Tier-1 reconfirm
    inconclusive — every dispatched tier inconclusive within budget
    no_dispatch  — no executable spec for any tier
    """
    disposition: str
    reason: str
    pov_path: Optional[str] = None


@dataclass
class AgentResult:
    candidate_id: str
    decision: AgentDecision
    route_trace: dict
    refinement: RefinementOutcome
    total_wall_ms: int
    reproducibility: Optional[dict] = None   # ReproVerdict dict when scored (R-track)
    triage: Optional[dict] = None            # ExploitTriage dict for a confirmed crash (Phase 9a)

    def to_dict(self) -> dict:
        return {
            "candidate_id": self.candidate_id,
            "decision": asdict(self.decision),
            "route_trace": self.route_trace,
            "refinement": asdict(self.refinement),
            "total_wall_ms": self.total_wall_ms,
            "reproducibility": self.reproducibility,
            "triage": self.triage,
        }


# --- Hypothesis assembly -----------------------------------------------------

def _hyp_from_candidate(c: Candidate) -> router_mod.Hypothesis:
    def _opt(cls, d):
        return cls(**d) if isinstance(d, dict) else None
    return router_mod.Hypothesis(
        hid=c.cid,
        description=c.description,
        class_hint=c.class_hint,
        tier1_fuzz=_opt(router_mod.Tier1FuzzSpec, c.tier1_fuzz),
        tier1_replay=_opt(router_mod.Tier1ReplaySpec, c.tier1_replay),
        tier1_kasan=_opt(router_mod.Tier1KasanReplaySpec, c.tier1_kasan),
        tier2_klee=_opt(router_mod.Tier2KleeSpec, c.tier2_klee),
        tier2_angr=_opt(router_mod.Tier2AngrSpec, c.tier2_angr),
        tier3_cbmc=_opt(router_mod.Tier3CbmcSpec, c.tier3_cbmc),
    )


# --- Disposition mapper ------------------------------------------------------

_ROUTER_TO_DISP = {
    router_mod.R_CONFIRMED: ("confirmed", "Tier-1 sanitizer-confirmed PoV"),
    router_mod.R_REFUTED: ("pruned", "Tier-2 UNSAT under modeled environment"),
    router_mod.R_PROVED_SAFE: ("pruned", "Tier-3 proved safe (bounded)"),
    router_mod.R_BMC_UNSAFE: ("candidate", "Tier-3 BMC witness (needs Tier-1 wrap)"),
    router_mod.R_CANDIDATE: ("candidate", "Tier-2 SAT (no runtime reconfirm)"),
    router_mod.R_INCONCLUSIVE: ("inconclusive", "all tiers inconclusive"),
    router_mod.R_NO_DISPATCH: ("no_dispatch", "no executable spec"),
}


def _decision_from_route(tr: router_mod.RouteTrace) -> AgentDecision:
    disp, default_reason = _ROUTER_TO_DISP.get(tr.final_verdict, ("inconclusive", tr.decision_reason))
    return AgentDecision(
        disposition=disp,
        reason=tr.decision_reason or default_reason,
        pov_path=tr.pov_path,
    )


# --- Refinement step ---------------------------------------------------------

def _maybe_refine(
    c: Candidate,
    decision: AgentDecision,
    route_verdict: str,
    *,
    client: Optional[llm_client.LLMClient],
    allow_rule_fallback: bool,
) -> tuple[AgentDecision, RefinementOutcome]:
    """If a refinement spec is attached and the verdict is in apply_on, refine.

    The refined verdict can only *strengthen* the original disposition:
      * unsafe → safe under new contract  ⇒ "pruned" (was "candidate")
      * unsafe → still unsafe              ⇒ keep "candidate" + witness preserved
      * inconclusive → safe                ⇒ "pruned"
      * inconclusive → unsafe              ⇒ "candidate" (BMC witness)
      * inconclusive → inconclusive        ⇒ unchanged

    The contract refinement loop never overrides Tier-1 confirmed crashes
    or refuted UNSATs — those are sound runtime/symbolic verdicts already
    (PLAN §8).
    """
    out = RefinementOutcome()
    spec = c.refine
    if not isinstance(spec, dict):
        return decision, out
    if route_verdict not in spec.get("apply_on", ("inconclusive", "bmc_unsafe")):
        return decision, out
    source = spec.get("source")
    if not source:
        return decision, out
    src_path = Path(source)
    if not src_path.exists():
        out.invoked = True
        out.reason = f"refinement source missing: {source}"
        return decision, out

    out.invoked = True
    out.reason = f"router={route_verdict}, refine source={source}"
    rv = stage_b.refine_unit(
        src_path,
        function=spec.get("function", "main"),
        property=spec.get("property", "memory-safety"),
        unwind=int(spec.get("unwind", 16)),
        max_iters=int(spec.get("max_iters", 3)),
        client=client,
        allow_rule_fallback=allow_rule_fallback,
    )
    out.iterations = len(rv.history) - 1 if rv.history else 0
    out.tokens_used = rv.total_tokens
    out.accumulated_contracts = list(rv.accumulated_contracts)
    out.initial_verdict = rv.history[0].verdict if rv.history else ""
    out.final_verdict = rv.final.verdict
    out.history = [asdict(s) for s in rv.history]

    # Promote disposition based on the refined Stage-B verdict.
    if rv.final.verdict == "safe":
        return AgentDecision(
            disposition="pruned",
            reason=("refinement: CBMC proved safe under contracts "
                    f"{rv.accumulated_contracts!r} (was {route_verdict})"),
            pov_path=None,
        ), out
    if rv.final.verdict == "unsafe":
        # Keep candidate disposition (BMC witness); refinement did not flip it.
        new_reason = (f"refinement attempted ({out.iterations} iter, "
                      f"tokens={out.tokens_used}); CBMC still unsafe")
        return AgentDecision(
            disposition="candidate",
            reason=new_reason,
            pov_path=decision.pov_path,
        ), out
    # inconclusive — leave the original decision unchanged.
    return decision, out


# --- Reproducibility step (R-track) ------------------------------------------

def _maybe_score_reproducibility(c: Candidate, decision: AgentDecision) -> Optional[dict]:
    """If a ``repro`` spec is attached and we have a runtime PoV, score
    reproducibility (and minimize) via the crash-reproducer pipeline.

    Opt-in and confined to ``confirmed`` dispositions: only a real runtime PoV
    is worth re-running for determinism. The re-run is the verdict authority;
    a low/zero ``repro_rate`` is reported honestly (never demoted to "safe").
    Any failure is swallowed into an ``error`` dict so it can't break the loop.
    """
    spec = c.repro
    if not isinstance(spec, dict) or decision.disposition != "confirmed":
        return None
    runs = int(spec.get("runs", 5))
    threshold = float(spec.get("threshold", 0.9))
    try:
        if spec.get("domain") == "kernel":
            from oracle.repro.kernel import measure_kernel_reproducibility
            qs = spec.get("qemu_script")
            if not qs:
                return None
            v = measure_kernel_reproducibility(
                Path(qs), runs=runs, threshold=threshold,
                timeout_seconds=int(spec.get("timeout_seconds", 120)),
                unit=c.cid,
                log_path=Path(spec["log_path"]) if spec.get("log_path") else None,
                build_id=spec.get("build_id", ""))
            return v.to_dict()
        # userspace
        poc = spec.get("poc")
        if not poc:
            return None
        minimize = bool(spec.get("minimize", True))
        from oracle.repro.pipeline import run_userspace_docker, run_userspace_local
        if spec.get("image"):
            v = run_userspace_docker(spec["image"], spec["harness_path"], Path(poc),
                                     runs=runs, threshold=threshold, minimize=minimize,
                                     unit=c.cid)
        elif spec.get("harness_bin"):
            v = run_userspace_local(Path(spec["harness_bin"]), Path(poc),
                                    runs=runs, threshold=threshold, minimize=minimize,
                                    unit=c.cid)
        else:
            return None
        return v.to_dict()
    except Exception as e:  # reproducibility scoring must never break the loop
        return {"verdict": "error", "error": repr(e)}


# --- Exploitability triage (Phase 9a) ----------------------------------------

def _maybe_triage(decision: AgentDecision, tr) -> Optional[dict]:
    """Classify the exploit primitive + severity of a confirmed/candidate crash.

    Read-only over the deciding tier's sanitizer/KASAN ``evidence_excerpt`` —
    adds no new trust, only structure. Proposer (Phase 9a): severity is a
    heuristic exploit-potential ranking, never a proof. Returns None when the
    disposition isn't crash-bearing or no sanitizer evidence is present.
    """
    if decision.disposition not in ("confirmed", "candidate", "bmc_unsafe"):
        return None
    chosen = None
    for a in tr.attempts:
        rv = a.raw_verdict or {}
        if rv.get("evidence_excerpt"):
            if rv.get("verdict") == "crash":
                chosen = rv
                break
            chosen = chosen or rv
    if not chosen:
        return None
    try:
        from exploit.triage import triage_from_text
        from schemas.reproducer import crash_signature
        sig = crash_signature(chosen.get("sanitizer"), chosen.get("crash_class"),
                              chosen.get("location"))
        return triage_from_text(chosen["evidence_excerpt"], unit=tr.hypothesis_id,
                                signature=sig).to_dict()
    except Exception as e:  # triage must never break the loop
        return {"primitive": "error", "error": repr(e)}


# --- Public entrypoint -------------------------------------------------------

def agent_step(
    c: Candidate,
    *,
    budget=None,
    dispatcher: Optional[Any] = None,
    client: Optional[llm_client.LLMClient] = None,
    allow_rule_fallback: bool = True,
) -> AgentResult:
    """Run the closed loop for one candidate.

    Sequence:
      1. Assemble Hypothesis from Candidate.
      2. Route → verdict.
      3. If candidate.refine is set and verdict ∈ apply_on, refine via
         Stage-B contract synthesis and re-decide.
      4. Emit final disposition (confirmed | pruned | candidate |
         inconclusive | no_dispatch) with the PoV path when available.
    """
    t0 = time.monotonic()
    hyp = _hyp_from_candidate(c)
    tr = router_mod.route(hyp, budget=budget, dispatcher=dispatcher)
    decision = _decision_from_route(tr)
    decision, ref = _maybe_refine(
        c, decision, tr.final_verdict,
        client=client, allow_rule_fallback=allow_rule_fallback,
    )
    repro = _maybe_score_reproducibility(c, decision)
    triage = _maybe_triage(decision, tr)
    total_ms = int((time.monotonic() - t0) * 1000)
    return AgentResult(
        candidate_id=c.cid,
        decision=decision,
        route_trace=tr.to_dict(),
        refinement=ref,
        total_wall_ms=total_ms,
        reproducibility=repro,
        triage=triage,
    )


def _candidate_from_json(d: dict) -> Candidate:
    return Candidate(
        cid=d["cid"],
        description=d.get("description", ""),
        class_hint=d.get("class_hint", "crash"),
        tier1_fuzz=d.get("tier1_fuzz"),  # may carry extra_cflags for live-lib link
        tier1_replay=d.get("tier1_replay"),
        tier1_kasan=d.get("tier1_kasan"),
        tier2_klee=d.get("tier2_klee"),
        tier2_angr=d.get("tier2_angr"),
        tier3_cbmc=d.get("tier3_cbmc"),
        refine=d.get("refine"),
        repro=d.get("repro"),
    )


# --- CLI ---------------------------------------------------------------------

def _cli() -> int:
    import argparse
    ap = argparse.ArgumentParser(description="Phase 4.1 closed agent loop.")
    ap.add_argument("--candidates", required=True,
                    help="JSON file: single Candidate or list of Candidates.")
    ap.add_argument("--out", required=True,
                    help="Write one JSONL row per candidate.")
    ap.add_argument("--summary", default=None,
                    help="Optional JSON summary (counts by disposition).")
    ap.add_argument("--dispatcher", default="heuristic",
                    choices=("heuristic", "llm"),
                    help="Router tier ordering policy.")
    args = ap.parse_args()

    data = json.loads(Path(args.candidates).read_text())
    cands = [data] if isinstance(data, dict) else list(data)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)

    dispatcher = None
    if args.dispatcher == "llm":
        from agent.router_llm import LLMDispatcher
        dispatcher = LLMDispatcher()

    rows = []
    with out.open("w") as fh:
        for d in cands:
            c = _candidate_from_json(d)
            r = agent_step(c, dispatcher=dispatcher)
            row = r.to_dict()
            fh.write(json.dumps(row) + "\n")
            rows.append(row)
            print(f"{c.cid}: {r.decision.disposition} — {r.decision.reason} "
                  f"(wall_ms={r.total_wall_ms}, "
                  f"refine={r.refinement.invoked} "
                  f"final={r.refinement.final_verdict or '-'})")

    if args.summary:
        by_disp: dict[str, int] = {}
        for r in rows:
            d = r["decision"]["disposition"]
            by_disp[d] = by_disp.get(d, 0) + 1
        Path(args.summary).write_text(json.dumps({
            "candidates": len(rows),
            "by_disposition": by_disp,
        }, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(_cli())
