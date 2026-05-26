"""Phase-3.3 LLM-backed dispatcher for the router.

The Phase-2.4 router orders tier execution via a hand-coded heuristic
(`agent.router._dispatch_order`). Phase 3.3 adds a learned-classifier
alternative that proposes the same kind of ordering using the small
"router" LLM role served by the Phase-0.2 gateway.

Design constraints (PLAN §8 / soundness-assumptions.md):

  1. The dispatcher only chooses an *ordering*; it never replaces an engine
     verdict. Soundness still rides on the engines.

  2. Output is filtered through `agent.router._sanitize_order`: any tier the
     LLM lists that isn't populated is dropped; any populated tier the LLM
     omits is appended (so dropping a populated tier cannot weaken precision).

  3. On gateway error / malformed JSON / empty filtered list the dispatcher
     falls back to the heuristic order — never blocks on the LLM.

  4. Caller controls the *trigger* but not the verdict. Cost-weights from
     `config/budget.yaml` still cap the tier the agent loop will pay for.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from llm.client import LLMClient, LLMUnavailable

from agent.router import Hypothesis

_SYSTEM = (
    "You are the tier router for a vulnerability-discovery agent. "
    "Given a hypothesis and the set of available oracle tiers, pick the order "
    "to try them so the cheapest tier that can decide the hypothesis runs first.\n"
    "Tiers:\n"
    "  tier1_fuzz       (cheap; libFuzzer/AFL++ + sanitizers, KASAN replay)\n"
    "  tier2_symbolic   (medium; KLEE / angr feasibility)\n"
    "  tier3_bmc        (expensive; CBMC bounded proof / cex)\n"
    "Pick Tier-1 first when an exploitable runtime crash is plausible. "
    "Pick Tier-2 first when the question is path-reachability under a constraint. "
    "Pick Tier-3 first when the property is small + bounded and a proof is desired.\n"
    'Reply with exactly one JSON object: {"order": ["tier1_fuzz", "tier2_symbolic", "tier3_bmc"], '
    '"reason": "<one short sentence>"}. Use only tier names from the "available" list provided. '
    "No prose, no code fences."
)


_FENCE_RE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL)
_OBJ_RE = re.compile(r"\{[^{}]*\}", re.DOTALL)


def _extract_json(text: str) -> Optional[dict]:
    """Pull the first plausible JSON object out of the model reply.

    The smoke models tend to wrap JSON in code fences or add a preamble; this
    handles both. Returns None on any parse failure — the dispatcher then
    falls back to the heuristic.
    """
    if not text:
        return None
    m = _FENCE_RE.search(text)
    if m:
        try:
            return json.loads(m.group(1))
        except json.JSONDecodeError:
            pass
    try:
        return json.loads(text.strip())
    except json.JSONDecodeError:
        pass
    for m2 in _OBJ_RE.finditer(text):
        try:
            return json.loads(m2.group(0))
        except json.JSONDecodeError:
            continue
    return None


def _summarize_hypothesis(hyp: Hypothesis, available: list[str]) -> str:
    """Compact, JSON-shaped description handed to the router model."""
    populated = {}
    if hyp.tier1_fuzz is not None:
        populated["tier1_fuzz"] = {"kind": "fuzz", "harness": hyp.tier1_fuzz.harness_src,
                                   "sanitizer": hyp.tier1_fuzz.sanitizer}
    if hyp.tier1_replay is not None:
        populated.setdefault("tier1_fuzz", {})["replay_poc"] = hyp.tier1_replay.poc_path
    if hyp.tier1_kasan is not None:
        populated.setdefault("tier1_fuzz", {})["kasan_log"] = hyp.tier1_kasan.dmesg_path
    if hyp.tier2_klee is not None:
        populated["tier2_symbolic"] = {"engine": "klee", "source": hyp.tier2_klee.source}
    elif hyp.tier2_angr is not None:
        populated["tier2_symbolic"] = {"engine": "angr", "binary": hyp.tier2_angr.binary,
                                       "target": hyp.tier2_angr.target}
    if hyp.tier3_cbmc is not None:
        populated["tier3_bmc"] = {"engine": "cbmc", "source": hyp.tier3_cbmc.source,
                                  "property": hyp.tier3_cbmc.property,
                                  "unwind": hyp.tier3_cbmc.unwind}
    payload = {
        "hid": hyp.hid,
        "description": hyp.description,
        "class_hint": hyp.class_hint,
        "available": available,
        "populated": populated,
    }
    return json.dumps(payload, indent=2)


@dataclass
class LLMDispatchTrace:
    """Optional bookkeeping the caller can attach for metrics."""
    used_llm: bool = False
    proposal: list[str] = field(default_factory=list)
    reason: str = ""
    tokens: int = 0
    latency_s: float = 0.0
    error: Optional[str] = None


@dataclass
class LLMDispatcher:
    """Callable ``(Hypothesis, available) -> list[str]`` backed by the router LLM.

    The dispatcher is *stateless across calls* but accumulates trace entries on
    ``self.traces`` so the metrics adapter can read per-hypothesis stats after a
    batch route.
    """
    client: Optional[LLMClient] = None
    max_tokens: int = 128
    temperature: float = 0.0
    role: str = "router"
    traces: list[LLMDispatchTrace] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.client is None:
            self.client = LLMClient(default_role=self.role)

    def __call__(self, hyp: Hypothesis, available: list[str]) -> list[str]:
        tr = LLMDispatchTrace()
        self.traces.append(tr)
        if len(available) <= 1:
            # Nothing to route — let the sanitizer fall through to the heuristic.
            tr.proposal = list(available)
            tr.reason = "single-tier hypothesis"
            return tr.proposal
        try:
            user = _summarize_hypothesis(hyp, available)
            res = self.client.chat(
                _SYSTEM, user, role=self.role,
                max_tokens=self.max_tokens, temperature=self.temperature,
            )
        except LLMUnavailable as e:
            tr.error = f"gateway: {e}"
            return []
        tr.used_llm = True
        tr.tokens = res.total_tokens
        tr.latency_s = res.latency_s
        obj = _extract_json(res.text)
        if not isinstance(obj, dict):
            tr.error = "no JSON object in reply"
            return []
        order = obj.get("order")
        if isinstance(order, list):
            tr.proposal = [t for t in order if isinstance(t, str)]
        tr.reason = obj.get("reason", "") if isinstance(obj.get("reason", ""), str) else ""
        return tr.proposal


# Functional shorthand: a one-shot dispatcher when the caller doesn't want to
# manage trace state. Keeps the same callable signature.
def llm_dispatcher() -> Callable[[Hypothesis, list[str]], list[str]]:
    d = LLMDispatcher()
    def _call(hyp: Hypothesis, available: list[str]) -> list[str]:
        return d(hyp, available)
    _call.traces = d.traces  # type: ignore[attr-defined]
    return _call
