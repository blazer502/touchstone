"""LLM-synthesized CBMC harnesses for Tier-3 (Phase 3.2).

Sits on top of `oracle/tier3_bmc/assertions.Hypothesis` — the LLM proposes the
preconditions and the property assertion, the existing `assertions.synthesize`
renders them into a CBMC harness, the existing `cbmc_driver.run_cbmc_oracle`
decides safe/unsafe/inconclusive.

The verdict still comes from CBMC (PLAN §8). The LLM only proposes the
property + assumptions; CBMC structurally rejects tautologies (`__CPROVER_assert(1)`
won't fail), and the loop here additionally drops degenerate assumptions
(`1 == 0`, `false`, empty body) that would assume the bug away.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Optional

from llm.client import LLMClient, LLMUnavailable
from .assertions import Hypothesis

log = logging.getLogger(__name__)


@dataclass
class BmcTarget:
    """Caller's view of a Tier-3 target."""
    name: str                       # short id for the harness
    includes: list[str]             # e.g. ["stdint.h"]
    source: str                     # target C source
    function_under_test: str        # e.g. "write_at"
    inputs: list[tuple[str, str]]   # [(type, name), ...]
    invocation: str                 # exact call: "write_at(i, v);"
    property_description: str       # plain English, e.g. "i must be strictly < N"
    seed_property: Optional[str] = None  # caller-supplied __CPROVER_assert expression
    seed_preconditions: Optional[list[str]] = None


@dataclass
class BmcHarnessSynthResult:
    hypothesis: Optional[Hypothesis] = None
    source: str = "none"            # "llm" | "rule" | "none"
    raw_response: str = ""
    tokens_used: int = 0
    latency_s: float = 0.0
    error: Optional[str] = None
    rejected_reason: Optional[str] = None


SYSTEM_PROMPT = """You are an expert C verification engineer assisting CBMC
(bounded model checking).

You will receive:
  * a target function and its C source,
  * the inputs it should be called with (already declared symbolic),
  * the exact invocation statement,
  * a plain-English description of the property of interest.

Your job is to emit ONE JSON object on a single line with two fields:
  {
    "preconditions": ["<C expr 1>", "<C expr 2>", ...],
    "assertion": "<C expression that should hold>"
  }

Rules:
  * Each precondition expression goes into `__CPROVER_assume(<expr>);`.
  * The assertion goes into `__CPROVER_assert(<expr>, "..."); — pick the
    *property* the caller asked about, not a tautology and not
    "the bug doesn't fire". For example, if the description says "i must be
    strictly < N", emit "i < N", not "1" and not "i != N".
  * Preconditions must be plausible caller contracts ("len <= CAP", "ptr != NULL").
    NEVER emit "0", "false", or "1 == 0" — those would assume the bug away.
  * No prose. No markdown. Only the JSON object.
"""


def _filter_proposal(text: str) -> tuple[Optional[dict], Optional[str]]:
    """Pull the JSON object out of the model's reply and screen it."""
    cleaned = text.strip()
    if cleaned.startswith("```"):
        # Drop fence and possibly a "json" language tag.
        lines = cleaned.splitlines()[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        cleaned = "\n".join(lines).strip()
    # Take the first {...} block.
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start < 0 or end <= start:
        return None, "no JSON object"
    snippet = cleaned[start:end + 1]
    try:
        obj = json.loads(snippet)
    except json.JSONDecodeError as e:
        return None, f"json decode: {e.msg}"
    if not isinstance(obj, dict):
        return None, "not an object"
    pres = obj.get("preconditions", [])
    asn = obj.get("assertion", "")
    if not isinstance(pres, list) or not all(isinstance(p, str) for p in pres):
        return None, "preconditions not list[str]"
    if not isinstance(asn, str) or not asn.strip():
        return None, "missing assertion"
    # Reject degenerate.
    degenerate = {"", "0", "1 == 0", "false", "1==0"}
    for p in pres:
        if p.strip() in degenerate:
            return None, f"degenerate precondition {p!r}"
    if asn.strip() in {"1", "true", "0 == 0"}:
        return None, f"tautological assertion {asn!r}"
    return obj, None


def _hypothesis_from(t: BmcTarget, *, preconditions: list[str], assertion: str,
                     msg: str) -> Hypothesis:
    return Hypothesis(
        name=t.name,
        includes=list(t.includes),
        target_source=t.source,
        inputs=list(t.inputs),
        preconditions=preconditions,
        invocation=t.invocation,
        assertion=assertion,
        assertion_msg=msg,
    )


def rule_based_harness(t: BmcTarget) -> BmcHarnessSynthResult:
    """Build a Hypothesis from caller-supplied seed_property / seed_preconditions.

    The rule path doesn't *infer* properties — it just trusts the caller's
    seeds. That's enough to keep the loop deterministic when the LLM is down
    (the seed is hand-written for the smoke).
    """
    if not t.seed_property:
        return BmcHarnessSynthResult(source="rule", error="rule_unsupported_no_seed",
                                     raw_response="rule path requires seed_property")
    h = _hypothesis_from(t, preconditions=list(t.seed_preconditions or []),
                         assertion=t.seed_property,
                         msg=t.property_description or "property violation")
    return BmcHarnessSynthResult(hypothesis=h, source="rule",
                                 raw_response=f"rule: seed property {t.seed_property!r}")


def _build_prompt(t: BmcTarget) -> str:
    inp = ", ".join(f"{ty} {nm}" for ty, nm in t.inputs) or "(none)"
    seed_p = "; ".join(t.seed_preconditions or []) or "(none)"
    return (
        f"# Target function: {t.function_under_test}\n"
        f"# Inputs (already declared symbolic): {inp}\n"
        f"# Invocation: {t.invocation}\n"
        f"# Property (English): {t.property_description}\n"
        f"# Caller's seed preconditions: {seed_p}\n"
        f"# Caller's seed assertion: {t.seed_property or '(none)'}\n\n"
        "## Source\n```c\n"
        f"{t.source.strip()}\n"
        "```\n\n"
        "Emit one JSON object with `preconditions` and `assertion` now."
    )


def synthesize(
    t: BmcTarget,
    *,
    client: Optional[LLMClient] = None,
    max_tokens: int = 384,
    allow_rule_fallback: bool = True,
) -> BmcHarnessSynthResult:
    client = client or LLMClient()
    try:
        r = client.chat(system=SYSTEM_PROMPT, user=_build_prompt(t),
                        role="synthesizer", max_tokens=max_tokens, temperature=0.0)
    except LLMUnavailable as e:
        log.info("LLM unavailable (%s); using rule-based harness", e)
        if not allow_rule_fallback:
            return BmcHarnessSynthResult(error=str(e))
        rb = rule_based_harness(t)
        rb.error = str(e)
        return rb

    obj, why = _filter_proposal(r.text)
    if obj is None:
        log.info("LLM bmc proposal rejected (%s); falling back to rule", why)
        if allow_rule_fallback:
            rb = rule_based_harness(t)
            rb.tokens_used = r.total_tokens
            rb.latency_s = r.latency_s
            rb.raw_response = f"LLM rejected ({why}); rule: {rb.raw_response}"
            rb.rejected_reason = why
            return rb
        return BmcHarnessSynthResult(source="none", raw_response=r.text,
                                     tokens_used=r.total_tokens, latency_s=r.latency_s,
                                     rejected_reason=why)
    h = _hypothesis_from(t, preconditions=obj["preconditions"], assertion=obj["assertion"],
                         msg=t.property_description or "property violation")
    return BmcHarnessSynthResult(hypothesis=h, source="llm",
                                 raw_response=r.text, tokens_used=r.total_tokens,
                                 latency_s=r.latency_s)
