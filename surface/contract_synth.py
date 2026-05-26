"""LLM-synthesized ACSL contracts + loop invariants for Stage B (Phase 3.1).

PLAN §2:
  synthesizer generates function contracts (ACSL for Frama-C), loop invariants,
  and stubs for callees; the sound engine validates; counterexamples are
  returned to the LLM for repair. Cap refinement iterations per function.

This module is the *proposer*. It never decides safe/unsafe — it only emits
candidate `__CPROVER_assume(...)` precondition strings (CBMC) or ACSL
`requires/loop invariant` strings (Frama-C). The verdict still comes from the
sound engine in `surface/stage_b.py`. Every proposed contract is recorded in
the verdict's `assumed_contracts` field and feeds into the Phase 1.4 proof
cache key — so a cache hit on an LLM-proven safe verdict is only valid when
the same contracts are still claimed.

A *rule-based* fallback synthesizer is kept alongside the LLM one. The fallback
extracts the bound-violating input value from a CBMC trace and emits an
obvious upper-bound assumption. It exists so the refinement loop is testable
even when the gateway is down — and so Phase 3.1's smoke is deterministic.
The LLM path is exercised when the gateway answers.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Optional

from llm.client import LLMClient, LLMUnavailable

log = logging.getLogger(__name__)


@dataclass
class SynthResult:
    """A round of synthesis: zero or more candidate contracts plus provenance."""
    contracts: list[str] = field(default_factory=list)
    source: str = ""              # "llm" | "rule" | "none"
    raw_response: str = ""
    tokens_used: int = 0
    latency_s: float = 0.0
    error: Optional[str] = None


# Allowed contract leading tokens. Anything else from the LLM is dropped — keeps
# us from accidentally executing arbitrary C the LLM wrote into the prompt.
_CONTRACT_PREFIXES = (
    "__CPROVER_assume(",
    "__CPROVER_loop_invariant(",
    "__CPROVER_assert(",
)


SYSTEM_PROMPT = """You are an expert C verification engineer assisting a CBMC bounded model checker.

You will receive:
  * the C source under verification,
  * the target function and property (e.g. memory-safety, no-oob),
  * the CBMC counterexample or unwinding-assertion failure from a prior run,
  * any contracts that were already in scope but failed to prove the property.

Your job is to propose ONE additional precondition that, if true, would
soundly eliminate the counterexample. The precondition MUST be a property the
calling context can plausibly guarantee — e.g. "len <= CAP" where CAP is a
buffer size, or "n <= 32" where 32 is a reasonable upper bound based on the
data structure. Do NOT propose conditions that simply assume the bug away
(e.g. "1 == 0" or "i != crash_index").

Reply with ONLY one line of the form:
  __CPROVER_assume(<C-expression>);
or one line of the form:
  __CPROVER_loop_invariant(<C-expression>);
No prose, no markdown, no triple backticks. If you cannot propose a sound
precondition, reply with the single token NONE.
"""


def _build_prompt(
    *,
    source: str,
    function: str,
    property: str,
    counterexample: str,
    prior_contracts: list[str],
    iter_index: int,
) -> str:
    parts = [
        f"# Target function: {function}",
        f"# Property: {property}",
        f"# Iteration: {iter_index}",
        "",
        "## Source",
        "```c",
        source.strip(),
        "```",
        "",
        "## Prior contracts (already in scope; insufficient on their own)",
    ]
    if prior_contracts:
        for c in prior_contracts:
            parts.append(f"  {c}")
    else:
        parts.append("  (none)")
    parts += [
        "",
        "## CBMC counterexample / failure (last 40 lines)",
        "```",
        "\n".join(counterexample.splitlines()[-40:]).strip(),
        "```",
        "",
        "Propose one precondition (see system prompt for format).",
    ]
    return "\n".join(parts)


def _extract_contract_lines(text: str) -> list[str]:
    """Pull contract lines from the model's output.

    The model is instructed to reply with a single line, but we are tolerant:
    accept any line that begins with one of `_CONTRACT_PREFIXES` and ends with
    `);`. Strip backticks/code-fences if present.
    """
    out: list[str] = []
    for raw in text.splitlines():
        line = raw.strip().strip("`").strip()
        # Allow a stray '// ...' comment tail but only on the contract line.
        if "//" in line:
            line = line.split("//", 1)[0].strip()
        if not line or line.upper() == "NONE":
            continue
        if not line.endswith(";"):
            # The model sometimes drops the semicolon; tolerate it.
            if line.endswith(")"):
                line = line + ";"
        if not line.endswith(");"):
            continue
        if not line.startswith(_CONTRACT_PREFIXES):
            continue
        # Reject obviously degenerate contracts.
        body = line[line.index("(") + 1: line.rindex(")")].strip()
        if body in ("", "0", "1 == 0", "false"):
            continue
        out.append(line)
    # Dedup while preserving order.
    seen: set[str] = set()
    uniq = []
    for c in out:
        if c not in seen:
            uniq.append(c)
            seen.add(c)
    return uniq


# ---------------------------------------------------------------------------
# Rule-based fallback synthesizer
# ---------------------------------------------------------------------------

# CBMC's text trace prints "State <n> ... file <f>.c function <fn> line <ln>"
# followed by "  <var>=<value> (<bits>)" assignments. We mine the last unsigned
# integer assignment to extract a candidate bound: if `len=33u (...)` appears
# in the trace and the source mentions `len <= CAP` style buffers, propose
# `__CPROVER_assume(<var> <= <buffer_cap>)`.
_TRACE_ASSIGN = re.compile(r"^\s*([A-Za-z_]\w*)=(-?\d+)([uli]*).*$", re.MULTILINE)
_BUFFER_DECL = re.compile(r"#\s*define\s+([A-Z_][A-Z0-9_]*)\s+(\d+)")
_ARRAY_DECL = re.compile(r"\b(?:unsigned\s+char|char|int|uint8_t|uint16_t|uint32_t)\s+\w+\s*\[\s*([A-Z_][A-Z0-9_]*|\d+)\s*\]")


def rule_based_synth(
    *,
    source_text: str,
    counterexample: str,
    prior_contracts: list[str],
) -> SynthResult:
    """Emit a single `__CPROVER_assume(<var> <= <cap>)` when possible.

    This is the deterministic fallback used when the LLM endpoint is down. It
    handles the canonical buffer-bound case (`bounded_copy`-style) by finding
    a numeric input in the CBMC trace that exceeds a known buffer cap.
    """
    # Gather candidate caps from `#define NAME <int>` and `T arr[NAME]`.
    cap_map = {m.group(1): int(m.group(2)) for m in _BUFFER_DECL.finditer(source_text)}
    array_caps = []
    for m in _ARRAY_DECL.finditer(source_text):
        token = m.group(1)
        if token.isdigit():
            array_caps.append(int(token))
        elif token in cap_map:
            array_caps.append(cap_map[token])
    if not array_caps:
        return SynthResult(source="rule", raw_response="(no array cap found)")
    cap = max(array_caps)
    cap_name = None
    for name, val in cap_map.items():
        if val == cap:
            cap_name = name
            break

    # Find numeric assignments in the trace; prefer named vars that exceed cap.
    best: tuple[str, int] | None = None
    for m in _TRACE_ASSIGN.finditer(counterexample):
        var, val = m.group(1), int(m.group(2))
        if var in {"return", "ret", "RET", "result"}:
            continue
        if val > cap and (best is None or val > best[1]):
            best = (var, val)
    if best is None:
        return SynthResult(source="rule", raw_response="(no bound-violating var in trace)")

    rhs = cap_name if cap_name else str(cap)
    contract = f"__CPROVER_assume({best[0]} < {rhs});"
    if contract in prior_contracts:
        return SynthResult(source="rule", raw_response=f"(duplicate of prior: {contract})")
    return SynthResult(
        contracts=[contract],
        source="rule",
        raw_response=f"rule-based: {best[0]}={best[1]} > cap {rhs}={cap}",
    )


# ---------------------------------------------------------------------------
# LLM-driven synthesizer (with fallback)
# ---------------------------------------------------------------------------


def synthesize(
    *,
    source_text: str,
    function: str,
    property: str,
    counterexample: str,
    prior_contracts: list[str],
    iter_index: int,
    client: Optional[LLMClient] = None,
    max_tokens: int = 256,
    allow_rule_fallback: bool = True,
) -> SynthResult:
    """One round of contract synthesis. Returns at most one contract.

    The LLM call is attempted first via `client.chat()`. On `LLMUnavailable`
    (gateway not up / model not loaded), fall back to `rule_based_synth` if
    `allow_rule_fallback` is set — this keeps the refinement loop testable in
    CI and lets the smoke run deterministically.
    """
    client = client or LLMClient()
    prompt = _build_prompt(
        source=source_text, function=function, property=property,
        counterexample=counterexample, prior_contracts=prior_contracts,
        iter_index=iter_index,
    )
    try:
        result = client.chat(
            system=SYSTEM_PROMPT, user=prompt,
            role="synthesizer", max_tokens=max_tokens, temperature=0.0,
        )
    except LLMUnavailable as e:
        log.info("LLM unavailable (%s); attempting rule-based fallback", e)
        if allow_rule_fallback:
            r = rule_based_synth(
                source_text=source_text, counterexample=counterexample,
                prior_contracts=prior_contracts,
            )
            r.error = str(e)
            return r
        return SynthResult(source="none", error=str(e))

    contracts = _extract_contract_lines(result.text)
    # Drop duplicates of prior contracts.
    contracts = [c for c in contracts if c not in prior_contracts]

    # Keep only the first proposal — refinement loops one contract at a time so
    # we can attribute each safe/unsafe transition to a specific assumption.
    if contracts:
        contracts = contracts[:1]
    if not contracts and allow_rule_fallback:
        # LLM responded but produced no usable contract — try rule path too.
        rb = rule_based_synth(
            source_text=source_text, counterexample=counterexample,
            prior_contracts=prior_contracts,
        )
        if rb.contracts:
            rb.raw_response = f"LLM produced nothing usable: {result.text!r}; rule: {rb.raw_response}"
            rb.tokens_used = result.total_tokens
            rb.latency_s = result.latency_s
            return rb
    return SynthResult(
        contracts=contracts,
        source="llm",
        raw_response=result.text,
        tokens_used=result.total_tokens,
        latency_s=result.latency_s,
    )
