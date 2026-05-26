"""LLM-synthesized KLEE symbolic drivers + constraint hints (Phase 3.2).

Produces a small C file that:
  1. declares the target's inputs symbolic via `klee_make_symbolic`,
  2. optionally adds `klee_assume(...)` constraint hints (cut path explosion),
  3. calls the target,
  4. has the property exposed so KLEE's `--exit-on-error-type` machinery
     stops on it.

The verdict is still `oracle/tier2_symbolic/klee_driver.run_klee` — the LLM
proposes the driver, KLEE decides sat/unsat. Symbolic SAT remains a Tier-1
reconfirm candidate per PLAN §8.

A rule-based fallback emits a generic driver for `T fn(T a, T b, ...)` style
functions when the gateway is down.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Optional

from llm.client import LLMClient, LLMUnavailable

log = logging.getLogger(__name__)


@dataclass
class SymbolicTarget:
    """Description of the function to wrap with KLEE symbolic inputs."""
    name: str
    signature: str                # "int divide(int n, int d)"
    source_snippet: str           # includes plus body
    property: str = "klee-default"  # informational; KLEE detects div/null/oob intrinsically
    constraint_hints: Optional[list[str]] = None   # ["d != 0", ...] caller-provided seeds
    description: str = ""
    # Symbols that must remain symbolic (no klee_assume that prunes them away).
    # If `property` = "div-by-zero", e.g. `must_not_assume=["d"]` blocks the
    # LLM from "helpfully" emitting `klee_assume(d != 0)` and assuming the bug
    # out of existence.
    must_not_assume: Optional[list[str]] = None


@dataclass
class DriverSynthResult:
    driver_c: str = ""
    source: str = "none"          # "llm" | "rule" | "none"
    raw_response: str = ""
    tokens_used: int = 0
    latency_s: float = 0.0
    error: Optional[str] = None
    rejected_reason: Optional[str] = None


SYSTEM_PROMPT = """You are an expert C verification engineer assisting KLEE
(symbolic execution under klee-uclibc + POSIX models).

You will receive:
  * a C source snippet defining the target function under test,
  * the function's name and signature,
  * a property string,
  * optional caller-provided constraint hints (klee_assume bodies).

Write a complete KLEE driver C file that:
  * `#include <klee/klee.h>` and any standard headers it needs,
  * pastes the target source verbatim,
  * defines `int main(void)` that:
      - declares each input variable,
      - calls `klee_make_symbolic(&var, sizeof(var), "var")` per input,
      - emits `klee_assume(<expr>);` for each constraint hint provided,
      - calls the target,
      - returns 0.

The property of interest is observed via KLEE's built-in error reporters
(div-by-zero, ptr, free, overflow, assert) — DO NOT write `klee_assert` unless
the caller explicitly asks for one; the engine catches the canonical bugs
automatically.

DO NOT add any klee_assume that would prevent the bug-of-interest from firing
(e.g. if the property is div-by-zero on `d`, do NOT emit klee_assume(d != 0)).
Any symbol listed under "must remain free" in the prompt is OFF LIMITS for
klee_assume — both directly and indirectly via arithmetic identities. Only
emit the constraint_hints the caller provided.

Output: ONLY the C source, beginning with `#include`. No markdown, no prose.
"""


_BANNED_CALLS = (
    "system(", "exec(", "execve(", "execvp(", "execl(", "execlp(", "execv(",
    "fork(", "popen(", "socket(", "fopen(",
)


_KLEE_ASSUME_RE = re.compile(r"klee_assume\s*\(([^)]*)\)")


def _filter_driver(text: str, *, must_not_assume: Optional[list[str]] = None
                   ) -> tuple[Optional[str], Optional[str]]:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        lines = cleaned.splitlines()[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        cleaned = "\n".join(lines).strip()
    if "#include" not in cleaned:
        return None, "no #include"
    if "klee_make_symbolic" not in cleaned:
        return None, "no klee_make_symbolic call"
    if "int main" not in cleaned:
        return None, "no main"
    for b in _BANNED_CALLS:
        if b in cleaned:
            return None, f"banned call {b!r}"
    # Reject klee_assume bodies that reference an off-limits symbol — the LLM
    # cannot prune away the bug-of-interest via a "helpful" constraint.
    if must_not_assume:
        for m in _KLEE_ASSUME_RE.finditer(cleaned):
            body = m.group(1)
            for sym in must_not_assume:
                if re.search(rf"\b{re.escape(sym)}\b", body):
                    return None, f"klee_assume mentions must-not-assume symbol {sym!r}: {body.strip()!r}"
    return cleaned, None


# ---------------------------------------------------------------------------
# Rule-based fallback.
# ---------------------------------------------------------------------------

# Minimal signature parser for `RET FN ( ARG1, ARG2, ... )`.
_SIG_RE = re.compile(r"^\s*[A-Za-z_][\w\s\*]*\b([A-Za-z_]\w*)\s*\((.*)\)\s*$")


def _parse_args(sig: str) -> list[tuple[str, str]]:
    m = _SIG_RE.match(sig.strip().rstrip(";"))
    if not m:
        return []
    args = m.group(2).strip()
    if args in ("", "void"):
        return []
    out: list[tuple[str, str]] = []
    for a in [s.strip() for s in args.split(",")]:
        parts = a.rsplit(" ", 1)
        if len(parts) != 2:
            return []
        ty, nm = parts[0].strip(), parts[1].lstrip("*").strip()
        if not nm or not ty:
            return []
        # We only support primitive non-pointer args in the rule path —
        # pointers need length pairing the LLM can do but the rule can't.
        if "*" in ty or "[" in a or "[" in nm:
            return []
        out.append((ty, nm))
    return out


def rule_based_driver(t: SymbolicTarget) -> DriverSynthResult:
    m = _SIG_RE.match(t.signature.strip().rstrip(";"))
    if not m:
        return DriverSynthResult(source="rule", error="rule_unsupported_signature",
                                 raw_response=f"rule path cannot parse {t.signature!r}")
    fn_name = m.group(1)
    args = _parse_args(t.signature)
    if not args:
        return DriverSynthResult(source="rule", error="rule_unsupported_signature",
                                 raw_response=f"rule path cannot parse args of {t.signature!r}")
    decls = "\n    ".join(f"{ty} {nm};" for ty, nm in args)
    syms = "\n    ".join(
        f'klee_make_symbolic(&{nm}, sizeof({nm}), "{nm}");' for _, nm in args
    )
    hints = ""
    if t.constraint_hints:
        hints = "\n    " + "\n    ".join(
            f"klee_assume({h});" for h in t.constraint_hints
        )
    call_args = ", ".join(nm for _, nm in args)
    body = f"""\
#include <klee/klee.h>

{t.source_snippet.strip()}

int main(void) {{
    {decls}
    {syms}{hints}
    (void){fn_name}({call_args});
    return 0;
}}
"""
    return DriverSynthResult(driver_c=body, source="rule",
                             raw_response=f"rule: primitive-arg wrapper for {fn_name}")


# ---------------------------------------------------------------------------
# LLM-driven synthesis with rule fallback.
# ---------------------------------------------------------------------------

def _build_prompt(t: SymbolicTarget) -> str:
    hints = "\n".join(f"  - {h}" for h in (t.constraint_hints or [])) or "  (none)"
    no_assume = ", ".join(t.must_not_assume or []) or "(none)"
    return (
        f"# Target: {t.name}\n"
        f"# Signature: {t.signature}\n"
        f"# Property of interest: {t.property}\n"
        f"# Must remain free (DO NOT klee_assume on these): {no_assume}\n"
        f"# Caller's allowed constraint hints:\n{hints}\n"
        f"# Context: {t.description or '(none)'}\n\n"
        "## Source\n```c\n"
        f"{t.source_snippet.strip()}\n"
        "```\n\n"
        "Emit the complete KLEE driver now."
    )


def synthesize(
    t: SymbolicTarget,
    *,
    client: Optional[LLMClient] = None,
    max_tokens: int = 768,
    allow_rule_fallback: bool = True,
) -> DriverSynthResult:
    client = client or LLMClient()
    try:
        r = client.chat(system=SYSTEM_PROMPT, user=_build_prompt(t),
                        role="synthesizer", max_tokens=max_tokens, temperature=0.0)
    except LLMUnavailable as e:
        log.info("LLM unavailable (%s); using rule-based driver", e)
        if not allow_rule_fallback:
            return DriverSynthResult(error=str(e))
        rb = rule_based_driver(t)
        rb.error = str(e)
        return rb

    driver, why = _filter_driver(r.text, must_not_assume=t.must_not_assume)
    if driver is None:
        log.info("LLM driver rejected (%s); falling back to rule", why)
        if allow_rule_fallback:
            rb = rule_based_driver(t)
            rb.tokens_used = r.total_tokens
            rb.latency_s = r.latency_s
            rb.raw_response = f"LLM rejected ({why}); rule: {rb.raw_response}"
            rb.rejected_reason = why
            return rb
        return DriverSynthResult(source="none", raw_response=r.text,
                                 tokens_used=r.total_tokens, latency_s=r.latency_s,
                                 rejected_reason=why)
    return DriverSynthResult(driver_c=driver, source="llm",
                             raw_response=r.text, tokens_used=r.total_tokens,
                             latency_s=r.latency_s)
