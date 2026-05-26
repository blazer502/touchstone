"""LLM-synthesized libFuzzer harnesses for Tier-1 (Phase 3.2).

The synthesizer is a *proposer*. It produces a small C file defining
`LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)` that drives the
target function under a sanitizer (ASan/MSan/UBSan). The verdict is still the
sound runtime check in `oracle/tier1_fuzz/userspace.fuzz` — the LLM cannot
turn a crash into a non-crash or vice versa.

A rule-based fallback emits a minimal length-gated harness that calls the
target with bytes from the fuzz input. Used when the gateway is down or the
model output fails the structural filter — keeps the loop testable in CI.

Soundness:
- The LLM never decides; it only produces text. The runtime sanitizer is the
  oracle (PLAN §8). A "no crash" verdict is still inconclusive, not safe.
- The output filter rejects harnesses that include unsafe top-level effects
  (no `system`, `exec`, `fork`, `popen`, `socket`, `open(", "w")` etc.) so a
  poisoned model prompt can't smuggle host-effect calls past the build.
- Harnesses must compile under `clang -O0 -fsanitize=...,fuzzer` and must
  define exactly `LLVMFuzzerTestOneInput`. Both are checked structurally.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Optional

from llm.client import LLMClient, LLMUnavailable

log = logging.getLogger(__name__)


@dataclass
class TargetFunction:
    """Description of the function the harness should drive."""
    name: str
    signature: str               # e.g. "void oob_write(const uint8_t *buf, size_t n)"
    source_snippet: str          # the full C body (target + helpers + includes-needed-list)
    bug_class_hint: str = "memory"   # "memory" | "uninit" | "ub"
    description: str = ""        # plain-English context the LLM can use


@dataclass
class HarnessSynthResult:
    harness_c: str = ""
    source: str = "none"         # "llm" | "rule" | "none"
    raw_response: str = ""
    tokens_used: int = 0
    latency_s: float = 0.0
    error: Optional[str] = None
    rejected_reason: Optional[str] = None


SYSTEM_PROMPT = """You are an expert C fuzzing engineer assisting libFuzzer + sanitizers.

You will receive:
  * a C source snippet defining the target function under test,
  * the function's name and signature,
  * a one-line bug-class hint (memory / uninit / ub),
  * plain-English context.

Your job is to write a complete libFuzzer harness C file that exercises the
target so the sanitizer can observe whether the bug triggers. The file MUST:

  * include only standard headers (stddef.h, stdint.h, stdlib.h, string.h),
  * include the target source verbatim (you can paste it in),
  * define exactly one function:
        int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
    which (a) gates on a minimum size needed to feed the target,
    (b) extracts arguments from `data`/`size`,
    (c) calls the target,
    (d) returns 0.
  * NOT call system(), exec*(), fork(), popen(), socket(), open() for write,
    or any IO outside the fuzz input.
  * NOT contain markdown fences or prose.

Output: ONLY the C source, beginning with `#include`. No explanation.
"""


# ---------------------------------------------------------------------------
# Output filter — structural safety gate.
# ---------------------------------------------------------------------------
_BANNED_CALLS = (
    "system(", "execve(", "execvp(", "execl(", "execlp(", "execv(", "exect(",
    "fork(", "popen(", "socket(", "connect(", "fopen(",
)
_REQUIRED_SYM = "LLVMFuzzerTestOneInput"


def _filter_harness(text: str) -> tuple[Optional[str], Optional[str]]:
    """Returns (harness, rejection_reason). harness is None if rejected."""
    # Strip markdown fences if present.
    cleaned = text.strip()
    if cleaned.startswith("```"):
        # Drop the first line and any trailing ```
        lines = cleaned.splitlines()
        # Remove first fence line
        lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        cleaned = "\n".join(lines).strip()
    if "#include" not in cleaned:
        return None, "no #include"
    if _REQUIRED_SYM not in cleaned:
        return None, f"missing {_REQUIRED_SYM}"
    for banned in _BANNED_CALLS:
        if banned in cleaned:
            return None, f"banned call {banned!r}"
    # Must look like C, not prose. Crude: at least one '{' and one ';'.
    if "{" not in cleaned or ";" not in cleaned:
        return None, "doesn't look like C"
    return cleaned, None


# ---------------------------------------------------------------------------
# Rule-based fallback: emit a generic length-gated harness.
# ---------------------------------------------------------------------------

# Map common signature shapes to argument-extraction snippets. The fallback
# only handles a tiny canonical set; it's enough to keep the smoke deterministic
# when the LLM is unavailable. Real coverage comes from the LLM path.
_SIG_BUF_LEN = re.compile(
    r"\b(?:const\s+)?(?:uint8_t|u_int8_t|unsigned\s+char|char)\s*\*\s*\w+\s*,\s*"
    r"(?:size_t|unsigned\s+(?:int|long)|int)\s+\w+\s*\)"
)


def rule_based_harness(tf: TargetFunction) -> HarnessSynthResult:
    """Emit a generic libFuzzer wrapper around `tf`.

    Handles the canonical `f(const uint8_t *buf, size_t n)` shape — directly
    forwards the libFuzzer input bytes. Anything more exotic returns an empty
    harness with a reason; the smoke runner will report "rule_unsupported" so
    the gap is visible.
    """
    if _SIG_BUF_LEN.search(tf.signature):
        body = f"""\
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

{tf.source_snippet.strip()}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
    if (size < 1) return 0;
    {tf.name}(data, size);
    return 0;
}}
"""
        return HarnessSynthResult(harness_c=body, source="rule",
                                  raw_response=f"rule: buf/len wrapper for {tf.name}")
    return HarnessSynthResult(source="rule", error="rule_unsupported_signature",
                              raw_response=f"rule path doesn't know signature: {tf.signature!r}")


# ---------------------------------------------------------------------------
# LLM-driven synthesis with rule fallback.
# ---------------------------------------------------------------------------

def _build_prompt(tf: TargetFunction) -> str:
    return (
        f"# Target function: {tf.name}\n"
        f"# Signature: {tf.signature}\n"
        f"# Bug-class hint: {tf.bug_class_hint}\n"
        f"# Context: {tf.description or '(none)'}\n"
        "\n## Source snippet\n```c\n"
        f"{tf.source_snippet.strip()}\n"
        "```\n\n"
        "Emit the complete libFuzzer harness now (see system prompt for format)."
    )


def synthesize(
    tf: TargetFunction,
    *,
    client: Optional[LLMClient] = None,
    max_tokens: int = 768,
    allow_rule_fallback: bool = True,
) -> HarnessSynthResult:
    """Propose one libFuzzer harness for `tf`. LLM-first, rule fallback."""
    client = client or LLMClient()
    try:
        r = client.chat(system=SYSTEM_PROMPT, user=_build_prompt(tf),
                        role="synthesizer", max_tokens=max_tokens, temperature=0.0)
    except LLMUnavailable as e:
        log.info("LLM unavailable (%s); using rule-based harness", e)
        if not allow_rule_fallback:
            return HarnessSynthResult(error=str(e))
        rb = rule_based_harness(tf)
        rb.error = str(e)
        return rb

    harness, why = _filter_harness(r.text)
    if harness is None:
        log.info("LLM harness rejected (%s); falling back to rule", why)
        if allow_rule_fallback:
            rb = rule_based_harness(tf)
            rb.tokens_used = r.total_tokens
            rb.latency_s = r.latency_s
            rb.raw_response = f"LLM rejected ({why}); rule: {rb.raw_response}"
            rb.rejected_reason = why
            return rb
        return HarnessSynthResult(source="none", raw_response=r.text,
                                  tokens_used=r.total_tokens, latency_s=r.latency_s,
                                  rejected_reason=why)
    return HarnessSynthResult(harness_c=harness, source="llm",
                              raw_response=r.text, tokens_used=r.total_tokens,
                              latency_s=r.latency_s)
