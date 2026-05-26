"""Helpers to assemble a Tier-3 BMC harness from a hypothesis.

A Tier-3 hypothesis is (location, property, triggering condition). At the BMC
level we encode it as a C harness that:

1. Declares the symbolic inputs (`__CPROVER_nondet_<type>()`),
2. Asserts the precondition / contract (`__CPROVER_assume(precondition)`),
3. Calls into the target function,
4. Asserts the property of interest (`__CPROVER_assert(property, msg)`).

The router (Phase 2.4) hands us those four pieces; we glue them into a small
self-contained C file. LLM-synthesized harnesses are a Phase 3.2 hook on top
of this generator — the generator itself is no-LLM.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional


@dataclass
class Hypothesis:
    """One BMC hypothesis (PLAN §3 Tier-3)."""
    name: str                    # short id, e.g. "off_by_one_oob"
    includes: list[str]          # C headers to include in the harness
    target_source: str           # C source body (functions under test)
    inputs: list[tuple[str, str]]  # [(type, name), ...] e.g. [("unsigned int", "i")]
    preconditions: list[str]     # __CPROVER_assume(...) expressions
    invocation: str              # C expression/statement calling into target
    assertion: str               # __CPROVER_assert expression (property)
    assertion_msg: str = "property violation"


def synthesize(h: Hypothesis) -> str:
    """Render a Hypothesis to a complete C harness string.

    Symbolic inputs are encoded as *uninitialized locals*, which CBMC treats
    as nondet — same effect as `__CPROVER_nondet_*()` but no extern decls to
    keep in sync with CBMC's builtin set.
    """
    inc = "\n".join(f"#include <{x}>" if not x.startswith("\"") else f"#include {x}"
                    for x in h.includes)
    decls = "\n    ".join(f"{ty} {nm};  /* nondet */" for ty, nm in h.inputs)
    pres = "\n    ".join(f"__CPROVER_assume({e});" for e in h.preconditions)
    return f"""/* Tier-3 BMC harness for hypothesis: {h.name} */
{inc}

{h.target_source}

int main(void) {{
    {decls}
    {pres}
    {h.invocation}
    __CPROVER_assert({h.assertion}, "{_escape(h.assertion_msg)}");
    return 0;
}}
"""


def _escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace("\"", "\\\"")


def write_harness(h: Hypothesis, dest: Path) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(synthesize(h))
    return dest
