"""Phase 5.1 — Callsite + guard extractor for spec mining (PLAN §3b.1).

For each callee F defined within the target tree, harvest every callsite and
its preceding guard chain in the caller. The output is a per-callee ledger
that Phase 5.2 will cluster into mined contracts and 5.2's outlier extractor
will mine for callsites that diverge from the dominant guard pattern.

Guard kinds extracted:

  - enclosing_if / enclosing_while / enclosing_for / enclosing_switch:
    constructs whose body lexically contains the callsite. The predicate
    is the parenthesised condition; polarity = "in_true_branch" or
    "in_false_branch" if the callsite is in an else clause.
  - lock_acquire: prior call to a recognised lock-acquire primitive (mutex_lock,
    spin_lock*, rcu_read_lock*, read_lock*, write_lock*, down_*, ...)
    → predicate canonicalised as "lock_held(<arg>)".
  - lock_assert: explicit assertion of lock state earlier in the function
    (lockdep_assert_held, rcu_read_lock_held, mutex_is_locked, ...).
  - capability_check: prior `if (!capable(X)) return ...;` (or ns_capable/
    file_ns_capable) → capable(X) established.
  - null_check: `if (!x || IS_ERR(x)) return/goto` patterns at function-top
    level before the callsite → x is non-NULL, non-err.
  - early_return: any `if (P) return/goto/break/continue;` at the same brace
    depth, earlier in the function → !P established at the callsite.
  - assert_neg: `BUG_ON(P)` (kernel) or `assert(!P)` earlier → !P established.

Sound-mining note (PLAN §3b, §8): this is the *proposer* leg of Component (3).
Mined contracts (Phase 5.2) and outliers built on top of these guards are
*conjectures* until verified by Stage B (forward proof) and Tier 2/3 (backward
refutation) in Phase 5.3. Over-detecting a guard here makes the mining noisier
but never unsound — the soundness gate is downstream, and final verdict
authority stays with the sound checker.

Reuses surface/reachability.py:
  - list_c_sources, ctags_function_starts, parse_function_bodies
  - CALL_BLACKLIST (we skip these as "callees" — they're macros / control kw)

No LLM (Phase 5 rule for 5.1).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from collections import defaultdict
from pathlib import Path

from surface.reachability import (
    CALL_BLACKLIST,
    ctags_function_starts,
    list_c_sources,
    parse_function_bodies,
)


# --------------------------------------------------------------------------- #
# Guard-recognition regexes
# --------------------------------------------------------------------------- #

# Lock acquires whose effect is "lock_held(<arg>)" downstream.
# Each entry: (regex, canonical-lock-name-template).
LOCK_ACQUIRE_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\brcu_read_lock_bh\s*\("), "rcu_read_lock_bh_held"),
    (re.compile(r"\brcu_read_lock_sched\s*\("), "rcu_read_lock_sched_held"),
    (re.compile(r"\brcu_read_lock\s*\("), "rcu_read_lock_held"),
    (re.compile(r"\bmutex_lock(?:_nested|_interruptible|_killable)?\s*\("),
     "mutex_held"),
    (re.compile(r"\bspin_lock(?:_bh|_irq|_irqsave|_nested)?\s*\("),
     "spin_held"),
    (re.compile(r"\bread_lock(?:_bh|_irq|_irqsave)?\s*\("), "read_lock_held"),
    (re.compile(r"\bwrite_lock(?:_bh|_irq|_irqsave)?\s*\("), "write_lock_held"),
    (re.compile(r"\bdown_read(?:_interruptible|_killable)?\s*\("),
     "rwsem_read_held"),
    (re.compile(r"\bdown_write(?:_interruptible|_killable)?\s*\("),
     "rwsem_write_held"),
    (re.compile(r"\bdown(?:_interruptible|_killable|_timeout)?\s*\("),
     "sem_held"),
    (re.compile(r"\blocal_irq_save\s*\("), "irqs_disabled"),
    (re.compile(r"\blocal_irq_disable\s*\("), "irqs_disabled"),
    (re.compile(r"\bpreempt_disable\s*\("), "preempt_disabled"),
    (re.compile(r"\blocal_bh_disable\s*\("), "bh_disabled"),
]

# Lock releases — when we see these, we forget the corresponding hold.
LOCK_RELEASE_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\brcu_read_unlock_bh\s*\("), "rcu_read_lock_bh_held"),
    (re.compile(r"\brcu_read_unlock_sched\s*\("), "rcu_read_lock_sched_held"),
    (re.compile(r"\brcu_read_unlock\s*\("), "rcu_read_lock_held"),
    (re.compile(r"\bmutex_unlock\s*\("), "mutex_held"),
    (re.compile(r"\bspin_unlock(?:_bh|_irq|_irqrestore)?\s*\("), "spin_held"),
    (re.compile(r"\bread_unlock(?:_bh|_irq|_irqrestore)?\s*\("),
     "read_lock_held"),
    (re.compile(r"\bwrite_unlock(?:_bh|_irq|_irqrestore)?\s*\("),
     "write_lock_held"),
    (re.compile(r"\bup_read\s*\("), "rwsem_read_held"),
    (re.compile(r"\bup_write\s*\("), "rwsem_write_held"),
    (re.compile(r"\bup\s*\("), "sem_held"),
    (re.compile(r"\blocal_irq_restore\s*\("), "irqs_disabled"),
    (re.compile(r"\blocal_irq_enable\s*\("), "irqs_disabled"),
    (re.compile(r"\bpreempt_enable\s*\("), "preempt_disabled"),
    (re.compile(r"\blocal_bh_enable\s*\("), "bh_disabled"),
]

# Lock-state assertions that *establish* a lock-held precondition without
# performing the acquire. Common kernel idiom.
LOCK_ASSERT_RE = re.compile(
    r"\b(lockdep_assert_held(?:_once|_write|_read)?|"
    r"lockdep_is_held|rcu_read_lock_held|rcu_read_lock_bh_held|"
    r"rcu_read_lock_sched_held|mutex_is_locked|spin_is_locked|"
    r"assert_spin_locked|rcu_dereference_protected)\s*\("
)

# Capability checks — present in either an `if (!capable(...))` early-return
# or as `WARN_ON(!capable(...))`. We capture all calls; downstream cluster step
# refines by polarity.
CAPABILITY_FUNCS = {
    "capable", "ns_capable", "ns_capable_noaudit", "ns_capable_setid",
    "file_ns_capable", "capable_wrt_inode_uidgid",
    "perfmon_capable", "bpf_capable", "checkpoint_restore_ns_capable",
}
CAPABILITY_RE = re.compile(
    r"\b(?P<fn>" + "|".join(re.escape(c) for c in CAPABILITY_FUNCS) + r")\s*\("
)

# Generic enclosing constructs.
ENCLOSING_KW_RE = re.compile(r"\b(if|while|for|switch)\b\s*\(")
ELSE_RE = re.compile(r"\belse\b")

# Negation idioms for null/error checks: `if (!x` or `if (x == NULL` or
# `IS_ERR(x)` or `IS_ERR_OR_NULL(x)`.
NULL_CHECK_RE = re.compile(
    r"\b(?:IS_ERR(?:_OR_NULL)?|PTR_ERR_OR_ZERO)\s*\(\s*([A-Za-z_]\w*)\s*\)"
)

# Hard asserts: BUG_ON(P) ⇒ !P established. (WARN_ON is logging-only; treat
# as evidence the developer at least *suspected* P, but emit it under a
# distinct kind so 5.2 can choose to weight it less.)
ASSERT_NEG_RE = re.compile(
    r"\b(?P<fn>BUG_ON|WARN_ON_ONCE|WARN_ON|VM_BUG_ON|MAYBE_BUILD_BUG_ON)"
    r"\s*\("
)


# --------------------------------------------------------------------------- #
# Comment stripping
# --------------------------------------------------------------------------- #

_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_LINE_COMMENT_RE = re.compile(r"//[^\n]*")


def _strip_c_comments(text: str) -> str:
    """Remove C-style comments while preserving line offsets.

    Comments are replaced with a same-length run of spaces (and embedded newlines
    are preserved) so guard-line numbers remain identical to the source file.
    Comments otherwise cause false-positive guard matches (e.g. a comment that
    mentions `capable(CAP_NET_ADMIN)` would be detected as a real check).
    """
    def _blank(m: re.Match) -> str:
        s = m.group(0)
        return "".join(c if c == "\n" else " " for c in s)
    text = _BLOCK_COMMENT_RE.sub(_blank, text)
    text = _LINE_COMMENT_RE.sub(_blank, text)
    return text


# --------------------------------------------------------------------------- #
# Paren-matching scan helper
# --------------------------------------------------------------------------- #

def _balanced_paren_extent(text: str, open_idx: int) -> int:
    """Index just past the `)` that matches the `(` at `open_idx`. -1 if unbalanced."""
    assert text[open_idx] == "("
    depth = 0
    i = open_idx
    n = len(text)
    in_str = False
    in_chr = False
    escape = False
    while i < n:
        c = text[i]
        if escape:
            escape = False
        elif in_str:
            if c == "\\":
                escape = True
            elif c == '"':
                in_str = False
        elif in_chr:
            if c == "\\":
                escape = True
            elif c == "'":
                in_chr = False
        else:
            if c == '"':
                in_str = True
            elif c == "'":
                in_chr = True
            elif c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0:
                    return i + 1
        i += 1
    return -1


def _grab_paren_arg(text: str, open_idx: int) -> str:
    """Return text inside the (...) starting at `(` at open_idx, trimmed."""
    close = _balanced_paren_extent(text, open_idx)
    if close < 0:
        return ""
    return text[open_idx + 1 : close - 1].strip()


# --------------------------------------------------------------------------- #
# Brace-aware single-pass guard scanner
# --------------------------------------------------------------------------- #

class _GuardState:
    """Live guard context maintained while scanning a function body."""

    def __init__(self) -> None:
        # Enclosing constructs as a depth-keyed stack. Each entry:
        # {"depth_after_open": int, "kind": str, "predicate": str,
        #  "polarity": str, "source_line": int}
        self.enclosing: list[dict] = []
        # Locks currently held (acquired earlier, not yet released).
        # name -> source_line of acquire
        self.locks_held: dict[str, int] = {}
        # Lock-state asserts seen earlier (sticky for the rest of the function;
        # the assert pins a precondition, it doesn't acquire).
        self.lock_asserts: list[dict] = []  # {predicate, source_line}
        # Capability checks seen earlier (sticky — capable() returning true is
        # a *positive* check, but at the syntactic level we don't reliably
        # know polarity; 5.2 refines).
        self.capability_checks: list[dict] = []
        # Generic early-return: `if (P) return/goto/...;` at fn-top level before
        # the callsite. We record P (with established polarity inverted in 5.2).
        self.early_returns: list[dict] = []
        # Null/IS_ERR checks of specific identifiers established as non-null/
        # non-err by prior `if (!x) return;` or `if (IS_ERR(x)) return;`
        self.null_checks: list[dict] = []
        # BUG_ON-style asserts.
        self.assert_negs: list[dict] = []

    def snapshot(self) -> list[dict]:
        """Flatten current guard state into a list ordered as a chain."""
        out: list[dict] = []
        # Locks held → conjuncts of the precondition.
        for name, ln in sorted(self.locks_held.items()):
            out.append({
                "kind": "lock_acquire",
                "predicate": name,
                "source_line": ln,
            })
        # Lock asserts (assertions, not acquires).
        out.extend(self.lock_asserts)
        # Capability checks.
        out.extend(self.capability_checks)
        # Null/IS_ERR checks.
        out.extend(self.null_checks)
        # BUG_ON-style asserts.
        out.extend(self.assert_negs)
        # Early returns (each contributes a "!P" precondition).
        out.extend(self.early_returns)
        # Enclosing constructs (innermost last).
        for e in self.enclosing:
            out.append({
                "kind": "enclosing_" + e["kind"],
                "predicate": e["predicate"],
                "polarity": e["polarity"],
                "source_line": e["source_line"],
            })
        return out


def _scan_line_for_locks(line: str, state: _GuardState, abs_line: int) -> None:
    # Order matters: try releases first so a line like "spin_unlock(...); spin_lock(...);"
    # ends up "held". But on a single line we scan in left-to-right text order.
    # Simpler: walk acquire-then-release in textual order using finditer.
    events: list[tuple[int, bool, str]] = []  # (pos, is_acquire, canonical-name)
    for pat, name in LOCK_ACQUIRE_PATTERNS:
        for m in pat.finditer(line):
            events.append((m.start(), True, name))
    for pat, name in LOCK_RELEASE_PATTERNS:
        for m in pat.finditer(line):
            events.append((m.start(), False, name))
    events.sort()
    for _, is_acquire, name in events:
        if is_acquire:
            state.locks_held.setdefault(name, abs_line)
        else:
            state.locks_held.pop(name, None)


def _scan_line_for_lock_asserts(
    line: str, state: _GuardState, abs_line: int
) -> None:
    for m in LOCK_ASSERT_RE.finditer(line):
        open_idx = line.find("(", m.end() - 1)
        if open_idx < 0:
            continue
        arg = _grab_paren_arg(line, open_idx)
        state.lock_asserts.append({
            "kind": "lock_assert",
            "predicate": f"{m.group(1)}({arg})",
            "source_line": abs_line,
        })


def _scan_line_for_capabilities(
    line: str, state: _GuardState, abs_line: int
) -> None:
    for m in CAPABILITY_RE.finditer(line):
        open_idx = m.end() - 1  # position of '('
        arg = _grab_paren_arg(line, open_idx)
        state.capability_checks.append({
            "kind": "capability_check",
            "predicate": f"{m.group('fn')}({arg})",
            "source_line": abs_line,
        })


def _scan_line_for_assert_neg(
    line: str, state: _GuardState, abs_line: int
) -> None:
    for m in ASSERT_NEG_RE.finditer(line):
        open_idx = m.end() - 1
        arg = _grab_paren_arg(line, open_idx)
        state.assert_negs.append({
            "kind": "assert_neg",
            "predicate": f"!({arg})",
            "macro": m.group("fn"),
            "source_line": abs_line,
        })


# Recognises a "this line *establishes* a precondition" pattern of the form
# `if (...) return/goto/break/continue ...;` whether the if-body is on the
# same line or on the next.
EARLY_RETURN_HEAD_RE = re.compile(
    r"\bif\s*\(",
)
EARLY_RETURN_BODY_RE = re.compile(
    r"\b(return|goto|break|continue)\b"
)

# Same set used to mark the *innermost enclosing* if-body as exit-bearing when
# we see a control-flow exit at its depth.
EXIT_STMT_RE = re.compile(
    r"^\s*(return|goto\s+\w+|break|continue)\b"
)


def _scan_for_early_return(
    lines: list[str], i: int, abs_line: int, state: _GuardState
) -> None:
    """If line i is `if (P) return/...;` (one-line or split), record !P."""
    line = lines[i]
    m = EARLY_RETURN_HEAD_RE.search(line)
    if not m:
        return
    paren_open = line.find("(", m.end() - 1)
    if paren_open < 0:
        return
    close = _balanced_paren_extent(line, paren_open)
    if close < 0:
        return
    predicate = line[paren_open + 1 : close - 1].strip()
    # Body: either on same line (after the closing paren) or on next line.
    same_line_tail = line[close:].strip()
    body_text = same_line_tail
    body_origin_line = abs_line
    if not body_text or body_text in ("", "{"):
        # Next non-blank line, if it exists.
        for j in range(i + 1, min(i + 3, len(lines))):
            tail = lines[j].strip()
            if tail:
                body_text = tail
                body_origin_line = abs_line + (j - i)
                break
    if not EARLY_RETURN_BODY_RE.search(body_text):
        return
    # Record !predicate (5.2 strips the !-wrapper to canonicalise).
    state.early_returns.append({
        "kind": "early_return",
        "predicate": f"!({predicate})",
        "exit_kind": EARLY_RETURN_BODY_RE.search(body_text).group(1),
        "source_line": abs_line,
        "exit_line": body_origin_line,
    })
    # Also: if the predicate has a recognised null/IS_ERR shape, mirror it
    # into null_checks for the per-class taxonomy in 5.4.
    for n in NULL_CHECK_RE.finditer(predicate):
        state.null_checks.append({
            "kind": "null_check",
            "predicate": f"!IS_ERR_OR_NULL({n.group(1)})",
            "source_line": abs_line,
        })
    # `if (!x) return` — bare negation of an identifier.
    bare_neg = re.match(r"!\s*([A-Za-z_]\w*)\s*$", predicate)
    if bare_neg:
        state.null_checks.append({
            "kind": "null_check",
            "predicate": f"{bare_neg.group(1)} != NULL",
            "source_line": abs_line,
        })


# --------------------------------------------------------------------------- #
# Enclosing-construct tracking
# --------------------------------------------------------------------------- #

def _open_braces_in(line: str) -> int:
    # We don't need to be string/char aware to first order — Linux is well-formatted.
    return line.count("{") - line.count("}")


def _scan_for_enclosing_open(
    line: str, abs_line: int, depth_before: int, state: _GuardState
) -> None:
    """Detect `if/while/for/switch (cond) {` on this line — push onto stack.

    Approximation: we push a guard the moment we see the keyword + parenthesised
    condition, regardless of whether `{` appears on this line or the next; the
    body will close it via brace tracking. (Stmt-form `if (x) foo();` without
    braces is also captured — we pop when brace depth returns to the parent.)

    `else` handling is NOT done here — it is owned by the per-line driver in
    extract_from_function, which mirrors the just-popped `in_true_branch` if
    into an `in_false_branch` frame at the correct depth.
    """
    for m in ENCLOSING_KW_RE.finditer(line):
        paren_open = line.find("(", m.end() - 1)
        if paren_open < 0:
            continue
        close = _balanced_paren_extent(line, paren_open)
        if close < 0:
            continue
        predicate = line[paren_open + 1 : close - 1].strip()
        state.enclosing.append({
            "depth_after_open": depth_before + 1,
            "kind": m.group(1),
            "predicate": predicate,
            "polarity": "in_true_branch",
            "source_line": abs_line,
            "body_exits": False,
        })


def _pop_enclosing_to(
    state: _GuardState, depth: int
) -> list[dict]:
    """Pop everything in the enclosing stack whose body has ended.

    Returns the popped entries (innermost-first) so an `else` on the same line
    can mirror the just-closed if into an `in_false_branch` frame.

    Side effect: any popped `in_true_branch` if whose body contained a
    control-flow exit (return/goto/break/continue) contributes an
    `early_return` entry to the persistent state — `!predicate` is established
    from this point on in the function.
    """
    popped: list[dict] = []
    while state.enclosing and state.enclosing[-1]["depth_after_open"] > depth:
        e = state.enclosing.pop()
        popped.append(e)
        if (
            e["kind"] == "if"
            and e["polarity"] == "in_true_branch"
            and e.get("body_exits")
        ):
            state.early_returns.append({
                "kind": "early_return",
                "predicate": f"!({e['predicate']})",
                "exit_kind": e["body_exits"],
                "source_line": e["source_line"],
            })
            # Mirror null/IS_ERR shapes into null_checks (5.4 taxonomy hook).
            pred = e["predicate"]
            for n in NULL_CHECK_RE.finditer(pred):
                state.null_checks.append({
                    "kind": "null_check",
                    "predicate": f"!IS_ERR_OR_NULL({n.group(1)})",
                    "source_line": e["source_line"],
                })
            bare_neg = re.match(r"!\s*([A-Za-z_]\w*)\s*$", pred)
            if bare_neg:
                state.null_checks.append({
                    "kind": "null_check",
                    "predicate": f"{bare_neg.group(1)} != NULL",
                    "source_line": e["source_line"],
                })
    return popped


# --------------------------------------------------------------------------- #
# Per-function extraction
# --------------------------------------------------------------------------- #

def _build_callee_regex(callees: set[str]) -> re.Pattern:
    """One regex that matches any callee from the set."""
    if not callees:
        # Genuinely match nothing (^$ matches blank lines and trips group(1)).
        return re.compile(r"(?!x)x")
    alt = "|".join(re.escape(c) for c in sorted(callees))
    return re.compile(rf"\b({alt})\s*\(")


def extract_from_function(
    caller: str,
    body: str,
    body_start_line: int,
    callee_re: re.Pattern,
    rel_file: str,
) -> dict[str, list[dict]]:
    """Return {callee: [callsite_record, ...]} for one caller's body."""
    out: dict[str, list[dict]] = defaultdict(list)
    state = _GuardState()
    # Strip comments line-preservingly so guard regexes don't match comment text.
    body = _strip_c_comments(body)
    lines = body.split("\n")
    # We seed depth at 0 — the body string starts at the function declarator
    # line per parse_function_bodies; the opening `{` of the function will
    # bump depth to 1, which is exactly the depth of the function's outermost
    # statements.
    depth = 0
    for i, line in enumerate(lines):
        abs_line = body_start_line + i
        opens = line.count("{")
        closes = line.count("}")

        # 1. Callsite snapshot uses the guard state AS-OF entry to this line
        #    (i.e. before any closes/opens on this line apply). Guards written
        #    on the same line as the call don't fold themselves into the snapshot.
        for m in callee_re.finditer(line):
            callee = m.group(1)
            # Self-call: not interesting for spec mining of caller's own
            # contract (recursion is rare in kernel and yields no signal).
            if callee == caller:
                continue
            out[callee].append({
                "caller": caller,
                "file": rel_file,
                "line": abs_line,
                "guards": state.snapshot(),
            })

        # 2. Apply closing braces FIRST so `} else {` correctly pops the
        #    just-finished true-branch before we record the else mirror.
        depth_after_closes = max(0, depth - closes)
        popped = _pop_enclosing_to(state, depth_after_closes)

        # 3. `else` recovery: on a line containing `else`, mirror the
        #    innermost just-popped `if` (if any) as an `in_false_branch` frame
        #    at the post-close depth + 1 (the body of the else).
        if ELSE_RE.search(line):
            mirror = next(
                (p for p in popped
                 if p["kind"] == "if" and p["polarity"] == "in_true_branch"),
                None,
            )
            if mirror is not None:
                state.enclosing.append({
                    "depth_after_open": depth_after_closes + 1,
                    "kind": "if",
                    "predicate": mirror["predicate"],
                    "polarity": "in_false_branch",
                    "source_line": abs_line,
                })

        # 4. In-line guard updates: locks, capability checks, asserts, early
        #    returns, and new enclosing-construct openers.
        _scan_line_for_locks(line, state, abs_line)
        _scan_line_for_lock_asserts(line, state, abs_line)
        _scan_line_for_capabilities(line, state, abs_line)
        _scan_line_for_assert_neg(line, state, abs_line)
        # Inline early-return: `if (P) return ...;` on the same line.
        _scan_for_early_return(lines, i, abs_line, state)
        # Mark the innermost active if-body as exit-bearing when a control-flow
        # exit appears at any depth inside it. The pop step then records !P.
        exit_m = EXIT_STMT_RE.search(line)
        if exit_m:
            for e in reversed(state.enclosing):
                if e["kind"] == "if" and not e.get("body_exits"):
                    e["body_exits"] = exit_m.group(1).split()[0]
                    break
        _scan_for_enclosing_open(line, abs_line, depth_after_closes, state)

        # 5. Update depth from this line's `{`.
        depth = depth_after_closes + opens
    return out


# --------------------------------------------------------------------------- #
# Driver
# --------------------------------------------------------------------------- #

def _safe_filename(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", name)


def _load_callee_set(
    fn_to_file: dict[str, str],
    callees_arg: list[str] | None,
    keep_set_path: Path | None,
) -> set[str]:
    if callees_arg:
        # Explicit caller-supplied list: trust it (don't filter against
        # fn_to_file — useful for mining patterns of external library calls
        # too, e.g. `kmalloc`, `copy_from_user`).
        return set(callees_arg)
    if keep_set_path is not None and keep_set_path.exists():
        d = json.loads(keep_set_path.read_text())
        return set(d.get("keep_set", [])) & set(fn_to_file)
    # Default: every defined function in scope. Bounded by scope, so finite.
    return set(fn_to_file)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Phase 5.1 callsite + guard extractor.")
    ap.add_argument("--source-root", required=True, type=Path)
    ap.add_argument("--scope", required=True, type=str,
                    help="Subdirectory under source-root to mine (e.g. net/netfilter).")
    ap.add_argument("--target", required=True, type=str)
    ap.add_argument("--callees", nargs="*",
                    help="Restrict mining to these callees (default: all defined).")
    ap.add_argument("--keep-set-from", type=Path,
                    help="Path to surface/slice/<target>.json; if given, mine only the keep_set.")
    ap.add_argument("--out-root", type=Path,
                    default=Path(__file__).resolve().parent / "callsites",
                    help="Output root: <out-root>/<target>/<callee>.json")
    ap.add_argument("--min-callsites", type=int, default=1,
                    help="Skip writing callee files with fewer than N callsites.")
    args = ap.parse_args(argv)

    source_root = args.source_root.resolve()
    scope_root = (source_root / args.scope).resolve()
    if not scope_root.is_dir():
        ap.error(f"scope not found: {scope_root}")

    files = list_c_sources(scope_root)
    print(f"[specmine] scanning {len(files)} sources under {scope_root}",
          file=sys.stderr)

    fn_starts = ctags_function_starts(files, source_root)
    fn_to_file: dict[str, str] = {}
    for relpath, starts in fn_starts.items():
        for name, _ in starts:
            fn_to_file.setdefault(name, relpath)

    callee_set = _load_callee_set(
        fn_to_file, args.callees, args.keep_set_from,
    )
    print(f"[specmine] defined={len(fn_to_file)} mining_callees={len(callee_set)}",
          file=sys.stderr)
    callee_re = _build_callee_regex(callee_set - CALL_BLACKLIST)

    # Aggregate callsites by callee across all files.
    per_callee: dict[str, list[dict]] = defaultdict(list)
    total_callers_scanned = 0
    t0 = time.time()
    for relpath, starts in fn_starts.items():
        path = source_root / relpath
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        bodies = parse_function_bodies(text, starts)
        for caller, body in bodies.items():
            # Find the caller's start line so guard `source_line` values are
            # absolute, not body-relative.
            start_line = next(
                (sl for (name, sl) in starts if name == caller), 1
            )
            slice_out = extract_from_function(
                caller=caller,
                body=body,
                body_start_line=start_line,
                callee_re=callee_re,
                rel_file=relpath,
            )
            for callee, records in slice_out.items():
                per_callee[callee].extend(records)
            total_callers_scanned += 1
    wall = time.time() - t0

    # Emit per-callee files.
    out_dir = args.out_root / args.target
    out_dir.mkdir(parents=True, exist_ok=True)
    callees_emitted = 0
    total_callsites = 0
    total_guards = 0
    callees_index: dict[str, dict] = {}
    for callee, records in per_callee.items():
        if len(records) < args.min_callsites:
            continue
        records.sort(key=lambda r: (r["file"], r["line"]))
        payload = {
            "callee": callee,
            "defined_in": fn_to_file.get(callee),
            "target": args.target,
            "scope": args.scope,
            "callsite_count": len(records),
            "callsites": records,
        }
        fname = _safe_filename(callee) + ".json"
        (out_dir / fname).write_text(json.dumps(payload, indent=2) + "\n")
        callees_emitted += 1
        total_callsites += len(records)
        total_guards += sum(len(r["guards"]) for r in records)
        callees_index[callee] = {
            "callsite_count": len(records),
            "out_file": fname,
        }

    summary = {
        "target": args.target,
        "source_root": str(source_root),
        "scope": args.scope,
        "generated_at": int(time.time()),
        "stats": {
            "defined_callees": len(fn_to_file),
            "mining_callees": len(callee_set),
            "callers_scanned": total_callers_scanned,
            "callees_with_callsites": len(per_callee),
            "callees_emitted": callees_emitted,
            "total_callsites": total_callsites,
            "total_guards": total_guards,
            "wall_seconds": round(wall, 2),
        },
        "callees": callees_index,
    }
    (out_dir / "_index.json").write_text(json.dumps(summary, indent=2) + "\n")

    print(f"[specmine] wrote {callees_emitted} callee ledgers "
          f"({total_callsites} callsites, {total_guards} guards) "
          f"in {wall:.1f}s -> {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
