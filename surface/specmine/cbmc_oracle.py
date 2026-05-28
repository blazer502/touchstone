"""Phase 5.3 — CBMC backward-harness synthesiser for spec-mining outliers.

Given an outlier `(callee=C, caller=F, missing_contract=G)` from Phase 5.2, build
a self-contained C source that CBMC can compile + verify, asserting at C's entry
that G must hold. Driving the harness through `F`'s body lets CBMC tell us
whether the violation is *feasible* under arbitrary inputs:

  - CBMC `unsafe` (assertion FAILURE)   → outlier is a CONFIRMED bug lead
  - CBMC `safe`                          → outlier REFUTED (G actually does hold)
  - CBMC `inconclusive` (timeout/unwind) → outlier remains a lead, no verdict

This is the *backward leg* of Phase 5.3's soundness gate: the mined-contract
proposer (5.2) only emits hypotheses; the sound checker (CBMC here, the same
engine Phase 1.3 / 2.3 / 3.1 already trust) is the verdict authority. Final
authority belongs to the engine (PLAN §8) — the harness synthesiser cannot flip
a `safe` to `unsafe`.

Lock-class contract modelling (MVP scope):
  - We model each lock-state as a private depth counter:
      static int __specmine_<lock>_depth = 0;
    plus macro overrides `rcu_read_lock()` → `__specmine_rcu_depth++` etc.
  - At C's entry we inject:
      __CPROVER_assert(__specmine_<lock>_depth > 0, "<G> must hold");
    so any feasible execution that reaches C without first acquiring the lock
    triggers the assertion (CBMC reports unsafe + a counterexample trace).
  - F's body is copied verbatim from the source (extracted via ctags + body
    slice — same machinery as 5.1's `parse_function_bodies`). main() calls F
    with nondet args.

Non-lock-class contracts (capability_check, null_check, early_return,
enclosing_if, …) are queued as a 5.3.x harness extension — the cleanest way to
model them in CBMC differs per class (capability via a `__specmine_cap_<X>` bool
nondet-by-default; null/early via `__CPROVER_assume(ptr != NULL)` reversal;
enclosing_if via a `__CPROVER_assume` of the predicate on the path TO the
callsite). For the 5.3 MVP we ship lock-class only and return
`unsupported_harness` cleanly for everything else; the driver maps that to
`infrastructure_pending` rather than to a verdict.
"""
from __future__ import annotations

import re
import subprocess
from collections import defaultdict
from pathlib import Path
from typing import Optional


# --------------------------------------------------------------------------- #
# Lock modelling
# --------------------------------------------------------------------------- #

# missing_contract -> (counter_var_name, list of acquire macros, list of release
# macros). The acquire macros translate to `__counter++`; release to `--`.
_LOCK_MODELS: dict[str, dict] = {
    "rcu_read_lock_held": {
        "counter": "__specmine_rcu_depth",
        "acquires": [
            "rcu_read_lock", "rcu_read_lock_bh", "rcu_read_lock_sched",
        ],
        "releases": [
            "rcu_read_unlock", "rcu_read_unlock_bh", "rcu_read_unlock_sched",
        ],
    },
    "rcu_read_lock_bh_held": {
        "counter": "__specmine_rcu_bh_depth",
        "acquires": ["rcu_read_lock_bh"],
        "releases": ["rcu_read_unlock_bh"],
    },
    "rcu_read_lock_sched_held": {
        "counter": "__specmine_rcu_sched_depth",
        "acquires": ["rcu_read_lock_sched"],
        "releases": ["rcu_read_unlock_sched"],
    },
    "mutex_held": {
        "counter": "__specmine_mutex_depth",
        "acquires": [
            "mutex_lock", "mutex_lock_nested", "mutex_lock_interruptible",
            "mutex_lock_killable",
        ],
        "releases": ["mutex_unlock"],
    },
    "spin_held": {
        "counter": "__specmine_spin_depth",
        "acquires": [
            "spin_lock", "spin_lock_bh", "spin_lock_irq",
            "spin_lock_irqsave", "spin_lock_nested",
        ],
        "releases": [
            "spin_unlock", "spin_unlock_bh", "spin_unlock_irq",
            "spin_unlock_irqrestore",
        ],
    },
}


def is_supported_contract(kind_class: str, missing_contract: str) -> bool:
    """Does the MVP harness synthesiser cover this outlier?"""
    if kind_class == "lock" and missing_contract in _LOCK_MODELS:
        return True
    if kind_class == "null":
        return True
    return False


# --------------------------------------------------------------------------- #
# Null / error-state modelling (Phase 5.6: null_init contract class)
# --------------------------------------------------------------------------- #

# A single pair of nondet globals model "the pointer argument is in an
# IS_ERR / NULL state". The macros below expand to *reads* of those globals;
# main() sets them to nondet_int() at startup so CBMC explores both states.
#
# For an outlier caller that *doesn't* check IS_ERR/IS_ERR_OR_NULL before
# invoking the callee, the wrapper assertion `__specmine_arg_is_err == 0 &&
# __specmine_arg_is_null == 0` fails on the nondet-true path → unsafe →
# confirmed bug. For a support caller that has `if (IS_ERR(p)) return;`,
# the IS_ERR-true path is pruned by the early-return and the wrapper
# assertion holds on the surviving path → safe → refuted.
_NULL_PRELUDE = """\
/* Null / error-state model (Phase 5.6 null_init harness). */
static int __specmine_arg_is_err = 0;
static int __specmine_arg_is_null = 0;

#define IS_ERR(p)           ((__specmine_arg_is_err) != 0)
#define IS_ERR_OR_NULL(p)   ((__specmine_arg_is_err) != 0 || (__specmine_arg_is_null) != 0)
#define IS_ERR_VALUE(p)     ((__specmine_arg_is_err) != 0)
#define PTR_ERR_OR_ZERO(p)  (__specmine_arg_is_err)
#define PTR_ERR(p)          (__specmine_arg_is_err)
"""


# --------------------------------------------------------------------------- #
# Caller-body extraction
# --------------------------------------------------------------------------- #

_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_LINE_COMMENT_RE = re.compile(r"//[^\n]*")


def _strip_c_comments_preserving_lines(text: str) -> str:
    def _blank(m: re.Match) -> str:
        s = m.group(0)
        return "".join(c if c == "\n" else " " for c in s)
    text = _BLOCK_COMMENT_RE.sub(_blank, text)
    text = _LINE_COMMENT_RE.sub(_blank, text)
    return text


def _ctags_function_starts(file_path: Path) -> list[tuple[str, int]]:
    """[(func_name, start_line), ...] sorted by start_line for one file."""
    cmd = ["ctags", "--c-kinds=f", "-x", str(file_path)]
    try:
        proc = subprocess.run(cmd, text=True, capture_output=True, check=False)
    except FileNotFoundError:
        return []
    out: list[tuple[str, int]] = []
    if proc.returncode != 0:
        return out
    for line in proc.stdout.splitlines():
        m = re.match(r"^(\S+)\s+function\s+(\d+)\s+\S+", line)
        if m:
            out.append((m.group(1), int(m.group(2))))
    out.sort(key=lambda x: x[1])
    return out


def extract_function_body(file_path: Path, func_name: str) -> Optional[tuple[str, int]]:
    """Return (body_text, body_start_line) for `func_name` in `file_path`, or None.

    Body is sliced between the function's ctags start-line and the next
    function's start-line (or EOF). Same approximation as `surface.reachability`
    uses; over-include is fine for our purposes since we only need a compilable
    block.
    """
    starts = _ctags_function_starts(file_path)
    if not starts:
        return None
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    lines = text.split("\n")
    for i, (name, start) in enumerate(starts):
        if name != func_name:
            continue
        end = starts[i + 1][1] - 1 if i + 1 < len(starts) else len(lines)
        body = "\n".join(lines[start - 1 : end])
        return body, start
    return None


def _looks_kernel_path(rel_file: str) -> bool:
    """Best-effort: is this source path likely a kernel translation unit?

    For the MVP we hard-classify files inside kernel subdirectories — net/, fs/,
    drivers/, mm/, arch/, kernel/, security/, sound/, block/, ipc/, lib/, init/
    — as kernel. CBMC can't ingest the kernel build without significant stubbing
    (no kmalloc/printk/MODULE_*/CONFIG_*/__user/inline-asm models in the default
    CBMC C library), so the driver maps these to `infrastructure_pending`.
    """
    parts = rel_file.split("/")
    if not parts:
        return False
    return parts[0] in {
        "net", "fs", "drivers", "mm", "arch", "kernel",
        "security", "sound", "block", "ipc", "lib", "init",
    }


# --------------------------------------------------------------------------- #
# Harness synthesis
# --------------------------------------------------------------------------- #

def _lock_prelude(missing_contract: str) -> str:
    """Emit the CBMC-friendly lock modelling: counters + macro overrides.

    Includes both *side-effecting* macros (acquires/releases mutate the
    counter) and *predicate* macros (e.g. `rcu_read_lock_held()` /
    `spin_is_locked(x)` / `lockdep_assert_held(x)`) so the caller's body
    compiles unchanged even when it uses assertion-style lock-state checks.
    """
    counters_emitted: list[str] = []
    macro_lines: list[str] = []
    for state, model in _LOCK_MODELS.items():
        counter = model["counter"]
        if counter in counters_emitted:
            continue
        counters_emitted.append(counter)
    declares = "\n".join(f"static int {c} = 0;" for c in counters_emitted)
    seen_macros: set[str] = set()
    for state, model in _LOCK_MODELS.items():
        counter = model["counter"]
        for fn in model["acquires"]:
            if fn in seen_macros:
                continue
            macro_lines.append(f"#define {fn}(...) do {{ {counter}++; }} while (0)")
            seen_macros.add(fn)
        for fn in model["releases"]:
            if fn in seen_macros:
                continue
            macro_lines.append(
                f"#define {fn}(...) do {{ if ({counter} > 0) {counter}--; }} while (0)"
            )
            seen_macros.add(fn)
    # Predicate macros: assertion-style lock-state checks expand to the
    # corresponding counter being > 0, so a guard like
    # `if (rcu_read_lock_held()) { call(...); }` lets CBMC prove the path is
    # taken only when RCU is held — the wrapper's assertion is then satisfied
    # on that path (CBMC returns SAFE → outlier REFUTED).
    predicate_macros = [
        ("rcu_read_lock_held",         "__specmine_rcu_depth"),
        ("rcu_read_lock_bh_held",      "__specmine_rcu_bh_depth"),
        ("rcu_read_lock_sched_held",   "__specmine_rcu_sched_depth"),
        ("spin_is_locked",             "__specmine_spin_depth"),
        ("assert_spin_locked",         "__specmine_spin_depth"),
        ("mutex_is_locked",            "__specmine_mutex_depth"),
    ]
    for fn, counter in predicate_macros:
        if fn in seen_macros:
            continue
        macro_lines.append(f"#define {fn}(...) (({counter}) > 0)")
        seen_macros.add(fn)
    # lockdep_assert_held(x) — a kernel assertion that the lock is held. In our
    # model we *trust* the assertion by assuming the relevant counter is > 0;
    # this is sound for the verifier because the kernel would BUG_ON otherwise.
    for fn in ("lockdep_assert_held", "lockdep_assert_held_once",
               "lockdep_assert_held_write", "lockdep_assert_held_read",
               "lockdep_is_held"):
        if fn in seen_macros:
            continue
        macro_lines.append(
            f"#define {fn}(x) __CPROVER_assume(__specmine_mutex_depth > 0 "
            f"|| __specmine_spin_depth > 0 || __specmine_rcu_depth > 0)"
        )
        seen_macros.add(fn)
    macros = "\n".join(macro_lines)
    return f"{declares}\n\n{macros}\n"


def _nondet_call_for(arg_count: int) -> str:
    """Generate a `func(nondet_int(), nondet_int(), ...)` argument list."""
    return ", ".join("(int) nondet_int()" for _ in range(arg_count))


def _arity_of(caller_body: str, func_name: str) -> int:
    """Best-effort: count parameters in `func_name(...)` declarator."""
    m = re.search(rf"\b{re.escape(func_name)}\s*\(([^)]*)\)\s*\{{", caller_body)
    if not m:
        return 1
    params = m.group(1).strip()
    if params in ("", "void"):
        return 0
    return params.count(",") + 1


def synthesise_harness(
    outlier: dict,
    source_root: Path,
    extra_preconditions: Optional[list[str]] = None,
) -> Optional[dict]:
    """Return {harness_source, asserted_contract, caller, callee, ...} or None.

    The returned dict carries the C source as a string under `source`; the
    driver writes it to disk and invokes the existing CBMC oracle on it.
    Returns None when the contract is out-of-scope for the MVP (caller is
    handled as `unsupported_harness` upstream).

    `extra_preconditions` (Phase 5.5 refinement plumbing): when provided, each
    string is emitted verbatim in main() between the symbolic-input decls and
    the caller invocation. The synthesizer's symbolic inputs are named
    `arg0`, `arg1`, …, `argN` so preconditions can reference them directly
    (e.g. `__CPROVER_assume(arg0 <= 4);` bounds the symbolic int that drives
    the caller). Used by `surface/specmine/refine.py` for the inconclusive →
    decisive refinement loop.
    """
    kind_class = outlier.get("contract_kind_class", "")
    missing = outlier.get("missing_contract", "")
    if not is_supported_contract(kind_class, missing):
        return None

    rel_file = outlier.get("file")
    caller = outlier.get("caller")
    callee = outlier.get("callee")
    if not (rel_file and caller and callee):
        return None
    if _looks_kernel_path(rel_file):
        # Kernel source → infrastructure_pending. The driver will see this
        # marker and route it to the right disposition.
        return {
            "unsupported": "kernel_source",
            "reason": (
                f"{rel_file} is under a kernel subdirectory; "
                "CBMC cannot ingest the kernel build without dedicated stubs. "
                "Phase 5.6 closed loop or a 5.3.x kernel-extraction hook owns "
                "this path."
            ),
            "caller": caller, "callee": callee,
        }

    source_path = source_root / rel_file
    if not source_path.is_file():
        return None
    extract = extract_function_body(source_path, caller)
    if extract is None:
        return None
    caller_body, _ = extract
    # Also pull the callee body so the harness compiles (it doesn't have to be
    # behavior-accurate; the assertion at entry is what matters).
    callee_extract = extract_function_body(source_path, callee)
    if callee_extract is None:
        # Allow callee to be a stub: emit one in the harness.
        callee_arity = 1
        callee_body = (
            f"static int {callee}(int x) {{\n"
            f"    return x;\n"
            f"}}\n"
        )
    else:
        body, _ = callee_extract
        callee_body = body
        callee_arity = _arity_of(body, callee)

    caller_body_clean = _strip_c_comments_preserving_lines(caller_body)
    caller_arity = _arity_of(caller_body_clean, caller)

    # Branch on contract class: lock-class asserts a counter > 0; null-class
    # asserts the nondet `__specmine_arg_is_err == 0 && _is_null == 0`. Both
    # classes use the same wrapper-rename trick on the caller body so a single
    # assertion adjudicates every callsite of `callee` in the caller.
    if kind_class == "lock":
        counter_var = _LOCK_MODELS[missing]["counter"]
        wrapper_property = f"{counter_var} > 0"
        wrapper_message = f"specmine: {missing} must hold at {callee} entry"
        prelude = _lock_prelude(missing)
    else:  # null_init
        wrapper_property = (
            "__specmine_arg_is_err == 0 && __specmine_arg_is_null == 0"
        )
        wrapper_message = (
            f"specmine: arg must be non-IS_ERR / non-NULL at {callee} entry"
        )
        # Emit BOTH lock and null preludes so a caller body that uses any
        # primitive from either family compiles cleanly. Lock counters stay at 0
        # → `__specmine_arg_is_*` are the only state the wrapper observes.
        prelude = _lock_prelude(missing) + "\n" + _NULL_PRELUDE

    wrapper_name = f"__specmine_wrap_{callee}"
    asserted_caller_body = re.sub(
        rf"\b{re.escape(callee)}\s*\(",
        f"{wrapper_name}(",
        caller_body_clean,
    )

    wrapper = (
        f"static int {wrapper_name}({', '.join('int a' + str(i) for i in range(callee_arity)) or 'void'}) {{\n"
        f"    __CPROVER_assert({wrapper_property}, \"{wrapper_message}\");\n"
        f"    return 0;\n"
        f"}}\n"
    )

    # Drive caller from main() with named symbolic input arguments so refinement
    # preconditions can reference them by name (`arg0`, `arg1`, …).
    nondet_decl = (
        "/* Nondeterministic int — CBMC enumerates feasible values. */\n"
        "int nondet_int(void);\n"
    )
    if caller_arity > 0:
        arg_decls = "\n".join(
            f"    int arg{i} = (int) nondet_int();" for i in range(caller_arity)
        )
        arg_list = ", ".join(f"arg{i}" for i in range(caller_arity))
    else:
        arg_decls = ""
        arg_list = ""
    preconds_block = ""
    if extra_preconditions:
        preconds_block = "\n".join(f"    {p}" for p in extra_preconditions)
    main_lines = ["int main(void) {"]
    if arg_decls:
        main_lines.append(arg_decls)
    if kind_class == "null":
        # Set null/err state to nondet at startup; macros above read these.
        main_lines.append("    __specmine_arg_is_err = (int) nondet_int();")
        main_lines.append("    __specmine_arg_is_null = (int) nondet_int();")
    if preconds_block:
        main_lines.append("    /* Phase 5.5 refinement preconditions */")
        main_lines.append(preconds_block)
    main_lines.append(f"    (void) {caller}({arg_list});")
    main_lines.append("    return 0;")
    main_lines.append("}\n")
    main_fn = "\n".join(main_lines)

    source = (
        "/* Auto-generated by surface/specmine/cbmc_oracle.py (Phase 5.3 backward leg). */\n"
        "/* Asserts the missing mined contract at the wrapped callee's entry; */\n"
        "/* CBMC reports UNSAFE when a feasible path violates the contract.   */\n\n"
        f"{prelude}\n"
        f"{nondet_decl}\n"
        f"{wrapper}\n"
        f"{asserted_caller_body}\n"
        f"{main_fn}"
    )

    return {
        "source": source,
        "asserted_contract": missing,
        "contract_kind_class": kind_class,
        "caller": caller,
        "callee": callee,
        "wrapper_name": wrapper_name,
        "wrapper_property": wrapper_property,
    }
