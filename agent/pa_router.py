"""PA-scale router — choose small-scale (precise) vs large-scale (scalable) PA
per target.

The core tension this resolves: precise program analysis (symbolic execution,
concolic, bounded model checking) is *sound and exact* but does NOT scale —
it works on a single extracted function / a bounded property with obtainable
LLVM bitcode. Scalable PA (kernel-grade static analyzers + coverage/directed
fuzzing) handles whole programs (the Linux kernel, large OSS targets) but
sacrifices path-feasibility/precision. Picking the wrong lane wastes effort:
KLEE on the kernel hangs; CBMC can't model it; conversely, fuzzing a tiny
checksum gate is silly when concolic solves it in one query.

So the agent decides the LANE from a `TargetProfile`, then proposes an ordered
engine plan. Verdict authority is unchanged — this only routes; the sound
oracle (sanitizer / BMC / syz-repro) still decides.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Optional


# Heuristic thresholds for "small enough that precise PA can decide".
SMALL_FUNCS = 80          # functions in scope
SMALL_LOC = 8000          # lines of code in scope


@dataclass
class TargetProfile:
    name: str
    is_kernel: bool = False
    scope_loc: Optional[int] = None        # LOC in the analysis scope
    scope_funcs: Optional[int] = None       # function count in scope
    target_function: Optional[str] = None   # a localized site, if any
    property_kind: str = "unknown"          # bounded | memory-safety | reachability | unknown
    bitcode_feasible: bool = False          # can we get LLVM bitcode for symbolic/BMC?
    has_fuzz_harness: bool = False          # libFuzzer/syzkaller entry available?


@dataclass
class PAStrategy:
    scale: str                              # small | large | hybrid
    engines: list[str] = field(default_factory=list)   # ordered PA engine plan
    rationale: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def _is_small_scope(p: TargetProfile) -> bool:
    if p.target_function is not None and p.scope_funcs is None and p.scope_loc is None:
        return True            # a single localized function = small by definition
    if p.scope_funcs is not None and p.scope_funcs <= SMALL_FUNCS:
        return True
    if p.scope_loc is not None and p.scope_loc <= SMALL_LOC:
        return True
    return False


def decide(p: TargetProfile) -> PAStrategy:
    """Pick the PA lane + an ordered engine plan for this target."""
    bounded = p.property_kind in ("bounded", "memory-safety")

    # 1. Kernel / whole-program / no bitcode -> LARGE-scale only.
    #    (symbolic/BMC don't scale here — established empirically.)
    if p.is_kernel or not p.bitcode_feasible:
        engines = ["static:smatch", "static:coccinelle", "reach:directed"]
        engines.append("fuzz:directed" if p.has_fuzz_harness else "fuzz:coverage")
        why = ("kernel/whole-program or no obtainable bitcode → scalable static "
               "analyzers + (directed) coverage fuzzing; symbolic/concolic/BMC "
               "do not scale to this target")
        return PAStrategy("large", engines, why)

    # 2. Small + bounded + bitcode-able -> SMALL-scale precise PA can DECIDE.
    if _is_small_scope(p) and bounded:
        engines = ["symbolic:klee", "bmc:cbmc"]
        if p.has_fuzz_harness:
            engines.append("fuzz:coverage")     # cheap pre-flight / cross-check
        why = ("small/bounded scope with obtainable bitcode → precise symbolic "
               "(KLEE) / bounded model checking (CBMC) can decide the property "
               "exactly and emit a counterexample")
        return PAStrategy("small", engines, why)

    # 3. Otherwise -> HYBRID: large-scale to localize + reach a small gate,
    #    then small-scale concolic to solve that localized gate.
    engines = ["static:smatch", "reach:directed"]
    engines.append("fuzz:directed" if p.has_fuzz_harness else "fuzz:coverage")
    engines.append("symbolic:klee@localized-gate")
    why = ("medium/unbounded scope → use scalable static+fuzz to localize and "
           "reach a small gate, then small-scale concolic on the extracted "
           "gate function to solve the hard branch")
    return PAStrategy("hybrid", engines, why)


# --- profile builders (benchmark-agnostic helpers) --------------------------

def profile_kernel(name: str, *, target_function: Optional[str] = None,
                   property_kind: str = "memory-safety",
                   has_fuzz_harness: bool = True) -> TargetProfile:
    """A Linux-kernel target: always large-scale (no bitcode, unbounded)."""
    return TargetProfile(name=name, is_kernel=True,
                         target_function=target_function,
                         property_kind=property_kind,
                         bitcode_feasible=False,
                         has_fuzz_harness=has_fuzz_harness)


def profile_extracted_function(name: str, target_function: str, *,
                               property_kind: str = "bounded",
                               loc: Optional[int] = None) -> TargetProfile:
    """A single extracted/standalone function with a bounded property —
    bitcode is obtainable (compile just this TU), so small-scale PA applies."""
    return TargetProfile(name=name, is_kernel=False, target_function=target_function,
                         scope_loc=loc, property_kind=property_kind,
                         bitcode_feasible=True, has_fuzz_harness=False)


def profile_oss_fuzz_target(name: str, *, scope_loc: Optional[int] = None,
                            scope_funcs: Optional[int] = None) -> TargetProfile:
    """A whole OSS-Fuzz libFuzzer target (large C/C++ tree, libFuzzer harness,
    whole-program bitcode impractical) → large-scale (corpus + coverage fuzz)."""
    return TargetProfile(name=name, is_kernel=False, scope_loc=scope_loc,
                         scope_funcs=scope_funcs, property_kind="memory-safety",
                         bitcode_feasible=False, has_fuzz_harness=True)


__all__ = ["TargetProfile", "PAStrategy", "decide",
           "profile_kernel", "profile_extracted_function", "profile_oss_fuzz_target"]
