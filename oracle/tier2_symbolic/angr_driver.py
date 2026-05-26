"""angr driver (Tier-2 binary feasibility).

PLAN §3 Tier-2: angr handles binary-only components. Use case here is small:
given an ELF and a target (symbol or address), decide if the target is
reachable from the entry under symbolic stdin / argv, and if so emit a
concrete reproducing input.

Soundness (recorded in ``docs/soundness-assumptions.md`` Tier-2 entries):
- angr replaces libc/syscalls with ``SimProcedures``. Unmodeled calls drop
  precision — reachability can be over- or under-approximated. We surface
  the count of unmodeled SimProcedures in the verdict's ``soundness_note``.
- A SAT state at the target is a *candidate* PoV (re-confirm in Tier-1).
- UNSAT (no states in active or found, simgr drained to deadended within
  budget) is sound only under the SimProcedure set we activated; report
  unsat only when no unmodeled procedures fired.

No LLM in this module.
"""
from __future__ import annotations

import argparse
import io
import json
import logging
import os
import sys
import time
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Optional, Union

from .verdict import Tier2Verdict


def _truncate(text: str, limit: int = 4000) -> str:
    return text if len(text) <= limit else text[:limit] + f"\n…[truncated {len(text)-limit} bytes]"


def _resolve_target(proj, target: Union[int, str]) -> int:
    """Resolve a target spec (hex int, decimal int, or symbol name) to an address."""
    if isinstance(target, int):
        return target
    if isinstance(target, str):
        if target.startswith("0x"):
            return int(target, 16)
        if target.isdigit():
            return int(target)
        sym = proj.loader.find_symbol(target)
        if sym is None:
            raise ValueError(f"symbol not found in binary: {target}")
        return sym.rebased_addr
    raise TypeError(f"unsupported target: {target!r}")


def explore(binary: Path, target: Union[int, str],
            stdin_size: int = 32, step_budget: int = 200,
            wall_seconds: int = 60, unit: Optional[str] = None,
            avoid: Optional[list[Union[int, str]]] = None) -> Tier2Verdict:
    """Run angr against ``binary``, looking for a state at ``target``."""
    import angr
    import claripy

    unit = unit or binary.stem
    log_buf = io.StringIO()
    # Quiet angr's chatter so the evidence excerpt fits in the verdict.
    logging.getLogger("angr").setLevel(logging.ERROR)
    logging.getLogger("cle").setLevel(logging.ERROR)

    t0 = time.monotonic()
    timed_out = False
    try:
        with redirect_stdout(log_buf), redirect_stderr(log_buf):
            proj = angr.Project(str(binary), auto_load_libs=False)
            tgt = _resolve_target(proj, target)
            avoid_addrs = [_resolve_target(proj, a) for a in (avoid or [])]

            stdin_bv = claripy.BVS("stdin", stdin_size * 8)
            state = proj.factory.entry_state(stdin=stdin_bv)

            simgr = proj.factory.simulation_manager(state)
            steps = 0
            while (simgr.active and steps < step_budget
                   and (time.monotonic() - t0) < wall_seconds
                   and not simgr.stashes.get("found")):
                simgr.explore(find=tgt, avoid=avoid_addrs, n=1)
                steps += 1
            if (time.monotonic() - t0) >= wall_seconds:
                timed_out = True

            found_stash = simgr.stashes.get("found", [])
            deadended = simgr.stashes.get("deadended", [])
            active = simgr.stashes.get("active", [])
            unconstrained = simgr.stashes.get("unconstrained", [])
            avoided = simgr.stashes.get("avoid", [])
            found_state = found_stash[0] if found_stash else None
            unmodeled = 0
            for st in (active + deadended + found_stash):
                # angr stashes unmodeled-syscall warnings under SimProcedure resolution failures
                if "stub" in str(getattr(st.history, "jumpkind", "")):
                    unmodeled += 1
    except Exception as e:  # pylint: disable=broad-except
        wall_ms = int((time.monotonic() - t0) * 1000)
        return Tier2Verdict(
            unit=unit, engine="angr", verdict="inconclusive", wall_ms=wall_ms,
            property=f"reach({target!r})",
            evidence_excerpt=_truncate(log_buf.getvalue() + f"\nEXCEPTION: {e!r}"),
            soundness_note="angr exploration raised an exception; treat as inconclusive.",
            assumed=[f"stdin_size={stdin_size}", f"step_budget={step_budget}", f"wall_seconds={wall_seconds}"],
        )
    wall_ms = int((time.monotonic() - t0) * 1000)

    pov_path: Optional[str] = None
    target_loc: Optional[str] = None
    if found_state is not None:
        # Concretize stdin
        try:
            concrete = found_state.solver.eval(stdin_bv, cast_to=bytes)
        except Exception:  # pylint: disable=broad-except
            concrete = None
        if concrete is not None:
            pov_file = Path(tempfile.mkstemp(prefix=f"angr-pov-{unit}-", suffix=".bin")[1])
            pov_file.write_bytes(concrete)
            pov_path = str(pov_file)
        # Try to recover a symbol name at the target address for readability
        sym = proj.loader.find_symbol(tgt)
        target_loc = (sym.name if sym else f"0x{tgt:x}")

    if found_state is not None:
        verdict = "sat"
        note = ("angr reached the target under symbolic stdin; concrete input written. "
                "Re-confirm in Tier-1 (binary may use SimProcedures that diverge from libc).")
    elif timed_out:
        verdict = "inconclusive"
        note = "angr wall budget exhausted before finding or refuting the target."
    elif active or unconstrained:
        verdict = "inconclusive"
        note = "angr step budget exhausted with live states remaining."
    elif unmodeled > 0:
        verdict = "inconclusive"
        note = (f"angr exploration ended with {unmodeled} state(s) that hit unmodeled "
                "syscalls/SimProcedures; unsat under that model is unsound.")
    else:
        # Drained to deadended with no live states and no unmodeled procs.
        verdict = "unsat"
        note = ("angr exhausted all paths to deadended without reaching the target; "
                "unsat is sound only under the SimProcedure set in use.")

    return Tier2Verdict(
        unit=unit, engine="angr", verdict=verdict, wall_ms=wall_ms,
        property=f"reach({target!r})",
        paths_explored=len(deadended) + len(found_stash) + len(active) + len(avoided),
        paths_completed=len(deadended) + len(found_stash) + len(avoided),
        pov_path=pov_path,
        target_location=target_loc,
        evidence_excerpt=_truncate(log_buf.getvalue() +
                                   f"\nstashes: active={len(active)} "
                                   f"deadended={len(deadended)} "
                                   f"found={len(found_stash)} "
                                   f"avoid={len(avoided)} "
                                   f"unconstrained={len(unconstrained)}"),
        soundness_note=note,
        assumed=[f"stdin_size={stdin_size}", f"step_budget={step_budget}",
                 f"wall_seconds={wall_seconds}", "auto_load_libs=False",
                 "default SimProcedure set"],
    )


def _cli() -> int:
    ap = argparse.ArgumentParser(description="Tier-2 angr driver (binary feasibility).")
    ap.add_argument("--binary", required=True)
    ap.add_argument("--target", required=True, help="Symbol name or 0xADDR")
    ap.add_argument("--avoid", action="append", default=[], help="Symbol or 0xADDR to avoid (repeatable)")
    ap.add_argument("--stdin-size", type=int, default=32)
    ap.add_argument("--step-budget", type=int, default=200)
    ap.add_argument("--wall-seconds", type=int, default=60)
    ap.add_argument("--unit", default=None)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    v = explore(Path(args.binary), args.target,
                stdin_size=args.stdin_size, step_budget=args.step_budget,
                wall_seconds=args.wall_seconds, unit=args.unit,
                avoid=args.avoid or None)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(v.to_dict(), indent=2))
    print(json.dumps(v.to_dict(), indent=2))
    return 0 if v.verdict in {"sat", "unsat"} else 1


if __name__ == "__main__":
    sys.exit(_cli())
