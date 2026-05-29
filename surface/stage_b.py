#!/usr/bin/env python3
"""Stage B sound safety proof driver (Phase 1.3 — no LLM).

Wraps two backends:
  * CBMC      — bounded model checker for definite small-scope answers
  * Frama-C/EVA — modular abstract interpretation (primary engine when available)

Both run inside their pinned Docker images so verdicts are reproducible.
Fixed contracts only (no LLM-synthesized contracts yet — that is Phase 3.1).

Verdict schema (per unit, written to surface/stageb/<target>.json):
  {
    "unit":      "<file>::<function>",
    "property":  "memory-safety" | "no-overflow" | "no-oob" | "no-uaf" | ...,
    "engine":   "cbmc" | "framac-eva",
    "verdict":  "safe" | "unsafe" | "inconclusive",
    "unwind":    int | null,            # CBMC unwind bound; null for EVA
    "time_ms":   int,
    "evidence":  "<short tool-output snippet or counterexample path>",
    "soundness_note": "<from docs/soundness-assumptions.md>"
  }

The driver is intentionally backend-agnostic at the call site so Phase 1.4's
proof cache can hash {unit, property, engine, unwind, assumed contracts} as the
cache key.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

from surface import proof_cache
from surface import contract_synth

REPO = Path(__file__).resolve().parent.parent
TOOLCHAIN_LOCK = REPO / "docs" / "toolchain.lock"


def _read_lock() -> dict[str, str]:
    out: dict[str, str] = {}
    if not TOOLCHAIN_LOCK.exists():
        return out
    for line in TOOLCHAIN_LOCK.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        out[k.strip()] = v.strip()
    return out


LOCK = _read_lock()
CBMC_IMG = f"touchstone/cbmc:{LOCK.get('CBMC_VERSION', '6.4.0')}"
FRAMAC_IMG = f"touchstone/framac:{LOCK.get('FRAMAC_VERSION', '29.0')}"
DOCKER = os.environ.get("DOCKER", "sudo docker")


@dataclass
class Verdict:
    unit: str
    property: str
    engine: str
    verdict: str
    unwind: Optional[int]
    time_ms: int
    evidence: str
    soundness_note: str
    assumed_contracts: list[str] = field(default_factory=list)


def _docker_image_present(image: str) -> bool:
    try:
        r = subprocess.run(
            shlex.split(DOCKER) + ["image", "inspect", image],
            capture_output=True, timeout=30,
        )
        return r.returncode == 0
    except Exception:
        return False


# ---------------------------------------------------------------------------
# CBMC backend
# ---------------------------------------------------------------------------

# Result strings CBMC prints. We parse text rather than --xml-ui to keep the
# driver dependency-light; CBMC's text output is stable across 6.x.
_CBMC_VIOLATED = re.compile(r"VERIFICATION FAILED")
_CBMC_OK = re.compile(r"VERIFICATION SUCCESSFUL")
_CBMC_UNWIND_FAIL = re.compile(r"unwinding assertion.*: FAILURE", re.IGNORECASE)


def run_cbmc(
    source: Path,
    function: str,
    property: str = "memory-safety",
    unwind: int = 16,
    extra_flags: list[str] | None = None,
    timeout_s: int = 120,
) -> Verdict:
    """Run CBMC on `source` checking `function`.

    Property flags map (PLAN §2 Stage B target properties):
        memory-safety -> --bounds-check --pointer-check --memory-leak-check
        no-overflow   -> --signed-overflow-check --unsigned-overflow-check
        no-oob        -> --bounds-check
        no-uaf        -> --pointer-check --memory-cleanup-check
    """
    flag_map = {
        "memory-safety": [
            "--bounds-check", "--pointer-check", "--pointer-overflow-check",
            "--memory-leak-check", "--memory-cleanup-check",
        ],
        "no-overflow": [
            "--signed-overflow-check", "--unsigned-overflow-check",
            "--conversion-check",
        ],
        "no-oob": ["--bounds-check"],
        "no-uaf": ["--pointer-check"],
    }
    flags = flag_map.get(property, flag_map["memory-safety"])
    extra_flags = extra_flags or []
    src_abs = source.resolve()
    src_dir = src_abs.parent
    src_name = src_abs.name

    cmd = (
        shlex.split(DOCKER)
        + ["run", "--rm", "-v", f"{src_dir}:/work:ro", "-w", "/work", CBMC_IMG, "cbmc"]
        + [src_name, "--function", function, f"--unwind", str(unwind),
           "--unwinding-assertions", "-DCBMC_HARNESS=1"]
        + flags + extra_flags
    )
    t0 = time.time()
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s)
    except subprocess.TimeoutExpired:
        return Verdict(
            unit=f"{source.name}::{function}", property=property, engine="cbmc",
            verdict="inconclusive", unwind=unwind,
            time_ms=int((time.time() - t0) * 1000),
            evidence="timeout",
            soundness_note="CBMC bounded-soundness only up to unwind; timeout extends nothing.",
        )
    dt_ms = int((time.time() - t0) * 1000)
    out = (r.stdout or "") + (r.stderr or "")

    if _CBMC_OK.search(out):
        verdict = "safe"
    elif _CBMC_UNWIND_FAIL.search(out):
        # The reachable behaviour exceeds the unwind bound — Phase 3 will
        # synthesize a loop invariant; for Phase 1.3 we record inconclusive.
        verdict = "inconclusive"
    elif _CBMC_VIOLATED.search(out):
        verdict = "unsafe"
    else:
        verdict = "inconclusive"

    # Keep a short evidence snippet (last 12 non-empty lines).
    tail = [ln for ln in out.splitlines() if ln.strip()][-12:]
    evidence = "\n".join(tail)[-2000:]

    note = (
        "Bounded-sound up to --unwind={u}. Without a verified loop invariant "
        "this is NOT an unbounded-safety claim (docs/soundness-assumptions.md "
        "Stage B / CBMC bounded loops)."
    ).format(u=unwind)

    return Verdict(
        unit=f"{source.name}::{function}",
        property=property,
        engine="cbmc",
        verdict=verdict,
        unwind=unwind,
        time_ms=dt_ms,
        evidence=evidence,
        soundness_note=note,
    )


# ---------------------------------------------------------------------------
# Frama-C / EVA backend (used when the docker image is available)
# ---------------------------------------------------------------------------

# EVA prints `[eva] done for function <name>` and per-property status lines like
# `[eva:alarm] <file>:<line>: ... : <STATUS>`. STATUS \in {VALID, UNKNOWN, INVALID}.
_EVA_INVALID = re.compile(r"\[eva:alarm\].*: (invalid|Invalid)", re.IGNORECASE)
_EVA_UNKNOWN = re.compile(r"\[eva:alarm\].*: (unknown|Unknown)", re.IGNORECASE)


def run_framac_eva(
    source: Path,
    function: str,
    property: str = "memory-safety",
    timeout_s: int = 300,
    extra_flags: list[str] | None = None,
) -> Verdict:
    """Run Frama-C with the EVA plugin on `source`, entry-point `function`."""
    if not _docker_image_present(FRAMAC_IMG):
        return Verdict(
            unit=f"{source.name}::{function}", property=property,
            engine="framac-eva", verdict="inconclusive", unwind=None,
            time_ms=0, evidence=f"image-missing:{FRAMAC_IMG}",
            soundness_note="Frama-C container not built; verdict unavailable.",
        )
    src_abs = source.resolve()
    src_dir = src_abs.parent
    src_name = src_abs.name
    extra_flags = extra_flags or []
    cmd = (
        shlex.split(DOCKER)
        + ["run", "--rm", "-v", f"{src_dir}:/work:ro", "-w", "/work", FRAMAC_IMG]
        + ["frama-c", "-eva", "-main", function, "-no-deps", "-no-results",
           "-eva-no-show-progress", "-kernel-warn-key", "annot:missing-spec=inactive",
           "-machdep", "x86_64", src_name]
        + extra_flags
    )
    t0 = time.time()
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s)
    except subprocess.TimeoutExpired:
        return Verdict(
            unit=f"{source.name}::{function}", property=property,
            engine="framac-eva", verdict="inconclusive", unwind=None,
            time_ms=int((time.time() - t0) * 1000), evidence="timeout",
            soundness_note="EVA timed out; refine ACSL contracts or widen domain.",
        )
    dt_ms = int((time.time() - t0) * 1000)
    out = (r.stdout or "") + (r.stderr or "")

    if _EVA_INVALID.search(out):
        verdict = "unsafe"
    elif _EVA_UNKNOWN.search(out):
        verdict = "inconclusive"
    elif "[eva:final-states]" in out or "[eva] done" in out:
        # No alarms reported and EVA actually terminated → all properties valid
        # under EVA's sound abstract domain.
        verdict = "safe"
    else:
        verdict = "inconclusive"

    tail = [ln for ln in out.splitlines() if ln.strip()][-12:]
    evidence = "\n".join(tail)[-2000:]

    note = (
        "EVA is sound under its abstract domain (interval+congruence+gauges by "
        "default). Function-boundary contracts must be verified or proof-cache "
        "matched (docs/soundness-assumptions.md Stage B / Frama-C/EVA)."
    )
    return Verdict(
        unit=f"{source.name}::{function}",
        property=property,
        engine="framac-eva",
        verdict=verdict,
        unwind=None,
        time_ms=dt_ms,
        evidence=evidence,
        soundness_note=note,
    )


# ---------------------------------------------------------------------------
# Manifest-driven batch runner
# ---------------------------------------------------------------------------

ENGINE_VERSION = {
    "cbmc": LOCK.get("CBMC_VERSION", "6.4.0"),
    "framac-eva": LOCK.get("FRAMAC_VERSION", "29.0"),
}


def _cache_key_for(
    source: Path, engine: str, property: str, unwind: Optional[int],
    contracts: list[str], build_flags: dict,
) -> proof_cache.CacheKey:
    return proof_cache.make_key(
        body_text=source.read_text(),
        property=property,
        engine=engine,
        engine_version=ENGINE_VERSION.get(engine, "unknown"),
        unwind=unwind,
        assumed_contracts=contracts,
        build_flags=build_flags,
    )


# ---------------------------------------------------------------------------
# Phase 3.1 — LLM-synthesized contract refinement loop
# ---------------------------------------------------------------------------


def _run_cbmc_with_trace(
    source: Path,
    function: str,
    *,
    property: str = "memory-safety",
    unwind: int = 16,
    timeout_s: int = 120,
) -> tuple[Verdict, str]:
    """Like `run_cbmc` but also passes `--trace` and returns the full text.

    The Verdict's `evidence` is still the truncated tail; the second tuple
    element is the complete CBMC output (capped at 32 KB) for the synthesizer.
    """
    flag_map = {
        "memory-safety": [
            "--bounds-check", "--pointer-check", "--pointer-overflow-check",
            "--memory-leak-check", "--memory-cleanup-check",
        ],
        "no-overflow": [
            "--signed-overflow-check", "--unsigned-overflow-check",
            "--conversion-check",
        ],
        "no-oob": ["--bounds-check"],
        "no-uaf": ["--pointer-check"],
    }
    flags = flag_map.get(property, flag_map["memory-safety"])
    src_abs = source.resolve()
    cmd = (
        shlex.split(DOCKER)
        + ["run", "--rm", "-v", f"{src_abs.parent}:/work:ro", "-w", "/work",
           CBMC_IMG, "cbmc", src_abs.name, "--function", function,
           "--unwind", str(unwind), "--unwinding-assertions",
           "--trace", "-DCBMC_HARNESS=1"]
        + flags
    )
    t0 = time.time()
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s)
    except subprocess.TimeoutExpired:
        v = Verdict(
            unit=f"{source.name}::{function}", property=property, engine="cbmc",
            verdict="inconclusive", unwind=unwind,
            time_ms=int((time.time() - t0) * 1000),
            evidence="timeout",
            soundness_note="CBMC bounded-soundness only up to unwind; timeout extends nothing.",
        )
        return v, "timeout"
    dt_ms = int((time.time() - t0) * 1000)
    out = (r.stdout or "") + (r.stderr or "")
    if _CBMC_OK.search(out):
        verdict = "safe"
    elif _CBMC_UNWIND_FAIL.search(out):
        verdict = "inconclusive"
    elif _CBMC_VIOLATED.search(out):
        verdict = "unsafe"
    else:
        verdict = "inconclusive"
    tail = [ln for ln in out.splitlines() if ln.strip()][-12:]
    evidence = "\n".join(tail)[-2000:]
    note = (
        f"Bounded-sound up to --unwind={unwind}. Without a verified loop "
        "invariant this is NOT an unbounded-safety claim "
        "(docs/soundness-assumptions.md Stage B / CBMC bounded loops)."
    )
    v = Verdict(
        unit=f"{source.name}::{function}", property=property, engine="cbmc",
        verdict=verdict, unwind=unwind, time_ms=dt_ms, evidence=evidence,
        soundness_note=note,
    )
    return v, out[-32_000:]

# Conventional marker: harness authors place `/* @CONTRACTS */` after variable
# declarations and before the first non-declaration statement. The refinement
# loop replaces this marker with the synthesized `__CPROVER_assume(...);` lines.
# When no marker is present we fall back to injecting just before the `return`
# of `main` — variables are then already in scope and the assumption still
# constrains the symbolic values CBMC has been carrying through.
_CONTRACT_MARKER = re.compile(r"/\*\s*@CONTRACTS\s*\*/")
_MAIN_RETURN = re.compile(
    r"(?P<indent>[ \t]*)return\s+0\s*;[ \t]*\n(?=\s*\})", re.MULTILINE,
)


def _inject_assumptions(source_text: str, contracts: list[str]) -> Optional[str]:
    """Inject `__CPROVER_assume(...);` lines so they constrain `main`'s vars.

    Order of preference:
      1. Replace `/* @CONTRACTS */` marker if present.
      2. Insert right before `return 0;` in `main` (post-declaration scope).

    Returns None when neither anchor is found.
    """
    block_lines = ["/* Phase 3.1: synthesized contracts */"] + list(contracts)
    if _CONTRACT_MARKER.search(source_text):
        replacement = "\n    ".join(block_lines)
        return _CONTRACT_MARKER.sub(replacement, source_text, count=1)
    m = _MAIN_RETURN.search(source_text)
    if m is None:
        return None
    indent = m.group("indent") or "    "
    block = "".join(f"{indent}{ln}\n" for ln in block_lines)
    return source_text[:m.start()] + block + source_text[m.start():]


@dataclass
class RefinementStep:
    iteration: int
    contracts_added: list[str]
    verdict: str
    time_ms: int
    synth_source: str             # "llm" | "rule" | "none"
    synth_tokens: int = 0
    synth_error: Optional[str] = None
    evidence: str = ""


@dataclass
class RefinedVerdict:
    final: Verdict
    accumulated_contracts: list[str]
    history: list[RefinementStep]
    total_tokens: int


def refine_unit(
    source: Path,
    function: str,
    property: str,
    *,
    unwind: int = 16,
    max_iters: int = 3,
    seed_contracts: Optional[list[str]] = None,
    client=None,
    allow_rule_fallback: bool = True,
) -> RefinedVerdict:
    """Refinement loop: CBMC ↔ LLM synthesizer.

    1. Run CBMC under `seed_contracts` (Phase 1.3 fixed contracts, may be []).
    2. If verdict == safe, stop.
    3. Otherwise, hand the source + trace to `contract_synth.synthesize`,
       collect the proposed assumption, re-run CBMC under the new contract.
    4. Repeat until safe, or no new contract is produced, or `max_iters` hit.

    The verdict returned is always the *engine's* verdict — the LLM never
    flips a safe/unsafe decision (PLAN §8). `accumulated_contracts` is what
    the final verdict is conditioned on, and feeds the Phase 1.4 cache key
    so a hit on this verdict is invalid if those contracts no longer hold.
    """
    src_text = source.read_text()
    contracts = list(seed_contracts or [])
    history: list[RefinementStep] = []
    total_tokens = 0

    # Build a working copy under a temp dir so we never mutate the input source.
    import tempfile
    work_root = Path(tempfile.mkdtemp(prefix="stageb-refine-"))
    work_src = work_root / source.name

    # The refinement loop captures the full CBMC text (with --trace) so the
    # synthesizer sees variable assignments — not just the last 12 evidence
    # lines that run_cbmc stores. We keep two outputs side by side: the
    # truncated `Verdict.evidence` for downstream metrics/cache, and a local
    # `full_trace` used only by the synth call this iteration.
    last_trace: str = ""

    def _run(text: str) -> Verdict:
        nonlocal last_trace
        work_src.write_text(text)
        v, full = _run_cbmc_with_trace(
            work_src, function, property=property, unwind=unwind,
        )
        last_trace = full
        return v

    # Iteration 0 — baseline (seed contracts only).
    current_text = src_text if not contracts else (
        _inject_assumptions(src_text, contracts) or src_text
    )
    v = _run(current_text)
    history.append(RefinementStep(
        iteration=0, contracts_added=[], verdict=v.verdict,
        time_ms=v.time_ms, synth_source="none", evidence=v.evidence[-400:],
    ))

    iteration = 0
    while v.verdict != "safe" and iteration < max_iters:
        iteration += 1
        synth = contract_synth.synthesize(
            source_text=current_text,
            function=function,
            property=property,
            counterexample=last_trace or v.evidence,
            prior_contracts=contracts,
            iter_index=iteration,
            client=client,
            allow_rule_fallback=allow_rule_fallback,
        )
        total_tokens += synth.tokens_used
        if not synth.contracts:
            history.append(RefinementStep(
                iteration=iteration, contracts_added=[], verdict=v.verdict,
                time_ms=0, synth_source=synth.source,
                synth_tokens=synth.tokens_used, synth_error=synth.error,
                evidence=f"no contract proposed: {synth.raw_response[-200:]}",
            ))
            break
        contracts.extend(synth.contracts)
        patched = _inject_assumptions(src_text, contracts)
        if patched is None:
            history.append(RefinementStep(
                iteration=iteration, contracts_added=synth.contracts,
                verdict=v.verdict, time_ms=0, synth_source=synth.source,
                synth_tokens=synth.tokens_used,
                synth_error="no main() to inject into",
                evidence="",
            ))
            break
        current_text = patched
        v = _run(current_text)
        history.append(RefinementStep(
            iteration=iteration, contracts_added=synth.contracts,
            verdict=v.verdict, time_ms=v.time_ms, synth_source=synth.source,
            synth_tokens=synth.tokens_used, synth_error=synth.error,
            evidence=v.evidence[-400:],
        ))

    v.assumed_contracts = list(contracts)
    return RefinedVerdict(
        final=v, accumulated_contracts=contracts,
        history=history, total_tokens=total_tokens,
    )


def refine_manifest(
    manifest_path: Path,
    out_path: Path,
    *,
    max_iters: int = 3,
    client=None,
    allow_rule_fallback: bool = True,
) -> dict:
    """Run `refine_unit` over every unit in a manifest, emit a summary JSON.

    Manifest schema is the same as `run_manifest`'s. The result file records
    per-unit history (each refinement step's verdict + which contract was
    added), the final verdict, and any soundness failures.
    """
    manifest = json.loads(manifest_path.read_text())
    base = manifest_path.parent
    results: list[dict] = []
    counts = {"safe": 0, "unsafe": 0, "inconclusive": 0}
    soundness_failures: list[dict] = []
    total_tokens = 0
    improved = 0  # baseline verdict != final verdict

    for u in manifest["units"]:
        src = (base / u["source"]).resolve()
        prop = u.get("property", "memory-safety")
        unwind = u.get("unwind", 16)
        expected = u.get("expected")
        seed = list(u.get("assumed_contracts", []))
        # Only CBMC is wired in the refinement loop (Phase 3.1).
        engines = u.get("engines", ["cbmc"])
        if "cbmc" not in engines:
            continue
        rv = refine_unit(
            src, u["function"], prop,
            unwind=unwind, max_iters=max_iters, seed_contracts=seed,
            client=client, allow_rule_fallback=allow_rule_fallback,
        )
        baseline_verdict = rv.history[0].verdict if rv.history else rv.final.verdict
        if baseline_verdict != rv.final.verdict:
            improved += 1
        v_dict = asdict(rv.final)
        v_dict["refinement_history"] = [asdict(h) for h in rv.history]
        v_dict["accumulated_contracts"] = rv.accumulated_contracts
        v_dict["baseline_verdict"] = baseline_verdict
        v_dict["synth_tokens"] = rv.total_tokens
        results.append(v_dict)
        counts[rv.final.verdict] = counts.get(rv.final.verdict, 0) + 1
        total_tokens += rv.total_tokens
        if expected and rv.final.verdict != expected and rv.final.verdict != "inconclusive":
            soundness_failures.append({
                "unit": rv.final.unit, "engine": rv.final.engine,
                "expected": expected, "got": rv.final.verdict,
            })

    summary = {
        "target": manifest["target"],
        "generated_at": int(time.time()),
        "manifest": str(manifest_path),
        "phase": "3.1-refinement",
        "max_iters": max_iters,
        "counts": counts,
        "improved_units": improved,
        "synth_tokens_total": total_tokens,
        "soundness_failures": soundness_failures,
        "results": results,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(summary, indent=2))
    return summary


def run_manifest(manifest_path: Path, out_path: Path, *, use_cache: bool = True) -> dict:
    """Run Stage B on every unit listed in a JSON manifest.

    Manifest schema:
      {"target": "...", "build_flags": {"sanitizer": "asan", ...},
       "units": [
        {"source": "rel/path.c", "function": "fn", "property": "memory-safety",
         "engines": ["cbmc"], "unwind": 16, "expected": "safe"|"unsafe"|null,
         "assumed_contracts": ["len <= CAP", ...]}
       ]}
    """
    manifest = json.loads(manifest_path.read_text())
    base = manifest_path.parent
    build_flags = manifest.get("build_flags", {})
    results = []
    counts = {"safe": 0, "unsafe": 0, "inconclusive": 0}
    soundness_failures = []  # expected=safe but we got unsafe (real bug pruned),
                             # or expected=unsafe but we got safe.
    cache_hits = 0
    cache_misses = 0
    for u in manifest["units"]:
        src = (base / u["source"]).resolve()
        prop = u.get("property", "memory-safety")
        unwind = u.get("unwind", 16)
        expected = u.get("expected")
        contracts = list(u.get("assumed_contracts", []))
        for eng in u.get("engines", ["cbmc"]):
            v = None
            key = _cache_key_for(src, eng, prop, unwind if eng == "cbmc" else None,
                                 contracts, build_flags)
            if use_cache:
                hit = proof_cache.lookup(key, current_contracts=contracts)
                if hit is not None:
                    v_dict = dict(hit.verdict)
                    v_dict["evidence"] = "[cache-hit] " + v_dict.get("evidence", "")
                    results.append(v_dict)
                    counts[v_dict["verdict"]] = counts.get(v_dict["verdict"], 0) + 1
                    cache_hits += 1
                    if expected and v_dict["verdict"] != expected and v_dict["verdict"] != "inconclusive":
                        soundness_failures.append({
                            "unit": v_dict["unit"], "engine": v_dict["engine"],
                            "expected": expected, "got": v_dict["verdict"],
                            "from_cache": True,
                        })
                    continue
            if eng == "cbmc":
                v = run_cbmc(src, u["function"], prop, unwind=unwind)
            elif eng == "framac-eva":
                v = run_framac_eva(src, u["function"], prop)
            else:
                continue
            v.assumed_contracts = contracts
            results.append(asdict(v))
            counts[v.verdict] = counts.get(v.verdict, 0) + 1
            cache_misses += 1
            # Only cache safe/unsafe verdicts; inconclusive shouldn't be sticky
            # (next run might try a higher unwind / better contracts).
            if use_cache and v.verdict in ("safe", "unsafe"):
                proof_cache.store(key, asdict(v), contracts, build_flags)
            if expected and v.verdict != expected and v.verdict != "inconclusive":
                soundness_failures.append({
                    "unit": v.unit, "engine": v.engine,
                    "expected": expected, "got": v.verdict,
                    "from_cache": False,
                })

    summary = {
        "target": manifest["target"],
        "generated_at": int(time.time()),
        "manifest": str(manifest_path),
        "counts": counts,
        "cache": {"hits": cache_hits, "misses": cache_misses},
        "soundness_failures": soundness_failures,
        "results": results,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(summary, indent=2))
    return summary


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--manifest", required=True, type=Path)
    p.add_argument("--out", required=True, type=Path)
    p.add_argument("--no-cache", action="store_true",
                   help="bypass proof cache (Phase 1.4) — every unit runs fresh")
    args = p.parse_args()
    s = run_manifest(args.manifest, args.out, use_cache=not args.no_cache)
    c = s["counts"]
    cache = s.get("cache", {})
    print(
        f"stage_b: safe={c.get('safe',0)} unsafe={c.get('unsafe',0)} "
        f"inconclusive={c.get('inconclusive',0)} "
        f"cache_hits={cache.get('hits',0)} cache_misses={cache.get('misses',0)} "
        f"soundness_failures={len(s['soundness_failures'])}"
    )
    return 1 if s["soundness_failures"] else 0


if __name__ == "__main__":
    sys.exit(main())
