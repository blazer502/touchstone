"""Phase 5.3 — Sound verification of spec-mining outliers (backward leg).

Reads Phase 5.2's outliers JSON and dispatches each suspect outlier through the
existing Phase 1.3 / 2.3 CBMC oracle (sound checker, final-verdict authority
per PLAN §8). The verifier never decides; it asks the engine and records the
engine's verdict.

Dispositions (mirroring Phase 1.5 / 2.5 vocabulary so 5.6's metrics adapter and
the existing soundness-gate counter can read this output uniformly):

  - confirmed             — engine returned UNSAFE *and* a witness PoV was
                            recorded by the engine. The only disposition that
                            counts toward the headline bug count.
  - refuted               — engine returned SAFE with engine-modeled
                            completeness (no `inconclusive` signal).
  - inconclusive          — engine timed out, unwinding-assertion failed, or
                            otherwise couldn't decide. Stays a lead.
  - infrastructure_pending — outlier requires harness infrastructure the MVP
                            doesn't yet emit (kernel source, non-lock contract
                            class, missing caller body, …). Documented in the
                            soundness note. NOT a confirmation.
  - proposer_deprioritized — outlier suspicion below --min-suspicion floor
                            (default 0.5). Funnel-economics skip — Phase 5.6
                            may revisit at a different threshold.

Soundness rule (PLAN §3b.3 + §8): a *confirmed* outlier requires both
``engine_verdict == "unsafe"`` AND ``pov_path is not None`` — i.e. the engine
returned an actual counterexample we can audit. Anything else stays
inconclusive or pending. ``false_confirmations`` is the gate counter; the
output JSON exposes it for the eval harness.

No LLM (Phase 5.3 rule).
"""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path
from typing import Optional

# Reuse existing engines (sound checker is the final verdict authority).
_REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO))
from oracle.tier3_bmc.cbmc_driver import run_cbmc_oracle  # noqa: E402

# Optional router-based dispatch (Phase 2.4/3.3 unified surface). Used when the
# caller passes --via-router, so spec-mining outliers flow through the same
# `agent.router.route()` Phase 5.6's closed loop will use.
from agent.router import (  # noqa: E402
    Hypothesis, Tier3CbmcSpec, route,
    R_BMC_UNSAFE, R_PROVED_SAFE, R_INCONCLUSIVE, R_NO_DISPATCH,
)

from surface.specmine.cbmc_oracle import (  # noqa: E402
    synthesise_harness, is_supported_contract,
)


DISPOSITIONS = (
    "confirmed",
    "refuted",
    "inconclusive",
    "infrastructure_pending",
    "proposer_deprioritized",
)


def _verify_one_via_router(
    base: dict,
    harness_path: Path,
    pov_dir: Path,
    safe_basename: str,
    unwind: int,
    timeout_s: int,
) -> dict:
    """Drive the same CBMC harness through `agent.router.route()`.

    Used when the caller passes --via-router. The router maps CBMC
    verdicts to its own vocabulary:
       R_PROVED_SAFE   ⇄ refuted
       R_BMC_UNSAFE    ⇄ confirmed (BMC witness; runtime replay is future work
                          for these synthesised harnesses, hence not R_CONFIRMED)
       R_INCONCLUSIVE  ⇄ inconclusive
       R_NO_DISPATCH   ⇄ infrastructure_pending (shouldn't happen with a
                          well-formed Tier3CbmcSpec attached).
    """
    hyp = Hypothesis(
        hid=f"specmine:{safe_basename}",
        description=(
            f"specmine outlier: {base.get('callee')} missing "
            f"{base.get('missing_contract')} in {base.get('caller')}"
        ),
        class_hint="bounded",
        tier3_cbmc=Tier3CbmcSpec(
            source=str(harness_path),
            function="main",
            property="assertion",
            unwind=unwind,
            timeout_s=timeout_s,
            unit=f"specmine:{safe_basename}",
        ),
    )
    t0 = time.monotonic()
    tr = route(hyp)
    wall_ms = int((time.monotonic() - t0) * 1000)
    # Pull the engine's own verdict + witness off the last cbmc Attempt.
    cbmc_attempts = [a for a in tr.attempts if a.engine == "cbmc"]
    engine_verdict = None
    evidence_excerpt = None
    soundness_note = None
    witness_path = tr.pov_path
    if cbmc_attempts:
        rv = cbmc_attempts[-1].raw_verdict or {}
        engine_verdict = rv.get("verdict")
        evidence_excerpt = (rv.get("evidence_excerpt") or "")[:512]
        soundness_note = rv.get("soundness_note")
        witness_path = witness_path or rv.get("pov_path")
    base["engine"] = "router(cbmc)"
    base["engine_verdict"] = engine_verdict
    base["engine_wall_ms"] = wall_ms
    base["evidence_excerpt"] = evidence_excerpt
    base["soundness_note"] = soundness_note
    base["witness_path"] = witness_path
    base["router_verdict"] = tr.final_verdict
    base["router_total_cost"] = tr.total_cost

    if tr.final_verdict == R_BMC_UNSAFE and witness_path:
        base["disposition"] = "confirmed"
    elif tr.final_verdict == R_BMC_UNSAFE:
        # Router said unsafe but the engine produced no witness → soundness
        # gate refuses to elevate to confirmed.
        base["disposition"] = "inconclusive"
        prior = soundness_note or ""
        base["soundness_note"] = (
            "Router returned BMC_UNSAFE but no PoV witness path was recorded; "
            f"refusing to mark confirmed without an audit-able cex. ({prior})"
        )
    elif tr.final_verdict == R_PROVED_SAFE:
        base["disposition"] = "refuted"
    elif tr.final_verdict == R_NO_DISPATCH:
        base["disposition"] = "infrastructure_pending"
        base["soundness_note"] = (
            "Router returned no_dispatch — no oracle tier accepted the spec. "
            "Check that Tier3CbmcSpec was attached and the CBMC image is built."
        )
    else:
        base["disposition"] = "inconclusive"
    return base


def _verify_one(
    outlier: dict,
    source_root: Path,
    out_dir: Path,
    min_suspicion: float,
    unwind: int,
    timeout_s: int,
    via_router: bool = False,
) -> dict:
    """Run the sound checker on one outlier; return a verified-outlier record."""
    base = dict(outlier)
    base.update({
        "disposition": None,
        "engine": None,
        "engine_verdict": None,
        "engine_wall_ms": None,
        "witness_path": None,
        "evidence_excerpt": None,
        "soundness_note": None,
    })

    suspicion = float(outlier.get("suspicion", 0.0) or 0.0)
    if suspicion < min_suspicion:
        base["disposition"] = "proposer_deprioritized"
        base["soundness_note"] = (
            f"suspicion={suspicion:.3f} < --min-suspicion={min_suspicion} "
            "(funnel economics — sound engine not invoked)."
        )
        return base

    kind_class = outlier.get("contract_kind_class", "")
    missing = outlier.get("missing_contract", "")
    if not is_supported_contract(kind_class, missing):
        base["disposition"] = "infrastructure_pending"
        base["soundness_note"] = (
            f"Contract class {kind_class!r}/{missing!r} not modelled by MVP "
            "harness synthesiser (lock-class only). Queued as 5.3.x hook; "
            "until then this outlier remains a proposer-level lead."
        )
        return base

    synth = synthesise_harness(outlier, source_root)
    if synth is None:
        base["disposition"] = "infrastructure_pending"
        base["soundness_note"] = (
            f"Harness synthesis returned None for caller={outlier.get('caller')!r} "
            f"in {outlier.get('file')!r} — caller body unavailable (ctags miss?), "
            "or source file not under --source-root. No verdict emitted."
        )
        return base
    if synth.get("unsupported"):
        base["disposition"] = "infrastructure_pending"
        base["soundness_note"] = synth["reason"]
        return base

    # Materialise the harness on disk and call CBMC.
    safe_basename = f"{outlier.get('callee', 'callee')}_{outlier.get('caller', 'caller')}"
    safe_basename = "".join(
        c if c.isalnum() or c in "_-." else "_" for c in safe_basename
    )
    harness_dir = out_dir / "harnesses"
    harness_dir.mkdir(parents=True, exist_ok=True)
    harness_path = harness_dir / f"{safe_basename}.c"
    harness_path.write_text(synth["source"])

    pov_dir = out_dir / "povs"
    pov_dir.mkdir(parents=True, exist_ok=True)

    if via_router:
        # Route through the same agent.router.route() Phase 5.6 will use.
        base["harness_path"] = str(harness_path)
        return _verify_one_via_router(
            base=base, harness_path=harness_path, pov_dir=pov_dir,
            safe_basename=safe_basename, unwind=unwind, timeout_s=timeout_s,
        )

    t0 = time.monotonic()
    v = run_cbmc_oracle(
        source=harness_path,
        function="main",
        property="assertion",
        unwind=unwind,
        timeout_s=timeout_s,
        out_dir=pov_dir,
        unit=f"specmine:{safe_basename}",
    )
    wall_ms = int((time.monotonic() - t0) * 1000)

    base["engine"] = "cbmc"
    base["engine_verdict"] = v.verdict
    base["engine_wall_ms"] = wall_ms
    base["evidence_excerpt"] = (v.evidence_excerpt or "")[:512]
    base["soundness_note"] = v.soundness_note
    base["witness_path"] = getattr(v, "pov_path", None)
    base["harness_path"] = str(harness_path)

    if v.verdict == "unsafe" and base["witness_path"]:
        # Soundness gate: confirmed requires BOTH unsafe AND a witness file.
        base["disposition"] = "confirmed"
    elif v.verdict == "unsafe":
        # Engine said unsafe but produced no witness — that's an engine
        # anomaly, not a confirmation. Mark inconclusive so the soundness
        # counter never fires off a witness-less verdict.
        base["disposition"] = "inconclusive"
        prior = base["soundness_note"] or ""
        base["soundness_note"] = (
            "Engine returned UNSAFE but no PoV witness was recorded; without "
            "an audit-able counterexample this does NOT count as confirmed. "
            f"({prior})"
        )
    elif v.verdict == "safe":
        base["disposition"] = "refuted"
    else:
        base["disposition"] = "inconclusive"
    return base


def verify_outliers(
    outliers_doc: dict,
    source_root: Path,
    out_dir: Path,
    min_suspicion: float,
    unwind: int,
    timeout_s: int,
    max_outliers: Optional[int] = None,
    via_router: bool = False,
) -> dict:
    """Run the sound checker on each outlier in the doc; return verified doc."""
    outliers = list(outliers_doc.get("outliers", []))
    if max_outliers is not None:
        outliers = outliers[:max_outliers]

    verified: list[dict] = []
    t0 = time.time()
    for o in outliers:
        verified.append(_verify_one(
            o, source_root, out_dir,
            min_suspicion=min_suspicion,
            unwind=unwind, timeout_s=timeout_s,
            via_router=via_router,
        ))
    wall = time.time() - t0

    by_disp: Counter[str] = Counter(v["disposition"] for v in verified)
    # false_confirmations is a structural gate: a "confirmed" without an
    # auditable witness OR with a missing harness should never happen here
    # (the _verify_one logic guards both), but we count anyway so the test
    # harness can assert == 0.
    false_confirmations = sum(
        1 for v in verified
        if v["disposition"] == "confirmed" and not v.get("witness_path")
    )

    return {
        "target": outliers_doc.get("target"),
        "generated_at": int(time.time()),
        "tau": outliers_doc.get("tau"),
        "min_support": outliers_doc.get("min_support"),
        "min_suspicion": min_suspicion,
        "unwind": unwind,
        "timeout_s": timeout_s,
        "engine": "cbmc",
        "stats": {
            "outliers_examined": len(verified),
            "by_disposition": dict(by_disp),
            "false_confirmations": false_confirmations,  # GATE
            "confirmed": by_disp.get("confirmed", 0),
            "refuted": by_disp.get("refuted", 0),
            "inconclusive": by_disp.get("inconclusive", 0),
            "infrastructure_pending": by_disp.get("infrastructure_pending", 0),
            "proposer_deprioritized": by_disp.get("proposer_deprioritized", 0),
            "wall_seconds": round(wall, 2),
        },
        "verified_outliers": verified,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Phase 5.3 sound verification.")
    ap.add_argument("--target", required=True, type=str)
    ap.add_argument("--outliers-from", type=Path,
                    help="Path to outliers JSON (default: derived from --target).")
    ap.add_argument("--source-root", required=True, type=Path,
                    help="Path the outlier 'file' fields are relative to.")
    ap.add_argument("--out", type=Path,
                    help="Output verified-outliers JSON path.")
    ap.add_argument("--min-suspicion", type=float, default=0.5,
                    help="Skip outliers below this suspicion (funnel economics).")
    ap.add_argument("--unwind", type=int, default=4,
                    help="CBMC --unwind value (default: 4).")
    ap.add_argument("--timeout-s", type=int, default=60,
                    help="CBMC per-outlier timeout (default: 60 s).")
    ap.add_argument("--max-outliers", type=int, default=None,
                    help="Cap on outliers verified (default: all).")
    ap.add_argument("--via-router", action="store_true",
                    help="Route through agent.router.route() instead of "
                         "calling CBMC directly (used by Phase 5.6).")
    args = ap.parse_args(argv)

    here = Path(__file__).resolve().parent
    outliers_path = (
        args.outliers_from or here / "outliers" / f"{args.target}.json"
    )
    if not outliers_path.exists():
        ap.error(f"outliers file missing: {outliers_path}")
    outliers_doc = json.loads(outliers_path.read_text())

    out_dir = here / "verified" / args.target
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = args.out or out_dir / "verified.json"

    verified_doc = verify_outliers(
        outliers_doc=outliers_doc,
        source_root=args.source_root.resolve(),
        out_dir=out_dir,
        min_suspicion=args.min_suspicion,
        unwind=args.unwind,
        timeout_s=args.timeout_s,
        max_outliers=args.max_outliers,
        via_router=args.via_router,
    )
    verified_doc["via_router"] = bool(args.via_router)
    out_path.write_text(json.dumps(verified_doc, indent=2, sort_keys=True) + "\n")

    s = verified_doc["stats"]
    print(
        f"[specmine] verified {s['outliers_examined']} outliers in "
        f"{s['wall_seconds']:.1f}s: "
        f"confirmed={s['confirmed']} refuted={s['refuted']} "
        f"inconclusive={s['inconclusive']} "
        f"pending={s['infrastructure_pending']} "
        f"depri={s['proposer_deprioritized']} "
        f"false_confirmations={s['false_confirmations']}"
    )
    print(f"[specmine] verified -> {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
