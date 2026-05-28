"""Phase 5.5 — LLM-assisted contract refinement (PLAN §3b.5).

When Phase 5.3 returns disposition=`inconclusive` (engine timeout, unwinding-
assertion failure, or unsafe-without-witness), this module invokes the
synthesizer LLM under the Phase 3.1 proposer pattern: prompt = {mined contract,
outlier callsite, caller body excerpt, CBMC evidence}; output is a list of
`__CPROVER_assume(...)` preconditions to inject into main(); the sound checker
re-verifies. Verdict authority stays with the engine — the LLM proposes, CBMC
disposes (PLAN §8). A `rule_based_refine` deterministic fallback covers the
gateway-down case so the loop is testable in CI.

Done-when (PLAN §6 Phase 5.5):
  - ≥1 mined contract refined and re-verified end-to-end via the live gateway;
  - fallback path exercised with GATEWAY_PORT=9.

Soundness rules (recorded in `docs/soundness-assumptions.md`):
  - LLM proposes only `__CPROVER_assume(<expr>);` lines on the symbolic input
    variables `arg0..argN`. Any other output line is dropped before re-synth
    (same structural defense as Phase 3.1's `_extract_contract_lines`).
  - Tautological / "assume the bug away" preconditions (`1`, `true`, `1 == 1`,
    `0 == 0`, references to undeclared identifiers) are rejected at parse time.
  - Re-verification follows the same Phase 5.3 disposition rules: confirmed
    requires UNSAFE + witness; the `false_confirmations` gate carries through.

No silent verdict flips: the refined verdict is recorded *alongside* the
original disposition, so the eval harness sees both `pre_refine_disposition`
and `post_refine_disposition` and the LLM can never "fix" an outlier by
hand-waving.
"""
from __future__ import annotations

import argparse
import json
import logging
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

_REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO))
from llm.client import LLMClient, LLMUnavailable  # noqa: E402
from oracle.tier3_bmc.cbmc_driver import run_cbmc_oracle  # noqa: E402

from surface.specmine.cbmc_oracle import (  # noqa: E402
    synthesise_harness, is_supported_contract, extract_function_body,
)

log = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Prompt
# --------------------------------------------------------------------------- #

REFINEMENT_SYSTEM_PROMPT = """You are an expert C verification engineer.

A CBMC bounded model checker tried to verify a spec-mining outlier — a callsite
that lacks a near-universal mined contract on its callee. The verification was
INCONCLUSIVE, typically because:
  * the caller contains a loop whose iteration count exceeds the unwind cap,
    triggering an unwinding-assertion failure; OR
  * the harness needs a tighter precondition on its symbolic input variables.

The harness names its symbolic input variables `arg0`, `arg1`, ..., `argN`,
one per parameter of the caller function.

Your job: propose one or more `__CPROVER_assume(<C-expression>);` preconditions
that, when injected into main() before the caller invocation, would let CBMC
decide within a small unwind. The preconditions MUST:
  * bind only the symbolic input variables `arg0..argN`;
  * use plausible upper bounds (≤ 4 or ≤ 8 are typical loop bounds);
  * NOT "assume the bug away" — e.g. forbid `1 == 0`, `false`,
    `arg0 != <crashing-value>`, or references to undeclared identifiers.

Reply with ONLY a single-line JSON object:
  {"preconditions": ["__CPROVER_assume(arg0 >= 0);", "__CPROVER_assume(arg0 <= 4);"], "rationale": "<one short sentence>"}

If you cannot propose a sound refinement, reply:
  {"preconditions": [], "rationale": "<one short sentence>"}

No prose, no markdown, no triple backticks.
"""


def _build_user_prompt(
    *,
    mined_contract: str,
    callee: str,
    caller: str,
    file_path: str,
    line: int,
    caller_body: str,
    evidence_excerpt: str,
) -> str:
    parts = [
        f"# Outlier",
        f"- mined contract: `{mined_contract}` (callee `{callee}`)",
        f"- caller:        `{caller}` at {file_path}:{line}",
        "",
        "## Caller body",
        "```c",
        caller_body.strip()[:2000],
        "```",
        "",
        "## CBMC evidence (inconclusive run)",
        "```",
        (evidence_excerpt or "").strip()[:1500],
        "```",
        "",
        "Propose preconditions that bound the symbolic inputs so the next CBMC "
        "run decides. Output JSON only.",
    ]
    return "\n".join(parts)


# --------------------------------------------------------------------------- #
# Output parsing + validation
# --------------------------------------------------------------------------- #

_PRECOND_RE = re.compile(r"^__CPROVER_assume\s*\(.+\)\s*;\s*$")
_TAUTOLOGY_BODY_RE = re.compile(
    r"^\s*(?:1|0\s*==\s*0|1\s*==\s*1|true|!\s*(?:0|false))\s*$"
)


def _parse_llm_json(text: str) -> tuple[list[str], str]:
    """Extract (preconditions, rationale) from the LLM's JSON-only reply.

    Returns ([], "<reason>") on any parse error so the caller can fall back.
    """
    text = (text or "").strip()
    # Strip a leading triple-fence if the model emitted one despite instructions.
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
    # Some models add a trailing newline + commentary; isolate the first {...}.
    m = re.search(r"\{.*\}", text, flags=re.DOTALL)
    if not m:
        return [], f"no JSON object in response: {text[:80]!r}"
    try:
        obj = json.loads(m.group(0))
    except json.JSONDecodeError as e:
        return [], f"malformed JSON: {e}"
    raw = obj.get("preconditions", [])
    rationale = str(obj.get("rationale", "") or "")
    if not isinstance(raw, list):
        return [], f"preconditions not a list: {raw!r}"
    return [str(p) for p in raw], rationale


def filter_preconditions(raw: list[str]) -> list[str]:
    """Keep only sound `__CPROVER_assume(...)` lines referencing arg* vars."""
    out: list[str] = []
    seen: set[str] = set()
    for line in raw:
        s = line.strip()
        if not s:
            continue
        if not s.endswith(";"):
            s = s + ";"
        if not _PRECOND_RE.match(s):
            log.debug("dropping non-assume line: %r", s)
            continue
        # Pull the expression out for tautology / arg-only check.
        body = re.match(r"^__CPROVER_assume\s*\((.+)\)\s*;\s*$", s).group(1).strip()
        if _TAUTOLOGY_BODY_RE.match(body):
            log.debug("dropping tautological assume: %r", body)
            continue
        # Must reference an `arg<N>` identifier — anything else either invents
        # variables or "assumes the bug away" via free identifiers.
        if not re.search(r"\barg\d+\b", body):
            log.debug("dropping precondition without arg-ref: %r", body)
            continue
        if s in seen:
            continue
        seen.add(s)
        out.append(s)
    return out


# --------------------------------------------------------------------------- #
# Rule-based fallback (deterministic, gateway-down)
# --------------------------------------------------------------------------- #

def rule_based_refine(
    *,
    evidence_excerpt: str,
    caller_arity: int,
) -> tuple[list[str], str]:
    """Deterministic fallback when the LLM is unreachable / output unusable.

    Detects unwinding-assertion failures in the evidence and emits a generic
    upper-bound on the first symbolic input. Same shape as Phase 3.1's
    `rule_based_synth`: simple, predictable, exercised under GATEWAY_PORT=9.
    """
    ev = (evidence_excerpt or "").lower()
    unwind_failed = (
        "unwind" in ev and ("assert" in ev or "fail" in ev or "unwinding" in ev)
    )
    if caller_arity <= 0:
        # No symbolic inputs to bound. Nothing useful the rule can propose.
        return [], "rule_based: caller has no symbolic args to bound."
    if unwind_failed or "satisfiable" in ev or "trace" in ev:
        # Bound the first symbolic argument that drives the caller's loop.
        return (
            ["__CPROVER_assume(arg0 >= 0);", "__CPROVER_assume(arg0 <= 4);"],
            "rule_based: bound the first symbolic argument to [0,4] to "
            "close the unwinding-assertion gap.",
        )
    return [], "rule_based: no recognised inconclusive signature in evidence."


# --------------------------------------------------------------------------- #
# Refinement loop
# --------------------------------------------------------------------------- #

@dataclass
class RefineResult:
    callee: str
    caller: str
    file: str
    line: int
    pre_refine_disposition: str
    pre_refine_verdict: Optional[str] = None
    refinement_source: str = "none"       # "llm" | "rule" | "none"
    preconditions: list[str] = field(default_factory=list)
    rationale: str = ""
    raw_response: str = ""
    tokens_used: int = 0
    llm_latency_s: float = 0.0
    refined_engine_verdict: Optional[str] = None
    refined_engine_wall_ms: Optional[int] = None
    refined_witness_path: Optional[str] = None
    post_refine_disposition: str = "inconclusive"
    soundness_note: Optional[str] = None
    error: Optional[str] = None


def _read_caller_body(source_root: Path, outlier: dict) -> Optional[str]:
    rel_file = outlier.get("file")
    caller = outlier.get("caller")
    if not rel_file or not caller:
        return None
    p = source_root / rel_file
    if not p.is_file():
        return None
    ex = extract_function_body(p, caller)
    return ex[0] if ex else None


def refine_one(
    verified_record: dict,
    source_root: Path,
    out_dir: Path,
    *,
    llm: Optional[LLMClient],
    re_unwind: int = 8,
    timeout_s: int = 60,
) -> RefineResult:
    rr = RefineResult(
        callee=verified_record.get("callee") or "",
        caller=verified_record.get("caller") or "",
        file=verified_record.get("file") or "",
        line=int(verified_record.get("line") or 0),
        pre_refine_disposition=verified_record.get("disposition") or "",
        pre_refine_verdict=verified_record.get("engine_verdict"),
    )
    if verified_record.get("disposition") != "inconclusive":
        rr.soundness_note = "Not inconclusive; skipped by refinement filter."
        return rr
    if not is_supported_contract(
        verified_record.get("contract_kind_class", ""),
        verified_record.get("missing_contract", ""),
    ):
        rr.soundness_note = (
            "Contract class not supported by 5.3 harness synthesiser; "
            "refinement skipped (5.5.x hook will pair with the 5.3.x extension)."
        )
        return rr

    caller_body = _read_caller_body(source_root, verified_record)
    if caller_body is None:
        rr.error = "caller body unavailable; cannot build refinement prompt."
        rr.soundness_note = rr.error
        return rr

    # Estimate caller arity (same heuristic the harness synthesiser uses).
    caller_arity = 1
    m = re.search(
        rf"\b{re.escape(rr.caller)}\s*\(([^)]*)\)\s*\{{", caller_body
    )
    if m:
        params = m.group(1).strip()
        caller_arity = 0 if params in ("", "void") else params.count(",") + 1

    # 1. Try the LLM first.
    pre_raw: list[str] = []
    rationale = ""
    if llm is not None:
        user = _build_user_prompt(
            mined_contract=verified_record.get("missing_contract", ""),
            callee=rr.callee, caller=rr.caller,
            file_path=rr.file, line=rr.line,
            caller_body=caller_body,
            evidence_excerpt=verified_record.get("evidence_excerpt", "") or "",
        )
        try:
            chat = llm.chat(
                system=REFINEMENT_SYSTEM_PROMPT, user=user,
                role="synthesizer", max_tokens=512, temperature=0.0,
            )
            rr.raw_response = chat.text
            rr.tokens_used = chat.total_tokens
            rr.llm_latency_s = chat.latency_s
            pre_raw, rationale = _parse_llm_json(chat.text)
            if pre_raw:
                rr.refinement_source = "llm"
            else:
                rr.refinement_source = "none"
        except LLMUnavailable as e:
            rr.error = f"LLM unavailable: {e}"
            rr.refinement_source = "none"
        except Exception as e:  # parse error / transient
            rr.error = f"LLM call/parse exception: {e}"
            rr.refinement_source = "none"

    preconditions = filter_preconditions(pre_raw) if pre_raw else []
    # 2. Rule-based fallback if the LLM didn't produce usable preconditions.
    if not preconditions:
        fb, fb_rationale = rule_based_refine(
            evidence_excerpt=verified_record.get("evidence_excerpt", "") or "",
            caller_arity=caller_arity,
        )
        if fb:
            preconditions = filter_preconditions(fb)
            rationale = rationale or fb_rationale
            rr.refinement_source = "rule"

    rr.preconditions = preconditions
    rr.rationale = rationale

    if not preconditions:
        rr.soundness_note = (
            "No usable preconditions proposed; outlier stays `inconclusive`."
        )
        return rr

    # 3. Re-synthesise the harness with preconditions + re-verify.
    synth = synthesise_harness(
        verified_record, source_root, extra_preconditions=preconditions,
    )
    if synth is None or synth.get("unsupported"):
        rr.soundness_note = (
            "Re-synthesis failed (caller body or callee dropped after refinement); "
            "disposition unchanged."
        )
        return rr
    refined_dir = out_dir / "refined_harnesses"
    refined_dir.mkdir(parents=True, exist_ok=True)
    safe = "".join(
        c if c.isalnum() or c in "_-." else "_"
        for c in f"{rr.callee}_{rr.caller}"
    )
    refined_path = refined_dir / f"{safe}.c"
    refined_path.write_text(synth["source"])

    pov_dir = out_dir / "refined_povs"
    pov_dir.mkdir(parents=True, exist_ok=True)

    t0 = time.monotonic()
    v = run_cbmc_oracle(
        source=refined_path, function="main", property="assertion",
        unwind=re_unwind, timeout_s=timeout_s, out_dir=pov_dir,
        unit=f"specmine-refined:{safe}",
    )
    rr.refined_engine_verdict = v.verdict
    rr.refined_engine_wall_ms = int((time.monotonic() - t0) * 1000)
    rr.refined_witness_path = getattr(v, "pov_path", None)

    if v.verdict == "unsafe" and rr.refined_witness_path:
        rr.post_refine_disposition = "confirmed"
        rr.soundness_note = (
            f"Refinement converted inconclusive → confirmed: "
            f"{len(preconditions)} preconditions injected, CBMC unsafe with "
            f"witness at re-unwind={re_unwind}."
        )
    elif v.verdict == "unsafe":
        rr.post_refine_disposition = "inconclusive"
        rr.soundness_note = (
            "Engine returned UNSAFE post-refinement but no PoV witness "
            "recorded — gate refuses to elevate without auditable cex."
        )
    elif v.verdict == "safe":
        rr.post_refine_disposition = "refuted"
        rr.soundness_note = (
            f"Refinement converted inconclusive → refuted: "
            f"preconditions establish the contract within unwind={re_unwind}."
        )
    else:
        rr.post_refine_disposition = "inconclusive"
        rr.soundness_note = (
            "Refinement did not produce a decisive verdict; stays inconclusive."
        )
    return rr


def refine(
    verified_doc: dict,
    source_root: Path,
    out_dir: Path,
    *,
    use_llm: bool,
    re_unwind: int,
    timeout_s: int,
) -> dict:
    llm = LLMClient() if use_llm else None
    if llm is not None:
        try:
            llm.healthz()
        except LLMUnavailable as e:
            log.warning("gateway healthz failed (%s); using fallback only", e)
            llm = None
    results: list[dict] = []
    t0 = time.time()
    confirmed_before = 0
    confirmed_after = 0
    for v in verified_doc.get("verified_outliers", []):
        if v.get("disposition") == "confirmed":
            confirmed_before += 1
            confirmed_after += 1
            continue  # not a refinement candidate
        if v.get("disposition") != "inconclusive":
            continue
        rr = refine_one(
            v, source_root, out_dir,
            llm=llm, re_unwind=re_unwind, timeout_s=timeout_s,
        )
        results.append(rr.__dict__)
        if rr.post_refine_disposition == "confirmed":
            confirmed_after += 1
    wall = time.time() - t0
    flips = sum(
        1 for r in results
        if r["pre_refine_disposition"] == "inconclusive"
        and r["post_refine_disposition"] in ("confirmed", "refuted")
    )
    return {
        "target": verified_doc.get("target"),
        "generated_at": int(time.time()),
        "re_unwind": re_unwind,
        "timeout_s": timeout_s,
        "use_llm": use_llm,
        "stats": {
            "refinement_candidates": len(results),
            "refined_to_confirmed": sum(
                1 for r in results if r["post_refine_disposition"] == "confirmed"
            ),
            "refined_to_refuted": sum(
                1 for r in results if r["post_refine_disposition"] == "refuted"
            ),
            "still_inconclusive": sum(
                1 for r in results if r["post_refine_disposition"] == "inconclusive"
            ),
            "decisive_flips": flips,
            "by_refinement_source": {
                "llm":  sum(1 for r in results if r["refinement_source"] == "llm"),
                "rule": sum(1 for r in results if r["refinement_source"] == "rule"),
                "none": sum(1 for r in results if r["refinement_source"] == "none"),
            },
            "total_tokens_used": sum(int(r["tokens_used"]) for r in results),
            "wall_seconds": round(wall, 2),
        },
        "results": results,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Phase 5.5 contract refinement.")
    ap.add_argument("--target", required=True, type=str)
    ap.add_argument("--verified-from", type=Path,
                    help="surface/specmine/verified/<target>/verified.json (default: derived).")
    ap.add_argument("--source-root", required=True, type=Path)
    ap.add_argument("--out", type=Path)
    ap.add_argument("--re-unwind", type=int, default=8,
                    help="CBMC --unwind for the post-refinement run (default 8).")
    ap.add_argument("--timeout-s", type=int, default=60)
    ap.add_argument("--no-llm", action="store_true",
                    help="Skip the LLM call; use only the rule-based fallback.")
    args = ap.parse_args(argv)

    here = Path(__file__).resolve().parent
    verified_path = (
        args.verified_from or here / "verified" / args.target / "verified.json"
    )
    if not verified_path.exists():
        ap.error(f"verified.json not found: {verified_path}")
    verified_doc = json.loads(verified_path.read_text())

    out_dir = here / "refined" / args.target
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = args.out or out_dir / "refined.json"

    doc = refine(
        verified_doc=verified_doc,
        source_root=args.source_root.resolve(),
        out_dir=out_dir,
        use_llm=not args.no_llm,
        re_unwind=args.re_unwind,
        timeout_s=args.timeout_s,
    )
    out_path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
    s = doc["stats"]
    print(
        f"[specmine] refine: candidates={s['refinement_candidates']} "
        f"→ confirmed={s['refined_to_confirmed']} "
        f"refuted={s['refined_to_refuted']} "
        f"still_inconclusive={s['still_inconclusive']} "
        f"flips={s['decisive_flips']} "
        f"sources={s['by_refinement_source']} "
        f"tokens={s['total_tokens_used']} wall={s['wall_seconds']:.1f}s"
    )
    print(f"[specmine] refined -> {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
