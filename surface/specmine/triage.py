"""Phase 6.1 — LLM triage / false-positive reducer (LLift / BugLens pattern).

Spec mining (Phase 5.2) produces many outlier *leads*; sound verification
(Phase 5.3, CBMC) is the expensive step. Today every outlier above the
suspicion floor spawns a CBMC run. LLift (OOPSLA'24) and BugLens (ASE'25)
showed that an LLM, given the lead + local context, is a strong *triage*
filter that reorders/defers low-plausibility findings before the heavy
analysis — BugLens lifted precision ~7× on taint-style kernel bugs.

Crucial soundness rule (PLAN §8): **triage only reorders / defers; it NEVER
refutes.** The sound checker keeps final-verdict authority. A "deferred"
outlier is checked last (or skipped only under an explicit budget cap), so:

  * with no budget cap, triage changes *order* only — the set of confirmed
    bugs is identical (zero confirmed-bug loss, by construction);
  * with a budget cap of K verifications, triage maximises the chance that
    the K spawned verifications include every real bug, because it ranks
    high-plausibility leads first.

The LLM produces a *plausibility score* ∈ [0,1] per outlier; the rule-based
fallback (gateway-down / malformed output) uses the Phase-5.2 suspicion as the
score, so the loop is deterministic in CI. Triage output is a ranking + score,
consumed by `surface/specmine/closed_loop.py --triage`.

No verdict authority here — this is a *scoping* layer, like Stage A.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

_REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO))
from llm.client import LLMClient, LLMUnavailable  # noqa: E402


TRIAGE_SYSTEM_PROMPT = """You are a senior kernel/security code auditor triaging
candidate bug leads produced by a specification-mining tool.

Each lead says: "callee F is preceded by guard G in X of Y callsites; this
callsite (in caller C) is missing G." Most such leads are REAL missing-guard
bugs, but some are benign deviations: the guard may be established by the
caller's own contract, the callsite may be on an error/cleanup path where the
guard doesn't apply, or the 'convention' may be a coincidence rather than a
requirement.

Score how likely this lead is a REAL bug worth expensive sound verification,
on a 0.0–1.0 scale:
  * 1.0  — almost certainly a real missing-guard bug (strong universal
            convention, security-relevant guard like a lock or capability
            check, no obvious reason the caller is exempt).
  * 0.5  — plausible but context-dependent.
  * 0.0  — almost certainly benign (the 'convention' is weak, the guard is
            cosmetic, or the caller clearly can't be exempt).

You are TRIAGING, not deciding. A low score only DEFERS verification; a sound
checker still has the final say. Do not try to prove or disprove the bug.

Reply with ONLY a single-line JSON object:
  {"score": 0.0-1.0, "reason": "<one short sentence>"}
No prose, no markdown.
"""


@dataclass
class TriageScore:
    callee: str
    caller: str
    file: str
    line: int
    missing_contract: str
    contract_kind_class: str
    suspicion: float
    triage_score: float
    triage_source: str = "rule"     # "llm" | "rule"
    reason: str = ""
    tokens_used: int = 0


def _build_user_prompt(o: dict) -> str:
    return "\n".join([
        "# Candidate bug lead",
        f"- callee:           {o.get('callee')}",
        f"- missing guard:    {o.get('missing_contract')}",
        f"- guard class:      {o.get('contract_kind_class')}",
        f"- convention:       {o.get('support_count')}/{o.get('callsite_count')} "
        f"callsites ({100*float(o.get('support_pct') or 0):.0f}%)",
        f"- this callsite:    caller {o.get('caller')} at "
        f"{o.get('file')}:{o.get('line')}",
        f"- mining suspicion: {float(o.get('suspicion') or 0):.3f}",
        "",
        "Score the likelihood this is a real bug worth sound verification. JSON only.",
    ])


_JSON_RE = re.compile(r"\{.*\}", re.DOTALL)


def _parse_score(text: str) -> tuple[Optional[float], str]:
    text = (text or "").strip()
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
    m = _JSON_RE.search(text)
    if not m:
        return None, f"no JSON in response: {text[:60]!r}"
    try:
        obj = json.loads(m.group(0))
    except json.JSONDecodeError as e:
        return None, f"malformed JSON: {e}"
    try:
        score = float(obj.get("score"))
    except (TypeError, ValueError):
        return None, f"score not a float: {obj.get('score')!r}"
    if not (0.0 <= score <= 1.0):
        # Clamp rather than reject — model sometimes returns 0-100.
        score = max(0.0, min(1.0, score / 100.0 if score > 1.0 else score))
    return score, str(obj.get("reason", "") or "")


def triage_one(o: dict, llm: Optional[LLMClient]) -> TriageScore:
    base = TriageScore(
        callee=o.get("callee") or "",
        caller=o.get("caller") or "",
        file=o.get("file") or "",
        line=int(o.get("line") or 0),
        missing_contract=o.get("missing_contract") or "",
        contract_kind_class=o.get("contract_kind_class") or "",
        suspicion=float(o.get("suspicion") or 0.0),
        triage_score=float(o.get("suspicion") or 0.0),  # rule default
    )
    if llm is None:
        base.reason = "rule: triage_score = mining suspicion (no LLM)."
        return base
    try:
        # max_tokens generous because small instruct models often emit a few
        # lines of reasoning before the JSON; `_parse_score` greps the JSON out
        # of the tail. Too small a cap truncates before any JSON appears.
        chat = llm.chat(
            system=TRIAGE_SYSTEM_PROMPT, user=_build_user_prompt(o),
            role="router", max_tokens=512, temperature=0.0,
        )
        base.tokens_used = chat.total_tokens
        score, reason = _parse_score(chat.text)
        if score is None:
            base.reason = f"rule fallback ({reason})"
            return base
        base.triage_score = score
        base.triage_source = "llm"
        base.reason = reason
    except LLMUnavailable as e:
        base.reason = f"rule fallback (LLM unavailable: {e})"
    except Exception as e:
        base.reason = f"rule fallback (exception: {e})"
    return base


def triage(
    outliers: list[dict],
    *,
    use_llm: bool,
) -> dict:
    llm = LLMClient() if use_llm else None
    if llm is not None:
        try:
            llm.healthz()
        except LLMUnavailable:
            llm = None
    scores: list[TriageScore] = []
    t0 = time.time()
    for o in outliers:
        scores.append(triage_one(o, llm))
    wall = time.time() - t0
    # Rank by triage_score desc, suspicion desc, then deterministic tiebreak.
    ranked = sorted(
        scores,
        key=lambda s: (-s.triage_score, -s.suspicion, s.callee, s.file, s.line),
    )
    return {
        "generated_at": int(time.time()),
        "use_llm": use_llm,
        "stats": {
            "outliers": len(scores),
            "by_source": {
                "llm":  sum(1 for s in scores if s.triage_source == "llm"),
                "rule": sum(1 for s in scores if s.triage_source == "rule"),
            },
            "total_tokens": sum(s.tokens_used for s in scores),
            "wall_seconds": round(wall, 2),
        },
        # Ranking is the headline output: (callee, caller, file, line) → rank.
        "ranking": [
            {
                "rank": i,
                "callee": s.callee, "caller": s.caller,
                "file": s.file, "line": s.line,
                "missing_contract": s.missing_contract,
                "contract_kind_class": s.contract_kind_class,
                "suspicion": s.suspicion,
                "triage_score": round(s.triage_score, 4),
                "triage_source": s.triage_source,
                "reason": s.reason,
                "tokens_used": s.tokens_used,
            }
            for i, s in enumerate(ranked)
        ],
    }


def triage_key(rec: dict) -> tuple:
    """Stable identity for matching a triage ranking entry to an outlier."""
    return (
        rec.get("callee"), rec.get("caller"),
        rec.get("file"), rec.get("line"),
        rec.get("missing_contract"),
    )


def order_outliers(
    outliers: list[dict], triage_doc: dict
) -> list[dict]:
    """Return `outliers` reordered to match a triage ranking.

    Outliers absent from the ranking go last, preserving their original order
    (stable). Triage only changes *order* — no outlier is dropped, so a
    budget-uncapped verification pass confirms the identical bug set.
    """
    rank_of: dict[tuple, int] = {}
    for r in triage_doc.get("ranking", []):
        rank_of[triage_key(r)] = r["rank"]
    big = len(outliers) + 1
    indexed = list(enumerate(outliers))
    indexed.sort(key=lambda iv: (rank_of.get(triage_key(iv[1]), big), iv[0]))
    return [o for _, o in indexed]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Phase 6.1 LLM triage.")
    ap.add_argument("--target", required=True, type=str)
    ap.add_argument("--outliers-from", type=Path)
    ap.add_argument("--out", type=Path)
    ap.add_argument("--no-llm", action="store_true")
    args = ap.parse_args(argv)

    here = Path(__file__).resolve().parent
    outliers_path = args.outliers_from or here / "outliers" / f"{args.target}.json"
    if not outliers_path.exists():
        ap.error(f"outliers not found: {outliers_path}")
    outliers = json.loads(outliers_path.read_text()).get("outliers", [])

    out_dir = here / "triage"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = args.out or out_dir / f"{args.target}.json"

    doc = triage(outliers, use_llm=not args.no_llm)
    doc["target"] = args.target
    out_path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
    s = doc["stats"]
    print(
        f"[specmine] triage: {s['outliers']} outliers ranked "
        f"(llm={s['by_source']['llm']} rule={s['by_source']['rule']}, "
        f"tokens={s['total_tokens']}, {s['wall_seconds']:.1f}s) -> {out_path}"
    )
    # Print the top few for visibility.
    for r in doc["ranking"][:5]:
        print(f"  #{r['rank']} score={r['triage_score']:.2f} "
              f"[{r['triage_source']}] {r['callee']}<-{r['caller']} "
              f"({r['contract_kind_class']}) :: {r['reason'][:60]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
