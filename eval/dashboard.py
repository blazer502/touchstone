"""Render `docs/dashboard.md` — the single entry point summarising current
verification state.

Aggregates:

  * Strategic direction summary (5 unique outputs)
  * Codebase roster (eval.roster.aggregate / eval/roster/manifest.json)
  * Bug witness catalog (run-logs/cex/**)
  * Soundness ledger size (run-logs/soundness-ledger.json)
  * Proof cache stats (surface.proof_cache.stats)
  * Patch-verify capability (agent.patch_verify smoke)
  * Incremental driver capability (surface.incremental impacted)

Self-regenerating: `python3 -m eval.dashboard` re-renders from current artifacts.
Idempotent — no side effects beyond writing docs/dashboard.md.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional


REPO_ROOT = Path(__file__).resolve().parents[1]
DOC_OUT = REPO_ROOT / "docs" / "dashboard.md"


def _read_json(rel: str) -> dict:
    p = (REPO_ROOT / rel)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text())
    except Exception:
        return {}


def _cex_catalog() -> List[dict]:
    """Collect every Witness-shaped JSON under run-logs/cex/**.

    Skips annotated copies and PatchVerifyResult-shaped files (the latter have
    no top-level `provenance` because they embed two cex by reference).
    """
    out: List[dict] = []
    cex_root = REPO_ROOT / "run-logs" / "cex"
    if not cex_root.exists():
        return out
    for p in sorted(cex_root.rglob("*.json")):
        if any("annotated" in part for part in p.parts):
            continue
        try:
            d = json.loads(p.read_text())
        except Exception:
            continue
        prov = d.get("provenance")
        if not isinstance(prov, dict):           # skip non-Cex shapes
            continue
        out.append({
            "path": str(p.relative_to(REPO_ROOT)),
            "task_id": prov.get("task_id"),
            "engine": prov.get("engine"),
            "tier": prov.get("tier"),
            "violated_name": d.get("violated", {}).get("name"),
            "location": d.get("violated", {}).get("location"),
        })
    return out


def _patch_verify_catalog() -> List[dict]:
    """Collect every PatchVerifyResult JSON under run-logs/cex/cve-patches/."""
    out: List[dict] = []
    root = REPO_ROOT / "run-logs" / "cex" / "cve-patches"
    if not root.exists():
        return out
    for p in sorted(root.rglob("*.json")):
        try:
            d = json.loads(p.read_text())
        except Exception:
            continue
        if "is_correct_fix" not in d:            # PatchVerifyResult marker
            continue
        meta = d.get("demo_meta", {}) or {}
        # LLM-proposed patches carry a `llm.model` field — surface it so the
        # row distinguishes "we verified the upstream fix" from "we verified
        # a third-party LLM's proposal".
        llm_meta = d.get("llm") or {}
        source = "upstream"
        if llm_meta.get("model") or meta.get("model_under_test"):
            source = f"LLM ({llm_meta.get('model', 'unknown')})"
        out.append({
            "path": str(p.relative_to(REPO_ROOT)),
            "task_id": meta.get("task_id") or "?",
            "library": meta.get("library") or "?",
            "source": source,
            "is_correct_fix": d.get("is_correct_fix"),
            "pre_verdict": d.get("pre_verdict", {}).get("verdict"),
            "post_verdict": d.get("post_verdict", {}).get("verdict"),
            "wall_ms": d.get("wall_ms"),
            "decision": d.get("decision"),
        })
    return out


def _ledger_count() -> int:
    """Count entries in the latest exported soundness ledger."""
    d = _read_json("run-logs/soundness-ledger.json")
    return d.get("count", 0)


def _cache_stats() -> dict:
    try:
        from surface import proof_cache as pc
        return pc.stats()
    except Exception:
        return {}


def _leaderboard_summary() -> Optional[dict]:
    """Latest completed full-1507 leaderboard run, if any.

    Iterates the candidate list in best-first order so the dashboard's
    "Current state" row always reflects the latest architecture.
    """
    candidates = [
        ("run-logs/leaderboard-all-features.json", "all features (F1-F4 + V1/V3)"),
        ("run-logs/leaderboard-bankfuzz.json", "bank + libFuzzer 10 s"),
        ("run-logs/leaderboard-bank-only.json", "bank only / no LLM"),
    ]
    for rel, label in candidates:
        d = _read_json(rel)
        agg = d.get("aggregate", {})
        if agg.get("attempted") == 1507:
            return {
                "label": d.get("agent_name", label),
                "pct_repro": agg.get("pct_reproducing_target_vuln_full"),
                "pct_post_patch": agg.get("pct_finding_post_patch_vuln_full"),
                "confirmed": agg.get("confirmed_reproduces_target"),
                "attempted": agg.get("attempted"),
                "wall_min": round(d.get("wall_ms_total", 0) / 60000.0, 1),
                "artifact": rel,
            }
    return None


def _roster_summary() -> dict:
    """Per-status counts from the roster manifest."""
    m = _read_json("eval/roster/manifest.json")
    if not m:
        return {}
    counts = {"done": 0, "deferred": 0, "not_setup": 0, "partial": 0, "shares": 0}
    for cb in m.get("codebases", []):
        # take stage_a status as the primary signal; oracle runs supplement
        sa = cb.get("stage_a", {}).get("status", "?")
        if sa not in counts:
            counts[sa] = 0
        counts[sa] += 1
    return {"by_stage_a_status": counts, "total": len(m.get("codebases", []))}


def render() -> str:
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    cex = _cex_catalog()
    patches = _patch_verify_catalog()
    ledger = _ledger_count()
    cache = _cache_stats()
    roster = _roster_summary()
    leader = _leaderboard_summary()

    lines: List[str] = []
    lines.append("# Verification dashboard")
    lines.append("")
    lines.append(f"Auto-generated by `python3 -m eval.dashboard` at {now}.")
    lines.append("This page is the single entry point for someone evaluating the project.")
    lines.append("Every claim below points at a concrete artifact under the repo.")
    lines.append("")

    # --- strategic positioning --------------------------------------------
    lines.append("## What this system uniquely produces")
    lines.append("")
    lines.append("See `docs/strategic-direction.md` for the full argument. Headline:")
    lines.append("")
    lines.append("| | Artifact class | Why LLM-only agents can't do this | Where we built it |")
    lines.append("|---|---|---|---|")
    lines.append("| **A** | Sound attack-surface reduction with audit trail | LLM has no sound reachability | `surface/` Stage A+B, 22.05 % netfilter |")
    lines.append("| **B** | Verified bug witness (input + path + violated property) | LLM guesses bytes, can't prove root cause | `schemas/witness.py`, 5 CyberGym confirms lifted |")
    lines.append("| **C** | Verified patch | LLM proposes, we prove | `agent/patch_verify.py` |")
    lines.append("| **D** | Persistent verified knowledge base | Agents are stateless | `surface/proof_cache.py` + bundle import/export |")
    lines.append("| **E** | Counterexample-driven LLM | No ground-truth cex source | `surface/contract_synth.py` + `must_not_assume` filter |")
    lines.append("")

    # --- current state ------------------------------------------------------
    lines.append("## Current state")
    lines.append("")
    lines.append("| Component | Value | Source |")
    lines.append("|---|---|---|")
    lines.append(f"| Witness artifacts on disk | **{len(cex)}** | `run-logs/cex/` |")
    lines.append(f"| Patch verifications on disk | **{len(patches)}** | `run-logs/cex/cve-patches/` |")
    lines.append(f"| Soundness ledger entries | **{ledger}** | `docs/soundness-assumptions.md` → `run-logs/soundness-ledger.json` |")
    lines.append(f"| Proof cache rows | **{cache.get('rows', 0)}** ({cache.get('fresh', 0)} fresh / {cache.get('stale', 0)} stale) | `surface/proofcache/` |")
    by_eng = cache.get("by_engine", {}) or {}
    if by_eng:
        eng_str = ", ".join(f"`{k}`×{v}" for k, v in by_eng.items())
        lines.append(f"| Cache by engine | {eng_str} | (per-row `key.engine`) |")
    if roster:
        cnts = roster.get("by_stage_a_status", {})
        cb_str = ", ".join(f"`{k}`={v}" for k, v in cnts.items() if v)
        lines.append(f"| Codebase roster | **{roster['total']}** ({cb_str}) | `eval/roster/manifest.json` |")
    if leader:
        lines.append(f"| CyberGym leaderboard (latest full 1 507) | **{leader['pct_repro']:.2f} %** repro, {leader['pct_post_patch']:.2f} % post-patch ({leader['confirmed']} confirms, {leader['wall_min']} min wall) | `{leader['artifact']}` |")
    lines.append("")

    # --- cex catalog --------------------------------------------------------
    if cex:
        lines.append("## Witness artifact catalog")
        lines.append("")
        lines.append("| Task | Tier | Engine | Violation | Location |")
        lines.append("|---|---|---|---|---|")
        for c in cex:
            tid = c.get("task_id") or "?"
            tier = c.get("tier") or "?"
            eng = c.get("engine") or "?"
            v = c.get("violated_name") or "?"
            loc = c.get("location") or "?"
            lines.append(f"| `{tid}` | {tier} | {eng} | {v} | `{loc}` |")
        lines.append("")
        lines.append("Each row links to a disclosure-grade JSON + bash reproducer; soundness")
        lines.append("anchors resolve via `python3 -m schemas.soundness_ledger annotate`.")
        lines.append("")

    if patches:
        lines.append("## Patch verifications")
        lines.append("")
        lines.append("| Task | Library | Source | pre | post | correct fix? | wall (ms) |")
        lines.append("|---|---|---|---|---|---|---|")
        for pv in patches:
            ok = "✅" if pv.get("is_correct_fix") else "❌"
            decision = f" / {pv['decision']}" if pv.get("decision") else ""
            lines.append(f"| `{pv.get('task_id')}` | {pv.get('library')} | "
                         f"{pv.get('source')} | "
                         f"{pv.get('pre_verdict')} | {pv.get('post_verdict')} | "
                         f"{ok}{decision} | {pv.get('wall_ms')} |")
        lines.append("")
        lines.append("Each row is a `PatchVerifyResult` from `agent/patch_verify.py` —")
        lines.append("BMC verdict pre+post, with the pre-side cex preserved when pre=unsafe.")
        lines.append("`Source = upstream` means we verified the disclosed upstream commit;")
        lines.append("`Source = LLM (<model>)` means we verified a fix that a third-party LLM")
        lines.append("proposed, demonstrating the *trust-layer* mode (strategic-direction.md §2 Output C).")
        lines.append("")

    # --- capabilities (with how-to commands) -------------------------------
    lines.append("## Capabilities")
    lines.append("")
    lines.append("```bash")
    lines.append("# A — Sound surface reduction")
    lines.append("python3 -m surface.stage_a --target linux-6.1.72-netfilter")
    lines.append("")
    lines.append("# B — Lift a confirm into a Witness (bytes + repro + disclosure JSON)")
    lines.append("python3 -m schemas.lift_cybergym --tasks arvo:1065")
    lines.append("")
    lines.append("# C — Verify a patch via BMC pre/post")
    lines.append("python3 -m agent.patch_verify verify <request.json>")
    lines.append("")
    lines.append("# D — Export / import verified knowledge")
    lines.append("python3 -m surface.proof_cache export run-logs/cache-bundle.ndjson")
    lines.append("python3 -m surface.proof_cache import run-logs/cache-bundle.ndjson")
    lines.append("")
    lines.append("# E — witness-driven contract synth (Stage B refinement)")
    lines.append("python3 -m surface.stage_b_refine_cli --manifest <m.json>")
    lines.append("")
    lines.append("# Incremental (P5) — minimal re-verify on git diff")
    lines.append("python3 -m surface.incremental --target linux-6.1.72-netfilter \\")
    lines.append("    impacted-git --git-from HEAD~1 --git-to HEAD")
    lines.append("```")
    lines.append("")

    # --- pointers -----------------------------------------------------------
    lines.append("## Where to read next")
    lines.append("")
    lines.append("- `docs/strategic-direction.md` — what we're building, why (5 unique outputs)")
    lines.append("- `docs/soundness-assumptions.md` — every approximation, auditably")
    lines.append("- `docs/codebase-roster.md` — per-codebase state table")
    lines.append("- `docs/leaderboard-results.md` — CyberGym leaderboard runs to date (current best: all features 12.48 % repro / 3.38 % post-patch = **#2 repro / #1 post-patch** on the public board, no LLM)")
    lines.append("- `docs/headline-metrics.md` — Phase-4 acceptance roll-up (legacy)")
    lines.append("- `docs/improvement-plan.md` — tactical CyberGym-specific plan (legacy; superseded)")
    lines.append("- `PROGRESS.md` — phase-by-phase history with decisions log")
    lines.append("")
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=Path, default=DOC_OUT)
    args = ap.parse_args(argv)
    rendered = render()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(rendered)
    print(json.dumps({"out": str(args.out), "bytes": len(rendered)}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
