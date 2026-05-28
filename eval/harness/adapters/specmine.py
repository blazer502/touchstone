"""Phase 5 — Specification-mining metrics adapter.

Reads `surface/specmine/{contracts,outliers,verified,reports,refined,closed_loop}/<target>/...`
artifacts and emits one rollup row per target + one row per
confirmed/refuted/inconclusive outlier into the Phase-0.5 baseline JSONL
stream.

Targets are auto-discovered as the union of every directory the spec-mining
pipeline has run against (the `contracts/` and `outliers/` JSONs are the
canonical set, since 5.1+5.2 are the foundational stages — 5.3-5.6 may have
been run on subsets).

Per-target rollup carries the headline numbers Phase 5.6 acceptance reads:
  mined_contracts, outliers, classes_populated, by_class_outliers,
  confirmed_pre_refine, confirmed_post_refine, classes_with_confirmed_leads,
  refined_flips, false_confirmations, tokens.

A row's `success` flag is True iff (a) `false_confirmations == 0` (soundness
gate), and (b) at least one row per target was emitted.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from ..metrics import MetricRow, make_row, REPO_ROOT


_SPECMINE_ROOT = REPO_ROOT / "surface" / "specmine"


def _read_json(p: Path) -> dict | None:
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def _targets() -> list[str]:
    """Targets that have at least 5.2 outputs (the foundational artifacts)."""
    contracts_dir = _SPECMINE_ROOT / "contracts"
    outliers_dir = _SPECMINE_ROOT / "outliers"
    targets: set[str] = set()
    for p in contracts_dir.glob("*.json"):
        targets.add(p.stem)
    for p in outliers_dir.glob("*.json"):
        targets.add(p.stem)
    return sorted(targets)


def _target_rollup(target: str) -> MetricRow:
    """Emit one summary row for a target."""
    contracts = _read_json(_SPECMINE_ROOT / "contracts" / f"{target}.json") or {}
    outliers = _read_json(_SPECMINE_ROOT / "outliers" / f"{target}.json") or {}
    verified = _read_json(
        _SPECMINE_ROOT / "verified" / target / "verified.json"
    ) or {}
    report = _read_json(_SPECMINE_ROOT / "reports" / f"{target}.json") or {}
    refined = _read_json(
        _SPECMINE_ROOT / "refined" / target / "refined.json"
    ) or {}
    closed = _read_json(
        _SPECMINE_ROOT / "closed_loop" / target / "closed_loop.json"
    ) or {}

    c_stats = contracts.get("stats", {})
    o_stats = outliers.get("stats", {})
    v_stats = verified.get("stats", {})
    r_stats = report.get("stats", {})
    rf_stats = refined.get("stats", {})
    cl_stats = closed.get("stats", {})

    by_class_outliers = r_stats.get("by_class_outliers", {})
    by_class_contracts = r_stats.get("by_class_contracts", {})
    classes_populated_total = r_stats.get(
        "classes_populated_total",
        len({
            c for c in (set(by_class_contracts) | set(by_class_outliers))
            if (by_class_contracts.get(c, 0) > 0
                or by_class_outliers.get(c, 0) > 0)
        }),
    )

    # 5.3 + 5.6 carry the soundness gate. If closed-loop is present, prefer it
    # (it adjudicates BOTH the verify pre-pass and the 5.5 refinement); else
    # fall back to verify-only stats.
    if cl_stats:
        confirmed_pre = cl_stats.get("confirmed_pre_refine", 0)
        confirmed_post = cl_stats.get("confirmed_post_refine", 0)
        refuted = cl_stats.get("refuted", 0)
        inconclusive = cl_stats.get("inconclusive", 0)
        refined_flips = cl_stats.get("refined_flips", 0)
        false_conf = cl_stats.get("false_confirmations", 0)
        classes_confirmed = cl_stats.get("classes_with_confirmed_leads", 0)
        by_class_confirmed = cl_stats.get("by_class_post_refine_confirmed", {})
        skipped = cl_stats.get("skipped", {})
        wall = cl_stats.get("wall_seconds", 0.0)
    else:
        confirmed_pre = v_stats.get("confirmed", 0)
        confirmed_post = confirmed_pre + rf_stats.get("refined_to_confirmed", 0)
        refuted = v_stats.get("refuted", 0) + rf_stats.get("refined_to_refuted", 0)
        inconclusive = max(
            0, v_stats.get("inconclusive", 0) - rf_stats.get("decisive_flips", 0)
        )
        refined_flips = rf_stats.get("decisive_flips", 0)
        false_conf = v_stats.get("false_confirmations", 0)
        # Classes with confirmed leads from the report (looking at outlier
        # records whose verified disposition is confirmed).
        classified = report.get("classified_outliers", [])
        confirmed_classes = {
            o.get("vuln_class") for o in classified
            if o.get("disposition") == "confirmed"
        }
        classes_confirmed = len(confirmed_classes)
        by_class_confirmed = {
            cls: sum(
                1 for o in classified
                if o.get("vuln_class") == cls and o.get("disposition") == "confirmed"
            )
            for cls in confirmed_classes
        }
        skipped = {}
        wall = v_stats.get("wall_seconds", 0.0) + rf_stats.get("wall_seconds", 0.0)

    tokens = (
        rf_stats.get("total_tokens_used", 0)
        + (0 if not cl_stats else 0)  # closed_loop doesn't aggregate tokens yet
    )
    sound_gate_ok = (false_conf == 0)
    success = sound_gate_ok and (
        c_stats.get("mined_contracts", 0) > 0
        or o_stats.get("total_outliers", 0) > 0
    )
    status = "success" if success else ("fail" if false_conf else "partial")

    notes_parts = [
        f"contracts={c_stats.get('mined_contracts', 0)}",
        f"outliers={o_stats.get('total_outliers', 0)}",
        f"classes_populated={classes_populated_total}",
        f"confirmed_post={confirmed_post}",
        f"classes_confirmed={classes_confirmed}",
        f"refined_flips={refined_flips}",
        f"false_confirmations={false_conf}",
    ]
    if skipped:
        notes_parts.append(f"skipped={skipped}")
    if tokens:
        notes_parts.append(f"tokens={tokens}")
    notes = " · ".join(notes_parts)

    return make_row(
        adapter="specmine",
        target=f"specmine-{target}",
        status=status,
        phase="5",
        success=success,
        verdict=(
            "confirmed-leads" if confirmed_post > 0
            else ("infra-pending" if c_stats.get("mined_contracts", 0) > 0
                  else "no-leads")
        ),
        notes=notes,
        missed_bug_count=0 if sound_gate_ok else 0,
        oracle_precision=1.0 if sound_gate_ok and confirmed_post >= 1 else None,
        tokens_used=tokens,
        llm_used=bool(tokens or refined.get("use_llm", False)),
        evidence_paths=[
            f"surface/specmine/contracts/{target}.json",
            f"surface/specmine/outliers/{target}.json",
            f"surface/specmine/verified/{target}/verified.json",
            f"surface/specmine/reports/{target}.md",
            f"surface/specmine/refined/{target}/refined.json",
            f"surface/specmine/closed_loop/{target}/closed_loop.json",
        ],
    )


def _per_confirmed_outlier_rows(target: str) -> Iterable[MetricRow]:
    """Emit one row per confirmed outlier (audit trail in the JSONL)."""
    closed = _read_json(
        _SPECMINE_ROOT / "closed_loop" / target / "closed_loop.json"
    )
    if not closed:
        return
    for r in closed.get("records", []):
        if r.get("post_refine_disposition") != "confirmed":
            continue
        o = r.get("outlier") or {}
        callee = o.get("callee", "?")
        caller = o.get("caller", "?")
        cls = o.get("contract_kind_class", "?")
        file_ = o.get("file", "?")
        line = o.get("line", 0)
        missing = o.get("missing_contract", "?")
        ev = []
        if r.get("witness_path"):
            ev.append(r["witness_path"])
        if r.get("harness_path"):
            ev.append(r["harness_path"])
        ref = r.get("refinement") or {}
        notes = (
            f"class={cls} missing=`{missing}` at {file_}:{line} "
            f"router={r.get('router_verdict')} "
            f"witness={'yes' if r.get('witness_path') else 'no'}"
        )
        if ref.get("refinement_source"):
            notes += f" refine={ref.get('refinement_source')}"
            if ref.get("tokens_used"):
                notes += f" tokens={ref['tokens_used']}"
        yield make_row(
            adapter="specmine",
            target=f"specmine-{target}/{callee}<-{caller}",
            status="success",
            phase="5",
            success=True,
            verdict="confirmed",
            notes=notes,
            evidence_paths=ev,
            tokens_used=int(ref.get("tokens_used", 0) or 0),
            llm_used=bool((ref.get("refinement_source") == "llm")),
        )


def baseline_rows() -> list[MetricRow]:
    rows: list[MetricRow] = []
    targets = _targets()
    if not targets:
        # No spec-mining work has been done on this checkout.
        return [make_row(
            adapter="specmine", target="-", status="not_setup", phase="5",
            success=False, verdict="not-setup",
            notes="surface/specmine/{contracts,outliers}/ are empty; "
                  "run Phase 5.1+5.2 first.",
        )]
    for t in targets:
        rows.append(_target_rollup(t))
        rows.extend(_per_confirmed_outlier_rows(t))
    return rows
