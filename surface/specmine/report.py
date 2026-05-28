"""Phase 5.4 — Per-class report formatter for spec-mining outliers (PLAN §3b.4).

Reads Phase 5.2's mined contracts + outliers (and, when available, Phase 5.3's
verified outliers), classifies each by `surface.specmine.taxonomy`, and emits:

  - `surface/specmine/reports/<target>.json` — per-outlier classified record +
    per-class stats, machine-readable for the 5.6 metrics adapter.
  - `surface/specmine/reports/<target>.md`   — human-readable markdown grouped
    by vuln class, one lead per outlier (PLAN §3b.4 deliverable).

The disposition column (when 5.3's verified.json is present) lets the report
distinguish a *proposer-level lead* (no verifier verdict yet, kernel source,
infrastructure-pending) from a *sound-checker confirmed bug*
(disposition=`confirmed`, witness recorded).

No LLM (Phase 5.4 rule).
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Optional

_REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO))
from surface.specmine.taxonomy import (  # noqa: E402
    ALL_CLASSES, CLASS_DISPLAY, classify_contract, lead_one_liner,
)


# --------------------------------------------------------------------------- #
# Loading
# --------------------------------------------------------------------------- #

def _load_optional(path: Path) -> Optional[dict]:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def _index_verified(verified_doc: Optional[dict]) -> dict[tuple, dict]:
    """Build a lookup key=(callee, caller, file, line, missing_contract) -> record.

    `missing_contract` is part of the key because the same callsite can carry
    multiple outliers (different canonical-key views of the same convention —
    e.g. `early !(IS_ERR(item))` vs `null !IS_ERR_OR_NULL(item)`). Each gets
    its own 5.3 disposition; without `missing_contract` in the key they
    collapse and the badge column lies.
    """
    if not verified_doc:
        return {}
    out: dict[tuple, dict] = {}
    for v in verified_doc.get("verified_outliers", []):
        k = (
            v.get("callee"), v.get("caller"),
            v.get("file"), v.get("line"),
            v.get("missing_contract"),
        )
        out[k] = v
    return out


def _verified_lookup(
    verified_index: dict[tuple, dict], outlier: dict
) -> Optional[dict]:
    k = (
        outlier.get("callee"), outlier.get("caller"),
        outlier.get("file"), outlier.get("line"),
        outlier.get("missing_contract"),
    )
    return verified_index.get(k)


# --------------------------------------------------------------------------- #
# Classification + report record assembly
# --------------------------------------------------------------------------- #

def _classify_outliers(
    outliers_doc: dict, verified_index: dict[tuple, dict]
) -> list[dict]:
    """Attach a vuln-class label + verifier disposition to each outlier."""
    out: list[dict] = []
    for o in outliers_doc.get("outliers", []):
        cls = classify_contract(
            o.get("contract_kind_class", ""),
            o.get("missing_contract", ""),
        )
        v = _verified_lookup(verified_index, o)
        rec = {
            "callee": o.get("callee"),
            "caller": o.get("caller"),
            "file": o.get("file"),
            "line": o.get("line"),
            "missing_contract": o.get("missing_contract"),
            "contract_kind_class": o.get("contract_kind_class"),
            "contract_kind_label": o.get("contract_kind_label"),
            "support_count": o.get("support_count"),
            "callsite_count": o.get("callsite_count"),
            "support_pct": o.get("support_pct"),
            "suspicion": o.get("suspicion"),
            "local_establishment": o.get("local_establishment"),
            "vuln_class": cls,
            "vuln_class_display": CLASS_DISPLAY[cls],
            "disposition": v.get("disposition") if v else None,
            "engine_verdict": v.get("engine_verdict") if v else None,
            "witness_path": v.get("witness_path") if v else None,
        }
        rec["lead"] = lead_one_liner(
            cls=cls,
            callee=rec["callee"] or "",
            caller=rec["caller"] or "",
            file_path=rec["file"] or "",
            line=int(rec["line"] or 0),
            missing_contract=rec["missing_contract"] or "",
            support_count=int(rec["support_count"] or 0),
            callsite_count=int(rec["callsite_count"] or 0),
        )
        out.append(rec)
    return out


def _classify_contracts(contracts_doc: dict) -> list[dict]:
    """Attach a class label to every mined contract (for the stats roll-up)."""
    out: list[dict] = []
    for c in contracts_doc.get("contracts", []):
        cls = classify_contract(
            c.get("kind_class", ""),
            c.get("predicate", ""),
        )
        out.append({
            **c,
            "vuln_class": cls,
            "vuln_class_display": CLASS_DISPLAY[cls],
        })
    return out


# --------------------------------------------------------------------------- #
# Markdown rendering
# --------------------------------------------------------------------------- #

def _render_markdown(
    target: str,
    contracts: list[dict],
    outliers: list[dict],
    verified_doc: Optional[dict],
) -> str:
    lines: list[str] = []
    lines.append(f"# Spec-mining report — `{target}`")
    lines.append("")
    lines.append("_Generated by Phase 5.4 (`surface/specmine/report.py`)._")
    lines.append("")

    # Header stats.
    by_class_contracts: Counter[str] = Counter(c["vuln_class"] for c in contracts)
    by_class_outliers: Counter[str] = Counter(o["vuln_class"] for o in outliers)
    by_disposition: Counter[str] = Counter(
        o["disposition"] or "unverified" for o in outliers
    )
    classes_populated = sum(
        1 for cls in ALL_CLASSES
        if by_class_contracts.get(cls, 0) > 0 or by_class_outliers.get(cls, 0) > 0
    )

    lines.append("## Headline")
    lines.append("")
    lines.append(f"- Mined contracts: **{len(contracts)}** across **{classes_populated}** vuln classes")
    lines.append(f"- Outliers (proposer leads): **{len(outliers)}**")
    if verified_doc is not None:
        s = verified_doc.get("stats", {})
        lines.append(
            f"- Verified (Phase 5.3): "
            f"confirmed={s.get('confirmed', 0)}, "
            f"refuted={s.get('refuted', 0)}, "
            f"inconclusive={s.get('inconclusive', 0)}, "
            f"infrastructure_pending={s.get('infrastructure_pending', 0)}, "
            f"proposer_deprioritized={s.get('proposer_deprioritized', 0)}, "
            f"**false_confirmations={s.get('false_confirmations', 0)}** "
            "(soundness gate)"
        )
    lines.append("")

    # Per-class counts.
    lines.append("## Vuln-class breakdown")
    lines.append("")
    lines.append("| Class | Mined contracts | Outlier leads |")
    lines.append("|---|---:|---:|")
    for cls in ALL_CLASSES:
        cc = by_class_contracts.get(cls, 0)
        oc = by_class_outliers.get(cls, 0)
        if cc == 0 and oc == 0:
            continue
        lines.append(f"| {CLASS_DISPLAY[cls]} | {cc} | {oc} |")
    lines.append("")

    # Per-class outlier sections.
    lines.append("## Outlier leads by class")
    lines.append("")
    by_class: dict[str, list[dict]] = defaultdict(list)
    for o in outliers:
        by_class[o["vuln_class"]].append(o)
    # Sort each class's outliers by suspicion desc.
    for cls in by_class:
        by_class[cls].sort(key=lambda o: (-float(o["suspicion"] or 0.0),
                                          o["callee"] or "",
                                          o["file"] or "",
                                          int(o["line"] or 0)))

    for cls in ALL_CLASSES:
        bucket = by_class.get(cls, [])
        if not bucket:
            continue
        lines.append(f"### {CLASS_DISPLAY[cls]}  ({len(bucket)} lead{'s' if len(bucket) != 1 else ''})")
        lines.append("")
        for o in bucket:
            badge = ""
            disp = o.get("disposition")
            if disp == "confirmed":
                badge = " **[CONFIRMED]**"
            elif disp == "refuted":
                badge = " [refuted]"
            elif disp == "inconclusive":
                badge = " [inconclusive]"
            elif disp == "infrastructure_pending":
                badge = " [infra-pending]"
            elif disp == "proposer_deprioritized":
                badge = " [deprioritized]"
            elif disp is None:
                badge = " [unverified]"
            lines.append(f"- {o['lead']}{badge}")
            sub = []
            sub.append(f"suspicion={float(o['suspicion'] or 0.0):.3f}")
            sub.append(f"support={int(o['support_count'] or 0)}/"
                       f"{int(o['callsite_count'] or 0)} "
                       f"({100*float(o['support_pct'] or 0.0):.0f}%)")
            if o.get("local_establishment") is not None:
                sub.append(f"local_est={float(o['local_establishment']):.0f}")
            if o.get("witness_path"):
                sub.append(f"witness=`{o['witness_path']}`")
            lines.append(f"  - {' · '.join(sub)}")
        lines.append("")

    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def build_report(
    target: str,
    contracts_path: Path,
    outliers_path: Path,
    verified_path: Optional[Path],
) -> tuple[dict, str]:
    contracts_doc = json.loads(contracts_path.read_text())
    outliers_doc = json.loads(outliers_path.read_text())
    verified_doc = _load_optional(verified_path) if verified_path else None
    verified_idx = _index_verified(verified_doc)

    classified_contracts = _classify_contracts(contracts_doc)
    classified_outliers = _classify_outliers(outliers_doc, verified_idx)

    by_class_contracts: Counter[str] = Counter(
        c["vuln_class"] for c in classified_contracts
    )
    by_class_outliers: Counter[str] = Counter(
        o["vuln_class"] for o in classified_outliers
    )
    by_disposition: Counter[str] = Counter(
        o["disposition"] or "unverified" for o in classified_outliers
    )
    classes_populated_total = sum(
        1 for cls in ALL_CLASSES
        if by_class_contracts.get(cls, 0) > 0 or by_class_outliers.get(cls, 0) > 0
    )

    json_doc = {
        "target": target,
        "generated_at": int(time.time()),
        "sources": {
            "contracts": str(contracts_path),
            "outliers": str(outliers_path),
            "verified": str(verified_path) if verified_path else None,
        },
        "stats": {
            "mined_contracts": len(classified_contracts),
            "outliers": len(classified_outliers),
            "classes_populated_total": classes_populated_total,
            "by_class_contracts": dict(by_class_contracts),
            "by_class_outliers": dict(by_class_outliers),
            "by_disposition": dict(by_disposition),
        },
        "classified_outliers": classified_outliers,
        "classified_contracts": classified_contracts,
    }
    md = _render_markdown(
        target=target,
        contracts=classified_contracts,
        outliers=classified_outliers,
        verified_doc=verified_doc,
    )
    return json_doc, md


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Phase 5.4 spec-mining report.")
    ap.add_argument("--target", required=True, type=str)
    ap.add_argument("--contracts-from", type=Path,
                    help="surface/specmine/contracts/<target>.json (default: derived).")
    ap.add_argument("--outliers-from", type=Path,
                    help="surface/specmine/outliers/<target>.json (default: derived).")
    ap.add_argument("--verified-from", type=Path,
                    help="surface/specmine/verified/<target>/verified.json (default: derived).")
    ap.add_argument("--out-json", type=Path)
    ap.add_argument("--out-md", type=Path)
    args = ap.parse_args(argv)

    here = Path(__file__).resolve().parent
    contracts_path = args.contracts_from or here / "contracts" / f"{args.target}.json"
    outliers_path = args.outliers_from or here / "outliers" / f"{args.target}.json"
    verified_path = args.verified_from or here / "verified" / args.target / "verified.json"

    if not contracts_path.exists():
        ap.error(f"contracts not found: {contracts_path}")
    if not outliers_path.exists():
        ap.error(f"outliers not found: {outliers_path}")

    reports_dir = here / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    out_json = args.out_json or reports_dir / f"{args.target}.json"
    out_md = args.out_md or reports_dir / f"{args.target}.md"

    json_doc, md = build_report(
        target=args.target,
        contracts_path=contracts_path,
        outliers_path=outliers_path,
        verified_path=verified_path if verified_path.exists() else None,
    )

    out_json.write_text(json.dumps(json_doc, indent=2, sort_keys=True) + "\n")
    out_md.write_text(md)

    s = json_doc["stats"]
    print(
        f"[specmine] report: contracts={s['mined_contracts']} "
        f"outliers={s['outliers']} classes_populated={s['classes_populated_total']} "
        f"disp={s['by_disposition']}"
    )
    print(f"[specmine] report json -> {out_json}")
    print(f"[specmine] report md   -> {out_md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
