"""Phase 6.5 — Variant analysis (Big Sleep / Naptime pattern).

Google's Big Sleep agent's strongest capability is *variant analysis*: given a
known (often recently-patched) bug, find structurally-similar siblings
elsewhere in the codebase. This module applies that idea to spec-mining: given
a *seed pattern* — a vuln class and/or a guard-predicate shape, e.g. from a
confirmed Phase-5.3 outlier or a known CVE — it searches the mined outliers for
siblings that share the seed's shape but live in a different callee/callsite.

Seed sources:
  * `--seed-class <vuln_class>`   — every outlier of that class is a sibling
    candidate (broad).
  * `--seed-contract "<predicate>"` — role-normalized predicate shape; siblings
    are outliers whose missing contract has the same shape (narrow, precise).
  * `--seed-callee <fn> --seed-from-report` — use a confirmed outlier on that
    callee as the seed and find its siblings on other callees.

Siblings are *proposer* leads (same status as any spec-mining outlier); the
sound checker (Phase 5.3) still decides. This turns a single confirmed bug into
a ranked hunt list of structurally-identical candidates across the tree.

No LLM (Phase 6.5 rule) — the shape match is structural. (An LLM variant-judge
is a natural 6.5.x hook, mirroring Big Sleep's agent.)
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from collections import Counter
from pathlib import Path

_HERE = Path(__file__).resolve()
sys.path.insert(0, str(_HERE.parents[2]))


def _shape_of(predicate: str) -> str:
    """Role-normalize a predicate to a structural shape.

    Strips concrete identifiers/literals to their syntactic roles so
    `!(IS_ERR(table))` and `!(IS_ERR(set))` share a shape, and
    `capable(CAP_NET_ADMIN)` and `capable(CAP_SYS_ADMIN)` share a shape.
    """
    s = predicate
    # Keep well-known guard function names; abstract their arguments to ARG.
    s = re.sub(r"\b(IS_ERR(?:_OR_NULL)?|capable|ns_capable|rcu_read_lock_held|"
               r"lockdep_assert_held|refcount_(?:read|inc_not_zero)|"
               r"atomic_read|mutex_is_locked|spin_is_locked)\s*\([^)]*\)",
               r"\1(ARG)", s)
    # Abstract remaining bare identifiers and numbers.
    s = re.sub(r"\b[A-Za-z_]\w*\b", "ID", s)
    s = re.sub(r"\b\d+\b", "N", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s


def load_classified_outliers(report_path: Path) -> list[dict]:
    doc = json.loads(report_path.read_text())
    return doc.get("classified_outliers", [])


def find_variants(
    outliers: list[dict],
    *,
    seed_class: str | None,
    seed_contract: str | None,
    seed_callee: str | None,
) -> dict:
    seed_shape = _shape_of(seed_contract) if seed_contract else None
    siblings: list[dict] = []
    for o in outliers:
        callee = o.get("callee")
        if seed_callee and callee == seed_callee:
            continue  # siblings live in OTHER callees
        match_class = (seed_class is None) or (o.get("vuln_class") == seed_class)
        match_shape = True
        if seed_shape is not None:
            match_shape = (_shape_of(o.get("missing_contract", "")) == seed_shape)
        if match_class and match_shape:
            siblings.append({
                "callee": callee,
                "caller": o.get("caller"),
                "file": o.get("file"),
                "line": o.get("line"),
                "missing_contract": o.get("missing_contract"),
                "vuln_class": o.get("vuln_class"),
                "shape": _shape_of(o.get("missing_contract", "")),
                "suspicion": o.get("suspicion"),
                "disposition": o.get("disposition"),
            })
    siblings.sort(key=lambda s: (-(float(s.get("suspicion") or 0)), s["callee"]))
    return {
        "seed": {
            "class": seed_class, "contract": seed_contract,
            "shape": seed_shape, "callee": seed_callee,
        },
        "sibling_count": len(siblings),
        "by_class": dict(Counter(s["vuln_class"] for s in siblings)),
        "siblings": siblings,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Phase 6.5 variant analysis.")
    ap.add_argument("--target", required=True, type=str)
    ap.add_argument("--report-from", type=Path, default=None,
                    help="surface/specmine/reports/<target>.json (default: derived).")
    ap.add_argument("--seed-class", type=str, default=None)
    ap.add_argument("--seed-contract", type=str, default=None)
    ap.add_argument("--seed-callee", type=str, default=None)
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args(argv)

    if not (args.seed_class or args.seed_contract):
        ap.error("provide at least --seed-class or --seed-contract")

    here = Path(__file__).resolve().parent
    report_path = args.report_from or here / "reports" / f"{args.target}.json"
    if not report_path.exists():
        ap.error(f"report not found: {report_path} (run Phase 5.4 first)")
    outliers = load_classified_outliers(report_path)

    res = find_variants(
        outliers, seed_class=args.seed_class,
        seed_contract=args.seed_contract, seed_callee=args.seed_callee,
    )
    res["target"] = args.target
    res["generated_at"] = int(time.time())

    out_dir = here / "variants"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = args.out or out_dir / f"{args.target}.json"
    out_path.write_text(json.dumps(res, indent=2, sort_keys=True) + "\n")

    print(f"[variant] seed(class={args.seed_class}, contract={args.seed_contract!r}) "
          f"-> {res['sibling_count']} siblings {res['by_class']}")
    for s in res["siblings"][:8]:
        print(f"  {s['callee']}<-{s['caller']} ({s['vuln_class']}) "
              f"`{s['missing_contract']}` susp={s['suspicion']} [{s['disposition']}]")
    print(f"[variant] -> {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
