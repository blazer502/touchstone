"""kernelCTF-historical field-target adapter (PLAN §5b.B.4).

Phase 0.4 reproduced CVE-2024-1086 under KASAN on Linux 6.1.72. This adapter
reads that dmesg evidence and emits a MetricRow. Phase 0.4 also ran static
scoping; we surface a row with the candidate-site counts so later phases can
diff against this baseline.
"""
from __future__ import annotations

import pathlib

from ..metrics import MetricRow, make_row, REPO_ROOT

KCTF = REPO_ROOT / "eval" / "kernelctf"
DMESG = KCTF / "artifacts" / "dmesg-cve-2024-1086.log"
SMATCH_OUT = KCTF / "scoping" / "smatch.out"
SPARSE_OUT = KCTF / "scoping" / "sparse.out"
COCCI_OUT = KCTF / "scoping" / "cocci.out"

KASAN_SIGNATURE = b"BUG: KASAN"


def _count_nonempty(p: pathlib.Path) -> int:
    if not p.exists():
        return 0
    return sum(1 for line in p.read_bytes().splitlines() if line.strip())


def baseline_rows() -> list[MetricRow]:
    rows: list[MetricRow] = []

    # Bug reproduction row.
    if DMESG.exists() and KASAN_SIGNATURE in DMESG.read_bytes():
        rows.append(make_row(
            adapter="kernelctf",
            target="CVE-2024-1086",
            status="success",
            success=True,
            verdict="KASAN UAF reproduced via published exploit on 6.1.72",
            notes="historical sanity check only; not a scored benchmark",
            evidence_paths=[str(DMESG.relative_to(REPO_ROOT))],
        ))
    else:
        rows.append(make_row(
            adapter="kernelctf", target="CVE-2024-1086", status="not_setup",
            notes="missing dmesg KASAN evidence",
        ))

    # Static scoping coverage row — Phase 1 will turn these into pruned slices.
    smatch_n = _count_nonempty(SMATCH_OUT)
    sparse_n = _count_nonempty(SPARSE_OUT)
    cocci_n = _count_nonempty(COCCI_OUT)
    rows.append(make_row(
        adapter="kernelctf",
        target="scoping/net-netfilter",
        status="success" if (smatch_n + sparse_n) > 0 else "not_setup",
        success=(smatch_n + sparse_n) > 0,
        verdict=f"smatch={smatch_n} sparse={sparse_n} cocci={cocci_n} findings",
        notes="raw candidate sites; pruning effect measured in Phase 1",
        evidence_paths=[
            str(SMATCH_OUT.relative_to(REPO_ROOT)),
            str(SPARSE_OUT.relative_to(REPO_ROOT)),
            str(COCCI_OUT.relative_to(REPO_ROOT)),
        ],
    ))
    return rows
