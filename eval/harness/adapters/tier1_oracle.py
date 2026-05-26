"""Tier-1 oracle adapter — reports crash-oracle verdicts.

Reads Tier1Verdict JSON files emitted by:
- oracle/tier1_fuzz/userspace.py  (libFuzzer fuzz + replay-docker)
- oracle/tier1_fuzz/kernel.py     (KASAN replay + syzkaller smoke)

In Phase 2.1 this maps three hand-written validations to MetricRows:
- synthetic_heap_oob   : libFuzzer fuzzes our deterministic harness
- arvo:1065 replay     : MSan via OSS-Fuzz harness in-container
- kernelctf KASAN      : CVE-2024-1086 use-after-free via dmesg parse
Plus one informational row for the syzkaller image-presence smoke.
"""
from __future__ import annotations

import json
from pathlib import Path

from ..metrics import MetricRow, make_row, REPO_ROOT

RUN_LOGS = REPO_ROOT / "run-logs"

SOURCES: list[tuple[str, str, str]] = [
    # (target_label, file_basename, tier1 latency tier key)
    ("synthetic_heap_oob", "phase2.1-synth-fuzz.json", "tier1"),
    ("arvo:1065-replay",   "phase2.1-arvo1065-replay.json", "tier1"),
    ("kernelctf:CVE-2024-1086", "phase2.1-kernel-kasan-replay.json", "tier1"),
    ("syzkaller-image",    "phase2.1-syzkaller-smoke.json", "tier1"),
]


def _row_from_verdict(target: str, path: Path) -> MetricRow:
    if not path.exists():
        return make_row(
            adapter="tier1_oracle", target=target, status="not_setup", phase="2.1",
            success=False, notes=f"missing {path.relative_to(REPO_ROOT)}",
        )
    v = json.loads(path.read_text())
    verdict = v.get("verdict")
    # Synthetic + arvo + kernelctf: a crash is the success signal (we are
    # validating that the oracle *fires*). syzkaller-smoke success is just
    # "image inspected without error" → verdict=no_crash; image-missing is
    # inconclusive and rendered as not_setup so it's visually distinct.
    if target.startswith("syzkaller"):
        if verdict == "no_crash":
            status, success = "success", True
        elif verdict == "inconclusive":
            status, success = "not_setup", False
        else:
            status, success = "fail", False
    else:
        status = "success" if verdict == "crash" else "fail"
        success = (verdict == "crash")
    note = (
        f"engine={v.get('engine')} sanitizer={v.get('sanitizer')} "
        f"class={v.get('crash_class')} loc={v.get('location')} "
        f"wall_ms={v.get('wall_ms')}"
    )
    return make_row(
        adapter="tier1_oracle", target=target,
        status=status, phase="2.1",
        success=success, verdict=verdict,
        notes=note,
        per_tier_latency_s={
            "tier1": (v.get("wall_ms", 0) / 1000.0) if v.get("wall_ms") else None,
            "tier2": None, "tier3": None,
        },
        evidence_paths=[str(path.relative_to(REPO_ROOT))],
    )


def baseline_rows() -> list[MetricRow]:
    rows: list[MetricRow] = []
    for target, fname, _ in SOURCES:
        rows.append(_row_from_verdict(target, RUN_LOGS / fname))
    return rows
