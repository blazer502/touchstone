"""Crash-reproducer adapter — reports reproducibility verdicts (R-track).

Reads ``ReproVerdict`` JSON files emitted by ``oracle/repro/pipeline.py``
(userspace) and ``oracle/repro/kernel.py`` (kernel). Each row records whether a
confirmed crash was turned into a reproducibility-scored reproducer:

- arvo:1065      : userspace OSS-Fuzz harness, MSan UoUV, repro_rate over N replays
- CVE-2024-1086  : kernel QEMU+KASAN, use-after-free, repro_rate over N boots

`success` = the bug was reproduced at the configured threshold
(verdict == "reproducible"). `flaky` / `unreproducible` are surfaced honestly
(not "safe").
"""
from __future__ import annotations

import json
from pathlib import Path

from ..metrics import MetricRow, REPO_ROOT, make_row

RUN_LOGS = REPO_ROOT / "run-logs"

# (target_label, file_basename, latency tier key)
SOURCES: list[tuple[str, str, str]] = [
    ("arvo:1065-reproducer", "repro-arvo1065.json", "tier1"),
    ("kernelctf:CVE-2024-1086-reproducer", "repro-cve-2024-1086.json", "tier1"),
]


def _row(target: str, path: Path, tier: str) -> MetricRow:
    if not path.exists():
        return make_row(adapter="reproducer", target=target, status="not_setup",
                        phase="R", success=False,
                        notes=f"missing {path.name} (run oracle.repro pipeline)")
    v = json.loads(path.read_text())
    verdict = v.get("verdict")
    success = verdict == "reproducible"
    status = "success" if success else ("fail" if verdict == "unreproducible" else "skipped")
    rep = v.get("reproducer") or {}
    note = (f"verdict={verdict} repro_rate={v.get('repro_rate')} runs={v.get('runs')} "
            f"sig={v.get('signature')} minimized={rep.get('minimized')} "
            f"build_id={rep.get('build_id')}")
    return make_row(
        adapter="reproducer", target=target, status=status, phase="R",
        success=success, verdict=verdict, notes=note,
        per_tier_latency_s={tier: (v.get("wall_ms", 0) / 1000.0) if v.get("wall_ms") else None,
                            "tier2": None, "tier3": None},
        evidence_paths=[str(path.relative_to(REPO_ROOT))],
    )


def baseline_rows() -> list[MetricRow]:
    return [_row(t, RUN_LOGS / f, tier) for t, f, tier in SOURCES]
