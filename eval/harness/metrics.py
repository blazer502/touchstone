"""Metric record schema + JSONL writer for the eval harness.

One row = one (adapter, task) outcome at one point in time. Downstream phases
(1 → 4) fill in fields that are zero/null in the Phase 0 baseline.

Fields tracked (PLAN §6 Phase 0.5):
- success           : adapter-specific pass/fail (e.g. CyberGym `vul!=0 ∧ fix==0`)
- attack_surface_reduction_pct : Component (1) pruning %, 0 until Phase 1
- missed_bug_count  : soundness gate; 0 required before pruning is trusted
- oracle_precision / oracle_recall : oracle confirmations, populated in Phase 2
- per_tier_latency_s : {tier1, tier2, tier3} wall-time
- tokens_used       : LLM tokens (0 in Phase 0 — no LLM in analysis path)
- gpu_util_peak_pct : sampled during LLM calls
"""
from __future__ import annotations

import dataclasses
import datetime as _dt
import json
import os
import pathlib
from typing import Any, Optional

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
RUN_LOGS = REPO_ROOT / "run-logs"


def _utcnow() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclasses.dataclass
class MetricRow:
    # Identity
    ts: str
    phase: str                     # e.g. "0.5"
    adapter: str                   # "cybergym" | "kernelctf" | "magma" | ...
    target: str                    # task id / bug id / "not_setup"
    status: str                    # "success" | "fail" | "not_setup" | "skipped"
    # Outcome
    success: Optional[bool] = None
    verdict: Optional[str] = None
    notes: Optional[str] = None
    # Component (1) pruning
    attack_surface_reduction_pct: float = 0.0
    missed_bug_count: int = 0
    # Component (2) oracle
    oracle_precision: Optional[float] = None
    oracle_recall: Optional[float] = None
    per_tier_latency_s: dict[str, Optional[float]] = dataclasses.field(
        default_factory=lambda: {"tier1": None, "tier2": None, "tier3": None}
    )
    # LLM cost
    tokens_used: int = 0
    cost_usd: float = 0.0
    gpu_util_peak_pct: Optional[float] = None
    # Provenance
    evidence_paths: list[str] = dataclasses.field(default_factory=list)
    llm_used: bool = False

    def to_json(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


class MetricWriter:
    """Append-only JSONL writer. One file per harness invocation."""

    def __init__(self, path: pathlib.Path):
        self.path = pathlib.Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = self.path.open("a", encoding="utf-8")

    def write(self, row: MetricRow) -> None:
        self._fh.write(json.dumps(row.to_json(), separators=(",", ":")) + "\n")
        self._fh.flush()
        os.fsync(self._fh.fileno())

    def close(self) -> None:
        self._fh.close()

    def __enter__(self) -> "MetricWriter":
        return self

    def __exit__(self, *a):
        self.close()


def make_row(adapter: str, target: str, status: str, **kw: Any) -> MetricRow:
    return MetricRow(ts=_utcnow(), phase=kw.pop("phase", "0.5"),
                     adapter=adapter, target=target, status=status, **kw)
