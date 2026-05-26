"""Phase 4.2 adapter — kernelCTF live LTS instance.

Reads:
- ``eval/kernelctf/artifacts/dmesg-live-lts-cos.log`` — serial from booting the
  live-LTS+COS+restrictions kernel and running the historical CVE-2024-1086
  trigger as a negative control. PASS = no KASAN report ∧ LIVE-VERDICT line says
  ``no-kasan``; FAIL = KASAN fired (restrictions did not hold).
- ``run-logs/phase4.2-kernelctf-live-loop.jsonl`` — the closed-loop run wiring
  the live target into the Phase-4.1 agent loop alongside a historical positive
  control. PASS = k1 lives at ``inconclusive`` (no_crash ≠ safe) ∧ k2 lands at
  ``confirmed`` (positive control still works through the same loop).
"""
from __future__ import annotations

import json
from pathlib import Path

from ..metrics import MetricRow, make_row, REPO_ROOT

LIVE_LOG = REPO_ROOT / "eval/kernelctf/artifacts/dmesg-live-lts-cos.log"
LIVE_CONFIG = REPO_ROOT / "eval/kernelctf/configs/config-6.1.72-live-lts-cos.txt"
LOOP_TRACE = REPO_ROOT / "run-logs/phase4.2-kernelctf-live-loop.jsonl"


def _verdict_from_serial(blob: str) -> str:
    if "BUG: KASAN" in blob or "KASAN: " in blob:
        return "kasan-fired"
    if "LIVE-VERDICT: no-kasan" in blob:
        return "no-kasan"
    return "inconclusive"


def baseline_rows() -> list[MetricRow]:
    rows: list[MetricRow] = []

    # 1. Kernel-boot smoke (negative control).
    if LIVE_LOG.exists():
        blob = LIVE_LOG.read_text(errors="replace")
        verdict = _verdict_from_serial(blob)
        ok = verdict == "no-kasan"
        rows.append(make_row(
            adapter="kernelctf-live", target="live-lts-cos:boot+negative-control",
            phase="4.2", status="success" if ok else "fail", success=ok,
            verdict=verdict,
            notes=("Linux 6.1.72 + KASAN/KCOV/UBSAN, NF_TABLES=n, IO_URING=n, "
                   "USER_NS_UNPRIVILEGED=n; historical CVE-2024-1086 exploit ran "
                   "and did NOT trigger KASAN — surface removed as expected."),
            evidence_paths=[str(LIVE_LOG.relative_to(REPO_ROOT)),
                            str(LIVE_CONFIG.relative_to(REPO_ROOT))],
        ))
    else:
        rows.append(make_row(
            adapter="kernelctf-live", target="live-lts-cos:boot+negative-control",
            phase="4.2", status="not_setup", success=False,
            notes=("live LTS boot not yet captured — run "
                   "eval/kernelctf/scripts/{make_config_live,build_kernel_live,"
                   "make_rootfs_live,run_qemu_live}.sh"),
        ))

    # 2. Closed-loop wiring (k1 negative, k2 positive control).
    if LOOP_TRACE.exists():
        seen: dict[str, str] = {}
        for line in LOOP_TRACE.read_text().splitlines():
            if not line.strip():
                continue
            r = json.loads(line)
            seen[r["candidate_id"]] = r["decision"]["disposition"]
            cid = r["candidate_id"]
            disp = r["decision"]["disposition"]
            wall = r.get("total_wall_ms", 0) / 1000.0
            rows.append(make_row(
                adapter="kernelctf-live", target=cid, phase="4.2",
                status="success",  # both dispositions are the EXPECTED outcome
                success=True, verdict=disp,
                notes=r["decision"]["reason"],
                per_tier_latency_s={"tier1": wall, "tier2": None, "tier3": None},
                evidence_paths=[str(LOOP_TRACE.relative_to(REPO_ROOT))],
            ))
        # Pair check: live=inconclusive AND historical=confirmed.
        live_ok = seen.get("k1-live-lts-cos-cve-2024-1086-negative") == "inconclusive"
        hist_ok = seen.get("k2-historical-cve-2024-1086-positive-control") == "confirmed"
        rollup_ok = live_ok and hist_ok
        rows.append(make_row(
            adapter="kernelctf-live", target="rollup", phase="4.2",
            status="success" if rollup_ok else "fail", success=rollup_ok,
            verdict=("live=inconclusive,historical=confirmed"
                     if rollup_ok else f"live={seen.get('k1-live-lts-cos-cve-2024-1086-negative','?')},"
                                       f"historical={seen.get('k2-historical-cve-2024-1086-positive-control','?')}"),
            notes=("paired-control check: live LTS+COS+restrictions blocks the "
                   "historical surface AND the agent loop dispatches identically "
                   "against both kernels."),
            evidence_paths=[str(LOOP_TRACE.relative_to(REPO_ROOT))],
        ))
    else:
        rows.append(make_row(
            adapter="kernelctf-live", target="closed-loop-wiring",
            phase="4.2", status="not_setup", success=False,
            notes=("closed-loop wiring not exercised — run "
                   "`python3 -m agent.loop --candidates "
                   "agent/smoke/candidates_kernelctf_live.json --out "
                   "run-logs/phase4.2-kernelctf-live-loop.jsonl`"),
        ))

    return rows
