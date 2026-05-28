"""CyberGym evaluation with the crash-reproducer pipeline (R-track).

For each subset task: discover a PoC from the deterministic seed bank, score it
with the CyberGym rule (vul crash AND fix clean), and — on a confirmed task —
measure reproducibility by re-submitting the winning PoC N times and
signature-matching the crash -> a ``ReproVerdict``.

This demonstrates the new capability layered on Gymbench: a confirmed CyberGym
PoV is upgraded into a reproducibility-scored reproducer. The *replay backend*
is CyberGym-specific (the submission server), but the verdict shape and signature
logic come from the generic ``schemas/reproducer`` — only the backend differs,
per docs/strategic-direction.md §8 (benchmark-agnostic rule).

Run (server-mode; no per-task image pulls needed)::

    CYBERGYM_SERVER_URL=http://127.0.0.1:8666 \\
    CYBERGYM_DATA_DIR=/mnt/data/chanyoung/cybergym/cybergym_data/data \\
    python3 -m eval.cybergym.run_repro_eval \\
        --tasks-file eval/cybergym/subset.json --bank-budget 12 \\
        --repro-runs 5 --out run-logs/repro-cybergym-eval.json
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import tempfile
import time
import uuid
from collections import Counter
from pathlib import Path

from eval.cybergym import adapter
from eval.cybergym.seed_generators import _FALLBACK_BANK
from schemas.reproducer import (
    DEFAULT_REPRO_THRESHOLD,
    DOMAIN_USERSPACE,
    Reproducer,
    ReproVerdict,
    classify_repro,
    crash_signature,
)

REPO_ROOT = Path(__file__).resolve().parents[2]


def _load_task_ids(p: Path) -> list[str]:
    data = json.loads(p.read_text())
    if isinstance(data, dict) and "tasks" in data:
        return [t["id"] for t in data["tasks"]]
    if isinstance(data, list):
        return [t if isinstance(t, str) else t["id"] for t in data]
    raise ValueError(f"unrecognized tasks-file schema: {p}")


def _server_replay_signature(bundle, poc_path: Path, timeout_s: int) -> str:
    """Submit the PoC to the server's vul image once; return its crash signature."""
    server_url = os.environ["CYBERGYM_SERVER_URL"]
    v = adapter._run_server_style(
        bundle.task_id, poc_path, mode="vul",
        unit=f"{bundle.task_id}:repro",
        server_url=server_url, agent_id=uuid.uuid4().hex,  # fresh id -> fresh run
        timeout_seconds=timeout_s)
    if v.verdict != "crash":
        return ""
    return crash_signature(v.sanitizer, v.crash_class, v.location)


def _measure_reproducibility(bundle, poc_bytes: bytes, *, runs: int,
                             threshold: float, timeout_s: int) -> ReproVerdict:
    work = Path(tempfile.mkdtemp(prefix="cg-repro-"))
    poc_path = work / "poc.bin"
    poc_path.write_bytes(poc_bytes)
    t0 = time.monotonic()
    samples = [_server_replay_signature(bundle, poc_path, timeout_s) for _ in range(runs)]
    nonempty = Counter(s for s in samples if s)
    if nonempty:
        sig, hits = nonempty.most_common(1)[0]
    else:
        sig, hits = "", 0
    rate = hits / runs if runs else 0.0
    wall = int((time.monotonic() - t0) * 1000)
    reproducer = None
    if sig:
        san, cls, loc = sig.split("|", 2)
        reproducer = Reproducer(
            signature=sig, domain=DOMAIN_USERSPACE, repro_rate=round(rate, 4),
            runs=runs, build_id=bundle.image_vul, engine="cybergym_server",
            replay_cmd=f"submit poc to {os.environ.get('CYBERGYM_SERVER_URL')} mode=vul",
            minimized=False, minimized_trigger_hex=(poc_bytes.hex() if len(poc_bytes) <= 64 else None),
            original_size_bytes=len(poc_bytes), minimized_size_bytes=len(poc_bytes),
            crash_class=(cls if cls != "?" else None), location=(loc if loc != "?" else None),
            wall_ms=wall)
    return ReproVerdict(
        unit=bundle.task_id, domain=DOMAIN_USERSPACE,
        verdict=classify_repro(rate, threshold), repro_rate=round(rate, 4), runs=runs,
        signature=sig, threshold=threshold, reproducer=reproducer, wall_ms=wall,
        soundness_note=("server-replay reproducibility: re-submit the winning PoC N times, "
                        "signature-match. finite-N estimate; unreproducible != safe."),
        assumed=[f"backend=cybergym_server", f"runs={runs}"])


def _discover_and_score(bundle, *, bank_budget: int, vul_timeout: int, fix_timeout: int):
    """Iterate the deterministic bank; return (winning_poc_bytes, score_dict, seed_tag)
    for the first PoC that satisfies the CyberGym rule, else (None, last_score, None)."""
    last = None
    for i, seed in enumerate(_FALLBACK_BANK[:bank_budget]):
        score = adapter.score_local(bundle, seed, vul_timeout=vul_timeout, fix_timeout=fix_timeout)
        last = score
        if score.get("success"):
            return seed, score, f"bank-{i:03d}"
    return None, last, None


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="CyberGym + reproducer-pipeline eval.")
    ap.add_argument("--tasks-file", type=Path, default=Path(__file__).resolve().parent / "subset.json")
    ap.add_argument("--bank-budget", type=int, default=12)
    ap.add_argument("--repro-runs", type=int, default=5)
    ap.add_argument("--threshold", type=float, default=DEFAULT_REPRO_THRESHOLD)
    ap.add_argument("--vul-timeout", type=int, default=30)
    ap.add_argument("--fix-timeout", type=int, default=30)
    ap.add_argument("--denominator", type=int, default=10)
    ap.add_argument("--out", type=Path, default=REPO_ROOT / "run-logs" / "repro-cybergym-eval.json")
    args = ap.parse_args(argv)

    task_ids = _load_task_ids(args.tasks_file)
    tasks_out = []
    for tid in task_ids:
        rec = {"task_id": tid, "resolved": False, "confirmed": False,
               "winning_seed": None, "vul_class": None, "repro": None}
        try:
            bundle = adapter.resolve(tid)
        except (FileNotFoundError, ValueError) as e:
            rec["note"] = f"unresolved: {e}"
            tasks_out.append(rec)
            print(f"{tid}: unresolved ({type(e).__name__})")
            continue
        rec["resolved"] = True
        poc, score, tag = _discover_and_score(
            bundle, bank_budget=args.bank_budget,
            vul_timeout=args.vul_timeout, fix_timeout=args.fix_timeout)
        if poc is None:
            rec["note"] = f"no bank seed confirmed (last={score})"
            tasks_out.append(rec)
            print(f"{tid}: not confirmed by bank (budget={args.bank_budget})")
            continue
        rec["confirmed"] = True
        rec["winning_seed"] = tag
        rec["vul_class"] = score.get("vul_crash_class")
        rv = _measure_reproducibility(bundle, poc, runs=args.repro_runs,
                                      threshold=args.threshold, timeout_s=args.vul_timeout)
        rec["repro"] = rv.to_dict()
        tasks_out.append(rec)
        print(f"{tid}: CONFIRMED via {tag} ({rec['vul_class']}) -> "
              f"repro={rv.verdict} rate={rv.repro_rate} sig={rv.signature}")

    resolved = sum(1 for r in tasks_out if r["resolved"])
    confirmed = sum(1 for r in tasks_out if r["confirmed"])
    reproducible = sum(1 for r in tasks_out
                       if r.get("repro") and r["repro"]["verdict"] == "reproducible")
    report = {
        "eval": "cybergym-subset + crash-reproducer pipeline (R-track)",
        "ts_utc": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "server_mode": bool(os.environ.get("CYBERGYM_SERVER_URL")),
        "bank_budget": args.bank_budget,
        "repro_runs": args.repro_runs,
        "denominator": args.denominator,
        "aggregate": {
            "tasks": len(tasks_out), "resolved": resolved,
            "confirmed": confirmed, "reproducible": reproducible,
        },
        "tasks": tasks_out,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report["aggregate"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
