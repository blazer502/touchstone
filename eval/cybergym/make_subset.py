"""Build a stratified Level-1 evaluation subset from the CyberGym task index.

The full universe is 1507 tasks across 188 projects, dominated by a handful of
big projects (binutils, ghostscript, ffmpeg). A good *measurement* subset must
(a) only include tasks whose vul AND fix binaries are materialised locally so
they are scorable without docker/server, and (b) mirror the project/language
mix of the full set so the subset score predicts the full-set score, while
(c) capping any single project so no one parser dominates the diagnostics.

Deterministic given the same seed. Writes a manifest:

    {"name": ..., "level": 1, "count": N, "tasks": [{"id","project","lang"}...]}

Usage:
    python3 -m eval.cybergym.make_subset --n 100 --seed 0 \
        --out eval/cybergym/subset_l1_100.json
"""
from __future__ import annotations

import argparse
import json
import os
import random
from collections import defaultdict
from pathlib import Path
from typing import Optional


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_TASKS_JSON = Path(os.environ.get(
    "CYBERGYM_TASKS_JSON",
    "/mnt/data/chanyoung/cybergym/cybergym_data/tasks.json",
))
SERVER_DATA_ROOT = Path(os.environ.get(
    "CYBERGYM_SERVER_DATA_DIR",
    "/mnt/data/chanyoung/cybergym/cybergym-server-data",
))


def _binaries_present(task_id: str, root: Path = SERVER_DATA_ROOT) -> bool:
    sub, _, ident = task_id.partition(":")
    if sub not in {"arvo", "oss-fuzz"}:
        return False
    for side in ("vul", "fix"):
        out = root / sub / ident / side / "out"
        if not out.exists():
            return False
        if not any(p.is_file() and os.access(p, os.X_OK) for p in out.iterdir()):
            return False
    return True


def build(n: int, seed: int, tasks_json: Path = DEFAULT_TASKS_JSON,
          per_project_cap: Optional[int] = None) -> dict:
    raw = json.loads(tasks_json.read_text())
    # Keep only locally-scorable tasks.
    scorable = [t for t in raw if _binaries_present(t["task_id"])]

    by_project: dict[str, list[dict]] = defaultdict(list)
    for t in scorable:
        by_project[t.get("project_name") or "?"].append(t)

    rng = random.Random(seed)
    for tasks in by_project.values():
        rng.shuffle(tasks)

    # Proportional allocation per project (mirror the full distribution),
    # capped so no single project dominates the diagnostics.
    total = len(scorable)
    if per_project_cap is None:
        per_project_cap = max(2, n // 12)   # ~8 for n=100

    # First pass: proportional quota, capped.
    quota: dict[str, int] = {}
    for proj, tasks in by_project.items():
        q = round(n * len(tasks) / total)
        quota[proj] = min(q, len(tasks), per_project_cap)

    picked: list[dict] = []
    for proj, tasks in by_project.items():
        picked.extend(tasks[: quota[proj]])

    # Adjust to exactly n: fill from unused tasks (project-diverse, round-robin)
    # or trim the largest projects first.
    if len(picked) < n:
        picked_ids = {t["task_id"] for t in picked}
        # Round-robin over projects sorted by remaining headroom.
        pools = {p: [t for t in ts if t["task_id"] not in picked_ids]
                 for p, ts in by_project.items()}
        order = sorted(pools, key=lambda p: -len(pools[p]))
        i = 0
        while len(picked) < n and any(pools.values()):
            p = order[i % len(order)]
            if pools[p]:
                picked.append(pools[p].pop())
            i += 1
    elif len(picked) > n:
        # Trim down to n, dropping extras from the most-represented projects
        # first so project diversity is preserved.
        proj_count: dict[str, int] = defaultdict(int)
        for t in picked:
            proj_count[t["project_name"]] += 1
        # Keep tasks from smaller projects preferentially.
        picked = sorted(picked, key=lambda t: proj_count[t["project_name"]])[:n]

    picked = sorted(picked, key=lambda t: t["task_id"])
    out = {
        "name": f"cybergym-l1-stratified-{len(picked)}",
        "level": 1,
        "seed": seed,
        "count": len(picked),
        "scorable_universe": total,
        "tasks": [
            {"id": t["task_id"],
             "project": t.get("project_name"),
             "lang": t.get("project_language"),
             "desc": (t.get("vulnerability_description") or "")[:200]}
            for t in picked
        ],
    }
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Build a stratified L1 eval subset")
    ap.add_argument("--n", type=int, default=100)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--tasks-json", type=Path, default=DEFAULT_TASKS_JSON)
    ap.add_argument("--per-project-cap", type=int, default=None)
    ap.add_argument("--out", type=Path,
                    default=REPO_ROOT / "eval" / "cybergym" / "subset_l1_100.json")
    args = ap.parse_args(argv)

    rec = build(args.n, args.seed, args.tasks_json, args.per_project_cap)
    args.out.write_text(json.dumps(rec, indent=2))

    from collections import Counter
    projs = Counter(t["project"] for t in rec["tasks"])
    langs = Counter(t["lang"] for t in rec["tasks"])
    print(f"wrote {rec['count']} tasks → {args.out}")
    print(f"scorable universe: {rec['scorable_universe']}")
    print(f"distinct projects: {len(projs)}; top: {projs.most_common(8)}")
    print(f"languages: {dict(langs)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
