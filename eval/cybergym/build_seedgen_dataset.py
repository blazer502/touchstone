"""Build a supervised dataset to fine-tune a small local model as a
structure-aware fuzzer-seed generator.

Objective (the specific purpose, per the 'hacking AI + program analysis'
goal): given a libFuzzer harness's source + a bug context, emit a format-VALID
input seed. Ground-truth targets are real seeds sampled from each harness's
own OSS-Fuzz corpus (the cached `oss-fuzz-corpus-cache`). This is the reusable
capability — it generalizes to fresh targets that have no corpus.

We dedup by unique (project, fuzzer) harness so the model learns across many
formats, not 100 copies of one. Targets are SHORT seeds (learnable as hex).

Output: chat-format JSONL for trl SFT.
"""
from __future__ import annotations

import argparse
import json
import os
import random
from pathlib import Path

from agent import harness_model as hm

CORPUS_CACHE = Path("/mnt/data/chanyoung/cybergym/oss-fuzz-corpus-cache")
DATA_DIR = Path("/mnt/data/chanyoung/cybergym/cybergym_data/data")
TASKS_JSON = Path("/mnt/data/chanyoung/cybergym/cybergym_data/tasks.json")
REPO = Path(__file__).resolve().parents[2]

_SYSTEM = ("You generate a single format-valid input seed for an OSS-Fuzz "
           "libFuzzer target, given its harness source. Output ONLY a hex "
           "string (the raw input bytes), no prose.")


def _project_task_index() -> dict:
    idx = {}
    for t in json.loads(TASKS_JSON.read_text()):
        idx.setdefault(t["project_name"], []).append(t)
    return idx


def _tarball_for(task) -> Path | None:
    tid = task["task_id"]
    sub, _, ident = tid.partition(":")
    tb = DATA_DIR / sub / ident / "repo-vul.tar.gz"
    return tb if tb.exists() else None


def build(out_path: Path, *, per_harness: int = 8, max_seed_bytes: int = 160,
          max_examples: int = 6000, seed: int = 0,
          holdout_frac: float = 0.35) -> dict:
    rng = random.Random(seed)
    proj_idx = _project_task_index()

    # Project-level train/holdout split so the seed generator is a GENERAL
    # capability evaluated ZERO-SHOT on held-out projects it never saw — no
    # benchmark-distribution leakage (strategic §8).
    all_projects = sorted({d.name.split("__", 1)[0]
                           for d in CORPUS_CACHE.iterdir()
                           if (d / ".done").exists() and "__" in d.name})
    rng.shuffle(all_projects)
    n_hold = int(len(all_projects) * holdout_frac)
    holdout_projects = set(all_projects[:n_hold])
    train_projects = set(all_projects[n_hold:])

    rows = []
    harnesses = 0
    for d in sorted(CORPUS_CACHE.iterdir()):
        if not (d / ".done").exists():
            continue
        name = d.name
        if "__" not in name:
            continue
        project, fuzzer = name.split("__", 1)
        if project not in train_projects:        # never train on held-out
            continue
        # sample small seeds from this harness's corpus
        files = [p for p in d.iterdir()
                 if p.is_file() and not p.name.startswith(".")]
        small = [p for p in files if 0 < p.stat().st_size <= max_seed_bytes]
        if not small:
            continue
        rng.shuffle(small)
        small = small[:per_harness]
        # harness source from a representative task of this project
        tasks = proj_idx.get(project, [])
        src = ""
        desc = ""
        for t in tasks[:4]:
            tb = _tarball_for(t)
            if tb is None:
                continue
            try:
                model = hm.build(t["task_id"], tb)
            except Exception:
                continue
            if model.harness.source:
                src = model.harness.source[:4000]
                desc = t.get("vulnerability_description", "") or ""
                break
        if not src:
            continue
        harnesses += 1
        for p in small:
            try:
                blob = p.read_bytes()
            except Exception:
                continue
            user = (f"Harness source:\n```c\n{src}\n```\n"
                    f"Bug context: {desc[:300] or '(memory-safety bug)'}\n"
                    f"Emit one valid input seed as a hex string.")
            rows.append({"messages": [
                {"role": "system", "content": _SYSTEM},
                {"role": "user", "content": user},
                {"role": "assistant", "content": blob.hex()},
            ]})
            if len(rows) >= max_examples:
                break
        if len(rows) >= max_examples:
            break

    rng.shuffle(rows)
    n_eval = min(200, len(rows) // 10)
    train, ev = rows[n_eval:], rows[:n_eval]
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w") as fh:
        for r in train:
            fh.write(json.dumps(r) + "\n")
    ev_path = out_path.with_name(out_path.stem + "-eval.jsonl")
    with ev_path.open("w") as fh:
        for r in ev:
            fh.write(json.dumps(r) + "\n")

    # Held-out CyberGym tasks (projects the model NEVER trained on) — the
    # zero-shot test set for honest, benchmark-agnostic evaluation.
    server_data = Path("/mnt/data/chanyoung/cybergym/cybergym-server-data")
    holdout_tasks = []
    for proj in sorted(holdout_projects):
        for t in proj_idx.get(proj, []):
            tid = t["task_id"]; sub, _, ident = tid.partition(":")
            if (server_data / sub / ident / "vul" / "out").exists():
                holdout_tasks.append(tid)
    hp = out_path.with_name("heldout_tasks.json")
    hp.write_text(json.dumps({"holdout_projects": sorted(holdout_projects),
                              "train_projects": sorted(train_projects),
                              "tasks": [{"id": t} for t in holdout_tasks]}, indent=2))
    return {"harnesses": harnesses, "train": len(train), "eval": len(ev),
            "train_projects": len(train_projects),
            "holdout_projects": len(holdout_projects),
            "holdout_tasks": len(holdout_tasks),
            "train_path": str(out_path), "eval_path": str(ev_path),
            "heldout_tasks_path": str(hp)}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path,
                    default=REPO / "run-logs" / "seedgen" / "train.jsonl")
    ap.add_argument("--per-harness", type=int, default=8)
    ap.add_argument("--max-seed-bytes", type=int, default=160)
    ap.add_argument("--max-examples", type=int, default=6000)
    args = ap.parse_args(argv)
    rec = build(args.out, per_harness=args.per_harness,
                max_seed_bytes=args.max_seed_bytes,
                max_examples=args.max_examples)
    print(json.dumps(rec, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
