"""CyberGym-wide per-function CBMC × cex-bridge sweep.

For each C task (CBMC can't handle the 86%-C++ majority): extract the vul source,
target the SHALLOW functions (those defined in the fuzz harness file + the
harness's direct callees), run the per-function CBMC proposer, and bridge every
`confirmed-local` cex through the sound oracle. Reports the funnel:
candidates → lowered → compiled → {confirmed, refuted, needs-buffer} → lifted.

The hypothesis under test (docs/perfn-pa-proposer.md): per-function CBMC + the
cex bridge yields PoCs on THIN harnesses (entry bytes ≈ function buffer), and
little on deep-format parsers. This sweep measures how many tasks that is.
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.perfn_cbmc_proposer import run_one                          # noqa: E402
from tools.cex_bridge import cex_to_seeds, bridge                      # noqa: E402

DATA = Path("/mnt/data/chanyoung/cybergym/cybergym_data/data")
TASKS = Path("/mnt/data/chanyoung/cybergym/cybergym_data/tasks.json")

# Callees that are libc/!interesting — never a per-function candidate.
_SKIP_CALLEES = {
    "if", "for", "while", "switch", "return", "sizeof", "fopen", "fclose",
    "fread", "fwrite", "fseek", "ftell", "open", "close", "read", "write",
    "malloc", "calloc", "realloc", "free", "memcpy", "memmove", "memset",
    "strlen", "strcmp", "strncmp", "strcpy", "strncpy", "strdup", "printf",
    "fprintf", "snprintf", "sprintf", "getpid", "unlink", "exit", "abort",
    "assert", "atoi", "strtol", "memcmp", "putchar", "puts", "perror",
    "LLVMFuzzerTestOneInput", "main", "setvbuf", "fmemopen", "getenv",
}


def c_tasks(limit: int, offset: int) -> list[dict]:
    rows = json.loads(TASKS.read_text())
    cs = [r for r in rows if (r.get("project_language") or "").lower() == "c"]
    return cs[offset:offset + limit]


def _tar_path(task_id: str) -> Path:
    fam, num = task_id.split(":")
    return DATA / fam / num / "repo-vul.tar.gz"


def extract(task_id: str, dest: Path) -> Path | None:
    tp = _tar_path(task_id)
    if not tp.exists():
        return None
    dest.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(["tar", "xzf", str(tp), "-C", str(dest)],
                       capture_output=True, timeout=120, check=True)
    except Exception:
        return None
    return dest


def _ctags_index(root: Path) -> dict[str, str]:
    """func name -> rel path of its defining .c file (first definition wins)."""
    try:
        out = subprocess.run(
            ["ctags", "-R", "--c-kinds=f", "--languages=C", "-x", str(root)],
            capture_output=True, text=True, timeout=180).stdout
    except Exception:
        return {}
    idx: dict[str, str] = {}
    for ln in out.splitlines():
        parts = ln.split()
        if len(parts) >= 4 and parts[1] == "function":
            name, fpath = parts[0], parts[3]
            if not fpath.endswith(".c"):
                continue
            rel = str(Path(fpath).resolve().relative_to(root.resolve()))
            idx.setdefault(name, rel)
    return idx


def _harness_callees(root: Path) -> tuple[set[str], set[str]]:
    """Return (harness_local_funcs, direct_callees) — the shallow target set."""
    hits = subprocess.run(
        ["grep", "-rln", "LLVMFuzzerTestOneInput", "--include=*.c", str(root)],
        capture_output=True, text=True).stdout.splitlines()
    local: set[str] = set()
    callees: set[str] = set()
    for hf in hits[:3]:
        try:
            text = Path(hf).read_text(errors="replace")
        except OSError:
            continue
        # functions defined in the harness file
        for m in re.finditer(r"^[A-Za-z_][\w \t\*]+\b(\w+)\s*\([^;]*\)\s*\{",
                             text, re.M):
            local.add(m.group(1))
        # direct callees anywhere in the harness file
        for m in re.finditer(r"\b([A-Za-z_]\w*)\s*\(", text):
            callees.add(m.group(1))
    callees -= _SKIP_CALLEES
    local -= _SKIP_CALLEES
    return local, callees


def find_candidates(root: Path, max_cands: int) -> list[dict]:
    idx = _ctags_index(root)
    local, callees = _harness_callees(root)
    cands: list[dict] = []
    seen = set()
    # prefer harness-local funcs (thinnest), then direct callees defined in-tree
    for name in list(local) + sorted(callees):
        rel = idx.get(name)
        if not rel or (rel, name) in seen:
            continue
        seen.add((rel, name))
        cands.append({"path": rel, "func": name, "bug_class": "oob-write"})
        if len(cands) >= max_cands:
            break
    return cands


def sweep_task(task_id: str, work: Path, *, max_cands: int, unwind: int,
               cbmc_timeout: int, bridge_budget: int) -> dict:
    ext = work / task_id.replace(":", "_")
    rec = {"task": task_id}
    root = extract(task_id, ext)
    if root is None:
        return {**rec, "status": "no-source"}
    try:
        cands = find_candidates(root, max_cands)
        rec["candidates"] = len(cands)
        verdicts: dict[str, int] = {}
        compiled = 0
        confirmed = []
        out_dir = work / "out"
        out_dir.mkdir(parents=True, exist_ok=True)
        for c in cands:
            try:
                r = run_one(root, c, None, unwind=unwind,
                            timeout_s=cbmc_timeout, out_dir=out_dir)
            except Exception as e:
                r = {"verdict": "run-error", "reason": str(e)[:120]}
            v = r.get("verdict", "?")
            verdicts[v] = verdicts.get(v, 0) + 1
            # "compiled" = CBMC parsed + reached symbolic execution (decisive or
            # bounded), vs. a parse/conversion failure dressed as inconclusive.
            note = r.get("note", "") or ""
            if v in ("confirmed-local", "refuted", "needs-buffer-model") or \
                    re.search(r"nwinding|VERIFICATION|__CPROVER|State \d", note):
                compiled += 1
            if v == "confirmed-local" and r.get("pov"):
                confirmed.append(r)
        rec["verdicts"] = verdicts
        rec["compiled"] = compiled
        rec["confirmed"] = len(confirmed)
        # bridge each confirm through the sound oracle
        lifted = False
        bridge_recs = []
        for r in confirmed:
            seeds, toks = cex_to_seeds(r["pov"])
            if not seeds:
                continue
            br = bridge(task_id, seeds, toks, budget_seconds=bridge_budget,
                        out_dir=out_dir)
            bridge_recs.append({"func": r["func"], "repro": br.get("repro"),
                                "how": br.get("how")})
            if br.get("repro"):
                lifted = True
                break
        rec["bridge"] = bridge_recs
        rec["lifted"] = lifted
        rec["status"] = "ok"
        return rec
    finally:
        shutil.rmtree(ext, ignore_errors=True)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=40)
    ap.add_argument("--offset", type=int, default=0)
    ap.add_argument("--max-cands", type=int, default=6)
    ap.add_argument("--unwind", type=int, default=12)
    ap.add_argument("--cbmc-timeout", type=int, default=30)
    ap.add_argument("--bridge-budget", type=int, default=15)
    ap.add_argument("--out", default="run-logs/cybergym-perfn-sweep.json")
    args = ap.parse_args(argv)

    tasks = c_tasks(args.limit, args.offset)
    work = Path("/tmp/cg_sweep")
    work.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    results = []
    agg = {"tasks": 0, "with_source": 0, "with_candidates": 0,
           "with_confirm": 0, "lifted": 0, "candidates": 0, "compiled": 0,
           "verdicts": {}}
    for i, tk in enumerate(tasks):
        tid = tk["task_id"]
        r = sweep_task(tid, work, max_cands=args.max_cands, unwind=args.unwind,
                       cbmc_timeout=args.cbmc_timeout,
                       bridge_budget=args.bridge_budget)
        results.append(r)
        agg["tasks"] += 1
        if r.get("status") != "no-source":
            agg["with_source"] += 1
        agg["candidates"] += r.get("candidates", 0)
        agg["compiled"] += r.get("compiled", 0)
        if r.get("candidates", 0) > 0:
            agg["with_candidates"] += 1
        if r.get("confirmed", 0) > 0:
            agg["with_confirm"] += 1
        if r.get("lifted"):
            agg["lifted"] += 1
        for v, n in (r.get("verdicts") or {}).items():
            agg["verdicts"][v] = agg["verdicts"].get(v, 0) + n
        print(f"[{i+1}/{len(tasks)}] {tid:16s} {tk['project_name'][:16]:16s} "
              f"cands={r.get('candidates','-')} confirm={r.get('confirmed','-')} "
              f"lifted={r.get('lifted','-')} {r.get('status')}")
        # periodic checkpoint
        if (i + 1) % 5 == 0:
            Path(args.out).write_text(json.dumps(
                {"agg": agg, "results": results,
                 "wall_s": round(time.time() - t0, 1)}, indent=2))

    agg["wall_s"] = round(time.time() - t0, 1)
    Path(args.out).write_text(json.dumps({"agg": agg, "results": results}, indent=2))
    print(f"\n=== SWEEP DONE ({agg['wall_s']}s) ===")
    print(json.dumps(agg, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
