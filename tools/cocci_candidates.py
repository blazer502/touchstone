"""Run kernel Coccinelle memory-safety scripts over a scope and emit a
warnings-JSON for agent.hyp_loop (the LLM-hypothesis x PA loop).

Coccinelle scales to the whole kernel (syntactic), so it's a valid large-scale
candidate source. Output rows: {tool, path, line, func, msg} — `func` resolved
from file:line via ctags so the reachability gate can score it.

Usage:
  python3 tools/cocci_candidates.py \
    --source-root eval/kernelctf-latest/linux/source --scope net/netfilter \
    --out run-logs/cocci-candidates.json
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

# Memory-safety-relevant cocci from the kernel tree (free/use-after patterns).
COCCI = [
    "scripts/coccinelle/free/kfree.cocci",
    "scripts/coccinelle/free/kfreeaddr.cocci",
    "scripts/coccinelle/free/ifnullfree.cocci",
    "scripts/coccinelle/iterators/use_after_iter.cocci",
    "scripts/coccinelle/free/put_device.cocci",
]
_LINE_RE = re.compile(r"^(?P<path>[^:]+):(?P<line>\d+):\d+(?:-\d+)?:\s*(?P<msg>.+)$")


def _func_index(src_file: Path) -> list[tuple[int, str]]:
    """(start_line, func_name) pairs via ctags, sorted by line."""
    try:
        r = subprocess.run(["ctags", "-x", "--c-kinds=f", "--language-force=c",
                            str(src_file)], capture_output=True, text=True, timeout=30)
    except Exception:
        return []
    out = []
    for ln in r.stdout.splitlines():
        parts = ln.split()
        if len(parts) >= 3 and parts[1] == "function" and parts[2].isdigit():
            out.append((int(parts[2]), parts[0]))
    return sorted(out)


def _func_at(idx: list[tuple[int, str]], line: int) -> str | None:
    best = None
    for start, name in idx:
        if start <= line:
            best = name
        else:
            break
    return best


def run(source_root: Path, scope: str, *, time_budget: int = 1200) -> list[dict]:
    source_root = source_root.resolve()
    scope_dir = source_root / scope
    rows: list[dict] = []
    func_cache: dict[str, list[tuple[int, str]]] = {}
    for cocci in COCCI:
        sp = source_root / cocci
        if not sp.exists():
            continue
        try:
            r = subprocess.run(
                ["spatch", "--sp-file", str(sp), "--dir", str(scope_dir),
                 "--very-quiet", "--no-includes", "--timeout", "30"],
                capture_output=True, text=True, timeout=time_budget, cwd=str(source_root))
        except subprocess.TimeoutExpired:
            print(f"[cocci] {cocci}: timeout", file=sys.stderr)
            continue
        except Exception as e:
            print(f"[cocci] {cocci}: {e}", file=sys.stderr)
            continue
        for ln in (r.stdout + "\n" + r.stderr).splitlines():
            m = _LINE_RE.match(ln.strip())
            if not m:
                continue
            path = m.group("path")
            # normalize to repo-relative path
            try:
                rel = str(Path(path).resolve().relative_to(source_root))
            except Exception:
                rel = path
            line = int(m.group("line"))
            fpath = source_root / rel
            if str(fpath) not in func_cache:
                func_cache[str(fpath)] = _func_index(fpath) if fpath.exists() else []
            rows.append({
                "tool": "coccinelle",
                "path": rel,
                "line": line,
                "func": _func_at(func_cache[str(fpath)], line),
                "msg": f"{Path(cocci).stem}: {m.group('msg')}",
            })
    return rows


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--source-root", default="eval/kernelctf-latest/linux/source")
    ap.add_argument("--scope", default="net/netfilter")
    ap.add_argument("--time-budget", type=int, default=1200)
    ap.add_argument("--out", default="run-logs/cocci-candidates.json")
    args = ap.parse_args(argv)
    rows = run(Path(args.source_root), args.scope, time_budget=args.time_budget)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(rows, indent=2))
    with_func = sum(1 for r in rows if r["func"])
    print(f"coccinelle candidates: {len(rows)} ({with_func} with resolved func) -> {args.out}")
    for r in rows[:8]:
        print(f"  {r['path']}:{r['line']} [{r['func']}] {r['msg'][:70]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
