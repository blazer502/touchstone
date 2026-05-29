"""Ingest a whole-kernel Smatch cross-function run (smatch_warns.txt) and emit a
memory-corruption candidates-JSON for agent.hyp_loop (the LLM-hypothesis x PA loop).

This is the *rich* candidate source: build_kernel_data.sh builds a cross-function
DB (caller_info / return_states / sizeof_param / frees_argument) so the second
pass surfaces interprocedural buffer-overflow / user-data / double-free warnings
the style pass cannot. We classify each warning to a memory-corruption bug class
(schemas.hypothesis.classify_warning) and keep only weaponizable / reachable
candidates. Soundness is unchanged: these are *priority candidates*, the sound
oracle (KASAN / syz-repro) still decides.

Streams the (multi-hundred-MB) warns file line by line.

Usage:
  python3 tools/smatch_candidates.py \
    --warns eval/kernelctf-latest/linux/source/smatch_warns.txt \
    --scope-any fs/ net/ drivers/ mm/ ipc/ \
    --out run-logs/smatch-candidates.json
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from surface.static_hints import SMATCH_RE, _strip_leading_dotslash  # noqa: E402
from schemas.hypothesis import classify_warning, WRITE_CAPABLE, BUG_CLASSES  # noqa: E402


def iter_candidates(warns_path: Path, scope_any: list[str] | None):
    """Yield classified memory-corruption rows, streaming the file."""
    with warns_path.open("r", errors="replace") as fh:
        for line in fh:
            m = SMATCH_RE.match(line.rstrip("\n"))
            if not m:
                continue
            msg = m.group("msg").strip()
            bug_class = classify_warning(msg)
            if bug_class is None:
                continue
            path = _strip_leading_dotslash(m.group("path"))
            if scope_any and not any(path.startswith(s) for s in scope_any):
                continue
            # user_rl= means smatch's cross-fn DB traced a USER-controlled value
            # to the array index — the genuinely weaponizable shape, vs a
            # bounded-enum/loop index it merely couldn't prove (a type-range FP).
            low = msg.lower()
            user_controlled = "user_rl=" in low or "user controlled" in low
            yield {
                "tool": "smatch",
                "path": path,
                "line": int(m.group("line")),
                "func": m.group("func"),
                "msg": msg,
                "sev": m.group("sev"),
                "bug_class": bug_class,
                "write_capable": bug_class in WRITE_CAPABLE,
                "user_controlled": user_controlled,
            }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--warns",
                    default="eval/kernelctf-latest/linux/source/smatch_warns.txt")
    ap.add_argument("--scope-any", nargs="*", default=None,
                    help="Keep candidates whose path starts with ANY of these "
                         "prefixes (e.g. fs/ net/ drivers/). Default: all.")
    ap.add_argument("--write-capable-only", action="store_true",
                    help="Keep only classes that can yield a write/control "
                         "primitive (uaf/double-free/oob-write/type-confusion/...).")
    ap.add_argument("--user-controlled-only", action="store_true",
                    help="Keep only candidates whose index smatch traced to a "
                         "user-controlled value (user_rl=) — the weaponizable "
                         "shape, filtering bounded-enum/loop type-range FPs.")
    ap.add_argument("--out", default="run-logs/smatch-candidates.json")
    args = ap.parse_args(argv)

    warns = Path(args.warns)
    if not warns.exists():
        ap.error(f"warns file missing: {warns}")

    rows: list[dict] = []
    by_class: Counter = Counter()
    by_subsys: Counter = Counter()
    for r in iter_candidates(warns, args.scope_any):
        if args.write_capable_only and not r["write_capable"]:
            continue
        if args.user_controlled_only and not r["user_controlled"]:
            continue
        rows.append(r)
        by_class[r["bug_class"]] += 1
        by_subsys[r["path"].split("/", 1)[0]] += 1

    # rank so genuinely-weaponizable candidates float up: user-controlled index
    # first, then write-capable, then by subsystem locality.
    rows.sort(key=lambda r: (not r["user_controlled"], not r["write_capable"],
                             r["path"]))

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(rows, indent=2))

    wc = sum(1 for r in rows if r["write_capable"])
    uc = sum(1 for r in rows if r["user_controlled"])
    ucw = sum(1 for r in rows if r["user_controlled"] and r["write_capable"])
    print(f"smatch candidates: {len(rows)} ({wc} write-capable, {uc} user-controlled, "
          f"{ucw} user-controlled+write-capable) -> {args.out}")
    print("by bug_class:")
    for c in BUG_CLASSES:
        if by_class.get(c):
            tag = " [write-capable]" if c in WRITE_CAPABLE else ""
            print(f"  {c:22s} {by_class[c]}{tag}")
    print("top subsystems:")
    for s, n in by_subsys.most_common(12):
        print(f"  {s:14s} {n}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
