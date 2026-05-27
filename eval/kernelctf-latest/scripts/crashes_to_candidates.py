#!/usr/bin/env python3
"""Scan syz-manager crashes/ dir, emit a candidate JSON for agent.loop.

Each crash dir under workdir-broad/crashes/ has:
  - description : one-line title
  - report0 / log0 / repro.* : the KASAN dmesg
We pick the FIRST `reportN` file as the KASAN dmesg (newest crash class is the one
syz-manager surfaced first); fall back to logN.

Output: a JSON list of Candidate dicts suitable for `python3 -m agent.loop --candidates`.
"""
from __future__ import annotations
import json
import sys
from pathlib import Path

SYZ_ROOT = Path(__file__).resolve().parents[1] / "syzkaller"

def main() -> int:
    out = []
    # Scan every workdir-*/crashes/* under syzkaller/.
    workdirs = sorted(SYZ_ROOT.glob("workdir-*"))
    if not workdirs:
        print(f"no workdirs under {SYZ_ROOT}", file=sys.stderr)
        return 1
    for wd in workdirs:
        crashes = wd / "crashes"
        if not crashes.exists():
            continue
        for d in sorted(crashes.iterdir()):
            if not d.is_dir():
                continue
            desc_f = d / "description"
            if not desc_f.exists():
                continue
            desc = desc_f.read_text(errors="replace").strip()
            # Prefer reportN (syzkaller's extracted bug report) over logN (raw
            # machine console). Among reportN, take the largest non-empty one.
            import re
            bug_re = re.compile(
                r"BUG:\s+(KASAN|KMSAN|KCSAN|kernel|soft|spinlock)|"
                r"UBSAN:|WARNING:\s+CPU|"
                r"INFO:\s+task\s+(?:hung|\S+:\d+\s+blocked)|"
                r"general\s+protection\s+fault|kernel\s+BUG\s+at|Oops:\s+\d|"
                r"watchdog:\s+BUG"
            )
            rep = None
            # Try report* first
            for rf in sorted(d.glob("report*"), key=lambda p: -p.stat().st_size):
                try:
                    txt = rf.read_text(errors="replace")
                except OSError:
                    continue
                if rf.stat().st_size < 200:
                    continue
                if bug_re.search(txt):
                    rep = rf
                    break
            # Fall back to log* with the banner
            if rep is None:
                for lf in sorted(d.glob("log*")):
                    try:
                        if bug_re.search(lf.read_text(errors="replace")):
                            rep = lf
                            break
                    except OSError:
                        continue
            # Last resort: largest report or log
            if rep is None:
                rep_files = sorted(d.glob("report*"), key=lambda p: -p.stat().st_size)
                rep = rep_files[0] if rep_files else None
            if rep is None:
                log_files = sorted(d.glob("log*"))
                if log_files:
                    rep = max(log_files, key=lambda p: p.stat().st_size)
            if rep is None:
                continue
            out.append({
                "cid": f"kctf-latest-{wd.name}-{d.name[:8]}",
                "description": desc,
                "class_hint": "kernel_uaf",
                "tier1_kasan": {
                    "dmesg_path": str(rep.resolve()),
                    "unit": f"kernelctf-latest:{wd.name}:{d.name[:12]}",
                }
            })
    print(json.dumps(out, indent=2))
    return 0

if __name__ == "__main__":
    sys.exit(main())
