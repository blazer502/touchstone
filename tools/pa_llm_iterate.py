"""LLM × PA × fuzz iteration step.

The closed loop: fuzz produces a bucket (even a DoS), the LLM ingests the
bucket + the source of the lockup site + prior hypotheses, and proposes
*refined* falsifiable hypotheses about whether nearby code hides a
memory-corruption bug the bucket might be masking. Each hypothesis MUST cite
specific file:line from the provided source — that's the anti-hallucination
gate. The sound oracle (KASAN / syz-repro) still decides; this is a
hypothesis refiner, not a verdict.

Usage:
  PYTHONPATH=. python3 tools/pa_llm_iterate.py \
    --bucket eval/kernelctf-latest/syzkaller/workdir-overnight/crashes/<hash> \
    --source-root eval/kernelctf-latest/linux/source \
    --out run-logs/pa-llm-iter1.json
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# match "BUG: ... in <func>" (also: "...in <func>+0xNN/0xNN")
_BUG_FN = re.compile(r"BUG:[^\n]*?\bin\s+(?P<fn>[A-Za-z_][\w]*)")


def parse_bucket(bucket: Path):
    desc = (bucket / "description").read_text(errors="replace").strip()
    fn = None
    m = _BUG_FN.search(desc)
    if m:
        fn = m.group("fn")
    report = ""
    rep0 = bucket / "report0"
    if rep0.exists():
        report = rep0.read_text(errors="replace")
    return {"description": desc, "lockup_fn": fn, "report_head": report[:4000]}


def find_function_source(source_root: Path, fn_name: str):
    """Locate <fn_name>'s definition and return a +/- 60-line slice.
    Strategy: grep for "<name>(" anywhere, then per file pick the line that
    looks like a definition (contains <name>(, doesn't end with `;` so it's
    not a forward decl, and ideally has a return-type-like prefix)."""
    import subprocess
    pat = re.escape(fn_name) + r"\s*\("
    try:
        out = subprocess.run(
            ["grep", "-rlnE", "--include=*.c", pat, str(source_root)],
            capture_output=True, text=True, timeout=60).stdout.splitlines()
    except Exception:
        return None
    # path preference: shorter path + subsystem prefix matching fn name part
    out.sort(key=lambda p: (len(p), p))
    for f in out[:30]:
        try:
            lines = Path(f).read_text(errors="replace").splitlines()
        except Exception:
            continue
        for i, ln in enumerate(lines):
            if re.search(r"\b" + re.escape(fn_name) + r"\s*\(", ln):
                stripped = ln.rstrip()
                # forward decl ends with ); — skip
                if stripped.endswith(";"):
                    continue
                # inside a function body or struct? heuristic: definition line
                # typically has a return-type-shaped prefix (static / int / void *
                # / struct foo * / size_t / etc.) before the name.
                before = ln.split(fn_name)[0]
                if not re.search(r"\b(static|inline|int|void|long|size_t|ssize_t|"
                                 r"u\d+|s\d+|bool|struct|enum|const|unsigned)\b",
                                 before):
                    continue
                lo, hi = max(0, i - 5), min(len(lines), i + 140)
                slice_ = "\n".join(
                    f"{j+1}: {lines[j]}" for j in range(lo, hi))
                rel = str(Path(f).resolve().relative_to(source_root.resolve()))
                return {"path": rel, "fn_start": i + 1, "slice": slice_}
    return None


_SYS = (
    "You are a kernel-security analyst. Given a fuzz bucket (a DoS soft-lockup "
    "the directed fuzzer produced) and the source of the lockup function, propose "
    "1-3 *falsifiable* hypotheses about whether the lockup is masking, or whether "
    "nearby code contains, a memory-corruption bug (uaf / oob-write / double-free "
    "/ refcount-underflow / type-confusion) reachable from the same unprivileged "
    "entry point. STRICT RULES:\n"
    "  1. Every hypothesis must cite specific file:line ranges *from the provided "
    "     source* — never invent locations or function names.\n"
    "  2. Bug-class must be one of: uaf, double-free, refcount-underflow, oob-write, "
    "     oob-read, uninit, type-confusion, lock-order-inversion. (Pure DoS / "
    "     soft-lockup is NOT memory-corruption — say so honestly if that's all.)\n"
    "  3. Each hypothesis must name a `falsifier`: a concrete observable the kernel "
    "     sanitizer (KASAN / KMSAN) would emit if the hypothesis holds.\n"
    "  4. trigger_sketch: ordered syscall steps to try and falsify the claim.\n"
    "  5. If the evidence does NOT support any memory-corruption hypothesis, return "
    "     `{\"hypotheses\": [], \"honest_finding\": \"no MC lead in this bucket\"}`. "
    "     Do not invent leads.\n"
    "Output JSON only — no prose, no markdown fences."
)


def build_prompt(bucket: dict, src: dict | None) -> str:
    parts = [
        f"BUCKET: {bucket['description']}",
        "REPORT HEAD (top stack frames):",
        bucket["report_head"][:2200],
        "",
    ]
    if src:
        parts += [
            f"SOURCE SLICE — {src['path']} around line {src['fn_start']}:",
            src["slice"][:6000],
        ]
    else:
        parts.append("SOURCE: function definition not located on disk.")
    parts += [
        "",
        "Return JSON like:",
        '{"hypotheses":[{"bug_class":"uaf","site":{"file":"...","line":N,"fn":"..."},'
        '"falsifier":"KASAN use-after-free fires at <site> after <trigger>",'
        '"evidence":[{"file":"...","line":N,"note":"..."}],'
        '"trigger_sketch":["socketpair(AF_UNIX,...)","sendmsg(...)","close(fd)","recvmsg(...)"]}],'
        '"honest_finding":"..."}',
    ]
    return "\n".join(parts)


HEAP_SPRAY = [
    "sendmsg$unix", "recvmsg$unix", "socketpair$unix",
    "msgsnd", "msgrcv", "msgget", "setxattr", "getxattr",
    "add_key", "keyctl", "sendmsg$netlink", "write$binfmt_misc",
]


def directed_cfg_for(hyp: dict, base_cfg: Path, hid: str) -> dict:
    cfg = json.loads(base_cfg.read_text())
    en = set(cfg.get("enable_syscalls", []) or [])
    en.update(HEAP_SPRAY)
    # add the syscalls from the trigger_sketch — best-effort syscall-name extract
    for step in hyp.get("trigger_sketch", []) or []:
        if not isinstance(step, str):
            continue
        m = re.match(r"\s*([A-Za-z_][\w$]*)", step)
        if m:
            en.add(m.group(1))
    cfg["enable_syscalls"] = sorted(en)
    cfg["workdir"] = f"/work/syzkaller/workdir-iter-{hid}"
    # NOTE: syz-manager strict-parses its config — no unknown fields allowed.
    # Hypothesis metadata is written to a sidecar (.meta.json) by main().
    return cfg


def call_llm(prompt: str) -> str:
    try:
        from openai import OpenAI
    except Exception:
        raise SystemExit("openai library not available")
    base = os.environ.get("CYBERGYM_LLM_BASE", "http://localhost:8000/v1")
    model = os.environ.get("CYBERGYM_LLM_MODEL", "synthesizer")
    client = OpenAI(base_url=base, api_key=os.environ.get("OPENAI_API_KEY", "x"))
    resp = client.chat.completions.create(
        model=model,
        messages=[{"role": "system", "content": _SYS},
                  {"role": "user", "content": prompt}],
        temperature=0.0, max_tokens=2000,
    )
    return resp.choices[0].message.content or ""


def parse_llm_json(text: str) -> dict:
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL)
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if not m:
        return {"hypotheses": [], "honest_finding": "LLM returned no JSON"}
    try:
        return json.loads(m.group(0))
    except Exception as e:
        return {"hypotheses": [], "honest_finding": f"JSON parse error: {e}"}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bucket", required=True, type=Path)
    ap.add_argument("--source-root",
                    default="eval/kernelctf-latest/linux/source", type=Path)
    ap.add_argument("--base-cfg",
                    default="eval/kernelctf-latest/syzkaller/manager-campaign.cfg",
                    type=Path)
    ap.add_argument("--out", required=True, type=Path)
    args = ap.parse_args(argv)

    bucket = parse_bucket(args.bucket)
    src = (find_function_source(args.source_root, bucket["lockup_fn"])
           if bucket["lockup_fn"] else None)
    prompt = build_prompt(bucket, src)
    raw = call_llm(prompt)
    parsed = parse_llm_json(raw)

    # build a directed-fuzz cfg per hypothesis (the next-iter test)
    cfgs = []
    for i, hyp in enumerate(parsed.get("hypotheses") or []):
        hid = f"{args.bucket.name[:8]}-h{i}"
        try:
            cfg = directed_cfg_for(hyp, args.base_cfg, hid)
            cfg_path = args.out.parent / f"iter-cfg-{hid}.json"
            cfg_path.write_text(json.dumps(cfg, indent=2))
            meta = {"iter": 2, "hypothesis_bug_class": hyp.get("bug_class"),
                    "site": hyp.get("site"),
                    "verdict_signal": "KASAN " + (hyp.get("bug_class") or "*")}
            (args.out.parent / f"iter-cfg-{hid}.meta.json").write_text(
                json.dumps(meta, indent=2))
            cfgs.append(str(cfg_path))
        except Exception as e:
            cfgs.append(f"cfg-error: {e}")

    out = {
        "iter": 2,
        "bucket": str(args.bucket),
        "lockup_fn": bucket["lockup_fn"],
        "source_located": bool(src),
        "source_path": (src or {}).get("path"),
        "llm_hypotheses": parsed.get("hypotheses") or [],
        "llm_honest_finding": parsed.get("honest_finding", ""),
        "directed_fuzz_cfgs": cfgs,
        "_raw": raw[:4000],
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(out, indent=2))
    print(f"iter=2  bucket={args.bucket.name[:8]}  fn={bucket['lockup_fn']}  "
          f"source_located={bool(src)}  hypotheses={len(out['llm_hypotheses'])}  "
          f"cfgs={len(cfgs)}")
    for h in out["llm_hypotheses"]:
        print(f"  [{h.get('bug_class','?')}] {h.get('site',{}).get('fn','?')} "
              f"({h.get('site',{}).get('file','?')}:"
              f"{h.get('site',{}).get('line','?')})  "
              f"falsifier: {(h.get('falsifier') or '')[:80]}")
    if not out["llm_hypotheses"]:
        print(f"  HONEST FINDING: {out['llm_honest_finding']}")
    print(f"record -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
