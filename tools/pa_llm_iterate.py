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

# Self-critique pass — runs AFTER the proposer. Forces the model into an
# adversarial stance to attack its own hypotheses, producing a confidence score
# and a concrete counter-argument. Hypotheses with confidence < 0.3 are dropped
# downstream. This is the agent's self-enhancement step: don't just propose,
# *attack the proposal*.
_CRITIC_SYS = (
    "You are an adversarial reviewer. For EACH proposed kernel-security hypothesis, "
    "play devil's advocate against your own prior claim. For each, output:\n"
    "  - hid: the same id you proposed.\n"
    "  - confidence (0.0-1.0): how strongly the cited source actually supports the "
    "    claim. 1.0 = a kernel-reviewer would call this a likely bug; 0.5 = plausible "
    "    pattern but no clear evidence; 0.2 = speculative pattern-matching; "
    "    0.0 = the cited source contradicts the claim or doesn't support it.\n"
    "  - counter_argument: the strongest specific reason the hypothesis might be "
    "    WRONG, citing file:line from the provided source (e.g., a guard, a "
    "    refcount, a lock that protects the access). One sentence.\n"
    "  - refined_falsifier: a sharper sanitizer signal+location, OR `null` if the "
    "    hypothesis should be dropped.\n"
    "STRICT: cite ONLY file:lines from the provided source. If you cannot find a "
    "guard/contradiction, set counter_argument='no obvious contradiction found' but "
    "still rate confidence based on how concretely the source supports the claim "
    "(speculation = low confidence even without counter-evidence).\n"
    "Output JSON only: {\"reviews\":[{...}]}"
)


def build_prompt(bucket: dict, src: dict | None,
                 history: list[dict] | None = None) -> str:
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
    if history:
        parts += ["",
                  "PRIOR ITERATIONS (do not re-propose hypotheses already falsified;"
                  " do learn from the patterns):"]
        for h in history[:10]:
            parts.append(
                f"  - iter {h.get('iter','?')}: "
                f"class={h.get('bug_class')} site={h.get('site')} "
                f"outcome={h.get('outcome','untested')} "
                f"reason={(h.get('reason') or '')[:120]}")
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


def load_history(path: Path | None) -> list[dict]:
    if not path or not path.exists():
        return []
    try:
        d = json.loads(path.read_text())
        if isinstance(d, list):
            return d
        if isinstance(d, dict) and "history" in d:
            return d["history"]
    except Exception:
        pass
    return []


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


def critique_hypotheses(hypotheses: list[dict], source_slice: str) -> dict:
    """Self-enhancement: adversarial second pass over the proposer's output.
    Returns {hid -> {confidence, counter_argument, refined_falsifier}}."""
    if not hypotheses:
        return {}
    # assign stable hids if missing
    for i, h in enumerate(hypotheses):
        h.setdefault("hid", f"h{i}")
    items = []
    for h in hypotheses:
        s = h.get("site", {})
        items.append(
            f"hid={h['hid']}  class={h.get('bug_class')}  site={s.get('file')}:"
            f"{s.get('line')} fn={s.get('fn')}  "
            f"falsifier={h.get('falsifier','')}  "
            f"evidence={h.get('evidence')}"
        )
    prompt = (
        "Provided source slice (the ONLY ground truth — cite only from here):\n"
        + (source_slice[:6000] if source_slice else "(none)")
        + "\n\nHypotheses to critique:\n  " + "\n  ".join(items)
        + "\n\nReturn JSON only: "
        '{"reviews":[{"hid":"...","confidence":0.0,"counter_argument":"...",'
        '"refined_falsifier":"..."}]}'
    )
    raw = call_llm_with(_CRITIC_SYS, prompt)
    parsed = parse_llm_json(raw)
    out = {}
    for r in parsed.get("reviews", []):
        hid = r.get("hid")
        if not hid:
            continue
        try:
            conf = float(r.get("confidence", 0.0))
        except (TypeError, ValueError):
            conf = 0.0
        out[hid] = {"confidence": conf,
                    "counter_argument": r.get("counter_argument", ""),
                    "refined_falsifier": r.get("refined_falsifier") or None}
    return out


def call_llm_with(system_prompt: str, user_prompt: str) -> str:
    try:
        from openai import OpenAI
    except Exception:
        raise SystemExit("openai library not available")
    base = os.environ.get("CYBERGYM_LLM_BASE", "http://localhost:8000/v1")
    model = os.environ.get("CYBERGYM_LLM_MODEL", "synthesizer")
    client = OpenAI(base_url=base, api_key=os.environ.get("OPENAI_API_KEY", "x"))
    resp = client.chat.completions.create(
        model=model,
        messages=[{"role": "system", "content": system_prompt},
                  {"role": "user", "content": user_prompt}],
        temperature=0.0, max_tokens=2000,
    )
    return resp.choices[0].message.content or ""


def call_llm(prompt: str) -> str:
    return call_llm_with(_SYS, prompt)


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
    ap.add_argument("--history", type=Path, default=None,
                    help="Prior iterations' outcomes — feeds the proposer.")
    ap.add_argument("--min-confidence", type=float, default=0.3,
                    help="Drop hypotheses the critic rates below this.")
    ap.add_argument("--no-critic", action="store_true",
                    help="Skip the adversarial critic pass (debug only).")
    args = ap.parse_args(argv)

    bucket = parse_bucket(args.bucket)
    src = (find_function_source(args.source_root, bucket["lockup_fn"])
           if bucket["lockup_fn"] else None)
    history = load_history(args.history)
    prompt = build_prompt(bucket, src, history)
    raw = call_llm(prompt)
    parsed = parse_llm_json(raw)
    hyps = parsed.get("hypotheses") or []

    # SELF-ENHANCEMENT: adversarial critic pass over the proposer's output
    critic_results: dict[str, dict] = {}
    if hyps and not args.no_critic:
        try:
            critic_results = critique_hypotheses(hyps, (src or {}).get("slice", ""))
        except Exception as e:
            print(f"[critic] skipped: {e}", file=sys.stderr)
    # attach + filter
    kept = []
    for i, hyp in enumerate(hyps):
        hyp.setdefault("hid", f"h{i}")
        rev = critic_results.get(hyp["hid"], {})
        hyp["confidence"] = rev.get("confidence", 0.0) if critic_results else None
        hyp["counter_argument"] = rev.get("counter_argument", "")
        if rev.get("refined_falsifier"):
            hyp["falsifier"] = rev["refined_falsifier"]
        if critic_results and hyp["confidence"] is not None and \
                hyp["confidence"] < args.min_confidence:
            hyp["status"] = "rejected-by-critic"
        else:
            kept.append(hyp)

    # build a directed-fuzz cfg per KEPT hypothesis (the next-iter test)
    cfgs = []
    for i, hyp in enumerate(kept):
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

    rejected = [h for h in hyps if h.get("status") == "rejected-by-critic"]
    out = {
        "iter": 2,
        "bucket": str(args.bucket),
        "lockup_fn": bucket["lockup_fn"],
        "source_located": bool(src),
        "source_path": (src or {}).get("path"),
        "history_used": len(history),
        "critic_enabled": not args.no_critic,
        "min_confidence": args.min_confidence,
        "llm_hypotheses_kept": kept,
        "llm_hypotheses_rejected": rejected,
        "llm_honest_finding": parsed.get("honest_finding", ""),
        "directed_fuzz_cfgs": cfgs,
        "_raw": raw[:4000],
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(out, indent=2))
    print(f"iter=2  bucket={args.bucket.name[:8]}  fn={bucket['lockup_fn']}  "
          f"source_located={bool(src)}  history={len(history)}  "
          f"proposed={len(hyps)}  kept={len(kept)}  rejected={len(rejected)}  "
          f"cfgs={len(cfgs)}")
    for h in kept:
        conf = h.get("confidence")
        print(f"  KEEP [{h.get('bug_class','?')} conf={conf}] "
              f"{h.get('site',{}).get('fn','?')} "
              f"({h.get('site',{}).get('file','?')}:"
              f"{h.get('site',{}).get('line','?')})")
        if h.get("counter_argument"):
            print(f"       counter: {h['counter_argument'][:100]}")
    for h in rejected:
        conf = h.get("confidence")
        print(f"  REJECT [{h.get('bug_class','?')} conf={conf}] "
              f"{h.get('site',{}).get('fn','?')}  "
              f"counter: {h.get('counter_argument','')[:80]}")
    if not hyps:
        print(f"  HONEST FINDING: {out['llm_honest_finding']}")
    print(f"record -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
