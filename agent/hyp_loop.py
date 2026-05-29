"""LLM-hypothesis × kernel-scale PA loop (Touchstone, task #9).

propose → reach-gate → LLM rank/refine → directed-fuzz test cfg.

The LLM is a *re-ranker/refiner of PA-grounded candidates*, never a bug
inventor: candidates come from static analyzers (Smatch/Coccinelle), the
reachability gate (directed.py) keeps only unprivileged-reachable sites, and
the open model only ranks + adds trigger/spray detail + cites the warning.
The sound oracle (KASAN/syz-repro) is the only verdict — this just produces
ranked, falsifiable `KernelBugHypothesis` objects + a focused fuzz cfg.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from surface.static_hints import parse_smatch                       # noqa: E402
from schemas.hypothesis import (KernelBugHypothesis, Site, Evidence,  # noqa: E402
                                classify_warning, WRITE_CAPABLE)
from exploit.reach import build_graph                                # noqa: E402
from oracle.tier1_fuzz.directed import distance_to_target            # noqa: E402

# Heap-spray syscalls a UAF/OOB hypothesis co-enables so a reached free actually
# corrupts adjacent objects (raising "freed-then-read" → controllable overwrite).
HEAP_SPRAY_SYSCALLS = [
    "sendmsg$unix", "recvmsg$unix", "socketpair$unix",
    "msgsnd", "msgrcv", "msgget", "setxattr", "getxattr",
    "add_key", "keyctl", "sendmsg$netlink", "write$binfmt_misc",
]


# --- candidate ingestion (analyzer-agnostic) --------------------------------

def load_warnings(smatch: str | None = None,
                  warnings_json: str | None = None) -> list[dict]:
    """Ingest static-analyzer warnings. Smatch via parse_smatch; any other
    analyzer (Coccinelle, CodeQL) via a generic JSON list of
    {tool, path, line, func, msg}."""
    ws: list[dict] = []
    if smatch and Path(smatch).exists():
        ws += parse_smatch(Path(smatch).read_text())
    if warnings_json and Path(warnings_json).exists():
        try:
            ws += json.loads(Path(warnings_json).read_text())
        except Exception:
            pass
    return ws


def to_candidates(warnings: list[dict], scope: str | None) -> list[dict]:
    """Keep only memory-corruption-relevant warnings within scope."""
    out = []
    for w in warnings:
        cls = classify_warning(w.get("msg", ""))
        if not cls:
            continue
        path = w.get("path", "") or ""
        if scope and scope not in path:
            continue
        out.append({**w, "bug_class": cls})
    return out


# --- reachability gate (directed.py) ----------------------------------------

def _entry_funcs(ep: str | None) -> list[str]:
    if not ep or not Path(ep).exists():
        return []
    try:
        return [e["func"] for e in json.loads(Path(ep).read_text()).get("entries", [])
                if "func" in e]
    except Exception:
        return []


def reach_gate(cands: list[dict], source_root: str, scope: str,
               entrypoints: str | None) -> list[dict]:
    """Annotate each candidate with unprivileged reachability (build graph once)."""
    cg, defined, _ = build_graph(Path(source_root), scope)
    entries = _entry_funcs(entrypoints)
    for c in cands:
        fn = c.get("func")
        if not fn or fn not in defined:
            c["reachability"] = {"in_scope": False, "unprivileged": False,
                                 "entry_surfaces": 0, "closest": []}
            continue
        dist = distance_to_target(cg, fn)
        ed = {e: dist[e] for e in entries if e in dist}
        c["reachability"] = {
            "in_scope": True, "unprivileged": len(ed) > 0,
            "entry_surfaces": len(ed),
            "closest": [{"entry": k, "distance": v}
                        for k, v in sorted(ed.items(), key=lambda kv: kv[1])[:3]],
        }
    return cands


# --- source slice (kernel source is a dir, not a tarball) -------------------

def _slice(source_root: str, path: str, line: int | None, win: int = 25) -> str:
    p = Path(source_root) / path
    if not p.exists() or not line:
        return ""
    try:
        lines = p.read_text(errors="replace").splitlines()
    except Exception:
        return ""
    lo, hi = max(0, line - win), min(len(lines), line + win)
    return "\n".join(f"{i+1}: {lines[i]}" for i in range(lo, hi))


# --- propose (heuristic prelim score + optional LLM refine) -----------------

def _hscore(c: dict) -> float:
    wc = 2.0 if c["bug_class"] in WRITE_CAPABLE else 1.0
    r = c.get("reachability", {})
    d = r.get("closest", [{}])[0].get("distance", 99) if r.get("closest") else 99
    return wc * (1.0 + 1.0 / (1 + d)) * (1.5 if r.get("unprivileged") else 1.0)


def propose(cands: list[dict], source_root: str, *, model=None,
            top_k: int = 20) -> list[KernelBugHypothesis]:
    pool = [c for c in cands if c.get("reachability", {}).get("in_scope")]
    pool.sort(key=_hscore, reverse=True)
    pool = pool[:top_k]
    hyps: list[KernelBugHypothesis] = []
    for c in pool:
        hid = hashlib.sha1(
            f"{c.get('path')}:{c.get('line')}:{c.get('func')}".encode()).hexdigest()[:10]
        h = KernelBugHypothesis(
            hid=hid, bug_class=c["bug_class"],
            site=Site(c.get("path", ""), c.get("line"), c.get("func")),
            falsifier=(f"KASAN {c['bug_class']} fires at {c.get('func')}, reached "
                       f"from an unprivileged syscall (else refuted)"),
            evidence=[Evidence(c.get("tool", "static"), c.get("path", ""),
                               c.get("line"), c.get("msg", ""))],
            reachability=c.get("reachability", {}),
            provenance={"proposer": "heuristic"},
        )
        h.score = round(_hscore(c), 3)
        hyps.append(h)
    if model is not None and hyps:
        try:
            hyps = _llm_refine(hyps, source_root, model)
        except Exception as e:
            print(f"[hyp_loop] LLM refine skipped: {e}", file=sys.stderr)
    return [h for h in hyps if h.is_valid_intake()]


_LLM_SYS = ("You triage static-analyzer findings into ranked, falsifiable "
            "kernel memory-corruption hypotheses. You may ONLY refine the given "
            "candidates (cite each by hid); never invent a new site. Output JSON "
            "only.")


def _llm_refine(hyps: list[KernelBugHypothesis], source_root: str, model):
    """One bounded model call: rank + add trigger_sketch/object/spray per hid.
    Citations enforced — refinements for unknown hids are dropped."""
    items = []
    for h in hyps[:12]:
        sl = _slice(source_root, h.site.file, h.site.line, win=18)
        items.append(f"hid={h.hid} class={h.bug_class} site={h.site.file}:{h.site.line} "
                     f"fn={h.site.fn} reach={h.reachability.get('unprivileged')}\n"
                     f"warning={h.evidence[0].msg}\nsource:\n{sl[:1200]}")
    user = ("Candidates:\n\n" + "\n---\n".join(items) +
            "\n\nReturn JSON: {\"ranked\":[{\"hid\":..,\"exploitability\":0-1,"
            "\"trigger_sketch\":[..],\"spray_object\":\"..\"}]} — most "
            "memory-corruption-exploitable first. JSON only.")
    resp = model([{"role": "system", "content": _LLM_SYS},
                  {"role": "user", "content": user}], max_tokens=1500)
    txt = getattr(resp, "content", None) or str(resp)
    txt = re.sub(r"<think>.*?</think>", "", txt, flags=re.DOTALL)
    m = re.search(r"\{.*\}", txt, re.DOTALL)
    if not m:
        return hyps
    try:
        ranked = json.loads(m.group(0)).get("ranked", [])
    except Exception:
        return hyps
    by_hid = {h.hid: h for h in hyps}
    order = []
    for r in ranked:
        h = by_hid.get(r.get("hid"))          # citation gate: must be a known hid
        if not h:
            continue
        h.provenance["proposer"] = "llm-refined"
        try:
            h.score = round(float(r.get("exploitability", h.score)), 3)
        except (TypeError, ValueError):
            pass
        ts = r.get("trigger_sketch")
        if isinstance(ts, list):
            h.trigger_sketch = [str(x) for x in ts][:8]
        elif isinstance(ts, str) and ts.strip():
            # model returned a single string — keep as one step, don't char-split
            h.trigger_sketch = [s.strip() for s in re.split(r"[;\n]", ts) if s.strip()][:8]
        if r.get("spray_object"):
            h.spray_hint = {"object": str(r["spray_object"])}
        order.append(h)
    # keep any not mentioned by the model, after the ranked ones
    rest = [h for h in hyps if h not in order]
    return order + rest


# --- directed-fuzz test cfg (the test leg) ----------------------------------

def directed_fuzz_cfg(hyp: KernelBugHypothesis, base_cfg_path: str,
                      out_path: str) -> dict:
    """Generate a focused syz-manager cfg for a hypothesis: co-enable heap-spray
    syscalls (so a reached UAF/OOB corrupts adjacent objects) on top of the base.
    NOTE: precise entry-func→syscall mapping (SyzDirect-grade) is unbuilt — this
    is a best-effort focus (spray set + base surface), launched via
    oracle.repro.kernel.run_syz_manager. KASAN is the verdict.
    """
    cfg = json.loads(Path(base_cfg_path).read_text())
    enabled = set(cfg.get("enable_syscalls", []) or [])
    enabled.update(HEAP_SPRAY_SYSCALLS)
    cfg["enable_syscalls"] = sorted(enabled)
    cfg["workdir"] = f"/work/syzkaller/workdir-hyp-{hyp.hid}"
    cfg["_touchstone_hypothesis"] = {"hid": hyp.hid, "bug_class": hyp.bug_class,
                                     "site": hyp.site.__dict__,
                                     "verdict_signal": "KASAN " + hyp.bug_class}
    Path(out_path).write_text(json.dumps(cfg, indent=2))
    return cfg


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="LLM-hypothesis x kernel-scale PA loop")
    ap.add_argument("--smatch", default="eval/kernelctf/scoping/smatch.out")
    ap.add_argument("--warnings-json", default=None,
                    help="generic analyzer warnings (Coccinelle/CodeQL) JSON list")
    ap.add_argument("--source-root", default="eval/kernelctf-latest/linux/source")
    ap.add_argument("--scope", default="net/netfilter")
    ap.add_argument("--entrypoints", default="surface/entrypoints/linux-6.12.91-net-netfilter.json")
    ap.add_argument("--top-k", type=int, default=20)
    ap.add_argument("--no-llm", action="store_true")
    ap.add_argument("--out", default="run-logs/hyp-loop.json")
    args = ap.parse_args(argv)

    t0 = time.time()
    warnings = load_warnings(args.smatch, args.warnings_json)
    cands = to_candidates(warnings, args.scope)
    cands = reach_gate(cands, args.source_root, args.scope, args.entrypoints)
    reachable = [c for c in cands if c.get("reachability", {}).get("unprivileged")]

    model = None
    if not args.no_llm:
        try:
            from agent.smol_poc_agent import make_default_model
            model = make_default_model(max_tokens=2000)
        except Exception as e:
            print(f"[hyp_loop] no LLM ({e}); heuristic ranking only", file=sys.stderr)

    hyps = propose(cands, args.source_root, model=model, top_k=args.top_k)
    rec = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "scope": args.scope, "warnings": len(warnings),
        "mem_corruption_candidates": len(cands),
        "reachable_unprivileged": len(reachable),
        "hypotheses": [h.to_dict() for h in hyps],
        "wall_s": round(time.time() - t0, 1),
    }
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(rec, indent=2))
    print(f"warnings={len(warnings)} mem-corruption-cands={len(cands)} "
          f"reachable-unpriv={len(reachable)} hypotheses={len(hyps)}")
    for h in hyps[:10]:
        print(f"  [{h.score:.2f}] {h.bug_class:18s} {h.site.fn} "
              f"({h.site.file}:{h.site.line}) unpriv={h.reachability.get('unprivileged')} "
              f"proposer={h.provenance.get('proposer')}")
    print(f"record -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
