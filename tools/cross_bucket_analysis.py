"""Multi-bucket cross-analysis — cluster crash buckets, treat each cluster as
aggregated evidence, propose stronger hypotheses than single-bucket analysis can.

Why this matters:
  - 1 bucket is noise; N concurring buckets at the same site is a real pattern.
  - When different triggers reach the SAME site, the root cause is likely in
    the function itself, not the trigger — and the LLM should be told that.
  - Syscall sets seen across multiple buckets' logs give cross-bucket trigger
    triangulation: the union/intersection of syscalls in the cluster narrows
    the actual reachable surface.

Reuses the proposer / critic / history machinery from pa_llm_iterate.py — same
citation-gate guarantee, same confidence-based filtering, but the evidence
fed to the LLM is now a CLUSTER, not a single bucket.

Usage:
  PYTHONPATH=. python3 tools/cross_bucket_analysis.py \
    --workdir eval/kernelctf-latest/syzkaller/workdir-overnight \
    --workdir eval/kernelctf-latest/syzkaller/workdir-iter-a21e71f7-h0 \
    --source-root eval/kernelctf-latest/linux/source \
    --out run-logs/cross-bucket-analysis.json
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

# import the single-bucket machinery (proposer, critic, history, cfg builder)
sys.path.insert(0, str(Path(__file__).resolve().parent))
import pa_llm_iterate as pl  # noqa: E402


_CROSS_SYS = (
    "You are a kernel-security analyst given a CLUSTER of N concurring crash "
    "buckets, all reaching the same function. Multi-bucket cross-analysis "
    "principle: when N>1 buckets reach the same site via DIFFERENT triggers, "
    "the root cause is likely *in the function itself*, not in the specific "
    "trigger. STRICT rules:\n"
    "  1. Every hypothesis cites specific file:line *from the provided source* "
    "     — never invent locations.\n"
    "  2. Bug-class: uaf / double-free / refcount-underflow / oob-write / "
    "     oob-read / uninit / type-confusion / lock-order-inversion. (dos-only "
    "     and lockup-only are honest findings, NOT memory-corruption.)\n"
    "  3. If all N buckets are DoS soft-lockups and the source shows a "
    "     loop/wait/lock at the lockup site, the honest finding is dos-only — "
    "     return `{\"hypotheses\":[],\"honest_finding\":\"dos-only cluster — "
    "     <one-sentence why>\"}`. Do not invent MC.\n"
    "  4. If stacks vary, prefer hypotheses fitting the COMMON portion of the "
    "     stacks (the shared frames closest to the crash).\n"
    "  5. Each hypothesis MUST name a `falsifier` (concrete sanitizer signal "
    "     and location) and a `trigger_sketch` (ordered syscalls).\n"
    "Output JSON only."
)


def cluster_buckets(bucket_dirs: list[Path]) -> dict[str, list[dict]]:
    """Group buckets by lockup_fn extracted from description.
    Each bucket gets: description, lockup_fn, report_head, log0_syscalls."""
    clusters: dict[str, list[dict]] = defaultdict(list)
    for d in bucket_dirs:
        info = pl.parse_bucket(d)
        info["dir"] = str(d)
        # extract syscall names called inside the syz program log
        log0 = d / "log0"
        info["log_syscalls"] = []
        if log0.exists():
            txt = log0.read_text(errors="replace")[:8000]
            # syzkaller programs look like:  fd = openat$X(...)
            #   or:  r0 = socketpair$unix(...)
            calls = re.findall(r"\b([a-z_][\w$]*)\s*\(", txt)
            # de-dupe + keep order
            seen = []
            for c in calls:
                if c not in seen and len(c) > 2:
                    seen.append(c)
            info["log_syscalls"] = seen[:40]
        # also pull top RIP from report0 for stack-variation reporting
        m = re.search(r"RIP: 0010:([^\n]+)", info["report_head"])
        info["top_rip"] = m.group(1).strip()[:160] if m else None
        key = info["lockup_fn"] or "(unknown)"
        clusters[key].append(info)
    return clusters


def build_cluster_prompt(fn: str, cluster: list[dict],
                         src: dict | None,
                         history: list[dict] | None) -> str:
    descs = sorted({b["description"] for b in cluster})
    syscalls_union = sorted({s for b in cluster for s in b.get("log_syscalls", [])})
    rips = sorted({b["top_rip"] for b in cluster if b.get("top_rip")})
    parts = [
        f"CLUSTER: function `{fn}`  —  {len(cluster)} concurring buckets.",
        f"Descriptions in cluster ({len(descs)} unique):",
        *[f"  - {d}" for d in descs[:6]],
        "",
        f"Syscall set seen across bucket logs (union, top 30): "
        f"{syscalls_union[:30]}",
        "",
        f"Top-of-stack RIPs across buckets ({len(rips)} unique):",
        *[f"  - {r}" for r in rips[:6]],
        "",
    ]
    if src:
        parts += [
            f"SOURCE — {src['path']} around line {src['fn_start']}:",
            src["slice"][:5500],
        ]
    else:
        parts.append("SOURCE: lockup-function definition not located on disk.")
    if history:
        parts += ["",
                  "PRIOR ITERATIONS (do not re-propose falsified hypotheses):"]
        for h in history[:10]:
            parts.append(
                f"  - iter {h.get('iter','?')}: class={h.get('bug_class')} "
                f"site={h.get('site')} outcome={h.get('outcome','untested')} "
                f"reason={(h.get('reason') or '')[:120]}")
    parts += [
        "",
        "Return JSON: {\"hypotheses\":[{\"bug_class\":\"...\","
        "\"site\":{\"file\":\"...\",\"line\":N,\"fn\":\"...\"},"
        "\"falsifier\":\"...\",\"evidence\":[{\"file\":\"...\",\"line\":N,"
        "\"note\":\"...\"}],\"trigger_sketch\":[\"...\"]}],"
        "\"honest_finding\":\"...\"}",
    ]
    return "\n".join(parts)


def analyze_cluster(fn: str, cluster: list[dict], source_root: Path,
                    base_cfg: Path, out_dir: Path,
                    history: list[dict], min_confidence: float,
                    no_critic: bool) -> dict:
    src = (pl.find_function_source(source_root, fn)
           if fn and fn != "(unknown)" else None)
    prompt = build_cluster_prompt(fn, cluster, src, history)
    raw = pl.call_llm_with(_CROSS_SYS, prompt)
    parsed = pl.parse_llm_json(raw)
    hyps = parsed.get("hypotheses") or []
    critic = {}
    if hyps and not no_critic:
        try:
            critic = pl.critique_hypotheses(hyps, (src or {}).get("slice", ""))
        except Exception as e:
            print(f"[critic] cluster fn={fn}: {e}", file=sys.stderr)
    kept, rejected = [], []
    for i, hyp in enumerate(hyps):
        hyp.setdefault("hid", f"h{i}")
        rev = critic.get(hyp["hid"], {})
        hyp["confidence"] = rev.get("confidence", 0.0) if critic else None
        hyp["counter_argument"] = rev.get("counter_argument", "")
        if rev.get("refined_falsifier"):
            hyp["falsifier"] = rev["refined_falsifier"]
        if critic and hyp["confidence"] is not None and \
                hyp["confidence"] < min_confidence:
            hyp["status"] = "rejected-by-critic"
            rejected.append(hyp)
        else:
            kept.append(hyp)
    cfgs = []
    for i, hyp in enumerate(kept):
        # cfg id includes cluster fn (truncated) so files don't collide
        slug = re.sub(r"\W+", "", fn)[:10] or "unk"
        hid = f"cluster-{slug}-h{i}"
        try:
            cfg = pl.directed_cfg_for(hyp, base_cfg, hid)
            cfg_path = out_dir / f"cluster-cfg-{hid}.json"
            cfg_path.write_text(json.dumps(cfg, indent=2))
            cfgs.append(str(cfg_path))
        except Exception as e:
            cfgs.append(f"cfg-error: {e}")
    return {
        "cluster_fn": fn,
        "cluster_size": len(cluster),
        "source_located": bool(src),
        "source_path": (src or {}).get("path"),
        "unique_descriptions": sorted({b["description"] for b in cluster}),
        "unique_top_rips": sorted({b["top_rip"] for b in cluster if b.get("top_rip")}),
        "syscalls_union": sorted({s for b in cluster for s in b.get("log_syscalls", [])}),
        "bucket_dirs": [b["dir"] for b in cluster],
        "hypotheses_kept": kept,
        "hypotheses_rejected": rejected,
        "honest_finding": parsed.get("honest_finding", ""),
        "directed_fuzz_cfgs": cfgs,
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workdir", action="append", required=True,
                    help="syzkaller workdir-X dir (must contain crashes/); "
                         "may be repeated to pool buckets across campaigns")
    ap.add_argument("--source-root",
                    default="eval/kernelctf-latest/linux/source", type=Path)
    ap.add_argument("--base-cfg",
                    default="eval/kernelctf-latest/syzkaller/manager-campaign.cfg",
                    type=Path)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--history", type=Path, default=None)
    ap.add_argument("--min-confidence", type=float, default=0.4)
    ap.add_argument("--min-cluster-size", type=int, default=1,
                    help="Skip clusters smaller than this (default 1 = all)")
    ap.add_argument("--no-critic", action="store_true")
    args = ap.parse_args(argv)

    all_dirs: list[Path] = []
    for w in args.workdir:
        cr = Path(w) / "crashes"
        if cr.exists():
            all_dirs.extend(sorted([d for d in cr.iterdir() if d.is_dir()]))
        else:
            print(f"[warn] no crashes dir at {cr}", file=sys.stderr)

    print(f"buckets pooled: {len(all_dirs)} across {len(args.workdir)} workdir(s)")

    clusters = cluster_buckets(all_dirs)
    print(f"clusters: {len(clusters)} (by lockup_fn)")

    history = pl.load_history(args.history)
    args.out.parent.mkdir(parents=True, exist_ok=True)

    results = []
    for fn, cluster in sorted(clusters.items(), key=lambda kv: -len(kv[1])):
        if len(cluster) < args.min_cluster_size:
            continue
        print(f"  analyzing cluster fn={fn}  n={len(cluster)} ...")
        r = analyze_cluster(fn, cluster, args.source_root, args.base_cfg,
                            args.out.parent, history, args.min_confidence,
                            args.no_critic)
        results.append(r)
        print(f"    kept={len(r['hypotheses_kept'])}  "
              f"rejected={len(r['hypotheses_rejected'])}  "
              f"honest_finding={(r['honest_finding'] or '')[:80]}")

    out = {
        "total_buckets": len(all_dirs),
        "n_clusters": len(clusters),
        "clusters": results,
    }
    args.out.write_text(json.dumps(out, indent=2))
    print(f"record -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
