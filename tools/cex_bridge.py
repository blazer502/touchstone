"""Local→global cex bridge: CBMC counterexample → libFuzzer seed/dict → oracle.

A `confirmed-local` cex from `tools/perfn_cbmc_proposer` is an assignment to an
*internal function's* parameters — NOT bytes at the harness entry. It cannot
become a scoring PoC directly (the inter-procedural path from
`LLVMFuzzerTestOneInput(data,size)` to that function is unsolved). What it CAN
do is de-randomize the fuzzer: the cex carries the exact byte pattern the
vulnerable code is sensitive to (e.g. a run of 0x80 that drives a LEB128
off-by-one). We extract those bytes and inject them as libFuzzer **seeds** and
**dictionary tokens**, then let the existing fuzz→oracle path place them.

The sound oracle (`local_oracle.score_native`, byte-identical to the CyberGym
scorer: vul=crash ∧ fix=no_crash) remains the only verdict. This bridge only
changes what the fuzzer starts from — it never asserts a reproduction.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agent.local_oracle import resolve_harness, score_native           # noqa: E402

# NOTE: the CyberGym native harnesses are AFL++ persistent drivers
# (aflpp_driver.c), not libFuzzer binaries — libFuzzer's in-process mutation
# (agent.libfuzzer_phase) reports 0 execs against them, and host afl-fuzz is
# policy-blocked (core_pattern). The driver's *replay* interface (`./h file`)
# works and is what the sound oracle uses, so the fuzz leg here is an
# oracle-scored byte mutator over the replay interface — sound, no external
# fuzzer needed.


def _lcg(seed: int):
    """Deterministic PRNG (no wall-clock/Math.random) for reproducible mutation."""
    x = seed & 0xFFFFFFFF
    while True:
        x = (1103515245 * x + 12345) & 0x7FFFFFFF
        yield x


def _mutate_replay(task_id: str, seeds: list[bytes], tokens: list[bytes], *,
                   budget_seconds: int, out_dir: Path) -> dict:
    """Mutate the cex seeds (repeat the pattern, splice dict tokens, flip bytes)
    and score each mutant via the sound oracle until one reproduces or the budget
    runs out. Replay-only, so it works on AFL++ drivers."""
    rng = _lcg(0xC0FFEE)
    base = list(seeds) or [b"\x00"]
    tried = 0
    deadline = time.time() + budget_seconds
    while time.time() < deadline:
        s = base[next(rng) % len(base)]
        r = next(rng) % 5
        if r == 0:                       # repeat the pattern (LEB-style runs)
            mut = s * (1 + next(rng) % 64)
        elif r == 1 and tokens:          # splice a dict token at an offset
            t = tokens[next(rng) % len(tokens)]
            off = next(rng) % (len(s) + 1)
            mut = s[:off] + t + s[off:]
        elif r == 2:                     # flip a byte
            mut = bytearray(s or b"\x00")
            mut[next(rng) % len(mut)] ^= (1 << (next(rng) % 8))
            mut = bytes(mut)
        elif r == 3:                     # extend with high-bit bytes
            mut = s + bytes([0x80]) * (1 + next(rng) % 32)
        else:                            # set a byte to a token's first byte
            mut = bytearray(s or b"\x00")
            if tokens:
                mut[next(rng) % len(mut)] = tokens[next(rng) % len(tokens)][0]
            mut = bytes(mut)
        tried += 1
        sc = score_native(task_id, mut)
        if sc and sc["success"]:
            (out_dir / f"{task_id.replace(':','_')}-poc-mutate").write_bytes(mut)
            return {"repro": True, "how": "mutate-replay", "tried": tried,
                    "vul_crash_class": sc["vul_crash_class"],
                    "vul_location": sc["vul_location"]}
    return {"repro": False, "tried": tried}

_ARR = re.compile(r"\{([^{}]*)\}")
_INT = re.compile(r"-?\d+")


def _bytes_from_array(val: str) -> bytes | None:
    """Parse a CBMC array assignment like '{ -128, -128, 0, ... }' into bytes."""
    m = _ARR.search(val)
    if not m:
        return None
    ints = [int(x) for x in _INT.findall(m.group(1))]
    if not ints:
        return None
    return bytes((x & 0xFF) for x in ints)


def _scalar_tokens(val: str) -> list[bytes]:
    """A scalar cex value (e.g. '255u', '0x80') → little-endian byte tokens at a
    few widths, so distinctive magic constants become dictionary entries."""
    m = re.search(r"(0x[0-9a-fA-F]+|\d+)", val)
    if not m:
        return []
    try:
        n = int(m.group(1), 0)
    except ValueError:
        return []
    if n == 0 or n > 0xFFFFFFFF:
        return []
    out = []
    for width in (1, 2, 4):
        if n < (1 << (8 * width)):
            out.append(n.to_bytes(width, "little"))
    return out


def cex_to_seeds(pov_path: str | Path) -> tuple[list[bytes], list[bytes]]:
    """Return (seeds, dict_tokens) extracted from one cex pov JSON."""
    try:
        pov = json.loads(Path(pov_path).read_text())
    except Exception:
        return [], []
    assign = pov.get("assignment", {})
    seeds: list[bytes] = []
    toks: list[bytes] = []
    for k, val in assign.items():
        if not isinstance(val, str):
            continue
        b = _bytes_from_array(val)
        if b:
            seeds.append(b)
            toks.append(b)
        else:
            toks.extend(_scalar_tokens(val))
    # dedup, drop trivial
    seeds = _dedup([s for s in seeds if s])
    toks = _dedup([t for t in toks if 0 < len(t) <= 16])
    return seeds, toks


def _dedup(xs: list[bytes]) -> list[bytes]:
    out, seen = [], set()
    for x in xs:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def _write_dict(tokens: list[bytes], dest: Path) -> Path | None:
    if not tokens:
        return None
    lines = []
    for i, t in enumerate(tokens):
        esc = "".join(f"\\x{b:02x}" for b in t)
        lines.append(f'tok{i}="{esc}"')
    dest.write_text("\n".join(lines))
    return dest


def bridge(task_id: str, seeds: list[bytes], tokens: list[bytes], *,
           budget_seconds: int, out_dir: Path) -> dict:
    """Direct-shot the cex seeds, then fuzz-around with the cex dict; score every
    candidate via the sound native oracle. Returns a result record."""
    hv = resolve_harness(task_id, "vul")
    rec = {"task": task_id, "n_seeds": len(seeds), "n_tokens": len(tokens),
           "harness": str(hv.binary) if hv else None}
    if hv is None:
        rec["repro"] = False
        rec["reason"] = "vul-harness-missing"
        return rec

    # 1) direct shot: is the raw cex byte-pattern already a scoring PoC?
    for i, s in enumerate(seeds):
        sc = score_native(task_id, s)
        if sc and sc["success"]:
            rec.update(repro=True, how="direct", seed_idx=i,
                       vul_crash_class=sc["vul_crash_class"],
                       vul_location=sc["vul_location"])
            (out_dir / f"{task_id.replace(':','_')}-poc-direct").write_bytes(s)
            return rec

    # 2) oracle-scored mutation around the cex seeds + dict tokens
    mr = _mutate_replay(task_id, seeds, tokens, budget_seconds=budget_seconds,
                        out_dir=out_dir)
    rec["mutants_tried"] = mr.get("tried")
    if mr.get("repro"):
        rec.update(repro=True, how=mr["how"],
                   vul_crash_class=mr.get("vul_crash_class"),
                   vul_location=mr.get("vul_location"))
        return rec
    rec["repro"] = False
    return rec


def _collect_povs(results_json: str, max_povs: int) -> list[str]:
    """Pull confirmed-local pov paths out of a perfn_cbmc_proposer results file."""
    d = json.loads(Path(results_json).read_text())
    povs = [r["pov"] for r in d.get("results", [])
            if r.get("verdict") == "confirmed-local" and r.get("pov")]
    return povs[:max_povs]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="CBMC cex → fuzz seed/dict → oracle")
    ap.add_argument("--task", required=True, help="CyberGym task id, e.g. arvo:40674")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--pov", action="append", help="cex pov JSON (repeatable)")
    g.add_argument("--from-results", help="perfn-cbmc results JSON; use its confirmed cexs")
    ap.add_argument("--max-povs", type=int, default=10)
    ap.add_argument("--budget-seconds", type=int, default=30)
    ap.add_argument("--baseline", action="store_true",
                    help="also run a no-cex fuzz (empty seed, no dict) for comparison")
    ap.add_argument("--out", default="run-logs/cex-bridge.json")
    args = ap.parse_args(argv)

    povs = args.pov or _collect_povs(args.from_results, args.max_povs)
    seeds, toks = [], []
    for p in povs:
        s, t = cex_to_seeds(p)
        seeds += s
        toks += t
    seeds, toks = _dedup(seeds), _dedup(toks)

    out_dir = Path(args.out).with_suffix("")
    out_dir.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    print(f"task={args.task} povs={len(povs)} cex-seeds={len(seeds)} "
          f"dict-tokens={len(toks)} budget={args.budget_seconds}s")
    cex_res = bridge(args.task, seeds, toks, budget_seconds=args.budget_seconds,
                     out_dir=out_dir)
    print(f"  CEX-seeded : repro={cex_res.get('repro')} how={cex_res.get('how','-')} "
          f"execs={cex_res.get('fuzz_execs','-')} crashes={cex_res.get('fuzz_crashes','-')}")

    rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "task": args.task, "povs": len(povs),
           "cex_seeds": len(seeds), "dict_tokens": len(toks),
           "cex_result": cex_res}

    if args.baseline:
        # No-cex control: same mutation budget but seeded with a single null byte
        # and no cex dictionary — isolates the cex's contribution.
        (out_dir / "baseline").mkdir(parents=True, exist_ok=True)
        base = _mutate_replay(args.task, [b"\x00"], [],
                              budget_seconds=args.budget_seconds,
                              out_dir=out_dir / "baseline")
        rec["baseline_result"] = base
        lift = bool(cex_res.get("repro")) and not base.get("repro")
        rec["cex_lift"] = lift
        print(f"  BASELINE   : repro={base.get('repro')} tried={base.get('tried')}")
        print(f"  CEX LIFT    : {lift}  (cex reproduced where baseline did not)")

    rec["wall_s"] = round(time.time() - t0, 1)
    Path(args.out).write_text(json.dumps(rec, indent=2))
    print(f"record -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
