"""Per-function LLM-proposer × CBMC verifier (the non-random hypothesis loop).

For each (file, func, bug_class) candidate:
  1. lower the function to a standalone slice (tools/perfn_lower),
  2. the LLM proposes caller-contract *preconditions* (`__CPROVER_assume`) — its
     job is to constrain the input space so CBMC's verdict is meaningful, NOT to
     assert the bug (the engine decides that),
  3. CBMC checks builtin memory-safety (bounds/pointer/overflow) on the real
     function body with nondet args under those assumptions,
  4. classify: refuted (SAFE) | confirmed-local (UNSAFE + concrete trigger) |
     inconclusive | wont-compile.

This replaces "directed fuzz heap-spray over noisy candidates" with a sound
per-function decision procedure. A SAFE soundly kills a hallucinated candidate;
an UNSAFE yields a concrete cex trigger to lift to an entry-point PoC. CBMC is
the verdict authority (PLAN §8); the LLM only proposes assumptions.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.perfn_lower import lower_function, LowerResult          # noqa: E402
from oracle.tier3_bmc.cbmc_driver import run_cbmc_oracle           # noqa: E402

# bug_class -> CBMC property family (cbmc_driver.flag_map keys)
# Kernel-idiom prelude: typedef the common non-standard kernel scalar types and
# neutralize sparse/RCU annotations so a sliced kernel function gets past the
# type wall. This is the start of a Track-2 kernel lowering layer; it does NOT
# model kmalloc/RCU/locks/CONFIG-conditional fields, so deep functions still
# fail (the documented kernel ceiling).
KERNEL_PRELUDE = """
typedef unsigned char u8; typedef unsigned short u16;
typedef unsigned int u32; typedef unsigned long long u64;
typedef signed char s8; typedef short s16; typedef int s32; typedef long long s64;
typedef unsigned char __u8; typedef unsigned short __u16;
typedef unsigned int __u32; typedef unsigned long long __u64;
typedef unsigned short __le16; typedef unsigned int __le32; typedef unsigned long long __le64;
typedef unsigned short __be16; typedef unsigned int __be32; typedef unsigned long long __be64;
typedef _Bool bool; typedef unsigned int gfp_t; typedef long long loff_t;
typedef struct { int counter; } atomic_t;
typedef struct { long counter; } atomic64_t;
#define __user
#define __kernel
#define __rcu
#define __iomem
#define __force
#define __must_check
#define __percpu
"""
_USE_KERNEL_PRELUDE = False

_PROP = {
    "oob-write": "memory-safety", "oob-read": "memory-safety",
    "uaf": "no-uaf", "double-free": "no-uaf",
    "uninit": "memory-safety", "type-confusion": "memory-safety",
    "refcount-underflow": "no-overflow", "off-by-one": "no-oob",
}


def _alloc_for(params: list[tuple[str, str]], expanded: set[str],
               pointee: dict[str, str], scalar_typedefs: set[str]) -> list[str]:
    """Allocate ONE valid object (nondet contents) for every pointer param whose
    pointee type is complete — a scalar/primitive or an expanded struct. This
    enacts the sound caller contract "each pointer param points to ≥1 valid
    object", eliminating the trivially-spurious invalid-pointer-param derefs
    that would otherwise be reported as bugs. Incomplete/opaque pass-through
    pointers (never dereferenced) stay nondet. Deeper pointer graphs (chains)
    remain over-approximate — the documented env-modeling limit."""
    complete = _PRIM_C | scalar_typedefs
    setup = []
    for ty, nm in params:
        tag = pointee.get(nm)
        if tag and tag in expanded:
            setup.append(f"struct {tag} _obj_{nm}; {nm} = &_obj_{nm};")
            continue
        # explicit "T *" pointer: allocate a T if T is a complete scalar type
        m = re.match(r"^\s*([A-Za-z_]\w*)\s*\*\s*$", ty)
        if m and m.group(1) in complete:
            setup.append(f"{m.group(1)} _obj_{nm}; {nm} = &_obj_{nm};")
    return setup


_PRIM_C = {
    "char", "short", "int", "long", "unsigned", "signed", "float", "double",
    "size_t", "ssize_t", "uint8_t", "uint16_t", "uint32_t", "uint64_t",
    "int8_t", "int16_t", "int32_t", "int64_t", "uintptr_t", "intptr_t",
    "_Bool", "bool", "off_t",
}


def buffer_model(params: list[tuple[str, str]], n: int = 8) -> tuple[list[str], set[str]]:
    """Model a byte-buffer contract: a `char*`/`uint8_t*` param paired with an
    `end`/`endptr` param becomes a nondet buffer of bounded length whose end
    pointer sits at the allocation edge — so the valid region is exactly
    [buf, end) and CBMC flags any read at/after `end` (a real OOB), not the
    spurious "param pointer is invalid". This is the structured contract a
    proposer supplies; here a heuristic stands in. Returns (setup_lines,
    modeled_param_names)."""
    names = {nm for _, nm in params}
    end_names = {nm for nm in names if re.search(r"end(ptr)?$", nm, re.I)}
    # integer length/size params that bound a buffer — must equal the modeled
    # allocation size, else the verdict is a length-model inconsistency, not a
    # bug. (Only non-pointer params.)
    len_names = {nm for ty, nm in params
                 if not ty.strip().endswith("*")
                 and re.search(r"(len|size|splen|length|count|num)", nm, re.I)}
    setup, modeled = [], set()
    for ty, nm in params:
        is_byte_ptr = re.search(r"(char|u?int8_t|uchar|byte)\s*\*", ty, re.I) \
            or (ty.strip().endswith("*") and re.search(r"char|byte", ty, re.I))
        if not is_byte_ptr or nm in end_names:
            continue
        end = next((e for e in end_names), None)
        setup.append(f"char _buf_{nm}[{n}]; {nm} = _buf_{nm};")
        modeled.add(nm)
        if end:
            setup.append(f"size_t _len_{nm}; __CPROVER_assume(_len_{nm} > 0 "
                         f"&& _len_{nm} <= {n}); {end} = _buf_{nm} + _len_{nm};")
            modeled.add(end)
        # bind any sibling length param to the real allocation size (consistency)
        for ln in len_names:
            setup.append(f"__CPROVER_assume({ln} == {n});")
            modeled.add(ln)
    return setup, modeled


def build_harness(lr: LowerResult, preconds: list[str], setup: list[str]) -> str:
    decls = "\n    ".join(f"{ty} {nm};" for ty, nm in lr.params)
    setup_s = "\n    ".join(setup)
    assumes = "\n    ".join(f"__CPROVER_assume({p});" for p in preconds)
    args = ", ".join(nm for _, nm in lr.params)
    fn = lr.sig.split("(")[0].split()[-1].lstrip("*")
    return f"""/* per-function CBMC harness: {fn} */
#include <stdint.h>
#include <stddef.h>
{KERNEL_PRELUDE if _USE_KERNEL_PRELUDE else ""}
{lr.type_decls}
{lr.macro_decls}

{lr.body}

int main(void) {{
    {decls}
    {setup_s}
    {assumes}
    {fn}({args});
    return 0;
}}
"""


_SYS = ("You assist CBMC. Given one C function and a suspected bug class, propose "
        "the caller-contract PRECONDITIONS a real caller guarantees, as C boolean "
        "expressions over the parameters, so CBMC does not explore impossible "
        "inputs. Do NOT assume the bug away (never emit a precondition that forces "
        "the safe branch). Output JSON only: {\"preconditions\":[\"expr\",...]}. "
        "Empty list is fine if the function is robust to arbitrary input.")


def propose_preconditions(lr: LowerResult, bug_class: str, model) -> list[str]:
    if model is None:
        return []
    user = (f"Function (bug class: {bug_class}):\n```c\n{lr.body[:2500]}\n```\n"
            f"Parameters: {[f'{t} {n}' for t, n in lr.params]}\n"
            "Propose preconditions (JSON only).")
    try:
        resp = model([{"role": "system", "content": _SYS},
                      {"role": "user", "content": user}], max_tokens=400)
        txt = getattr(resp, "content", None) or str(resp)
        txt = re.sub(r"<think>.*?</think>", "", txt, flags=re.DOTALL)
        m = re.search(r"\{.*\}", txt, re.DOTALL)
        if not m:
            return []
        pres = json.loads(m.group(0)).get("preconditions", [])
        bad = {"", "0", "false", "1==0", "1 == 0"}
        return [p for p in pres if isinstance(p, str) and p.strip() not in bad][:6]
    except Exception as e:
        print(f"  [llm precond skipped: {e}]", file=sys.stderr)
        return []


def run_one(source_root: Path, cand: dict, model, *, unwind: int,
            timeout_s: int, out_dir: Path) -> dict:
    rel, func = cand["path"], cand["func"]
    bug_class = cand.get("bug_class", "oob-write")
    lr = lower_function(source_root, rel, func)
    rec = {"path": rel, "func": func, "bug_class": bug_class}
    if not lr.ok:
        rec.update(verdict="wont-lower", reason=lr.reason)
        return rec
    rec["resolved_types"] = len(lr.resolved_types)
    rec["invented_macros"] = lr.invented_macros
    preconds = propose_preconditions(lr, bug_class, model)
    rec["preconditions"] = preconds
    # pointee map: typedef param-type -> expanded tag (best-effort via lr decls)
    expanded = {m.group(1) for m in re.finditer(r"^struct (\w+) \{", lr.type_decls, re.M)}
    pointee: dict[str, str] = {}
    for ty, nm in lr.params:
        tm = re.search(rf"typedef\s+struct\s+(\w+)\s*\*+\s*{re.escape(ty)}\s*;",
                       lr.type_decls)
        if tm:
            pointee[nm] = tm.group(1)
    # scalar typedefs (RHS not a pointer / struct / union) → safe to allocate
    scalar_typedefs = {
        m.group(2) for m in re.finditer(
            r"typedef\s+([^;]*?)\b(\w+)\s*;", lr.type_decls)
        if "*" not in m.group(1) and not re.search(r"\b(struct|union)\b", m.group(1))
    }
    bufset, modeled = buffer_model(lr.params)
    obj_setup = _alloc_for([(t, n) for t, n in lr.params if n not in modeled],
                           expanded, pointee, scalar_typedefs)
    setup = bufset + obj_setup
    rec["buffer_modeled"] = sorted(modeled)
    harness = build_harness(lr, preconds, setup)
    hpath = out_dir / f"{func}.c"
    hpath.write_text(harness)
    prop = _PROP.get(bug_class, "memory-safety")
    try:
        v = run_cbmc_oracle(hpath, function="main", property=prop,
                            unwind=unwind, timeout_s=timeout_s, out_dir=out_dir)
    except Exception as e:
        rec.update(verdict="cbmc-error", reason=str(e)[:200])
        return rec
    rec["cbmc_verdict"] = v.verdict
    rec["wall_ms"] = v.wall_ms
    if v.verdict == "unsafe":
        # Soundness guard: a cex that relies on a pointer PARAM being an
        # unconstrained/invalid pointer is an env-modeling artifact (a real
        # caller passes a valid object), NOT a bug. Never count it as a confirm
        # — the project's no-false-confirmation rule. Such functions need an
        # explicit buffer/object model before per-function CBMC can decide them.
        param_names = {nm for _, nm in lr.params}
        spurious = False
        try:
            pov = json.loads(Path(v.pov_path).read_text()).get("assignment", {})
            for k, val in pov.items():
                if k in param_names and isinstance(val, str) and "INVALID" in val:
                    spurious = True
                    break
        except Exception:
            pass
        if spurious:
            rec["verdict"] = "needs-buffer-model"
            rec["note"] = "cex relies on unconstrained pointer param (spurious)"
            rec["pov"] = v.pov_path
            return rec
        rec["verdict"] = "confirmed-local"
        rec["pov"] = v.pov_path
        rec["target_location"] = v.target_location
    elif v.verdict == "safe":
        rec["verdict"] = "refuted"
    else:
        rec["verdict"] = "inconclusive"
        rec["note"] = (v.evidence_excerpt or "")[:400]
    return rec


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--source-root", required=True)
    ap.add_argument("--candidates", required=True,
                    help="JSON list of {path, func, bug_class}")
    ap.add_argument("--limit", type=int, default=10)
    ap.add_argument("--unwind", type=int, default=6)
    ap.add_argument("--timeout-s", type=int, default=90)
    ap.add_argument("--no-llm", action="store_true")
    ap.add_argument("--kernel", action="store_true",
                    help="inject the kernel-idiom prelude (u32/__le/atomic_t/__user...)")
    ap.add_argument("--out", default="run-logs/perfn-cbmc.json")
    args = ap.parse_args(argv)
    if args.kernel:
        globals()["_USE_KERNEL_PRELUDE"] = True

    cands = json.loads(Path(args.candidates).read_text())
    if isinstance(cands, dict):
        cands = cands.get("candidates", [])
    # de-dup by (path, func), keep order
    seen, uniq = set(), []
    for c in cands:
        k = (c.get("path"), c.get("func"))
        if k in seen or not all(k):
            continue
        seen.add(k)
        uniq.append(c)
    uniq = uniq[:args.limit]

    model = None
    if not args.no_llm:
        try:
            from agent.smol_poc_agent import make_default_model
            model = make_default_model(max_tokens=600)
        except Exception as e:
            print(f"[no LLM: {e}] running builtin-checks only", file=sys.stderr)

    out_dir = Path(args.out).with_suffix("")
    out_dir.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    results = []
    tally: dict[str, int] = {}
    for i, c in enumerate(uniq):
        r = run_one(Path(args.source_root), c, model,
                    unwind=args.unwind, timeout_s=args.timeout_s, out_dir=out_dir)
        results.append(r)
        tally[r["verdict"]] = tally.get(r["verdict"], 0) + 1
        print(f"[{i+1}/{len(uniq)}] {r['verdict']:16s} {c['func'][:34]:34s} "
              f"{c['path']}  cbmc={r.get('cbmc_verdict','-')} "
              f"{r.get('wall_ms','')}")
    rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "source_root": args.source_root, "n": len(uniq),
           "llm": model is not None, "tally": tally,
           "wall_s": round(time.time() - t0, 1), "results": results}
    Path(args.out).write_text(json.dumps(rec, indent=2))
    print(f"\nTALLY {tally}  ({rec['wall_s']}s)  -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
