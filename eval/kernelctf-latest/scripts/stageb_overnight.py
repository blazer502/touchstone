#!/usr/bin/env python3
"""Stage B overnight: pick N kernel functions from Stage A surface, ask the
CPU LLM to synthesize a CBMC harness, run Stage B contract refinement loop,
log verdicts.

This is the verifier-first arm of touchstone applied to the
kernelctf-latest target. It does NOT fuzz — it builds modular proofs.

For each kernel function in the input list:
  1. Locate the function source in linux/source/.
  2. Ask the LLM (synthesizer role) to build a standalone CBMC harness:
       - reproduce the function (or its essence) with CBMC-compatible typedefs
       - call it from main() with __CPROVER_assume-driven symbolic inputs
       - mark the precondition slot with `/* @CONTRACTS */`
  3. Run `surface.stage_b.refine_unit` on the harness:
       - CBMC verifies under the (empty initially) contract
       - on unsafe, ask the LLM for a refining precondition
       - re-verify; loop up to 3 iters
  4. Capture verdict + accumulated contracts; record.

Output: one JSONL row per unit at the path given by --out.

Bounded by:
  --limit N           pick at most N functions (default 8)
  --cbmc-timeout SEC  per-CBMC-call timeout (default 120s)
  --wall-cap SEC      total wall-clock budget; abort cleanly when exceeded
"""
from __future__ import annotations
import argparse
import json
import os
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))

from llm.client import LLMClient
from surface import stage_b


HARNESS_SYSTEM = """You write CBMC harnesses for Linux kernel functions.

Output strictly C code, no prose. The harness must:
  1. Define minimal CBMC-friendly stand-ins for any kernel types referenced
     (e.g. struct page, struct inode, struct list_head). Use opaque/byte
     arrays where the actual layout doesn't affect the property under
     verification.
  2. Inline the function-under-verification verbatim, replacing kernel
     macros with simple equivalents where needed (likely/unlikely, READ_ONCE,
     container_of, etc.). If the function depends on a callable defined
     elsewhere, either inline a minimal stub or call a nondeterministic helper.
  3. Wrap the call in a `#ifdef CBMC_HARNESS int main(void) { ... }` block.
     Inputs to the function must be declared symbolic (i.e. uninitialised
     locals, or `extern` declarations) and constrained via __CPROVER_assume.
  4. Place a `/* @CONTRACTS */` marker on its own line immediately before the
     call site, so the refinement loop can inject preconditions there.

Hard rules:
  - NO __CPROVER_assume(false), NO __CPROVER_assert(false). Never restrict
    the reachable state to false.
  - NO host-effect calls (printf, exit, system, syscall).
  - All pointer dereferences must be reachable under the symbolic inputs.

If the function is impractical to harness in this format (e.g. relies on
linked-list traversal of dynamically allocated state), return the literal
string `// SKIP: <one-line reason>` and nothing else.
"""

HARNESS_USER = """Function: {fn}
Source file: {src_path}

Source listing:
```c
{source}
```

Property to verify: memory-safety (CBMC --bounds-check --pointer-check).

Produce ONLY the harness C source. Do NOT include the original source file
verbatim if it has includes — replace #include with the minimal typedefs/macros
you need."""


def extract_function(linux_src: Path, fn_name: str, src_file: str) -> str | None:
    """Crudely extract the body of `fn_name` from `src_file`. Returns the
    text or None if not found / unparseable. This is heuristic; real
    extraction would use clang/libclang."""
    p = linux_src / src_file
    if not p.exists():
        return None
    text = p.read_text(errors="replace")
    import re
    # Match: optional storage class, return type (possibly multi-token),
    # the function name, an opening paren, ... an opening brace at column 0.
    pat = re.compile(
        rf"^(?:static\s+|inline\s+|extern\s+|noinline\s+|__\w+\s+)*"
        rf"(?:const\s+|volatile\s+|unsigned\s+|signed\s+)*"
        rf"\w[\w\s\*]*?\s+{re.escape(fn_name)}\s*\(",
        re.MULTILINE,
    )
    m = pat.search(text)
    if not m:
        return None
    start = m.start()
    # Find the matching opening brace then balance it.
    brace_open = text.find("{", m.end())
    if brace_open < 0:
        return None
    depth = 1
    i = brace_open + 1
    while i < len(text) and depth > 0:
        c = text[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
        i += 1
    if depth != 0:
        return None
    body = text[start:i]
    if len(body) > 6000:
        return None  # Too big — skip
    return body


def pick_units(tasks_dir: Path, limit: int) -> list[dict]:
    """Pick up to `limit` (cluster, function, src_path) units from the Stage
    A surface, prioritising clusters with non-trivial code patterns."""
    out: list[dict] = []
    for f in sorted(tasks_dir.glob("*.json")):
        if f.name == "_index.json":
            continue
        try:
            d = json.loads(f.read_text())
        except json.JSONDecodeError:
            continue
        sources = d.get("sources", [])
        exports = d.get("exports", [])[:3]
        for src in sources[:1]:
            for fn in exports:
                out.append({
                    "cluster": d.get("cluster", f.stem),
                    "function": fn,
                    "src_file": src.get("path", ""),
                })
                if len(out) >= limit:
                    return out
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tasks-dir", default="surface/tasks/linux-6.12.91-net-netfilter",
                    type=Path)
    ap.add_argument("--linux-src", default="eval/kernelctf-latest/linux/source",
                    type=Path)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--harness-dir", default="run-logs/stageb-overnight/harnesses",
                    type=Path)
    ap.add_argument("--limit", type=int, default=8)
    ap.add_argument("--cbmc-timeout", type=int, default=120)
    ap.add_argument("--unwind", type=int, default=8)
    ap.add_argument("--max-refine-iters", type=int, default=3)
    ap.add_argument("--wall-cap", type=int, default=14400, help="seconds")
    args = ap.parse_args()

    args.harness_dir.mkdir(parents=True, exist_ok=True)
    args.out.parent.mkdir(parents=True, exist_ok=True)

    units = pick_units(args.tasks_dir, args.limit)
    print(f"[stageb-overnight] picked {len(units)} units")

    client = LLMClient(default_role="synthesizer")
    deadline = time.time() + args.wall_cap

    with args.out.open("w") as outfh:
        for i, u in enumerate(units, start=1):
            if time.time() > deadline:
                print(f"[stageb-overnight] wall-cap reached after {i-1} units")
                break
            fn = u["function"]
            src_file = u["src_file"]
            print(f"[stageb-overnight] {i}/{len(units)} cluster={u['cluster']} fn={fn} src={src_file}")
            row: dict = {
                "cluster": u["cluster"],
                "function": fn,
                "src_file": src_file,
            }

            # 1. Extract the source body
            body = extract_function(args.linux_src, fn, src_file)
            if body is None:
                row["status"] = "extract-failed"
                outfh.write(json.dumps(row) + "\n"); outfh.flush(); continue
            row["src_loc"] = body.count("\n") + 1

            # 2. Ask LLM to synthesize a CBMC harness
            try:
                r = client.chat(
                    system=HARNESS_SYSTEM,
                    user=HARNESS_USER.format(fn=fn, src_path=src_file, source=body),
                    max_tokens=2048,
                )
                harness = r.text
                row["llm_tokens_harness"] = r.total_tokens
                row["llm_latency_harness_s"] = r.latency_s
            except Exception as e:
                row["status"] = f"llm-harness-error: {e}"
                outfh.write(json.dumps(row) + "\n"); outfh.flush(); continue

            # Extract just the C code from the LLM's response
            if harness.lstrip().startswith("// SKIP"):
                row["status"] = "skipped-by-llm"
                row["llm_skip_reason"] = harness.strip()[:200]
                outfh.write(json.dumps(row) + "\n"); outfh.flush(); continue
            # Strip ```c fences if present
            if "```" in harness:
                import re
                m = re.search(r"```(?:c|C)?\n(.*?)```", harness, re.DOTALL)
                if m:
                    harness = m.group(1)
            harness_path = args.harness_dir / f"{u['cluster']}_{fn}.c"
            harness_path.write_text(harness)

            # 3. Run Stage B refine_unit
            try:
                rv = stage_b.refine_unit(
                    harness_path,
                    function="main",
                    property="memory-safety",
                    unwind=args.unwind,
                    max_iters=args.max_refine_iters,
                    client=client,
                    allow_rule_fallback=True,
                )
            except Exception as e:
                row["status"] = f"stage_b-error: {type(e).__name__}: {str(e)[:200]}"
                outfh.write(json.dumps(row) + "\n"); outfh.flush(); continue

            # Guard: a CBMC "unsafe" on a harness that fails to *compile/link*
            # the function-under-test is a harness-synthesis defect, NOT a kernel
            # bug. CBMC is sound here (it never claims safe), but the LLM gave it
            # a broken translation unit. Downgrade so the verdict isn't mistaken
            # for a real finding. Real unsafe verdicts (a genuine bounds/pointer
            # violation reached through a well-formed harness) are preserved.
            HARNESS_DEFECT_MARKERS = (
                "no body for callee",
                "is not declared",
                "conflicting types",
                "implicit declaration",
                "use of undeclared",
                "parse error",
                "conversion error",
                "CONVERSION ERROR",
            )
            evidence = (rv.final.evidence or "")
            verdict = rv.final.verdict
            if verdict == "unsafe" and any(m in evidence for m in HARNESS_DEFECT_MARKERS):
                row["status"] = "harness-invalid"
                row["verdict"] = "harness-invalid"
                row["defect_evidence"] = evidence[-400:]
                row["iters"] = len(rv.history) - 1
                outfh.write(json.dumps(row) + "\n"); outfh.flush()
                print(f"  -> harness-invalid (CBMC could not build the function-under-test)")
                continue

            row["status"] = "ok"
            row["verdict"] = verdict
            row["iters"] = len(rv.history) - 1
            row["contracts"] = list(rv.accumulated_contracts)
            row["llm_tokens_refine"] = rv.total_tokens
            outfh.write(json.dumps(row) + "\n"); outfh.flush()
            print(f"  -> verdict={rv.final.verdict} contracts={len(rv.accumulated_contracts)} iters={row['iters']}")

    print(f"[stageb-overnight] done; output at {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
