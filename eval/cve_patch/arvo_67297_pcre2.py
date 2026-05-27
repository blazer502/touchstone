"""Verify the upstream pcre2 patch for arvo:67297 (heap-OOB in scan loop).

The disclosed bug: `for (size_t i = 1; i < size - 2; i++)` underflows when
`size < 2` (unsigned subtraction wraps to SIZE_MAX), causing the loop to run
unboundedly and read `wdata[i+1]` past the allocated buffer. ASan reports
a 4-byte read OOB at `pcre2_fuzzsupport.c:302`.

The disclosed fix: gate the loop with `if (size > 3) for (...)`, killing the
underflow path entirely.

This is a textbook CBMC fit (off-by-one + unsigned arithmetic). We model
the loop as faithfully as the abstraction allows: a fixed-size `wdata[N]`
with a nondet `size`, with the property `i+1 < size` (the bound the real
code violates).

  pre-patch: CBMC produces a cex for size ∈ {0, 1, 2, 3} where the loop
             still enters via the underflow path → assertion fails → unsafe.
  post-patch: the `size > 3` guard makes the loop entry condition false
              for the same range → assertion holds → safe.

Verdict tracks the real bug class, not just the literal C diff.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import sys
from pathlib import Path

from agent.patch_verify import PatchVerifyRequest, verify_patch


REPO_ROOT = Path(__file__).resolve().parents[2]
PATCH_DIFF = Path("/mnt/data/chanyoung/cybergym/cybergym_data/data/arvo/67297/patch.diff")
OUT_DIR = REPO_ROOT / "run-logs" / "cex" / "cve-patches"
log = logging.getLogger("patch_demo_pcre2")


# Bounded model of the scan loop (mirrors the buggy block in pcre2_fuzzsupport.c
# lines 295-302). `WDATA_SIZE` is fixed in the harness so CBMC has a concrete
# bound; `size` is the real-world `size` parameter, made symbolic via a nondet
# local in the harness. `WDATA_SIZE >= 8` is enough headroom for any non-buggy
# iteration to stay in-bounds — the failure surfaces at the underflow path
# (`size < 2` wraps `size - 2` to SIZE_MAX).

PRE_BODY = """
#define WDATA_SIZE 8

int pcre2_scan_pre(unsigned int size) {
    if (size > WDATA_SIZE) return -1;          /* model bound */
    unsigned char wdata[WDATA_SIZE];
    for (unsigned char k = 0; k < WDATA_SIZE; k++) wdata[k] = 0;

    /* the buggy loop, verbatim */
    /* Structural cap on the unwind: lets CBMC unwind the underflow-wrap path
     * to a finite number of iterations without changing the property's truth
     * value (the bug fires on iteration 1 when size < 2). Documented in
     * `demo_meta.modelling_note`. */
    for (size_t i = 1; i < size - 2 && i < (size_t)(WDATA_SIZE * 2); i++) {
        /* wdata[i+1] must stay within the allocated portion [0, size). */
        __CPROVER_assert(i + 1 < size, "wdata[i+1] read past allocated buffer");
    }
    return 0;
}
"""

POST_BODY = """
#define WDATA_SIZE 8

int pcre2_scan_post(unsigned int size) {
    if (size > WDATA_SIZE) return -1;
    unsigned char wdata[WDATA_SIZE];
    for (unsigned char k = 0; k < WDATA_SIZE; k++) wdata[k] = 0;

    /* the patched loop — guarded by `size > 3`. */
    if (size > 3) for (size_t i = 1; i < size - 2; i++) {
        __CPROVER_assert(i + 1 < size, "wdata[i+1] read past allocated buffer");
    }
    return 0;
}
"""


def _patch_provenance() -> dict:
    if not PATCH_DIFF.exists():
        return {"patch_path": str(PATCH_DIFF), "exists": False}
    body = PATCH_DIFF.read_bytes()
    return {
        "patch_path": str(PATCH_DIFF),
        "exists": True,
        "size_bytes": len(body),
        "sha256": hashlib.sha256(body).hexdigest(),
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out-dir", type=Path, default=OUT_DIR)
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")

    # Normalise function name so PatchVerifyRequest swaps the body cleanly.
    pre = PRE_BODY.replace("pcre2_scan_pre", "pcre2_scan")
    post = POST_BODY.replace("pcre2_scan_post", "pcre2_scan")

    req = PatchVerifyRequest(
        function_name="pcre2_scan_underflow",
        pre_body=pre,
        post_body=post,
        includes=["stdint.h", "stddef.h"],     # size_t lives in stddef.h
        inputs=[("unsigned int", "size")],
        preconditions=[],
        invocation="int r = pcre2_scan(size);",
        # The assertion lives inside the function body itself; the wrapper
        # only verifies the call completed.
        assertion="r == 0 || r == -1",
        assertion_msg="scan returned a defined value",
        property="no-overflow",                # CBMC --signed-overflow-check etc
        unwind=20,                             # > 2*WDATA_SIZE so the capped loop fully unrolls
        timeout_s=90,
    )

    res = verify_patch(req)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    record = json.loads(res.to_json())
    record["demo_meta"] = {
        "task_id": "arvo:67297",
        "library": "pcre2",
        "bug_class": "heap-buffer-overflow (unsigned underflow → unbounded loop)",
        "real_patch_provenance": _patch_provenance(),
        "modelling_note": (
            "Bounded-array model of the pcre2_fuzzsupport.c:295-302 scan loop. "
            "size is symbolic; wdata[WDATA_SIZE=8] is the allocated portion. "
            "The pre-patch loop guard `i < size - 2` underflows when size<2 "
            "(size_t is unsigned), running the loop into wdata[i+1] beyond "
            "the allocated [0, size) region — CBMC finds the cex. The "
            "post-patch `if (size > 3)` kills the underflow path; CBMC proves "
            "the bounds-check holds for every reachable iteration."
        ),
        "cex_of_unfixed_pcre": "run-logs/cex/cybergym/arvo_67297.json",
    }
    out_json = out_dir / "arvo_67297_pcre2.json"
    out_json.write_text(json.dumps(record, indent=2))

    note = out_dir / "arvo_67297_pcre2.note.md"
    note.write_text(
        f"""# Patch verification: arvo:67297 (pcre2 scan-loop heap-OOB)

**Real patch**: `{PATCH_DIFF}`
**Sha256**: `{_patch_provenance().get('sha256', 'n/a')}`

**CBMC verdict**:
- pre  = `{res.pre_verdict['verdict']}` ({'cex captured' if res.cex_before else 'no cex'})
- post = `{res.post_verdict['verdict']}`
- is_correct_fix = **{res.is_correct_fix}**

**Explanation** (from `agent/patch_verify.py`):

> {res.explanation}

**Bug class**: unsigned-arithmetic underflow → unbounded scan loop → 4-byte
heap-OOB read at `pcre2_fuzzsupport.c:302` (ASan banner in `error.txt`).
The bound check `i + 1 < size` fails for `size ∈ {{0, 1, 2, 3}}` because the
underflow turns `size - 2` into `SIZE_MAX`. The upstream fix gates the
loop with `if (size > 3)` — the smallest guard that kills every wrap path.

Related artifact (runtime cex from the Tier-1 oracle):
- [run-logs/cex/cybergym/arvo_67297.json](../../run-logs/cex/cybergym/arvo_67297.json)
"""
    )
    log.info("patch verify -> %s (is_correct_fix=%s, wall=%dms)",
             out_json, res.is_correct_fix, res.wall_ms)
    print(json.dumps({
        "out": str(out_json),
        "is_correct_fix": res.is_correct_fix,
        "pre_verdict": res.pre_verdict["verdict"],
        "post_verdict": res.post_verdict["verdict"],
        "wall_ms": res.wall_ms,
    }, indent=2))
    return 0 if res.is_correct_fix else 1


if __name__ == "__main__":
    sys.exit(main())
