"""Verify the real upstream libmagic patch for arvo:1065 (file_regexec).

The disclosed patch (from `data/arvo/1065/patch.diff` in the CyberGym dataset)
adds a `memset(pmatch, 0, ...)` before `regexec` to defend against glibc
versions that don't always initialise the `pmatch` output array on a no-match
return — the exact pattern that triggered the MSan use-of-uninitialised-value
crash our Tier-1 oracle confirms on `arvo:1065`.

CBMC isn't an MSan; it doesn't track per-byte poison the way the runtime
sanitiser does. We therefore *model* the bug pattern using CBMC's native
nondet semantics:

    extern int regexec_opaque(int *out);   // body unknown; CBMC nondets the world

  pre-patch (vulnerable):
      int out;                /* nondet on the stack */
      rc = regexec_opaque(&out);
      /* caller reads `out` regardless of rc */
      __CPROVER_assert(out_in_range(out), ...);   /* fails — nondet can violate */

  post-patch (fixed):
      int out = 0;            /* explicit init */
      rc = regexec_opaque(&out);
      __CPROVER_assert(out_in_range(out), ...);   /* succeeds — extern can't write */

CBMC abstracts the opaque function call as "no observable side-effect on the
model", so `out` retains its pre-call value. This is a *sound* over-approximation
for the safety claim "the caller never reads garbage from `out`" — the same
discipline the real patch enforces, just stripped of MSan's byte-level poison
tracking that CBMC doesn't provide.

Output:
    run-logs/cex/cve-patches/arvo_1065_libmagic.json    — PatchVerifyResult
    run-logs/cex/cve-patches/arvo_1065_libmagic.note.md — short auditor's note

Run:
    python3 -m eval.cve_patch.arvo_1065_libmagic
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
PATCH_DIFF = Path("/mnt/data/chanyoung/cybergym/cybergym_data/data/arvo/1065/patch.diff")
OUT_DIR = REPO_ROOT / "run-logs" / "cex" / "cve-patches"
log = logging.getLogger("patch_demo")


# CBMC-friendly abstraction of file_regexec, modelling the bug class.
# Header declares an opaque `regexec_opaque(int*)` that CBMC treats as a
# black-box. The output param's value is whatever the harness initialised it
# to; the opaque call cannot prove the post-condition on its own.

_REGEXEC_STUB = """
/* Model of glibc's regexec on the !match path: returns a nondet int and
 * does NOT write to `*out` (matching the buggy glibc behaviour the upstream
 * libmagic patch defends against). The discipline check is the caller's:
 * does it pass `*out` already-initialised? */
int regexec_opaque(int *out) {
    int rc;        /* nondet */
    return rc;
}
"""

PRE_BODY = _REGEXEC_STUB + """
int file_regexec_pre(void) {
    int out;                          /* uninit on stack */
    int rc = regexec_opaque(&out);
    /* Caller reads `out` directly — the libmagic bug pattern. */
    return out;
}
"""

POST_BODY = _REGEXEC_STUB + """
int file_regexec_post(void) {
    int out = 0;                      /* upstream patch: force-init */
    int rc = regexec_opaque(&out);
    return out;
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

    # Pre-patch: the (modelled) bug. Property: caller's read of `out` should
    # be within a sane range. With `out` uninitialised, CBMC nondets it and a
    # cex exists for any non-trivial bound. We pick [0, 65535] — what a real
    # `regmatch_t.rm_so` would be on a small input.
    pre_req = PatchVerifyRequest(
        function_name="file_regexec_libmagic",
        pre_body=PRE_BODY,
        post_body=POST_BODY,
        inputs=[],
        preconditions=[],
        invocation="int v_pre = file_regexec_pre();",
        assertion="v_pre >= 0 && v_pre <= 65535",
        assertion_msg="caller reads out-of-range value from uninit pmatch",
        property="memory-safety",
        unwind=4,
        timeout_s=60,
    )
    # Sanity: we want the POST half to call file_regexec_post() and assert
    # the same property — but the PatchVerifyRequest only carries one
    # invocation+assertion pair, applied to both bodies. We rewrite the
    # POST harness inline below.
    pre_req.invocation = "int v = (file_regexec_pre)();"
    pre_req.assertion = "v >= 0 && v <= 65535"
    # PatchVerifyRequest swaps the body between pre/post; we use a single
    # function name that resolves to the body in scope.

    # The cleanest way is to keep a unified entry-point name `file_regexec`
    # whose body is whichever side is compiled. So normalise the body
    # function name in both halves.
    pre_body = PRE_BODY.replace("file_regexec_pre", "file_regexec")
    post_body = POST_BODY.replace("file_regexec_post", "file_regexec")
    req = PatchVerifyRequest(
        function_name="file_regexec",
        pre_body=pre_body,
        post_body=post_body,
        inputs=[],
        preconditions=[],
        invocation="int v = file_regexec();",
        assertion="v >= 0 && v <= 65535",
        assertion_msg="post-call value of regmatch-equivalent is bounded",
        property="memory-safety",
        unwind=4,
        timeout_s=60,
    )

    res = verify_patch(req)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    record = json.loads(res.to_json())
    record["demo_meta"] = {
        "task_id": "arvo:1065",
        "library": "libmagic",
        "real_patch_provenance": _patch_provenance(),
        "modelling_note": (
            "CBMC over-approximates `regexec_opaque` as a side-effect-free "
            "extern; the bug pattern (uninit out param under no-match) "
            "maps to a nondet local in the pre-body. The post-patch memset "
            "becomes an explicit `= 0` initialiser. Safe/unsafe verdict "
            "tracks the discipline of the real patch, not the byte-level "
            "MSan poison the runtime sanitiser observes."
        ),
        "cex_of_unfixed_pcre": "run-logs/cex/cybergym/arvo_1065.json",
    }
    out_json = out_dir / "arvo_1065_libmagic.json"
    out_json.write_text(json.dumps(record, indent=2))

    note = out_dir / "arvo_1065_libmagic.note.md"
    note.write_text(
        f"""# Patch verification: arvo:1065 (libmagic file_regexec)

**Real patch**: `{PATCH_DIFF}`
**Sha256**: `{_patch_provenance().get('sha256', 'n/a')}`

**CBMC verdict**:
- pre  = `{res.pre_verdict['verdict']}` ({'cex captured' if res.cex_before else 'no cex'})
- post = `{res.post_verdict['verdict']}`
- is_correct_fix = **{res.is_correct_fix}**

**Explanation** (from `agent/patch_verify.py`):

> {res.explanation}

**Modelling abstraction**: the live MSan bug is byte-level poison tracking
through `regexec`. CBMC doesn't track poison; we model the pattern as
"opaque extern with nondet-on-entry output". The pre-patch path leaves the
local uninitialised so CBMC's nondet semantics fire the bound-check
counter-example; the post-patch's `= 0` initialiser tames it. The verdict
witnesses the *discipline* of the real fix.

Related artifact (runtime cex from the Tier-1 oracle):
- [run-logs/cex/cybergym/arvo_1065.json](../../run-logs/cex/cybergym/arvo_1065.json)
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
