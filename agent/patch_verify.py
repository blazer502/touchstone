"""Patch verification API — sound trust layer over LLM-proposed patches.

Given a function's pre- and post-patch source plus the property the patch is
supposed to close, run Tier-3 BMC on both and answer: did the patch turn an
unsafe verdict into a safe verdict? Both halves must succeed for the patch
to be accepted.

This is what positions us complementarily to OpenHands / Cybench / SWE-agent
style LLM agents — they propose, we verify. Strategic doc §2 (Output C
"Verified patch") + §4 (P3).
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import List, Optional

from oracle.tier3_bmc.assertions import Hypothesis, synthesize, write_harness
from oracle.tier3_bmc.cbmc_driver import run_cbmc_oracle
from oracle.tier3_bmc.verdict import Tier3Verdict
from schemas.witness import Witness, from_tier3


log = logging.getLogger("patch_verify")


# --- request / result -------------------------------------------------------

@dataclass
class PatchVerifyRequest:
    """The minimal description of a patch we need to verify.

    `function_name` is a label for logging only — CBMC sees `main()` as its
    entry. `pre_body` and `post_body` are full C source bodies (functions,
    types, includes — anything the harness can compile against). The harness
    is synthesized by `oracle.tier3_bmc.assertions.synthesize`; the caller
    provides the property + symbolic inputs.
    """
    function_name: str
    pre_body: str
    post_body: str
    inputs: List[tuple[str, str]] = field(default_factory=list)
    preconditions: List[str] = field(default_factory=list)
    invocation: str = ""
    assertion: str = ""
    assertion_msg: str = "patch property"
    includes: List[str] = field(default_factory=lambda: ["stdint.h"])
    property: str = "memory-safety"    # CBMC --pointer-check etc; default OK
    unwind: int = 16
    timeout_s: int = 120


@dataclass
class PatchVerifyResult:
    is_correct_fix: bool
    pre_verdict: dict
    post_verdict: dict
    cex_before: Optional[dict]
    cex_after: Optional[dict]
    wall_ms: int
    explanation: str
    soundness_anchor_ids: List[str] = field(default_factory=list)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(asdict(self), indent=indent)


# --- core -------------------------------------------------------------------

def _harness_for(req: PatchVerifyRequest, body: str) -> Hypothesis:
    return Hypothesis(
        name=f"{req.function_name}",
        includes=req.includes,
        target_source=body,
        inputs=list(req.inputs),
        preconditions=list(req.preconditions),
        invocation=req.invocation,
        assertion=req.assertion,
        assertion_msg=req.assertion_msg,
    )


def _run_side(req: PatchVerifyRequest, body: str, side: str,
              work_dir: Path) -> Tier3Verdict:
    h = _harness_for(req, body)
    src = work_dir / f"{side}.c"
    write_harness(h, src)
    return run_cbmc_oracle(
        source=src, function="main", property=req.property,
        unwind=req.unwind, timeout_s=req.timeout_s,
        out_dir=work_dir / f"{side}-out",
        unit=f"{req.function_name}::{side}",
    )


def verify_patch(req: PatchVerifyRequest, *, work_dir: Optional[Path] = None) -> PatchVerifyResult:
    """Run BMC on the pre/post-patch bodies and decide correctness.

    Correct-fix definition: `pre == unsafe AND post == safe`. Any other pair
    is rejected (the patch either didn't fix the bug, or introduced new
    over-/under-approximation that CBMC can't decide on).
    """
    work_dir = work_dir or Path(tempfile.mkdtemp(prefix="patch-verify-"))
    work_dir.mkdir(parents=True, exist_ok=True)

    t0 = time.monotonic()
    pre = _run_side(req, req.pre_body, "pre", work_dir)
    post = _run_side(req, req.post_body, "post", work_dir)
    wall_ms = int((time.monotonic() - t0) * 1000)

    cex_before = from_tier3(pre).to_disclosure_blob() if pre.verdict == "unsafe" else None
    cex_after = from_tier3(post).to_disclosure_blob() if post.verdict == "unsafe" else None

    is_correct = (pre.verdict == "unsafe" and post.verdict == "safe")
    if pre.verdict != "unsafe":
        why = (f"PRE-side did not surface the bug "
               f"(verdict={pre.verdict}); patch unverifiable.")
    elif post.verdict != "safe":
        why = (f"POST-side still not proven safe "
               f"(verdict={post.verdict}); patch incorrect or under-specified.")
    else:
        why = "pre=unsafe → post=safe; patch closes the bug under the supplied contract."

    return PatchVerifyResult(
        is_correct_fix=is_correct,
        pre_verdict=pre.to_dict(),
        post_verdict=post.to_dict(),
        cex_before=cex_before,
        cex_after=cex_after,
        wall_ms=wall_ms,
        explanation=why,
        soundness_anchor_ids=[
            "oracle-tier-3-bmc/tier-3-cbmc-verdict-semantics",
            "oracle-tier-3-bmc/tier-3-harness-nondet-idiom",
        ],
    )


# --- CLI --------------------------------------------------------------------

def _cmd_verify(args) -> int:
    req_dict = json.loads(Path(args.request).read_text())
    inputs = [tuple(x) for x in req_dict.pop("inputs", [])]
    req = PatchVerifyRequest(inputs=inputs, **req_dict)
    res = verify_patch(req)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(res.to_json())
    log.info("patch verify: %s (pre=%s post=%s) wall=%dms -> %s",
             "OK" if res.is_correct_fix else "REJECT",
             res.pre_verdict["verdict"], res.post_verdict["verdict"],
             res.wall_ms, args.out)
    print(res.to_json())
    return 0 if res.is_correct_fix else 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sp = sub.add_parser("verify",
                        help="run patch verification from a JSON request file")
    sp.add_argument("request", help="JSON with PatchVerifyRequest fields")
    sp.add_argument("--out", default="run-logs/patch-verify-result.json")
    sp.set_defaults(func=_cmd_verify)
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
