"""Trust-layer demo: LLM proposes a patch, we verify it via BMC.

The most strategically valuable thing the verification stack does: receive a
patch from a third party (an LLM agent, a human contributor, an automated
fuzzer-fix tool) and decide whether it's a *sound* fix — independently of how
plausible it looks.

This script does the full round-trip on the arvo:67297 pcre2 underflow:

  1. Build a buggy minimal function body (mirrors the pcre2_fuzzsupport.c
     scan loop) and a bug description.
  2. Send (buggy_body + bug_description) to the LLM gateway (DeepSeek-R1-
     Distill-Llama-70B per the current `config/models.yaml` smoke profile).
  3. Parse out the LLM's proposed replacement body from the reply (strips
     `<think>` reasoning blocks; keeps the fenced C code).
  4. Run `agent.patch_verify(buggy_body, llm_proposed_body, ...)`.
  5. Report ✅ (sound fix) or ❌ (cex shows the proposal still bug-vulnerable).

Output: `run-logs/cex/cve-patches/llm_proposed_arvo_67297.json` carries the
full transcript + verify result + a `decision` field summarising the outcome.
"""
from __future__ import annotations

import argparse
import json
import logging
import re
import sys
from pathlib import Path

from agent.patch_verify import PatchVerifyRequest, verify_patch
from llm.client import LLMClient, LLMUnavailable


REPO_ROOT = Path(__file__).resolve().parents[2]
OUT_DIR = REPO_ROOT / "run-logs" / "cex" / "cve-patches"
log = logging.getLogger("llm_patch_demo")


BUG_DESCRIPTION = """\
Heap-buffer-overflow in pcre2: the function below loops over a buffer
`wdata` of size `size` (allocated by the caller). The loop bound `size - 2`
underflows when `size < 2` because `size_t` is unsigned, wrapping to
SIZE_MAX and causing the loop to read past the end of `wdata`. The reported
crash is a 4-byte heap-OOB at `wdata[i+1]`.
"""


# Minimal CBMC-friendly model of the pre-patch scan loop. Same structural cap
# as eval/cve_patch/arvo_67297_pcre2.py so the harness compiles + bounds.
BUGGY_BODY = """\
#define WDATA_SIZE 8

int pcre2_scan(unsigned int size) {
    if (size > WDATA_SIZE) return -1;
    unsigned char wdata[WDATA_SIZE];
    for (unsigned char k = 0; k < WDATA_SIZE; k++) wdata[k] = 0;

    for (size_t i = 1; i < size - 2 && i < (size_t)(WDATA_SIZE * 2); i++) {
        __CPROVER_assert(i + 1 < size, "wdata[i+1] read past allocated buffer");
    }
    return 0;
}
"""


SYSTEM_PROMPT = """\
You receive a buggy C function and a description of its bug. You propose a
*minimal* fix. Reply with ONE fenced C code block containing the FULL
replacement function body (and any required `#define`s), nothing else.

Constraints:
- Keep the function signature: `int pcre2_scan(unsigned int size)`.
- Keep the `WDATA_SIZE` define and the `__CPROVER_assert` line — those are
  the harness's verification anchors and must remain untouched.
- Do not introduce calls to undeclared functions.
- Output the function body as-is; no commentary outside the code block.
"""


_CODE_BLOCK_RE = re.compile(r"```(?:c|cpp|C)?\s*\n(.*?)\n```", re.DOTALL)
_THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL)


def _extract_proposal(reply_text: str) -> str | None:
    """Strip reasoning blocks, pull the first fenced C block."""
    cleaned = _THINK_RE.sub("", reply_text)
    m = _CODE_BLOCK_RE.search(cleaned)
    if m:
        return m.group(1).strip()
    # No fence — accept anything that looks like a function body starting with
    # `#define` or `int pcre2_scan`.
    for marker in ("#define WDATA_SIZE", "int pcre2_scan"):
        i = cleaned.find(marker)
        if i != -1:
            return cleaned[i:].strip()
    return None


def _decide(pre_verdict: str, post_verdict: str) -> tuple[str, str]:
    """Map (pre, post) into a human-readable decision."""
    if pre_verdict == "unsafe" and post_verdict == "safe":
        return ("ACCEPT", "LLM's patch closes the bug under our model.")
    if pre_verdict == "unsafe" and post_verdict == "unsafe":
        return ("REJECT_UNFIXED",
                "LLM's patch still leaves the bug reachable — cex preserved.")
    if pre_verdict == "unsafe" and post_verdict == "inconclusive":
        return ("REJECT_INCONCLUSIVE",
                "LLM's patch may have broken the harness contract or introduced "
                "unboundedness — CBMC could not decide.")
    if pre_verdict != "unsafe":
        return ("PRE_NOT_UNSAFE",
                f"Pre-patch verdict was {pre_verdict}; the bug model isn't "
                "exposed correctly — nothing to verify against.")
    return ("UNKNOWN", f"pre={pre_verdict}, post={post_verdict}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out-dir", type=Path, default=OUT_DIR)
    ap.add_argument("--role", default="synthesizer",
                    help="LLM gateway role to call")
    ap.add_argument("--max-tokens", type=int, default=2048)
    ap.add_argument("--temperature", type=float, default=0.0)
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")

    # DeepSeek-R1-Distill emits long <think> reasoning prefixes; bump the
    # client timeout to give the gateway room before failing.
    client = LLMClient(default_role=args.role, timeout_s=600.0)
    user_prompt = (
        f"# Bug description\n{BUG_DESCRIPTION}\n\n"
        "# Buggy function (verbatim)\n```c\n" + BUGGY_BODY + "```\n\n"
        "Propose the fix."
    )
    log.info("calling LLM (role=%s, max_tokens=%d) ...",
             args.role, args.max_tokens)
    try:
        rep = client.chat(SYSTEM_PROMPT, user_prompt,
                          max_tokens=args.max_tokens,
                          temperature=args.temperature)
    except LLMUnavailable as e:
        log.error("LLM gateway unavailable: %s", e)
        return 2
    log.info("LLM reply: %d tokens (prompt=%d, completion=%d) in %.2fs",
             rep.total_tokens, rep.prompt_tokens, rep.completion_tokens,
             rep.latency_s)

    proposal = _extract_proposal(rep.text)
    if proposal is None:
        log.error("could not extract a C code block from the LLM reply")
        out = {
            "decision": "PARSE_FAIL",
            "llm": {
                "role": rep.role, "model": rep.model,
                "prompt_tokens": rep.prompt_tokens,
                "completion_tokens": rep.completion_tokens,
                "latency_s": rep.latency_s,
                "raw_reply": rep.text,
            },
        }
        (OUT_DIR / "llm_proposed_arvo_67297.json").parent.mkdir(
            parents=True, exist_ok=True)
        (OUT_DIR / "llm_proposed_arvo_67297.json").write_text(
            json.dumps(out, indent=2))
        return 3

    log.info("LLM proposed %d-byte body", len(proposal))

    # Normalise function name in both halves so the harness compiles.
    pre = BUGGY_BODY
    post = proposal
    req = PatchVerifyRequest(
        function_name="pcre2_scan_llm_proposed",
        pre_body=pre,
        post_body=post,
        includes=["stdint.h", "stddef.h"],
        inputs=[("unsigned int", "size")],
        preconditions=[],
        invocation="int r = pcre2_scan(size);",
        assertion="r == 0 || r == -1",
        assertion_msg="scan returned a defined value",
        property="no-overflow",
        unwind=20,
        timeout_s=90,
    )
    res = verify_patch(req)
    decision, decision_note = _decide(res.pre_verdict["verdict"],
                                      res.post_verdict["verdict"])
    log.info("decision=%s pre=%s post=%s wall=%dms",
             decision, res.pre_verdict["verdict"],
             res.post_verdict["verdict"], res.wall_ms)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    record = json.loads(res.to_json())
    record["decision"] = decision
    record["decision_note"] = decision_note
    record["demo_meta"] = {
        "task_id": "arvo:67297",
        "library": "pcre2",
        "bug_class": "unsigned-underflow → heap-OOB",
        "model_under_test": "third-party LLM proposal",
    }
    record["llm"] = {
        "role": rep.role,
        "model": rep.model,
        "prompt_tokens": rep.prompt_tokens,
        "completion_tokens": rep.completion_tokens,
        "total_tokens": rep.total_tokens,
        "latency_s": rep.latency_s,
        "proposed_body": proposal,
        "raw_reply": rep.text,
        "system_prompt": SYSTEM_PROMPT,
        "user_prompt": user_prompt,
    }
    out_path = out_dir / "llm_proposed_arvo_67297.json"
    out_path.write_text(json.dumps(record, indent=2))

    print(json.dumps({
        "out": str(out_path),
        "decision": decision,
        "is_correct_fix": res.is_correct_fix,
        "pre_verdict": res.pre_verdict["verdict"],
        "post_verdict": res.post_verdict["verdict"],
        "llm_tokens": rep.total_tokens,
        "llm_latency_s": rep.latency_s,
        "proposal_excerpt": proposal[:300] + ("..." if len(proposal) > 300 else ""),
    }, indent=2))
    return 0 if res.is_correct_fix else 1


if __name__ == "__main__":
    sys.exit(main())
