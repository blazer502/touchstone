"""Smoke for patch_verify on a known off-by-one fix.

Pre-patch: `buf[i]` with no bounds-check (CBMC --pointer-check should yell).
Post-patch: same but guarded by `if (i >= 16) return -1;`.

Run: `python3 -m agent.test_patch_verify`
"""
from __future__ import annotations

import sys

from agent.patch_verify import PatchVerifyRequest, verify_patch


PRE = """
int foo(int i) {
    int buf[16];
    return buf[i];
}
"""

POST = """
int foo(int i) {
    int buf[16];
    if (i < 0 || i >= 16) return -1;
    return buf[i];
}
"""


def main() -> int:
    req = PatchVerifyRequest(
        function_name="foo",
        pre_body=PRE,
        post_body=POST,
        inputs=[("int", "i")],
        preconditions=[],
        invocation="foo(i);",
        assertion="1",                   # no extra property — rely on --pointer-check
        assertion_msg="oob via buf[i]",
        property="no-oob",               # picks --bounds-check + --pointer-check flags
        unwind=4,
    )
    res = verify_patch(req)
    print(res.to_json())
    if not res.is_correct_fix:
        print("FAIL:", res.explanation, file=sys.stderr)
        return 1
    print("OK — patch verified.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
