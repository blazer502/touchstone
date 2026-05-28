"""Phase 5.4 — Vuln-class taxonomy for spec-mining (PLAN §3b.4).

Classifies each mined contract / outlier by the *shape* of the missing guard
into one of the PLAN §3b.4 vuln classes:

  locking | auth_capability | bounds_length | null_init | refcount |
  state_machine | taint_sanitization | resource_cleanup | other

A class label is the breadth-of-vuln-class deliverable — it lets a confirmed
outlier be reported as e.g. "missing rcu_read_lock_held before
__nf_conntrack_helper_find" (class=locking) or "missing IS_ERR check before
nft_ctx_init" (class=null_init), instead of an undifferentiated "spec
violation". The class is purely a *label*; final verdict authority still
belongs to the sound checker (Phase 5.3) per PLAN §8.

Classification rules:
  - 5.2's canonical `kind_class` carries the direct mappings:
        lock → locking, cap → auth_capability, null → null_init.
  - For kind-agnostic kinds (early/neg/if_true/if_false/for/while/switch), the
    predicate text itself is regex-classified — ordered most-specific first
    (null_init before bounds_length because `IS_ERR(table)` should not be
    misclassified by the trailing identifier `table`).

This module exposes `classify_contract(kind_class, predicate) -> str` so 5.5
(LLM refinement, classifies the refined contract) and 5.6 (closed-loop metrics)
can reuse the same labels.

No LLM (Phase 5.4 rule).
"""
from __future__ import annotations

import re


# Class labels (match PLAN §3b.4 names).
LOCKING = "locking"
AUTH_CAPABILITY = "auth_capability"
BOUNDS_LENGTH = "bounds_length"
NULL_INIT = "null_init"
REFCOUNT = "refcount"
STATE_MACHINE = "state_machine"
TAINT_SANITIZATION = "taint_sanitization"
RESOURCE_CLEANUP = "resource_cleanup"
OTHER = "other"

ALL_CLASSES: tuple[str, ...] = (
    LOCKING, AUTH_CAPABILITY, BOUNDS_LENGTH, NULL_INIT, REFCOUNT,
    STATE_MACHINE, TAINT_SANITIZATION, RESOURCE_CLEANUP, OTHER,
)

# Human-readable display names (used by the report formatter).
CLASS_DISPLAY: dict[str, str] = {
    LOCKING:            "Locking / RCU",
    AUTH_CAPABILITY:    "Auth / Capability",
    BOUNDS_LENGTH:      "Bounds / Length",
    NULL_INIT:          "Null / Init / Error check",
    REFCOUNT:           "Refcount",
    STATE_MACHINE:      "State machine",
    TAINT_SANITIZATION: "Taint sanitization",
    RESOURCE_CLEANUP:   "Resource cleanup",
    OTHER:              "Other (uncategorised)",
}


# --------------------------------------------------------------------------- #
# Predicate-content classifiers
# Ordered most-specific first — early matches win.
# --------------------------------------------------------------------------- #

_NULL_INIT_RES: list[re.Pattern] = [
    re.compile(r"\bIS_ERR(?:_OR_NULL)?\s*\("),
    re.compile(r"\bPTR_ERR_OR_ZERO\s*\("),
    re.compile(r"\bIS_ERR_VALUE\s*\("),
    # No leading `\b` — `=` is a non-word character, so `\b==` only matches
    # when the prior char is a word char (e.g. `x==NULL`). Real predicates
    # almost always have spaces (`x == NULL`), so anchor on `==`/`!=` directly.
    re.compile(r"!=\s*NULL\b"),
    re.compile(r"==\s*NULL\b"),
    # Bare `!x` form  (5.2 emits `!(!arg)` for the early-return mirror).
    re.compile(r"^\s*!\s*\(?\s*!\s*[A-Za-z_]\w*\s*\)?\s*$"),
    re.compile(r"^\s*!\s*[A-Za-z_]\w*\s*$"),
]

_CAPABILITY_RES: list[re.Pattern] = [
    re.compile(
        r"\b(?:capable|ns_capable|ns_capable_noaudit|ns_capable_setid|"
        r"file_ns_capable|capable_wrt_inode_uidgid|perfmon_capable|"
        r"bpf_capable|checkpoint_restore_ns_capable)\s*\("
    ),
]

_LOCKING_RES: list[re.Pattern] = [
    re.compile(
        r"\b(?:lockdep_assert_held(?:_once|_write|_read)?|"
        r"lockdep_is_held|rcu_read_lock_held|rcu_read_lock_bh_held|"
        r"rcu_read_lock_sched_held|spin_is_locked|mutex_is_locked|"
        r"assert_spin_locked|rcu_dereference_protected)\b"
    ),
    re.compile(r"_lock_held\b"),
]

_REFCOUNT_RES: list[re.Pattern] = [
    re.compile(r"\brefcount_(?:read|inc|dec|add|sub|set|dec_and_test)\s*\("),
    re.compile(r"\batomic_(?:read|inc|dec|add|sub|dec_and_test)\s*\("),
    re.compile(r"\bkref_(?:read|get|put|init)\s*\("),
    re.compile(r"->\s*(?:refcnt|refcount|users|usecnt|kref)\b"),
    re.compile(r"\b(?:refcnt|refcount|users|usecnt)\s*[<>=!]"),
    # Module ref-counting (try_module_get / module_get / module_put). The kernel
    # treats these as refcount operations on `struct module`; an outlier that
    # skips the matched put is a real refcount-leak / use-after-free shape.
    re.compile(r"\b(?:try_module_get|module_get|module_put)\s*\("),
]

_STATE_MACHINE_RES: list[re.Pattern] = [
    re.compile(r"->\s*(?:state|status|flags|stage|phase|step|mode)\b"),
    re.compile(r"\bstate\s*[<>=!]=?\s*[A-Z_]"),
    re.compile(r"->\s*(?:msg_type|cmd|opcode|nlh|nlmsg_type)\b"),
    re.compile(r"\b(?:NFT_|NFNL_|GENL_|NL_|NLA_|IP_VS_|IPSET_)"),
]

_TAINT_SANITIZATION_RES: list[re.Pattern] = [
    re.compile(
        r"\b(?:strnlen|strncpy|strlcpy|strscpy|copy_from_user|copy_to_user|"
        r"memcpy_from_iter|memcpy_to_iter|nla_strlcpy|nla_strscpy|"
        r"snprintf|scnprintf|kstrtouint|kstrtoul|kstrdup)\s*\("
    ),
    re.compile(r"\b(?:escape|quote|sanitize|html_encode|url_encode|"
               r"shell_quote)\s*\("),
]

_RESOURCE_CLEANUP_RES: list[re.Pattern] = [
    re.compile(r"\b(?:kfree|kvfree|vfree|free_)\b"),
    re.compile(r"\b(?:put_|release_|close_|destroy_|cleanup_)\w*\s*\("),
    re.compile(r"\b(?:fput|iput|dput|sock_put|skb_put)\s*\("),
]

_BOUNDS_LENGTH_RES: list[re.Pattern] = [
    # Identifier ending in a "length-ish" suffix.
    re.compile(
        r"\b[A-Za-z_]\w*(?:len|size|count|cnt|nr|num|cap|limit|max|min|"
        r"_n\b|width|height)"
    ),
    re.compile(r"\bARRAY_SIZE\s*\("),
    re.compile(r"\boff(?:set)?\b"),
    # Comparison with a small integer literal.
    re.compile(r"[<>]=?\s*\d+\b"),
    re.compile(r"\b\d+\s*[<>]=?"),
]


def _predicate_class(predicate: str) -> str:
    """Classify a predicate by its content alone (kind-class agnostic)."""
    for r in _NULL_INIT_RES:
        if r.search(predicate):
            return NULL_INIT
    for r in _CAPABILITY_RES:
        if r.search(predicate):
            return AUTH_CAPABILITY
    for r in _LOCKING_RES:
        if r.search(predicate):
            return LOCKING
    for r in _REFCOUNT_RES:
        if r.search(predicate):
            return REFCOUNT
    for r in _STATE_MACHINE_RES:
        if r.search(predicate):
            return STATE_MACHINE
    for r in _TAINT_SANITIZATION_RES:
        if r.search(predicate):
            return TAINT_SANITIZATION
    for r in _RESOURCE_CLEANUP_RES:
        if r.search(predicate):
            return RESOURCE_CLEANUP
    for r in _BOUNDS_LENGTH_RES:
        if r.search(predicate):
            return BOUNDS_LENGTH
    return OTHER


def classify_contract(kind_class: str, predicate: str) -> str:
    """Return the PLAN §3b.4 vuln-class label for a (kind_class, predicate) pair."""
    # Direct mappings from 5.2's canonical kind_class.
    if kind_class == "lock":
        return LOCKING
    if kind_class == "cap":
        return AUTH_CAPABILITY
    if kind_class == "null":
        return NULL_INIT
    # Predicate-content classification for the rest.
    return _predicate_class(predicate)


# --------------------------------------------------------------------------- #
# Per-class lead-line templates
# --------------------------------------------------------------------------- #

def lead_one_liner(
    cls: str,
    callee: str,
    caller: str,
    file_path: str,
    line: int,
    missing_contract: str,
    support_count: int,
    callsite_count: int,
) -> str:
    """Return a one-line human-readable lead for one outlier in class `cls`."""
    support = f"{support_count}/{callsite_count}"
    loc = f"{file_path}:{line}"
    if cls == LOCKING:
        return (
            f"Missing `{missing_contract}` acquisition before `{callee}` at "
            f"{loc} (caller `{caller}`); convention is {support} callsites."
        )
    if cls == AUTH_CAPABILITY:
        return (
            f"Missing capability check `{missing_contract}` before `{callee}` "
            f"at {loc} (caller `{caller}`); {support} callsites perform this check."
        )
    if cls == BOUNDS_LENGTH:
        return (
            f"Missing bounds/length guard `{missing_contract}` before `{callee}` "
            f"at {loc} (caller `{caller}`); {support} callsites bound the input."
        )
    if cls == NULL_INIT:
        return (
            f"Missing null/error check `{missing_contract}` before `{callee}` "
            f"at {loc} (caller `{caller}`); {support} callsites validate the pointer."
        )
    if cls == REFCOUNT:
        return (
            f"Missing refcount guard `{missing_contract}` before `{callee}` at "
            f"{loc} (caller `{caller}`); {support} callsites check the refcount."
        )
    if cls == STATE_MACHINE:
        return (
            f"Missing state-machine guard `{missing_contract}` before `{callee}` "
            f"at {loc} (caller `{caller}`); {support} callsites validate the state."
        )
    if cls == TAINT_SANITIZATION:
        return (
            f"Missing taint-sanitization step `{missing_contract}` before `{callee}` "
            f"at {loc} (caller `{caller}`); {support} callsites sanitize first."
        )
    if cls == RESOURCE_CLEANUP:
        return (
            f"Missing resource-cleanup step `{missing_contract}` near `{callee}` "
            f"at {loc} (caller `{caller}`); {support} callsites pair the cleanup."
        )
    return (
        f"Outlier: `{callee}` missing `{missing_contract}` at {loc} "
        f"(caller `{caller}`); convention is {support} callsites."
    )
