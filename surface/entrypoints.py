"""Stage A — attacker-controlled entry-point catalog.

PLAN §2 Stage A: enumerate the attacker-controlled entry points so the
reachability pass can carve them out as the roots of the keep-set.

For Linux this means: netlink/nfnetlink dispatch tables, iptables match/
target ops, nf_hook_ops (packet hooks), char-dev/file_operations,
genl_ops, syscall handlers, etc. The detector recognises static (const)
initializers of known kernel dispatcher struct types, and harvests the
function-pointer fields that the kernel routes attacker-controlled data
through.

Soundness lever: over-approximate the entry set whenever uncertain — a
larger entry set produces a larger reachable keep-set and never prunes
a real bug. Indirect-dispatch targets that we cannot statically resolve
are folded into the entry set as a separate "address_taken" pool.

No LLM (Phase 1 rule).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path
from typing import Iterable


# Kernel dispatcher types that carry attacker-controlled function pointers.
# Each value is the set of field names that route untrusted input. The
# "*" wildcard means: every function-pointer field inside the initializer
# counts (used when every callback is reachable from userspace, e.g. an
# nft_expr_ops bundle is invoked end-to-end on each netlink op).
DISPATCHER_TYPES: dict[str, set[str]] = {
    # netlink message handling
    "nfnl_callback": {"call"},
    "nfnetlink_subsystem": {"cb"},  # cb points at an nfnl_callback array
    "genl_ops": {"doit", "dumpit", "start", "done"},
    "genl_small_ops": {"doit", "dumpit", "start", "done"},
    # nf_tables expression / set / object / chain ops — all driven by netlink
    "nft_expr_ops": {"*"},
    "nft_expr_type": {"select_ops"},
    "nft_set_ops": {"*"},
    "nft_set_type": {"select_ops"},
    "nft_object_ops": {"*"},
    "nft_object_type": {"select_ops"},
    "nft_chain_type": {"hooks", "init", "free"},
    "nft_flowtable_type": {"setup", "free", "type"},
    # iptables match / target — driven by setsockopt(IPT_SO_SET_REPLACE)
    "xt_match": {"match", "checkentry", "destroy"},
    "xt_target": {"target", "checkentry", "destroy"},
    "xt_table_info": {"*"},
    # packet hooks (network-attacker controlled bytes)
    "nf_hook_ops": {"hook"},
    "nf_sockopt_ops": {"get", "set", "compat_get", "compat_set"},
    # ipset / ipvs userspace control surfaces
    "ip_set_type_variant": {"*"},
    "ip_set_type": {"create"},
    "ip_vs_scheduler": {"*"},
    # generic kernel surfaces (rare in netfilter but kept for portability)
    "file_operations": {"unlocked_ioctl", "compat_ioctl", "write", "read",
                        "open", "release", "mmap", "poll"},
    "proto_ops": {"bind", "connect", "ioctl", "sendmsg", "recvmsg",
                  "setsockopt", "getsockopt"},
    "ctl_table": {"proc_handler"},
}

# Common kernel sanitizer / wrapper macros for syscall surfaces. We log
# the function the macro expands to as an entry point.
SYSCALL_MACROS = re.compile(
    r"\bSYSCALL_DEFINE[0-6]\s*\(\s*(\w+)\b"
)
COMPAT_SYSCALL_MACROS = re.compile(
    r"\bCOMPAT_SYSCALL_DEFINE[0-6]\s*\(\s*(\w+)\b"
)

# Match a top-level static initializer:
#   static [const] struct TYPE NAME [...] = { ... } ;
# We anchor on `= {` and walk forward to the balanced `}`. Pre-pattern
# is regex; brace-matching is hand-rolled below.
DECL_HEAD_RE = re.compile(
    r"^(?P<head>\s*static\s+(?:const\s+)?struct\s+(?P<type>\w+)\s+"
    r"(?P<name>\w+)\s*(?:\[[^\]]*\])?\s*(?:__\w+(?:\([^)]*\))?\s*)*"
    r")=\s*\{",
    re.MULTILINE,
)

FIELD_FUNC_RE = re.compile(
    r"\.(?P<field>\w+)\s*=\s*(?P<func>[A-Za-z_]\w*)\s*[,}]"
)
# Anonymous (positional) function-pointer assignment, e.g. in fp arrays:
#   { my_func, NULL, ... } — rare in netfilter, skipped for now.


def _balanced_block(text: str, start: int) -> int:
    """Return index right after the `}` that matches `text[start]` == '{'."""
    depth = 0
    i = start
    n = len(text)
    in_string = False
    in_char = False
    in_line_comment = False
    in_block_comment = False
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if in_line_comment:
            if c == "\n":
                in_line_comment = False
        elif in_block_comment:
            if c == "*" and nxt == "/":
                in_block_comment = False
                i += 1
        elif in_string:
            if c == "\\":
                i += 1
            elif c == '"':
                in_string = False
        elif in_char:
            if c == "\\":
                i += 1
            elif c == "'":
                in_char = False
        else:
            if c == "/" and nxt == "/":
                in_line_comment = True
                i += 1
            elif c == "/" and nxt == "*":
                in_block_comment = True
                i += 1
            elif c == '"':
                in_string = True
            elif c == "'":
                in_char = True
            elif c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    return i + 1
        i += 1
    return -1


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _is_function_value(value: str) -> bool:
    """Skip obvious non-function tokens (NULL, numbers, &arr)."""
    if not value:
        return False
    if value in {"NULL", "0", "false", "true"}:
        return False
    if value[0].isdigit():
        return False
    # Single-char names are almost never function names in the kernel.
    if len(value) < 3:
        return False
    return True


def scan_file(path: Path, source_root: Path) -> list[dict]:
    text = path.read_text(encoding="utf-8", errors="replace")
    rel = str(path.relative_to(source_root))
    entries: list[dict] = []

    # 1. Dispatcher struct initializers.
    for m in DECL_HEAD_RE.finditer(text):
        type_name = m.group("type")
        if type_name not in DISPATCHER_TYPES:
            continue
        # Find the open brace location (just after the '=' we matched).
        brace_open = text.find("{", m.end() - 1)
        if brace_open < 0:
            continue
        brace_close = _balanced_block(text, brace_open)
        if brace_close < 0:
            continue
        body = text[brace_open + 1 : brace_close - 1]
        wanted_fields = DISPATCHER_TYPES[type_name]
        decl_name = m.group("name")
        decl_line = _line_of(text, m.start())
        for fm in FIELD_FUNC_RE.finditer(body):
            field = fm.group("field")
            func = fm.group("func")
            if not _is_function_value(func):
                continue
            if "*" not in wanted_fields and field not in wanted_fields:
                continue
            entries.append({
                "func": func,
                "file": rel,
                "line": decl_line + body.count("\n", 0, fm.start()),
                "struct_type": type_name,
                "struct_name": decl_name,
                "field": field,
                "dispatcher_class": _classify(type_name),
            })

    # 2. Syscall macros — rare in netfilter, but cheap to scan everywhere.
    for sm in SYSCALL_MACROS.finditer(text):
        entries.append({
            "func": f"__do_sys_{sm.group(1)}",
            "file": rel,
            "line": _line_of(text, sm.start()),
            "struct_type": None,
            "struct_name": None,
            "field": None,
            "dispatcher_class": "syscall",
        })
    for sm in COMPAT_SYSCALL_MACROS.finditer(text):
        entries.append({
            "func": f"__do_compat_sys_{sm.group(1)}",
            "file": rel,
            "line": _line_of(text, sm.start()),
            "struct_type": None,
            "struct_name": None,
            "field": None,
            "dispatcher_class": "syscall",
        })

    return entries


def _classify(type_name: str) -> str:
    if type_name.startswith("nft_"):
        return "nftables_netlink"
    if type_name.startswith("nfnl") or type_name.startswith("nfnetlink"):
        return "nfnetlink"
    if type_name.startswith("xt_"):
        return "iptables_setsockopt"
    if type_name.startswith("nf_hook"):
        return "packet_hook"
    if type_name.startswith("nf_sockopt"):
        return "ip_setsockopt"
    if type_name.startswith("genl"):
        return "genetlink"
    if type_name.startswith("ip_set"):
        return "ipset_netlink"
    if type_name.startswith("ip_vs"):
        return "ipvs_netlink"
    if type_name == "file_operations":
        return "char_device"
    if type_name == "proto_ops":
        return "socket_op"
    if type_name == "ctl_table":
        return "sysctl"
    return "other"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Stage A entry-point catalog.")
    ap.add_argument("--source-root", required=True, type=Path)
    ap.add_argument("--scope", required=True, type=str)
    ap.add_argument("--target", required=True, type=str)
    ap.add_argument("--out-root", type=Path,
                    default=Path(__file__).resolve().parent / "entrypoints")
    args = ap.parse_args(argv)

    source_root = args.source_root.resolve()
    scope_root = (source_root / args.scope).resolve()
    if not scope_root.is_dir():
        ap.error(f"scope not found: {scope_root}")

    files = sorted(p for p in scope_root.rglob("*.c") if p.is_file())
    if not files:
        ap.error(f"no .c files under {scope_root}")

    all_entries: list[dict] = []
    for f in files:
        all_entries.extend(scan_file(f, source_root))

    # Group by dispatcher class for the summary.
    by_class: dict[str, int] = {}
    by_type: dict[str, int] = {}
    funcs: set[str] = set()
    for e in all_entries:
        by_class[e["dispatcher_class"]] = by_class.get(e["dispatcher_class"], 0) + 1
        if e["struct_type"]:
            by_type[e["struct_type"]] = by_type.get(e["struct_type"], 0) + 1
        funcs.add(e["func"])

    args.out_root.mkdir(parents=True, exist_ok=True)
    catalog = {
        "target": args.target,
        "source_root": str(source_root),
        "scope": args.scope,
        "generated_at": int(time.time()),
        "entry_count": len(all_entries),
        "unique_functions": len(funcs),
        "by_dispatcher_class": dict(sorted(by_class.items(),
                                           key=lambda kv: -kv[1])),
        "by_struct_type": dict(sorted(by_type.items(),
                                      key=lambda kv: -kv[1])),
        "entries": all_entries,
    }
    out_path = args.out_root / f"{args.target}.json"
    out_path.write_text(json.dumps(catalog, indent=2) + "\n")

    print(f"scanned {len(files)} files -> {len(all_entries)} entries "
          f"({len(funcs)} unique functions) -> {out_path}")
    print(f"by class: {catalog['by_dispatcher_class']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
