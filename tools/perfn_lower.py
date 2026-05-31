"""Per-function lowering: make one extracted C function compile standalone.

The wall that blocks per-function CBMC/KLEE (Track 2 of the per-function PA
plan): a sliced function body references structs / typedefs / macros that live
in headers not in the slice, so it won't compile in isolation. This module
harvests the *type closure* a function needs from the source tree and emits a
small, self-contained C harness:

    <harvested typedefs + struct/union/enum bodies>
    <#defines for unresolved ALL_CAPS macro constants>
    <the function body verbatim>
    int main(void){ <nondet args> <assumes> <call> <assert> }

Undefined *callees* are intentionally left undefined — CBMC and KLEE both treat
a function with no body as returning nondet, which is the sound over-approx we
want (the verdict authority stays the engine, PLAN §8).

This is deliberately heuristic (regex, not a full C parser). It will fail to
lower some functions; `lower_function` reports that honestly via `reason`
instead of emitting broken C. The point is to measure how far a cheap lowering
gets, not to be a clang front-end.
"""
from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from surface.specmine.cbmc_oracle import extract_function_body  # noqa: E402

_IDENT = re.compile(r"\b([A-Za-z_]\w*)\b")
# C keywords / builtins we never treat as a harvestable type or a macro const.
_KEYWORDS = {
    "if", "else", "for", "while", "do", "switch", "case", "default", "break",
    "continue", "return", "goto", "sizeof", "typedef", "struct", "union",
    "enum", "static", "inline", "const", "volatile", "extern", "register",
    "void", "char", "short", "int", "long", "float", "double", "signed",
    "unsigned", "_Bool", "bool", "true", "false", "NULL", "restrict",
}
_PRIM_TYPES = {
    "u8", "u16", "u32", "u64", "s8", "s16", "s32", "s64", "size_t", "ssize_t",
    "uint8_t", "uint16_t", "uint32_t", "uint64_t", "int8_t", "int16_t",
    "int32_t", "int64_t", "uintptr_t", "intptr_t", "off_t", "loff_t", "gfp_t",
    "__u8", "__u16", "__u32", "__u64", "__s8", "__s16", "__s32", "__s64",
    "__le16", "__le32", "__le64", "__be16", "__be32", "__be64",
}


@dataclass
class LowerResult:
    ok: bool
    reason: str = ""
    sig: str = ""                       # function signature line
    body: str = ""                      # verbatim function body
    type_decls: str = ""                # harvested typedef/struct/enum decls
    macro_decls: str = ""               # #define for unresolved macro constants
    params: list = field(default_factory=list)   # [(type, name), ...]
    resolved_types: list = field(default_factory=list)
    unresolved_types: list = field(default_factory=list)
    invented_macros: list = field(default_factory=list)


# --------------------------------------------------------------------------- #
# header index
# --------------------------------------------------------------------------- #

def _header_files(source_root: Path, near: Path, limit: int = 400) -> list[Path]:
    """Headers to scan: prefer the target file's directory + its parents, then a
    bounded sweep of the tree (keeps the grep cheap on big kernels)."""
    near_dir = near.parent
    pref = sorted(near_dir.glob("*.h"))
    pref += sorted(near_dir.parent.glob("*.h")) if near_dir != source_root else []
    seen = set(pref)
    rest = []
    for h in source_root.rglob("*.h"):
        if h in seen:
            continue
        rest.append(h)
        if len(rest) >= limit:
            break
    return pref + rest


def build_type_index(headers: list[Path]) -> tuple[dict, dict, dict, dict]:
    """Return (typedef_map, aggregate_map, enum_consts, macro_map).

    typedef_map:  NAME -> "typedef ... NAME;"  (full line, may name a struct tag)
    aggregate_map: TAG  -> full "struct/union/enum TAG { ... };" block
    enum_consts:  CONST -> its enum TAG (so we can emit the whole enum)
    macro_map:    NAME -> "#define NAME value"  (object-like macros only)
    """
    typedef_map: dict[str, str] = {}
    aggregate_map: dict[str, str] = {}
    enum_consts: dict[str, str] = {}
    macro_map: dict[str, str] = {}
    td_re = re.compile(r"typedef\s+[^;{}]+?\b(\w+)\s*;")
    # function-pointer typedef: typedef ret (*NAME)(args);
    fnptr_re = re.compile(r"typedef\s+[^;{}]+?\(\s*\*\s*(\w+)\s*\)\s*\([^;]*\)\s*;")
    # object-like macro: #define NAME value   (NOT function-like `NAME(`)
    mac_re = re.compile(r"^\s*#\s*define\s+([A-Za-z_]\w*)\s+(\S.*?)\s*$")
    agg_open = re.compile(r"^\s*(?:typedef\s+)?(struct|union|enum)\s+(\w+)\s*\{")
    for h in headers:
        try:
            text = h.read_text(errors="replace")
        except OSError:
            continue
        for m in fnptr_re.finditer(text):
            typedef_map.setdefault(m.group(1), m.group(0))
        for m in td_re.finditer(text):
            typedef_map.setdefault(m.group(1), m.group(0))
        for ln in text.split("\n"):
            mm = mac_re.match(ln)
            if mm and not re.match(rf"{mm.group(1)}\s*\(", ln[ln.find(mm.group(1)):]):
                # object-like only: the char after NAME is whitespace, not '('
                after = ln[ln.find("#"):]
                if re.match(r"^\s*#\s*define\s+\w+\s", after):
                    macro_map.setdefault(mm.group(1), f"#define {mm.group(1)} {mm.group(2)}")
        lines = text.split("\n")
        i = 0
        while i < len(lines):
            mo = agg_open.match(lines[i])
            if not mo:
                i += 1
                continue
            kind, tag = mo.group(1), mo.group(2)
            depth = lines[i].count("{") - lines[i].count("}")
            blk = [lines[i]]
            j = i + 1
            while j < len(lines) and depth > 0:
                depth += lines[j].count("{") - lines[j].count("}")
                blk.append(lines[j])
                j += 1
            block = "\n".join(blk)
            aggregate_map.setdefault(tag, block)
            if kind == "enum":
                for cm in re.finditer(r"\b([A-Z_][A-Z0-9_]*)\b", block):
                    enum_consts.setdefault(cm.group(1), tag)
            i = j
    return typedef_map, aggregate_map, enum_consts, macro_map


# --------------------------------------------------------------------------- #
# closure
# --------------------------------------------------------------------------- #

def _struct_tag_of_typedef(td_line: str) -> Optional[str]:
    m = re.search(r"\b(?:struct|union|enum)\s+(\w+)", td_line)
    return m.group(1) if m else None


def _declares_field(block: str, fields: set[str]) -> bool:
    """Does this aggregate body declare one of `fields` as a member?"""
    for ln in block.split("\n")[1:]:  # skip the `struct X {` opener
        m = re.search(r"\b(\w+)\s*(?:\[[^\]]*\])?\s*;", ln)
        if m and m.group(1) in fields:
            return True
    return False


def _value_embedded_tags(block: str, aggregate_map: dict) -> list[str]:
    """Struct/union members embedded *by value* (no `*`) — these need full
    definitions, not just a forward decl, for the outer struct to size."""
    out = []
    for ln in block.split("\n")[1:]:
        m = re.match(r"\s*(?:struct|union)\s+(\w+)\s+(?!\*)\w+\s*(?:\[[^\]]*\])?\s*;", ln)
        if m and m.group(1) in aggregate_map:
            out.append(m.group(1))
    return out


def harvest(body: str, sig: str, typedef_map: dict, aggregate_map: dict,
            enum_consts: dict) -> tuple[list[str], list[str], list[str]]:
    """Worklist closure over the types a function references, with field-driven
    expansion: a struct gets a full body only if the function accesses one of
    its fields (or it's value-embedded in one that does); otherwise it's just
    forward-declared. This keeps the lowered slice small — a pointer that's only
    passed through (e.g. an opaque handle) costs one `struct X;`, not its whole
    transitive closure. Returns (ordered_decls, resolved_names, unresolved)."""
    accessed = set(re.findall(r"(?:->|\.)\s*([A-Za-z_]\w*)", body))
    seed = set(_IDENT.findall(sig + "\n" + body)) - _KEYWORDS
    work = list(seed)
    seen: set[str] = set()
    typedef_lines: list[str] = []
    forward_tags: list[str] = []
    expanded_blocks: list[str] = []
    expanded_tags: set[str] = set()
    enums_done: set[str] = set()
    resolved: list[str] = []

    def add_tokens(text: str):
        for t in set(_IDENT.findall(text)) - _KEYWORDS:
            if t not in seen:
                work.append(t)

    def expand_tag(tag: str):
        if tag in expanded_tags or tag not in aggregate_map:
            return
        expanded_tags.add(tag)
        blk = aggregate_map[tag]
        expanded_blocks.append(blk)
        resolved.append("struct " + tag)
        add_tokens(blk)
        for emb in _value_embedded_tags(blk, aggregate_map):
            expand_tag(emb)

    while work:
        name = work.pop()
        if name in seen:
            continue
        seen.add(name)
        if name in _PRIM_TYPES:
            continue
        if name in typedef_map:
            line = typedef_map[name]
            typedef_lines.append(line)
            resolved.append(name)
            add_tokens(line)
            tag = _struct_tag_of_typedef(line)
            if tag:
                forward_tags.append(tag)
                if tag in aggregate_map and _declares_field(aggregate_map[tag], accessed):
                    expand_tag(tag)
        elif name in aggregate_map:
            forward_tags.append(name)
            if _declares_field(aggregate_map[name], accessed):
                expand_tag(name)
        elif name in enum_consts:
            tag = enum_consts[name]
            if tag not in enums_done:
                enums_done.add(tag)
                expanded_blocks.append(aggregate_map[tag])
                resolved.append("enum " + tag)
                add_tokens(aggregate_map[tag])
        # else: a callee (engine nondet-stubs it), local var, or macro const.

    fwd = [f"struct {t};" for t in forward_tags if t not in expanded_tags]
    ordered = _dedup(fwd) + _dedup(typedef_lines) + _dedup(expanded_blocks)
    return ordered, resolved, []


def _dedup(xs: list[str]) -> list[str]:
    out, seen = [], set()
    for x in xs:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


# --------------------------------------------------------------------------- #
# signature parsing (params for the harness call)
# --------------------------------------------------------------------------- #

def parse_params(sig: str) -> list[tuple[str, str]]:
    """Best-effort: parse `ret name(type a, type b)` into [(type, name), ...]."""
    m = re.search(r"\b\w+\s*\(([^)]*)\)", sig.replace("\n", " "))
    if not m:
        return []
    inner = m.group(1).strip()
    if inner in ("", "void"):
        return []
    out = []
    for i, part in enumerate(inner.split(",")):
        part = part.strip()
        pm = re.match(r"^(.*?)(\*?\s*)(\w+)$", part)
        if not pm:
            out.append((part or "long", f"a{i}"))
            continue
        ty = (pm.group(1) + pm.group(2)).strip()
        nm = pm.group(3)
        out.append((ty or "long", nm))
    return out


# --------------------------------------------------------------------------- #
# top level
# --------------------------------------------------------------------------- #

def _clean_body(fpath: Path, start: int) -> Optional[str]:
    """Trim the ctags over-slice to exactly one function: recover a lone
    return-type line above the name, then brace-match from the first `{`."""
    try:
        lines = fpath.read_text(errors="replace").split("\n")
    except OSError:
        return None
    si = start - 1                       # 0-based name line
    # Recover a return-type-only line directly above (K&R layout).
    if si > 0:
        prev = lines[si - 1].strip()
        if prev and not prev.endswith((";", "{", "}", ")", ",", "*/")) \
                and re.match(r"^[\w \t\*]+$", prev):
            si -= 1
    # Find the first `{` at/after the name line, then balance braces.
    text_from = "\n".join(lines[si:])
    open_idx = text_from.find("{")
    if open_idx < 0:
        return None
    depth, end = 0, None
    for k, ch in enumerate(text_from[open_idx:], start=open_idx):
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                end = k + 1
                break
    if end is None:
        return None
    return text_from[:end]


def lower_function(source_root: Path, rel_file: str, func: str) -> LowerResult:
    fpath = source_root / rel_file
    if not fpath.exists():
        return LowerResult(False, reason=f"file-missing:{rel_file}")
    ext = extract_function_body(fpath, func)
    if not ext:
        return LowerResult(False, reason="extract-failed")
    _raw, start = ext
    body = _clean_body(fpath, start)
    if not body:
        return LowerResult(False, reason="body-trim-failed")
    sig = body.split("{", 1)[0].strip()

    # Scan the target .c too: some constants (e.g. length caps) are file-local
    # #defines, not in headers; missing them and inventing 0 corrupts the guard.
    headers = [fpath] + _header_files(source_root, fpath)
    typedef_map, aggregate_map, enum_consts, macro_map = build_type_index(headers)
    decls, resolved, _unres = harvest(body, sig, typedef_map, aggregate_map,
                                      enum_consts)

    known = set()
    for d in decls:
        known |= set(_IDENT.findall(d))
    # Identifiers the body references that aren't types, locals, or enum consts.
    body_ids = set(_IDENT.findall(body)) - _KEYWORDS - _PRIM_TYPES - known
    body_ids -= set(enum_consts)
    # Emit the REAL object-like macro defs we harvested (handles mixed-case like
    # DW_FORM_addrx4); recurse one level so a macro defined via another resolves.
    real_macros: list[str] = []
    macro_seen: set[str] = set()
    work = [t for t in body_ids if t in macro_map]
    while work:
        t = work.pop()
        if t in macro_seen:
            continue
        macro_seen.add(t)
        real_macros.append(macro_map[t])
        for tok in _IDENT.findall(macro_map[t].split(None, 2)[-1]):
            if tok in macro_map and tok not in macro_seen:
                work.append(tok)
    # Truly-unknown ALL_CAPS tokens (no real def found) → invent as 0 so the
    # slice compiles; keeps the verdict the engine's. Mixed-case unknowns are
    # left alone (likely callees the engine nondet-stubs).
    invented = sorted(t for t in body_ids
                      if t not in macro_seen and re.fullmatch(r"[A-Z_][A-Z0-9_]{2,}", t))
    macro_decls = "\n".join(real_macros + [f"#define {t} 0" for t in invented])

    params = parse_params(sig)
    return LowerResult(
        ok=True, sig=sig, body=body,
        type_decls="\n".join(decls),
        macro_decls=macro_decls,
        params=params,
        resolved_types=resolved,
        unresolved_types=invented,
        invented_macros=invented,
    )


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Lower one C function to standalone")
    ap.add_argument("source_root")
    ap.add_argument("rel_file")
    ap.add_argument("func")
    a = ap.parse_args()
    r = lower_function(Path(a.source_root), a.rel_file, a.func)
    if not r.ok:
        print("LOWER FAILED:", r.reason)
        raise SystemExit(1)
    print(f"// resolved={r.resolved_types}")
    print(f"// invented_macros={r.invented_macros}")
    print(f"// params={r.params}")
    print(r.type_decls)
    print(r.macro_decls)
    print(r.body)
