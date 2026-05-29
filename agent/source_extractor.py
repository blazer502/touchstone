"""P2: extract a function body from `repo-vul.tar.gz` around a `file:line`.

CyberGym tasks expose `error.txt` (level 2/3) containing a sanitizer stack
trace; the canonical violation site is named `file:line` in the top frame.
This module reads the corresponding source out of the per-task tarball so
the LLM-guided agent can reason against actual code, not just the bug
description text.

Cached: per-task extraction lands in `/tmp/touchstone-source-cache/<task_id>/`
so the (tar reads + line slice) doesn't repeat across multi-turn iterations.

Usage:
    from agent.source_extractor import extract_function_around

    snippet = extract_function_around(
        tarball=Path(".../arvo/1065/repo-vul.tar.gz"),
        file_hint="/src/file/src/funcs.c",   # full or partial path
        line_hint=478,
        window=40,                            # lines of context
    )
    print(snippet.text)
"""
from __future__ import annotations

import logging
import re
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

log = logging.getLogger("source_extractor")


@dataclass
class SourceSnippet:
    """A self-contained slice of source code around a known violation site."""
    file: str                    # path within the tarball
    line: int                    # 1-based; the requested anchor line
    fn_start: int                # 1-based line of the enclosing function header
    fn_end: int                  # inclusive last line of the function
    text: str                    # full function body OR ±window slice if no fn found
    truncated: bool = False
    cache_path: Optional[str] = None


CACHE_ROOT = Path("/tmp") / "touchstone-source-cache"


# Match a C function header at a top-level position. We're lenient: returns
# True for a line that *looks like* a function start (ident followed by `(`
# at column 0..7 and not ending in `;`). Good enough for libFuzzer harnesses
# and the OSS-Fuzz codebases the agent sees.
_FN_HEADER_RE = re.compile(r"^[ \t]{0,7}[\w *]+?\s*\b\w+\s*\([^;]*$")


def _normalise_tar_member_match(tar_path: str, hint: str) -> bool:
    """Match a tar member name against a hint that may be absolute / partial.

    Examples:
        tar_path="src/file/src/funcs.c",  hint="/src/file/src/funcs.c"  → True
        tar_path="src/file/src/funcs.c",  hint="src/funcs.c"             → True
        tar_path="src/file/src/funcs.c",  hint="funcs.c"                 → True
    """
    hint = hint.lstrip("/").strip()
    if not hint:
        return False
    if tar_path == hint:
        return True
    if tar_path.endswith("/" + hint) or tar_path.endswith(hint):
        return True
    # try matching by the last N path components
    parts = hint.split("/")
    while parts:
        suffix = "/".join(parts)
        if tar_path.endswith(suffix):
            return True
        parts.pop(0)
    return False


def _read_from_tar(tarball: Path, file_hint: str) -> Optional[tuple[str, str]]:
    """Return (member_path, file_content) for the first match of `file_hint`."""
    with tarfile.open(tarball, "r:*") as tf:
        for m in tf.getmembers():
            if not m.isfile():
                continue
            if _normalise_tar_member_match(m.name, file_hint):
                fobj = tf.extractfile(m)
                if fobj is None:
                    continue
                try:
                    return m.name, fobj.read().decode("utf-8", errors="replace")
                except Exception:
                    return m.name, fobj.read().decode("latin-1", errors="replace")
    return None


def _function_span(lines: list[str], anchor_line_1based: int) -> tuple[int, int]:
    """Find the enclosing C function span using brace counting.

    Walks UP from the anchor line looking for a function-header pattern; then
    walks DOWN counting braces to find the matching close. Returns 1-based
    (start, end). Falls back to (anchor-window, anchor+window) if no header
    is found.
    """
    n = len(lines)
    i = min(max(anchor_line_1based - 1, 0), n - 1)

    # Walk up to find a candidate function header line followed by `{`.
    start = None
    j = i
    while j >= 0:
        line = lines[j]
        if _FN_HEADER_RE.match(line):
            # ensure the next non-blank line opens a brace OR this line ends with {
            k = j
            while k < n and "{" not in lines[k]:
                if ";" in lines[k]:
                    break
                k += 1
            if k < n and "{" in lines[k]:
                start = j
                break
        j -= 1
    if start is None:
        # fallback: ± window from anchor
        win = 30
        return max(1, anchor_line_1based - win), min(n, anchor_line_1based + win)

    # Brace-count down from start.
    depth = 0
    end = start
    seen_open = False
    for k in range(start, n):
        line = lines[k]
        for ch in line:
            if ch == "{":
                depth += 1
                seen_open = True
            elif ch == "}":
                depth -= 1
                if seen_open and depth == 0:
                    end = k
                    return start + 1, end + 1
        end = k
    return start + 1, end + 1


def extract_function_around(
    tarball: Path,
    file_hint: str,
    line_hint: int,
    *,
    window: int = 40,
    max_bytes: int = 6000,
    cache_key: Optional[str] = None,
) -> Optional[SourceSnippet]:
    """Pull the function body that contains `file_hint:line_hint` from `tarball`.

    Returns None if the file isn't in the tarball. If the enclosing function
    can't be found cleanly (no clear header / brace mismatch), falls back to a
    ±`window`-line slice.

    The returned `text` is the source slice itself. `max_bytes` truncates very
    long functions so the LLM prompt stays bounded; `truncated=True` records
    the cut. The result is cached under `/tmp/touchstone-source-cache/<key>/`.
    """
    cache_dir = CACHE_ROOT / (cache_key or tarball.stem)
    cache_dir.mkdir(parents=True, exist_ok=True)

    file_slug = re.sub(r"[^a-zA-Z0-9._-]+", "_", file_hint.lstrip("/"))
    cache_path = cache_dir / f"{file_slug}.{line_hint}.txt"
    if cache_path.exists():
        try:
            cached_text = cache_path.read_text()
            # cache hit; parse the simple header we wrote
            return SourceSnippet(
                file=file_hint, line=line_hint, fn_start=0, fn_end=0,
                text=cached_text, truncated=len(cached_text) >= max_bytes,
                cache_path=str(cache_path),
            )
        except Exception:
            pass

    hit = _read_from_tar(tarball, file_hint)
    if hit is None:
        log.warning("file %r not found in %s", file_hint, tarball)
        return None
    member, body = hit
    lines = body.splitlines()
    fn_start, fn_end = _function_span(lines, line_hint)

    # Optionally expand symmetric window around the anchor if function span is
    # tiny — gives the LLM context above/below.
    span_lines = lines[fn_start - 1:fn_end]
    if fn_end - fn_start + 1 < 8:
        lo = max(1, line_hint - window)
        hi = min(len(lines), line_hint + window)
        span_lines = lines[lo - 1:hi]
        fn_start, fn_end = lo, hi

    text = "\n".join(span_lines)
    truncated = False
    if len(text) > max_bytes:
        text = text[:max_bytes] + f"\n/* ... [truncated; original {len(text)} bytes] ... */"
        truncated = True

    # Add a header so the LLM knows what it's looking at.
    header = f"// {member}, lines {fn_start}..{fn_end} (anchor line {line_hint})"
    full = header + "\n" + text

    try:
        cache_path.write_text(full)
    except Exception:
        cache_path = None

    return SourceSnippet(
        file=member, line=line_hint,
        fn_start=fn_start, fn_end=fn_end,
        text=full, truncated=truncated,
        cache_path=str(cache_path) if cache_path else None,
    )


# Parse a CyberGym `error.txt` to surface the canonical `file:line` from the
# top sanitizer frame. Conservative — returns the first non-libfuzzer frame.
_FRAME_RE = re.compile(r"#\d+\s+0x[0-9a-f]+\s+in\s+\S+\s+(?P<path>[^\s:]+):(?P<line>\d+)")


def first_user_frame(error_text: str) -> Optional[tuple[str, int]]:
    """Return (file_path, line) of the first non-libfuzzer/no-asan-runtime frame
    in a sanitizer stack trace, or None.
    """
    skip_substrings = (
        "/libfuzzer/", "/llvm-project/",
        "/sanitizer_common/", "/asan_", "/msan_", "/ubsan_",
        "FuzzerLoop", "FuzzerDriver", "FuzzerMain",
    )
    for m in _FRAME_RE.finditer(error_text):
        path = m.group("path")
        if any(s in path for s in skip_substrings):
            continue
        return path, int(m.group("line"))
    return None
