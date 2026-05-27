"""F3: bug-class-aware seed corpus augmentation.

When a benchmark task exposes a `bug_class_hint()` (off-by-one, integer-
overflow, null-deref, ...) we know *which kinds* of inputs are most likely
to drive the bug. Rather than relying on libFuzzer's default mutator to
re-discover boundary values from scratch, we pre-seed the corpus with a
small library of class-specific test inputs. The mutator then mixes those
in with the format-specific seeds from the deterministic bank.

This is benchmark-agnostic — any `BenchmarkTask` that returns a bug class
string benefits. The class names match the standard sanitizer
vocabulary (`heap-buffer-overflow`, `use-after-free`, etc.) so adapters
for new benchmarks don't need a translation table.

Seeds are tiny on purpose (≤ 256 bytes each). libFuzzer's coverage
feedback decides which expand under mutation; we just plant the seed.
"""
from __future__ import annotations

from typing import Optional


# Numeric boundary patterns — useful whenever the bug centres on size /
# offset / count fields. 1, 2, 4, 8 byte width variants in both endians.
_INT_BOUNDARIES = [
    b"",                                  # zero-length input
    b"\x00",
    b"\x01",
    b"\xff",
    b"\x7f",
    b"\x80",
    b"\x00\x00",
    b"\xff\xff",
    b"\x00\x00\x00\x00",
    b"\xff\xff\xff\xff",
    b"\x80\x00\x00\x00",                  # INT32_MIN little-endian
    b"\x00\x00\x00\x80",                  # INT32_MIN big-endian
    b"\x7f\xff\xff\xff",                  # INT32_MAX little-endian
    b"\xff\xff\xff\x7f",                  # INT32_MAX big-endian
    b"\xff\xff\xff\xff\xff\xff\xff\xff",  # 64-bit -1 / SIZE_MAX
    b"\x80\x00\x00\x00\x00\x00\x00\x00",  # INT64_MIN
]


# Length-amplification patterns — buffer overflow / OOB classes.
_LENGTH_AMP = [
    b"A" * 4,
    b"A" * 64,
    b"A" * 256,
    b"A" * 4096,
    b"\xff" * 4096,
    b"\x00" * 4096,
    bytes(range(256)),
    bytes(range(256)) * 2,
]


# Format-string / printf-class triggers.
_FMT_PATTERNS = [
    b"%n%s%x",
    b"%s" * 8,
    b"%n",
    b"%99999999s",
]


# UTF-8 / wide-char patterns.
_UNICODE_PATTERNS = [
    b"\xc0\x80",                          # overlong NUL
    b"\xed\xa0\x80",                      # surrogate
    b"\xff\xfe",                          # BOM
    b"\xef\xbb\xbf",                      # UTF-8 BOM
    b"\xfe\xff",                          # UTF-16 BE BOM
]


# Format-aware structural patterns that frequently parse and dispatch.
_STRUCTURAL_PATTERNS = [
    b"<a><b></b></a>",                    # XML / HTML
    b"{ }",                               # JSON empty
    b'{"a":null}',
    b"---\na: ~\n",                       # YAML
    b"GET / HTTP/1.1\r\n\r\n",            # HTTP
]


# Class → seeds map. Unknown classes get an empty list (just the bank).
_BY_CLASS: dict[str, list[bytes]] = {
    "integer-overflow":         _INT_BOUNDARIES,
    "div-by-zero":              _INT_BOUNDARIES[:8],            # numeric zeros
    "null-deref":               [b"", b"\x00" * 8, b"\x00" * 64],
    "heap-buffer-overflow":     _LENGTH_AMP + _INT_BOUNDARIES[:4],
    "stack-buffer-overflow":    _LENGTH_AMP,
    "global-buffer-overflow":   _LENGTH_AMP[:4],
    "out-of-bounds":            _LENGTH_AMP + _INT_BOUNDARIES[:4],
    "use-after-free":           _STRUCTURAL_PATTERNS + [b"A" * 32, b"B" * 32],
    "double-free":              _STRUCTURAL_PATTERNS + [b"\x00" * 32],
    "use-of-uninitialized-value": [b"", b"\x00", b"\x00" * 16],  # uninit usually
                                                                  # not seed-sensitive
    "undefined-behavior":       _INT_BOUNDARIES,
    # Conservative buckets for anything matched loosely.
    "format-string":            _FMT_PATTERNS,
    "unicode":                  _UNICODE_PATTERNS,
}


def seeds_for(bug_class: Optional[str]) -> list[bytes]:
    """Return the class-specific seed bundle, deduplicated. Empty when the
    class is unknown — caller should fall back to format-only seeds."""
    if not bug_class:
        return []
    raw = _BY_CLASS.get(bug_class, [])
    # Dedup while preserving order.
    seen: set[bytes] = set()
    out: list[bytes] = []
    for b in raw:
        if b in seen:
            continue
        seen.add(b)
        out.append(b)
    return out


def augmented_seeds(default_bank: list[bytes],
                    bug_class: Optional[str]) -> list[bytes]:
    """Return the default bank with class-specific seeds appended.

    Bank-first ordering preserves the existing format-header coverage (PDF,
    PNG, ZIP, etc.) — those carry many parser harnesses, so we don't want
    to displace them by truncation. Class seeds tail the list as a
    supplement; they are also passed to libFuzzer's seed corpus, so the
    mutator picks them up even if `bank_budget` doesn't reach them on the
    deterministic-bank pass.
    """
    extras = seeds_for(bug_class)
    out: list[bytes] = []
    seen: set[bytes] = set()
    for b in list(default_bank) + extras:
        if b in seen:
            continue
        seen.add(b)
        out.append(b)
    return out


__all__ = ["seeds_for", "augmented_seeds"]
