"""Phase 1 PA core: mine the fuzz harness + a magic-constant dictionary
from `repo-vul.tar.gz`.

CyberGym targets are OSS-Fuzz libFuzzer harnesses. The harness source (the
file defining `LLVMFuzzerTestOneInput`) and the parser source it drives are
*inside the per-task tarball*. Two things in that source crack the gates a
blind byte mutator can't:

  1. **Magic constants** — `memcmp(buf, "\\x89PNG", 4)`, `case 0x4d5a:`,
     `if (!strcmp(tag, "RIFF"))`. A libFuzzer `-dict` of these lets the
     mutator splice the right bytes at the right offset instead of brute-
     forcing a 2^32 header.
  2. **Input modality** — whether the harness consumes raw bytes, a
     `FuzzedDataProvider` stream, or writes the data to a temp file. Recorded
     here for the directed/LLM phases; the dictionary helps regardless.

Everything is benchmark-agnostic: it operates on a tarball of source, not on
any CyberGym-specific field. Results are cached per task under /tmp.

Verdict authority is unchanged — this only proposes seeds/dictionary; the
sound oracle still decides.
"""
from __future__ import annotations

import logging
import re
import tarfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

log = logging.getLogger("harness_model")

_SRC_EXT = (".c", ".cc", ".cpp", ".cxx", ".c++", ".h", ".hpp", ".hh", ".hxx",
            ".inc")
_CACHE_ROOT = Path("/tmp") / "veri-agent-harness-cache"

# Scan caps so a 40 MB tree doesn't blow the per-task budget.
_MAX_SCAN_FILES = 4000
_MAX_SCAN_BYTES = 24 * 1024 * 1024
_MAX_TOKENS = 1024
_MIN_TOK = 1
_MAX_TOK = 64


@dataclass
class HarnessInfo:
    member: Optional[str]              # tar path of the harness source
    source: str                       # harness function source (best-effort)
    modality: str                     # raw | fuzzed-data-provider | file-indirect | unknown
    full_source_present: bool = False


@dataclass
class HarnessModel:
    task_id: str
    harness: HarnessInfo
    dict_tokens: list[bytes] = field(default_factory=list)
    seeds: list[bytes] = field(default_factory=list)
    # In-tree project test assets harvested from the source tarball (disclosed
    # at level1): the project's own libFuzzer corpus seeds + dictionaries.
    # Known-bug artifacts (crash-/poc-/leak-/oom-/timeout-) are EXCLUDED so a
    # reproduction stays a genuine search, not a replay of the shipped answer.
    intree_seeds: list[bytes] = field(default_factory=list)
    intree_dict_tokens: list[bytes] = field(default_factory=list)


# --- C string-literal decoding ---------------------------------------------

_ESCAPES = {"n": b"\n", "t": b"\t", "r": b"\r", "0": b"\x00",
            "\\": b"\\", '"': b'"', "'": b"'", "a": b"\a", "b": b"\b",
            "f": b"\f", "v": b"\v"}


def _decode_c_string(s: str) -> Optional[bytes]:
    """Decode a C string-literal body (without surrounding quotes) to bytes."""
    out = bytearray()
    i = 0
    n = len(s)
    try:
        while i < n:
            ch = s[i]
            if ch != "\\":
                out += ch.encode("latin-1", "ignore")
                i += 1
                continue
            i += 1
            if i >= n:
                break
            e = s[i]
            if e == "x":
                j = i + 1
                hexd = ""
                while j < n and len(hexd) < 2 and s[j] in "0123456789abcdefABCDEF":
                    hexd += s[j]
                    j += 1
                if hexd:
                    out.append(int(hexd, 16))
                    i = j
                    continue
                i += 1
            elif e in "01234567":
                j = i
                octd = ""
                while j < n and len(octd) < 3 and s[j] in "01234567":
                    octd += s[j]
                    j += 1
                out.append(int(octd, 8) & 0xFF)
                i = j
            elif e in _ESCAPES:
                out += _ESCAPES[e]
                i += 1
            else:
                out += e.encode("latin-1", "ignore")
                i += 1
        return bytes(out)
    except Exception:
        return None


# --- token regexes ----------------------------------------------------------

# A string literal: "..." with escapes. Captures the body.
_STR_RE = re.compile(r'"((?:[^"\\\n]|\\.)*)"')
# Comparison helpers taking a string-literal argument (either position).
_CMP_RE = re.compile(
    r'\b(?:memcmp|strncmp|strcmp|strcasecmp|strncasecmp|strstr|strncasecmp|'
    r'memmem|g_str_has_prefix|starts_with|!strcmp|!memcmp)\b[^;]{0,120}?'
    r'"((?:[^"\\\n]|\\.)*)"')
# Magic integer compared with == or in a switch case label.
_MAGIC_INT_RE = re.compile(
    r'(?:==|!=|case)\s*(0x[0-9A-Fa-f]{2,8})\b')


def _looks_useless(tok: bytes) -> bool:
    if not tok or len(tok) < _MIN_TOK or len(tok) > _MAX_TOK:
        return True
    # printf-style format strings: dominated by %-specifiers and whitespace.
    if tok.count(b"%") >= 2 and len(tok) <= 8:
        return True
    # all-whitespace
    if tok.strip() == b"":
        return True
    return False


def _int_to_byte_variants(hexstr: str) -> list[bytes]:
    """Turn 0xDEADBEEF into both big- and little-endian byte tokens."""
    h = hexstr[2:]
    if len(h) % 2:
        h = "0" + h
    raw = bytes.fromhex(h)
    le = raw[::-1]
    out = [raw]
    if le != raw:
        out.append(le)
    return out


def _harness_modality(src: str) -> str:
    if "FuzzedDataProvider" in src or "ConsumeIntegral" in src \
            or "ConsumeBytes" in src or "ConsumeRandomLengthString" in src:
        return "fuzzed-data-provider"
    # OSS-Fuzz harnesses that dump the buffer to a temp file then open it.
    if re.search(r'(mkstemp|tmpfile|fopen|/tmp/|write\s*\([^,]+,\s*[Dd]ata)', src) \
            and "LLVMFuzzerTestOneInput" in src:
        return "file-indirect"
    if "LLVMFuzzerTestOneInput" in src:
        return "raw"
    return "unknown"


def _find_harness(tf: tarfile.TarFile) -> HarnessInfo:
    """Locate the LLVMFuzzerTestOneInput harness source in the tarball."""
    best: Optional[tuple[str, str]] = None
    for m in tf.getmembers():
        if not m.isfile():
            continue
        if not m.name.endswith(_SRC_EXT):
            continue
        # OSS-Fuzz harness file names usually contain 'fuzz'. Read those first;
        # but the canonical detector is the entrypoint symbol.
        if m.size > 512 * 1024:
            continue
        if "fuzz" not in m.name.lower() and "harness" not in m.name.lower():
            continue
        fo = tf.extractfile(m)
        if fo is None:
            continue
        try:
            body = fo.read().decode("utf-8", errors="replace")
        except Exception:
            continue
        if "LLVMFuzzerTestOneInput" in body:
            best = (m.name, body)
            break
    if best is None:
        return HarnessInfo(member=None, source="", modality="unknown")
    member, body = best
    return HarnessInfo(member=member, source=body,
                       modality=_harness_modality(body),
                       full_source_present=True)


def _extract_tokens(text: str, *, cmp_tokens: set, str_tokens: set,
                    int_tokens: set) -> None:
    for m in _CMP_RE.finditer(text):
        tok = _decode_c_string(m.group(1))
        if tok and not _looks_useless(tok):
            cmp_tokens.add(tok)
    for m in _STR_RE.finditer(text):
        tok = _decode_c_string(m.group(1))
        if tok and not _looks_useless(tok):
            str_tokens.add(tok)
    for m in _MAGIC_INT_RE.finditer(text):
        for v in _int_to_byte_variants(m.group(1)):
            if not _looks_useless(v):
                int_tokens.add(v)


def build(task_id: str, tarball: Path, *, use_cache: bool = True) -> HarnessModel:
    """Mine the harness + dictionary + seeds from a per-task source tarball."""
    cache_dir = _CACHE_ROOT / task_id.replace(":", "_")
    dict_cache = cache_dir / "dict.bin"
    meta_cache = cache_dir / "meta.txt"
    if use_cache and dict_cache.exists() and meta_cache.exists():
        try:
            toks = [bytes.fromhex(l) for l in
                    dict_cache.read_text().splitlines() if l]
            meta = meta_cache.read_text().splitlines()
            modality = meta[0] if meta else "unknown"
            member = meta[1] if len(meta) > 1 else None
            return HarnessModel(
                task_id=task_id,
                harness=HarnessInfo(member=member or None, source="",
                                    modality=modality, full_source_present=bool(member)),
                dict_tokens=toks,
                seeds=_seeds_from_tokens(toks),
            )
        except Exception:
            pass

    cmp_tokens: set = set()
    str_tokens: set = set()
    int_tokens: set = set()
    harness = HarnessInfo(member=None, source="", modality="unknown")

    try:
        with tarfile.open(tarball, "r:*") as tf:
            harness = _find_harness(tf)
            if harness.source:
                _extract_tokens(harness.source, cmp_tokens=cmp_tokens,
                                str_tokens=str_tokens, int_tokens=int_tokens)
    except Exception as e:
        log.warning("[%s] harness scan failed: %s", task_id, e)

    # Second pass for the dictionary across the broader source tree.
    scanned_files = 0
    scanned_bytes = 0
    try:
        with tarfile.open(tarball, "r:*") as tf:
            for m in tf:
                if scanned_files >= _MAX_SCAN_FILES or scanned_bytes >= _MAX_SCAN_BYTES:
                    break
                if not m.isfile() or not m.name.endswith(_SRC_EXT):
                    continue
                if m.size > 2 * 1024 * 1024:
                    continue
                fo = tf.extractfile(m)
                if fo is None:
                    continue
                try:
                    body = fo.read().decode("utf-8", errors="replace")
                except Exception:
                    continue
                scanned_files += 1
                scanned_bytes += len(body)
                _extract_tokens(body, cmp_tokens=cmp_tokens,
                                str_tokens=str_tokens, int_tokens=int_tokens)
                if len(cmp_tokens) + len(str_tokens) + len(int_tokens) > 6000:
                    break
    except Exception as e:
        log.warning("[%s] dict scan failed: %s", task_id, e)

    # Rank: comparison tokens (highest signal) → magic ints → strings.
    ordered: list[bytes] = []
    seen: set = set()
    for group in (sorted(cmp_tokens, key=len),
                  sorted(int_tokens, key=len),
                  sorted(str_tokens, key=len)):
        for t in group:
            if t in seen:
                continue
            seen.add(t)
            ordered.append(t)
            if len(ordered) >= _MAX_TOKENS:
                break
        if len(ordered) >= _MAX_TOKENS:
            break

    model = HarnessModel(task_id=task_id, harness=harness,
                         dict_tokens=ordered, seeds=_seeds_from_tokens(ordered))

    # Cache.
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
        dict_cache.write_text("\n".join(t.hex() for t in ordered))
        meta_cache.write_text(f"{harness.modality}\n{harness.member or ''}")
    except Exception:
        pass
    return model


def _seeds_from_tokens(tokens: list[bytes], *, limit: int = 24) -> list[bytes]:
    """A few corpus seeds built from the most magic-looking tokens.

    Header-magic tokens (short, used in comparisons) become standalone seeds
    plus a padded variant so the parser proceeds past the magic check.
    """
    seeds: list[bytes] = []
    for t in tokens[:limit]:
        if 2 <= len(t) <= 16:
            seeds.append(t)
            seeds.append(t + b"\x00" * 16)
    return seeds


# --- in-tree project test-asset harvest ------------------------------------

_DICT_FILE_RE = re.compile(
    r'(?:\.dict$|/dictionaries?/[^/]+$|(?:^|/)dictionary\.txt$)', re.I)
_CORPUS_PATH_RE = re.compile(
    r'(?:^|/)(?:corpus|seeds?|seed_corpus|testcases?|test_corpus|'
    r'regression|inputs)(?:/)|_corpus/|_seed_corpus/', re.I)
# Known-bug artifacts = the shipped answer; never use as a "find".
_ARTIFACT_RE = re.compile(r'(?:^|/)(?:crash|poc|leak|oom|timeout|slow-unit)[-_]', re.I)
_SKIP_SEED_EXT = (".sh", ".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".py",
                  ".md", ".txt", ".cmake", ".am", ".in", ".ac", ".json",
                  ".yaml", ".yml", ".go", ".rs", ".java", ".m4", ".options")


def _parse_dict_file(text: str) -> list[bytes]:
    toks: list[bytes] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.search(r'"((?:[^"\\]|\\.)*)"', line)
        if m:
            b = _decode_c_string(m.group(1))
            if b and not _looks_useless(b):
                toks.append(b)
    return toks


def harvest_intree(task_id: str, tarball: Path, *,
                   cache_root: Path = _CACHE_ROOT,
                   max_seeds: int = 6000, max_seed_bytes: int = 256 * 1024,
                   max_dict: int = 3000) -> tuple[Optional[Path], list[bytes]]:
    """Harvest the project's OWN in-tree libFuzzer corpus + dictionaries from
    the disclosed source tarball. Returns (corpus_dir | None, dict_tokens).

    Excludes crash-/poc-/leak-/oom- artifacts (the shipped answer) so a hit
    is a genuine search seeded by the project's normal test corpus, not a
    replay of a committed PoC. Cached per task.
    """
    cache_dir = cache_root / task_id.replace(":", "_") / "intree-corpus"
    done = cache_dir / ".done"
    dict_cache = cache_root / task_id.replace(":", "_") / "intree.dict.txt"
    if done.exists():
        toks = []
        if dict_cache.exists():
            toks = [bytes.fromhex(l) for l in dict_cache.read_text().splitlines() if l]
        files = [p for p in cache_dir.iterdir() if p.is_file() and not p.name.startswith(".")]
        return (cache_dir if files else None), toks

    cache_dir.mkdir(parents=True, exist_ok=True)
    seeds_written = 0
    dict_tokens: list[bytes] = []
    try:
        with tarfile.open(tarball, "r:*") as tf:
            for m in tf:
                if not m.isfile():
                    continue
                name = m.name
                base = name.rsplit("/", 1)[-1]
                if _DICT_FILE_RE.search(name) and not name.endswith(_SRC_EXT):
                    if len(dict_tokens) >= max_dict:
                        continue
                    fo = tf.extractfile(m)
                    if fo is None:
                        continue
                    try:
                        text = fo.read().decode("utf-8", errors="replace")
                    except Exception:
                        continue
                    dict_tokens.extend(_parse_dict_file(text)[:max_dict - len(dict_tokens)])
                    continue
                if _CORPUS_PATH_RE.search(name):
                    if _ARTIFACT_RE.search(base):
                        continue
                    if base.lower().endswith(_SKIP_SEED_EXT):
                        continue
                    if seeds_written >= max_seeds or m.size <= 0 or m.size > max_seed_bytes:
                        continue
                    fo = tf.extractfile(m)
                    if fo is None:
                        continue
                    try:
                        data = fo.read()
                    except Exception:
                        continue
                    if 0 < len(data) <= max_seed_bytes:
                        (cache_dir / f"it{seeds_written:06d}").write_bytes(data)
                        seeds_written += 1
    except Exception as e:
        log.warning("[%s] intree harvest failed: %s", task_id, e)

    try:
        dict_cache.write_text("\n".join(t.hex() for t in dict_tokens))
        done.write_text(f"seeds={seeds_written} dict={len(dict_tokens)}")
    except Exception:
        pass
    log.info("[%s] intree harvest: %d seeds, %d dict tokens",
             task_id, seeds_written, len(dict_tokens))
    return (cache_dir if seeds_written else None), dict_tokens


def write_libfuzzer_dict(tokens: list[bytes], path: Path) -> Optional[Path]:
    """Write tokens in libFuzzer `-dict` format. Returns path or None if empty."""
    if not tokens:
        return None
    lines = []
    for i, t in enumerate(tokens):
        esc = "".join(
            chr(b) if 32 <= b < 127 and b not in (0x22, 0x5C) else f"\\x{b:02x}"
            for b in t
        )
        lines.append(f'kw{i}="{esc}"')
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines))
    return path
