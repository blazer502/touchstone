"""Machine-readable soundness ledger built from `docs/soundness-assumptions.md`.

The markdown doc is the human source of truth; this module parses it into
JSON-shape entries so that Cex artifacts can cross-reference assumptions by
stable id, and downstream tooling (audit dashboards, disclosure attachments,
incremental analysis driver) can read the same ledger.

Schema:

    LedgerEntry:
        anchor_id    : "<section_slug>/<inner_slug>"
        section      : section header text (verbatim)
        tool         : free-text tool / scope name (extracted from `<backticked>` prefix)
        title        : human-readable property name (the bolded headline)
        body         : the remaining bullet text (markdown, multiline allowed)

CLI:

    python3 -m schemas.soundness_ledger export run-logs/soundness-ledger.json
    python3 -m schemas.soundness_ledger lookup tier-1/no-crash-not-safe
    python3 -m schemas.soundness_ledger validate run-logs/cex/cybergym/*.json
        -- checks every cex's `soundness.soundness_anchor_ids` resolves
"""
from __future__ import annotations

import argparse
import glob
import json
import logging
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DOC = REPO_ROOT / "docs" / "soundness-assumptions.md"
log = logging.getLogger("soundness_ledger")


# --- model -------------------------------------------------------------------

@dataclass
class LedgerEntry:
    anchor_id: str
    section: str
    tool: str
    title: str
    body: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Ledger:
    source: str
    entries: List[LedgerEntry] = field(default_factory=list)

    def index(self) -> Dict[str, LedgerEntry]:
        return {e.anchor_id: e for e in self.entries}

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "entries": [e.to_dict() for e in self.entries],
            "count": len(self.entries),
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


# --- parsing -----------------------------------------------------------------

_SECTION_RE = re.compile(r"^##\s+(.+?)\s*$")
# Matches one of these patterns at the start of a list item body:
#   `tool` — title.
#   `tool` -- title.
#   `tool/sub` — title.
#   **`tool` — title.**   (also tolerated; the outer ** is stripped first)
_BULLET_HEAD_RE = re.compile(
    r"^\s*\*\*\s*"
    r"(?:`(?P<tool>[^`]+)`\s*)?"            # backticked tool, optional
    r"(?:[—-]|--)\s*"                       # em-dash / en-dash / "--"
    r"(?P<title>.+?)\s*\*\*\s*"             # bold title text up to closing ** (with optional trailing period)
    r"(?P<body>.*)$",                       # rest of the bullet (this line)
    flags=re.DOTALL,
)


def _slug(s: str) -> str:
    s = s.lower()
    s = re.sub(r"[`'\"]+", "", s)
    s = re.sub(r"[^a-z0-9]+", "-", s).strip("-")
    return s or "anon"


def parse_ledger(path: Path = DEFAULT_DOC) -> Ledger:
    """Parse the markdown ledger into structured entries.

    The parser is intentionally permissive: any top-level `## Section` followed
    by `- **...**` bullets is harvested. Sub-bulleted continuation lines
    (indented `  -` etc.) are appended to the current bullet's body.
    """
    if not path.exists():
        raise FileNotFoundError(path)
    text = path.read_text(encoding="utf-8", errors="replace")

    section = "(prelude)"
    entries: List[LedgerEntry] = []
    cur_entry: Optional[LedgerEntry] = None
    seen_keys: set[str] = set()

    for line in text.splitlines():
        m = _SECTION_RE.match(line)
        if m:
            section = m.group(1).strip()
            cur_entry = None
            continue
        # Top-level bullet (single-space indent or none, starts with `- **`).
        if re.match(r"^\s{0,2}-\s+\*\*", line):
            body_line = line.lstrip().lstrip("-").lstrip()
            hm = _BULLET_HEAD_RE.match(body_line)
            if not hm:
                # Malformed bullet — keep walking, skip.
                cur_entry = None
                continue
            tool = (hm.group("tool") or "").strip()
            title = hm.group("title").strip().rstrip(".")
            tail = hm.group("body").strip()
            sec_slug = _slug(section)
            inner_slug = _slug(f"{tool}-{title}")
            base = f"{sec_slug}/{inner_slug}"
            anchor = base
            n = 2
            while anchor in seen_keys:
                anchor = f"{base}-{n}"
                n += 1
            seen_keys.add(anchor)
            cur_entry = LedgerEntry(
                anchor_id=anchor,
                section=section,
                tool=tool,
                title=title,
                body=tail,
            )
            entries.append(cur_entry)
            continue
        # Continuation: nested bullet or indented prose.
        if cur_entry is not None and (line.startswith("    ") or line.startswith("\t")
                                       or re.match(r"^\s{0,3}-\s+(?!\*\*)", line)):
            cur_entry.body = (cur_entry.body + "\n" + line).strip()
            continue
        # Blank line ends the current entry's continuation.
        if not line.strip():
            cur_entry = None

    return Ledger(source=str(path), entries=entries)


# --- API ---------------------------------------------------------------------

_LEDGER_CACHE: Optional[Ledger] = None


def get_ledger(path: Path = DEFAULT_DOC) -> Ledger:
    global _LEDGER_CACHE
    if _LEDGER_CACHE is None or _LEDGER_CACHE.source != str(path):
        _LEDGER_CACHE = parse_ledger(path)
    return _LEDGER_CACHE


def resolve(anchor_ids: Iterable[str], path: Path = DEFAULT_DOC) -> Dict[str, Optional[LedgerEntry]]:
    """Look up multiple anchor ids at once. Unknown ids map to None."""
    idx = get_ledger(path).index()
    return {a: idx.get(a) for a in anchor_ids}


def annotate_cex_dict(cex_dict: dict, path: Path = DEFAULT_DOC) -> dict:
    """Augment a Cex disclosure-blob dict with resolved ledger entries.

    Adds `cex_dict["soundness"]["resolved"]` = list of LedgerEntry-dicts (or
    `{anchor_id, found: False}` for unresolved). Non-destructive: the original
    `soundness_anchor_ids` is preserved.
    """
    ids = cex_dict.get("soundness", {}).get("soundness_anchor_ids", []) or []
    resolved = []
    for a in ids:
        entry = get_ledger(path).index().get(a)
        if entry is None:
            resolved.append({"anchor_id": a, "found": False})
        else:
            resolved.append({"anchor_id": a, "found": True, **entry.to_dict()})
    cex_dict.setdefault("soundness", {})["resolved"] = resolved
    return cex_dict


# --- CLI ---------------------------------------------------------------------

def _cmd_export(args) -> int:
    ledger = parse_ledger(args.doc)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(ledger.to_json())
    log.info("ledger -> %s (%d entries)", out, len(ledger.entries))
    print(json.dumps({"path": str(out), "count": len(ledger.entries)}))
    return 0


def _cmd_lookup(args) -> int:
    entry = get_ledger(args.doc).index().get(args.anchor)
    if entry is None:
        print(json.dumps({"anchor_id": args.anchor, "found": False}), file=sys.stderr)
        return 1
    print(entry.to_json() if hasattr(entry, "to_json") else json.dumps(entry.to_dict(), indent=2))
    return 0


def _cmd_validate(args) -> int:
    idx = get_ledger(args.doc).index()
    missing: list[tuple[str, str]] = []
    checked = 0
    for pat in args.files:
        for p in glob.glob(pat):
            d = json.loads(Path(p).read_text())
            ids = d.get("soundness", {}).get("soundness_anchor_ids", []) or []
            for a in ids:
                checked += 1
                if a not in idx:
                    missing.append((p, a))
    if missing:
        for p, a in missing:
            print(f"MISSING {a} in {p}")
        return 1
    print(json.dumps({"checked": checked, "missing": 0, "ledger_entries": len(idx)}))
    return 0


def _cmd_annotate(args) -> int:
    out_dir = Path(args.out) if args.out else None
    if out_dir:
        out_dir.mkdir(parents=True, exist_ok=True)
    n = 0
    for pat in args.files:
        for p in glob.glob(pat):
            d = json.loads(Path(p).read_text())
            annotate_cex_dict(d, path=args.doc)
            if out_dir:
                dst = out_dir / Path(p).name
                dst.write_text(json.dumps(d, indent=2))
            else:
                Path(p).write_text(json.dumps(d, indent=2))
            n += 1
    print(json.dumps({"annotated": n}))
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--doc", type=Path, default=DEFAULT_DOC,
                    help="path to soundness-assumptions.md")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("export", help="dump full ledger to JSON")
    sp.add_argument("out", type=str)
    sp.set_defaults(func=_cmd_export)

    sp = sub.add_parser("lookup", help="resolve one anchor_id")
    sp.add_argument("anchor", type=str)
    sp.set_defaults(func=_cmd_lookup)

    sp = sub.add_parser("validate", help="check Cex JSONs all reference known anchors")
    sp.add_argument("files", nargs="+")
    sp.set_defaults(func=_cmd_validate)

    sp = sub.add_parser("annotate", help="rewrite Cex JSONs to embed resolved ledger entries")
    sp.add_argument("files", nargs="+")
    sp.add_argument("--out", type=str, default=None,
                    help="output dir; if omitted, rewrites in-place")
    sp.set_defaults(func=_cmd_annotate)

    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
