"""Tier-1 (crash-oracle) verdict schema.

Mirrors `surface/stage_b.py`'s verdict pattern so router/metrics code can
treat Stage B and Tier-1 results uniformly.

Soundness rule (PLAN §3 Tier-1):
- A sanitizer-confirmed crash is high-precision "crash".
- *No crash within budget* is **inconclusive**, NEVER "safe".
  Only a sound engine (Stage B / Tier-3 BMC) may emit "safe".
"""
from __future__ import annotations

from dataclasses import dataclass, asdict, field
from typing import Optional, List


VERDICT_CRASH = "crash"
VERDICT_NO_CRASH = "no_crash"          # ran clean within budget — Tier-1 reports as inconclusive overall
VERDICT_INCONCLUSIVE = "inconclusive"

ENGINES = {"libfuzzer", "aflpp", "syzkaller_replay", "syzkaller_fuzz", "kasan_replay"}
SANITIZERS = {"ASan", "MSan", "UBSan", "KASAN", "KMSAN", "KCSAN", "TSan", "none"}


@dataclass
class Tier1Verdict:
    unit: str                            # task id / harness id
    engine: str                          # one of ENGINES
    sanitizer: str                       # one of SANITIZERS
    verdict: str                         # crash | no_crash | inconclusive
    wall_ms: int
    crash_class: Optional[str] = None    # "heap-buffer-overflow", "use-of-uninitialized-value", etc.
    location: Optional[str] = None       # "file.c:line" or "function+offset"
    pov_path: Optional[str] = None       # absolute path to reproducing input
    evidence_excerpt: str = ""           # truncated sanitizer / dmesg excerpt
    soundness_note: str = ""
    assumed: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def from_libfuzzer_log(text: str) -> tuple[Optional[str], Optional[str]]:
    """Parse a libFuzzer/ASan/MSan/UBSan stderr blob.

    Returns (crash_class, location) — either may be None if not present.
    Recognises the canonical sanitizer banner lines; deliberately conservative.
    """
    import re

    cls = None
    loc = None
    # ASan / MSan / UBSan banner: "==PID==ERROR: AddressSanitizer: heap-buffer-overflow on address ..."
    m = re.search(r"ERROR:\s+(?:Address|Memory|Undefined(?:Behavior)?|Thread|Leak)Sanitizer:\s+([\w\-]+)", text)
    if m:
        cls = m.group(1)
    else:
        # libFuzzer summary: "SUMMARY: AddressSanitizer: heap-buffer-overflow file.c:42:5 in fn"
        m = re.search(r"SUMMARY:\s+\w+Sanitizer:\s+([\w\-]+)", text)
        if m:
            cls = m.group(1)
    # Top frame: "    #0 0x... in fn /path/file.c:LINE:COL"
    m = re.search(r"#0\s+0x[0-9a-f]+\s+in\s+\S+\s+(\S+?):(\d+)(?::\d+)?", text)
    if m:
        loc = f"{m.group(1)}:{m.group(2)}"
    elif (m := re.search(r"SUMMARY:[^\n]*?(\S+\.(?:c|cc|cpp|h|hpp)):(\d+)", text)):
        loc = f"{m.group(1)}:{m.group(2)}"
    return cls, loc


def from_kasan_log(text: str) -> tuple[Optional[str], Optional[str]]:
    """Parse a KASAN dmesg blob.

    Returns (crash_class, location).
    """
    import re

    cls = None
    loc = None
    # "BUG: KASAN: use-after-free in ip_rcv+0x6b1/0x730"
    m = re.search(r"BUG:\s+KASAN:\s+([\w\-]+)\s+in\s+(\S+)", text)
    if m:
        cls = m.group(1)
        loc = m.group(2)
    elif (m := re.search(r"BUG:\s+KASAN:\s+([\w\-]+)", text)):
        cls = m.group(1)
    return cls, loc
