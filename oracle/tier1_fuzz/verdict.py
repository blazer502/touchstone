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


# Kernel BUG signatures beyond KASAN. Each tuple is (regex, sanitizer, class_tmpl, location_tmpl).
# Ordered most-specific-first; first match wins.
_KERN_BUG_PATTERNS = [
    (r"BUG:\s+KASAN:\s+([\w\-]+)\s+in\s+(\S+)",                       "KASAN",  "{1}",                       "{2}"),
    (r"BUG:\s+KASAN:\s+([\w\-]+)",                                     "KASAN",  "{1}",                       None),
    (r"BUG:\s+KMSAN:\s+([\w\-]+)\s+in\s+(\S+)",                       "KMSAN",  "{1}",                       "{2}"),
    (r"BUG:\s+KMSAN:\s+([\w\-]+)",                                     "KMSAN",  "{1}",                       None),
    (r"BUG:\s+KCSAN:\s+data-race\s+in\s+(\S+)",                       "KCSAN",  "data-race",                 "{1}"),
    (r"BUG:\s+KCSAN:\s+([\w\-]+)",                                     "KCSAN",  "{1}",                       None),
    (r"UBSAN:\s+([\w\-]+)\s+in\s+(\S+):(\d+)",                        "UBSAN",  "{1}",                       "{2}:{3}"),
    (r"UBSAN:\s+([\w\-]+)",                                            "UBSAN",  "{1}",                       None),
    (r"BUG:\s+kernel\s+NULL\s+pointer\s+dereference",                  "kernel", "null-deref",                None),
    (r"BUG:\s+unable\s+to\s+handle\s+(?:kernel\s+)?paging\s+request",  "kernel", "bad-paging",                None),
    (r"general\s+protection\s+fault",                                  "kernel", "general-protection-fault",  None),
    (r"kernel\s+BUG\s+at\s+(\S+:\d+)",                                 "kernel", "kernel-bug",                "{1}"),
    (r"Oops:\s+\d+",                                                   "kernel", "oops",                      None),
    (r"BUG:\s+soft\s+lockup",                                          "kernel", "soft-lockup",               None),
    (r"BUG:\s+spinlock\s+(\w+)",                                       "kernel", "spinlock-{1}",              None),
    (r"watchdog:\s+BUG:\s+(\S+\s+lockup)",                             "kernel", "watchdog-{1}",              None),
    (r"INFO:\s+task\s+hung",                                           "kernel", "task-hung",                 None),
    (r"INFO:\s+task\s+\S+:\d+\s+blocked\s+for\s+more\s+than",          "kernel", "task-hung",                 None),
    (r"INFO:\s+rcu_sched\s+self-detected",                             "kernel", "rcu-stall",                 None),
    (r"INFO:\s+rcu_preempt\s+detected",                                "kernel", "rcu-stall",                 None),
    # Debug-infra exhaustion: lockdep's static tables overflowed. NOT a bug —
    # cannot occur on a production (no-LOCKDEP) kernel. Lowest signal.
    (r"BUG:\s+MAX_LOCKDEP_(?:ENTRIES|CHAINS|KEYS|STACK_TRACE_ENTRIES)\s+too\s+low", "kernel", "lockdep-table-exhaustion", None),
    (r"WARNING:\s+possible\s+circular\s+locking\s+dependency",         "kernel", "lockdep-deadlock",          None),
    (r"WARNING:\s+suspicious\s+RCU\s+usage",                           "kernel", "lockdep-rcu",               None),
    (r"WARNING:\s+possible\s+irq\s+lock\s+inversion",                  "kernel", "lockdep-irq-inversion",     None),
    (r"WARNING:\s+possible\s+recursive\s+locking",                     "kernel", "lockdep-recursive",         None),
    # rwsem magic-number corruption: lock object was freed/zeroed while in use.
    # Strong memory-corruption indicator (UAF on the lock or its container struct).
    (r"DEBUG_RWSEMS_WARN_ON\(sem->magic\s*!=\s*sem\)",                 "kernel", "rwsem-magic-corruption",    None),
    # spinlock bad magic — same idea on spinlocks
    (r"BUG:\s+spinlock\s+bad\s+magic",                                 "kernel", "spinlock-bad-magic",        None),
    # list_head poison — corruption indicator
    (r"list_(?:add|del)\s+corruption",                                 "kernel", "list-corruption",           None),
    (r"WARNING.*?list_(?:add|del)\s+corruption",                       "kernel", "list-corruption",           None),
    # refcount issues
    (r"refcount_t:\s+(?:underflow|saturated|addition\s+on\s+0)",       "kernel", "refcount-corruption",       None),
    (r"WARNING:\s+CPU:",                                               "kernel", "warning",                   None),
    (r"WARNING:\s+",                                                   "kernel", "warning",                   None),
]


def from_kernel_bug_log(text: str) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """Parse a kernel dmesg for ANY known BUG/WARN/DoS signature.

    Returns (sanitizer, crash_class, location). All may be None if nothing
    matched. The first pattern that hits wins (most-specific-first ordering).
    """
    import re

    for pat, san, cls_tmpl, loc_tmpl in _KERN_BUG_PATTERNS:
        m = re.search(pat, text, re.MULTILINE)
        if not m:
            continue
        groups = list(m.groups())
        def _fmt(t: Optional[str]) -> Optional[str]:
            if t is None:
                return None
            out = t
            for i, g in enumerate(groups, start=1):
                out = out.replace("{" + str(i) + "}", g if g else "")
            return out
        # Also try to attach the top kernel-mode RIP if we don't have a location.
        loc = _fmt(loc_tmpl)
        if loc is None:
            rip = re.search(r"RIP:\s+0010:(\S+)", text)
            if rip:
                loc = rip.group(1)
        return san, _fmt(cls_tmpl), loc
    return None, None, None


# Severity ranking for kernel bug classes.
#   crash : memory-safety + hard kernel oopses (highest priority)
#   warn  : WARNs, UBSAN, KCSAN data-races (audit-worthy, not always exploitable)
#   dos   : soft-lockup, hangs, rcu-stalls (DoS class only)
_CRASH_SEVERITY_BY_SAN = {
    "KASAN": "crash",
    "KMSAN": "crash",
    "KCSAN": "warn",
    "UBSAN": "warn",
}
_CRASH_SEVERITY_BY_KCLASS = {
    "null-deref": "crash",
    "bad-paging": "crash",
    "general-protection-fault": "crash",
    "kernel-bug": "crash",
    "oops": "crash",
    "rwsem-magic-corruption": "crash",
    "spinlock-bad-magic": "crash",
    "list-corruption": "crash",
    "refcount-corruption": "crash",
    "soft-lockup": "dos",
    "task-hung": "dos",
    "rcu-stall": "dos",
    "lockdep-deadlock": "warn",
    "lockdep-rcu": "warn",
    "lockdep-irq-inversion": "warn",
    "lockdep-recursive": "warn",
    "lockdep-table-exhaustion": "dos",
    "warning": "warn",
}


def classify_kernel_bug(sanitizer: Optional[str], cls: Optional[str]) -> str:
    """(sanitizer, class) → one of {'crash', 'warn', 'dos', 'unknown'}."""
    if sanitizer is None or cls is None:
        return "unknown"
    if sanitizer in _CRASH_SEVERITY_BY_SAN:
        return _CRASH_SEVERITY_BY_SAN[sanitizer]
    if sanitizer == "kernel":
        # Exact match wins over prefix match (e.g. "lockdep-table-exhaustion"
        # must not be swallowed by the "lockdep-" prefix of "lockdep-deadlock").
        if cls in _CRASH_SEVERITY_BY_KCLASS:
            return _CRASH_SEVERITY_BY_KCLASS[cls]
        for prefix, sev in _CRASH_SEVERITY_BY_KCLASS.items():
            if cls.startswith(prefix.split("-")[0] + "-"):
                return sev
    return "unknown"
