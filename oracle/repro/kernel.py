"""Kernel reproducer backend (R2 synthesis + R3 N-times VM re-run).

R2 — synthesize a candidate standalone reproducer from a syz-manager crash
bucket: ``syz-repro`` -> ``syz-prog2c`` when syzkaller binaries are present,
reuse an already-extracted C reproducer if the bucket has one, else fall back
to a bug-class syzlang template. When no syzkaller binaries are present on the
host (the common case here), synthesis degrades to a clean
``infrastructure_pending`` result — the same honest-stub discipline as
``oracle/tier2_symbolic/s2e_driver.py`` and ``kernel.syzkaller_smoke``.

R3 — measure reproducibility by booting the target N times under QEMU+KASAN
(reusing ``oracle.tier1_fuzz.kernel.kasan_replay``) and counting boots whose
crash *signature* matches the target bucket -> ``repro_rate`` -> ``ReproVerdict``.
This is what the 8 h overnight fuzz run never produced: it found crash buckets
but ``repros_succeeded=0`` and nothing scored/recorded the determinism.

Soundness (``docs/soundness-assumptions.md``):
- ``repro_rate`` is a finite-N frequency estimate; ``unreproducible`` = not
  reproduced within N boots under this build, NOT "safe".
- The KASAN re-run is the verdict authority. A template-/LLM-proposed syscall
  sequence is a *candidate*, never a verdict (PLAN §8).
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import List, Optional, Tuple

from oracle.tier1_fuzz.kernel import kasan_replay
from schemas.reproducer import (
    DEFAULT_REPRO_THRESHOLD,
    DOMAIN_KERNEL,
    Reproducer,
    ReproVerdict,
    classify_repro,
    crash_signature,
)

_SYZLANG_DIR = Path(__file__).resolve().parents[1] / "tier1_fuzz" / "syzlang"

# Synthesis statuses.
SYNTH_REUSED = "reused_existing"            # bucket already had a C reproducer
SYNTH_OK = "synthesized"                    # syz-repro + syz-prog2c produced one
SYNTH_TEMPLATE = "template_proposed"        # bug-class syzlang template (unverified candidate)
SYNTH_PENDING = "infrastructure_pending"    # syzkaller binaries absent, no template match


@dataclass
class ReproSynthesisResult:
    status: str
    method: str
    program_path: Optional[str] = None
    fingerprint: Optional[str] = None       # bug-class / subsystem the candidate targets
    reason: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# R2 — synthesis
# ---------------------------------------------------------------------------

def _locate_syz_tools() -> dict:
    """Find syz-repro / syz-prog2c on host (SYZKALLER_BIN dir or PATH)."""
    out = {"syz-repro": None, "syz-prog2c": None}
    binroot = os.environ.get("SYZKALLER_BIN")
    for tool in out:
        if binroot:
            cand = Path(binroot) / tool
            if cand.exists():
                out[tool] = str(cand)
                continue
        found = shutil.which(tool)
        if found:
            out[tool] = found
    return out


# Keyword -> syzlang template. Most-specific first. The template is a *candidate*
# syscall surface for the bug class, not a verified reproducer.
_TEMPLATE_MAP = [
    (("nf_tables", "nft", "netfilter", "nf_conntrack"), "nf_tables_cve_2024_1086.txt"),
]


def _match_template(*texts: Optional[str]) -> Optional[Path]:
    hay = " ".join(t.lower() for t in texts if t)
    for keys, fname in _TEMPLATE_MAP:
        if any(k in hay for k in keys):
            p = _SYZLANG_DIR / fname
            if p.exists():
                return p
    return None


def _find_existing_repro(bucket_dir: Path) -> Optional[Path]:
    """syz-manager sometimes leaves repro.cprog / repro.prog in a crash bucket."""
    for name in ("repro.cprog", "repro.prog", "reproducer.c"):
        p = bucket_dir / name
        if p.exists() and p.stat().st_size > 0:
            return p
    return None


def synthesize_kernel_reproducer(*, bucket_dir: Optional[Path] = None,
                                 log0: Optional[Path] = None,
                                 crash_class: Optional[str] = None,
                                 description: Optional[str] = None,
                                 subsystem_hint: Optional[str] = None,
                                 manager_cfg: Optional[Path] = None,
                                 out_dir: Optional[Path] = None) -> ReproSynthesisResult:
    """Best-effort kernel reproducer synthesis with honest degradation.

    Order: reuse existing C reproducer -> syz-repro+prog2c (needs binaries +
    a manager config + VM) -> bug-class template -> infrastructure_pending.
    """
    # 1. reuse an already-extracted reproducer.
    if bucket_dir is not None:
        existing = _find_existing_repro(bucket_dir)
        if existing is not None:
            return ReproSynthesisResult(
                status=SYNTH_REUSED, method="existing-cprog",
                program_path=str(existing), fingerprint=crash_class,
                reason="bucket already contained an extracted reproducer")

    # 2. syz-repro -> syz-prog2c (requires binaries AND a manager config + VM).
    tools = _locate_syz_tools()
    log0 = log0 or (bucket_dir / "log0" if bucket_dir else None)
    if tools["syz-repro"] and tools["syz-prog2c"] and manager_cfg and log0 and Path(log0).exists():
        out_dir = out_dir or (bucket_dir or Path.cwd())
        prog = Path(out_dir) / "repro.syz"
        cprog = Path(out_dir) / "repro.cprog"
        try:
            r = subprocess.run([tools["syz-repro"], "-config", str(manager_cfg),
                                "-output", str(prog), str(log0)],
                               capture_output=True, text=True, timeout=1800)
            if r.returncode == 0 and prog.exists():
                c = subprocess.run([tools["syz-prog2c"], "-prog", str(prog)],
                                  capture_output=True, text=True, timeout=120)
                if c.returncode == 0 and c.stdout:
                    cprog.write_text(c.stdout)
                    return ReproSynthesisResult(
                        status=SYNTH_OK, method="syz-repro+prog2c",
                        program_path=str(cprog), fingerprint=crash_class,
                        reason="syz-repro reproduced; prog2c emitted standalone C")
        except subprocess.TimeoutExpired:
            pass  # fall through to template

    # 3. bug-class template fallback (unverified candidate).
    tmpl = _match_template(crash_class, description, subsystem_hint)
    if tmpl is not None:
        return ReproSynthesisResult(
            status=SYNTH_TEMPLATE, method=f"template:{tmpl.name}",
            program_path=str(tmpl), fingerprint=(subsystem_hint or crash_class),
            reason=("syzkaller binaries unavailable; emitted a bug-class syzlang "
                    "template as an UNVERIFIED candidate surface. R3 re-run / "
                    "directed fuzzing decides whether it actually fires."))

    # 4. honest infrastructure_pending.
    missing = [k for k, v in tools.items() if v is None]
    return ReproSynthesisResult(
        status=SYNTH_PENDING, method="none", program_path=None,
        fingerprint=crash_class,
        reason=(f"no reproducer synthesizable: missing syzkaller tools {missing} "
                "(set SYZKALLER_BIN or build veri-agent/syzkaller image) and no "
                "bug-class template matched. Wired interface; pending infra."))


# ---------------------------------------------------------------------------
# R3 — N-times VM re-run determinism
# ---------------------------------------------------------------------------

def _boot_once(qemu_script: Path, log_path: Optional[Path], unit: str,
               timeout_seconds: int) -> str:
    """One QEMU+KASAN boot; return the crash signature ("" if no crash)."""
    v = kasan_replay(qemu_script, log_path=log_path, unit=unit,
                     timeout_seconds=timeout_seconds)
    if v.verdict != "crash":
        return ""
    return crash_signature(v.sanitizer, v.crash_class, v.location)


def measure_kernel_reproducibility(qemu_script: Path, *,
                                   runs: int = 3,
                                   target_signature: Optional[str] = None,
                                   threshold: float = DEFAULT_REPRO_THRESHOLD,
                                   timeout_seconds: int = 120,
                                   unit: str = "kernelctf-historical",
                                   log_path: Optional[Path] = None,
                                   build_id: str = "") -> ReproVerdict:
    """Boot ``qemu_script`` ``runs`` times, score signature-matched reproducibility."""
    t0 = time.monotonic()
    from collections import Counter
    samples: List[str] = []
    for _ in range(runs):
        samples.append(_boot_once(qemu_script, log_path, unit, timeout_seconds))

    nonempty = Counter(s for s in samples if s)
    if target_signature:
        sig = target_signature
        hits = sum(1 for s in samples if s == sig)
    elif nonempty:
        sig, hits = nonempty.most_common(1)[0]
    else:
        sig, hits = "", 0
    repro_rate = hits / runs if runs else 0.0
    wall_ms = int((time.monotonic() - t0) * 1000)
    assumed = [f"backend=qemu+KASAN", f"qemu_script={qemu_script.name}",
               f"runs={runs}", f"timeout={timeout_seconds}s"]

    reproducer = None
    if sig:
        san, cls, loc = sig.split("|", 2)
        reproducer = Reproducer(
            signature=sig, domain=DOMAIN_KERNEL, repro_rate=round(repro_rate, 4),
            runs=runs, build_id=build_id, engine="kasan_replay",
            replay_cmd=f"bash {qemu_script}", minimized=False,
            original_trigger_path=str(qemu_script),
            crash_class=(cls if cls != "?" else None),
            location=(loc if loc != "?" else None),
            wall_ms=wall_ms)

    return ReproVerdict(
        unit=unit, domain=DOMAIN_KERNEL, verdict=classify_repro(repro_rate, threshold),
        repro_rate=round(repro_rate, 4), runs=runs, signature=sig, threshold=threshold,
        reproducer=reproducer, wall_ms=wall_ms,
        soundness_note=("repro_rate is a finite-N boot-frequency estimate; "
                        "'unreproducible' = not reproduced within N boots under this "
                        "build, NOT 'safe'. KASAN re-run is the verdict authority."),
        assumed=assumed)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _cli() -> int:
    ap = argparse.ArgumentParser(description="Kernel reproducer (R2 synth + R3 re-run).")
    sub = ap.add_subparsers(dest="cmd", required=True)

    ps = sub.add_parser("synth", help="Synthesize a candidate kernel reproducer.")
    ps.add_argument("--bucket-dir", default=None)
    ps.add_argument("--log0", default=None)
    ps.add_argument("--crash-class", default=None)
    ps.add_argument("--description", default=None)
    ps.add_argument("--subsystem", default=None)
    ps.add_argument("--manager-cfg", default=None)
    ps.add_argument("--out", required=True)

    pr = sub.add_parser("replay", help="Measure reproducibility by booting N times.")
    pr.add_argument("--qemu-script", required=True)
    pr.add_argument("--runs", type=int, default=3)
    pr.add_argument("--target-signature", default=None)
    pr.add_argument("--timeout-seconds", type=int, default=120)
    pr.add_argument("--unit", default="kernelctf-historical")
    pr.add_argument("--log-path", default=None)
    pr.add_argument("--build-id", default="")
    pr.add_argument("--out", required=True)

    args = ap.parse_args()
    if args.cmd == "synth":
        res = synthesize_kernel_reproducer(
            bucket_dir=Path(args.bucket_dir) if args.bucket_dir else None,
            log0=Path(args.log0) if args.log0 else None,
            crash_class=args.crash_class, description=args.description,
            subsystem_hint=args.subsystem,
            manager_cfg=Path(args.manager_cfg) if args.manager_cfg else None)
        payload = res.to_dict()
        ok = res.status in (SYNTH_OK, SYNTH_REUSED)
    else:
        v = measure_kernel_reproducibility(
            Path(args.qemu_script), runs=args.runs,
            target_signature=args.target_signature, timeout_seconds=args.timeout_seconds,
            unit=args.unit, log_path=Path(args.log_path) if args.log_path else None,
            build_id=args.build_id)
        payload = v.to_dict()
        ok = v.verdict == "reproducible"

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2))
    print(json.dumps(payload, indent=2))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(_cli())
