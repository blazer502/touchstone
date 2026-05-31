"""Whole-TU per-function harness (P0 of docs/whole-tu-compile-scope.md).

Clears the slice-lowering compile wall (6.7% on real projects) by compiling the
*real translation unit* with its real headers instead of harvesting a type
closure. The harness `#include`s the target's `.c` — which (a) brings in every
real type/macro/struct (no harvesting), and (b) makes a `static` target visible
(a separate linked harness can't call a static function). Params are modeled
soundly with `malloc(sizeof(*p))` (one valid object per pointer — no struct tag
needed, the compiler knows the size) plus the byte-buffer/endptr/length contract.

A single safe `docker run` does `goto-cc … && cbmc …` with the memory cap +
in-container timeout from cbmc_driver (see [[feedback-cbmc-docker-timeout]]).
Returns a verdict object shaped like Tier3Verdict so the existing
`perfn_cbmc_proposer.run_one` classification (soundness guards, cex extraction)
works unchanged.
"""
from __future__ import annotations

import json
import re
import shlex
import subprocess
import time
from pathlib import Path
from types import SimpleNamespace

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from surface import stage_b as _stage_b                                # noqa: E402
from oracle.tier3_bmc.cbmc_driver import (_extract_pov,                 # noqa: E402
                                          _extract_target_location,
                                          CBMC_MEM_LIMIT)
from tools.perfn_lower import extract_function_body, _clean_body, parse_params  # noqa: E402
from tools.perfn_cbmc_proposer import buffer_model                     # noqa: E402

# Iterative compile-repair (P2 build-flag acquisition): goto-cc the harness;
# on failure, harvest the compiler's own "undeclared identifier" / "unknown type
# name" errors and synthesize exactly those defines/typedefs (the dominant
# whole-TU failure is undefined config.h macros like PACKAGE_VERSION), then
# retry. Bounded iterations; stops early when a round adds nothing (the error
# isn't define-fixable). This learns the build flags from the compiler instead
# of guessing HAVE_*/running ./configure. CAVEAT: a config macro that's really a
# size/value gets `0`, which can skew a verdict — repaired-TU verdicts are
# lower-confidence until a real config.h is used; the bridge oracle is still the
# final word, so a wrong confirm just fails to reproduce.
_REPAIR_TMPL = r''': > /work/auto_defs.h
ok=0
for i in 1 2 3 4 5 6; do
  if goto-cc @IDIRS@ -include /work/auto_defs.h -w -c /work/harness.c -o /work/h.gb 2>/work/gcc.err; then ok=1; break; fi
  before=$(wc -l < /work/auto_defs.h)
  grep -oE "'[A-Za-z_][A-Za-z0-9_]*' undeclared" /work/gcc.err | tr -d "'" | awk '{print $1}' | sort -u | while read n; do echo "#define $n 0" >> /work/auto_defs.h; done
  grep -oE "failed to find symbol '[A-Za-z_][A-Za-z0-9_]*'" /work/gcc.err | sed "s/.*'\(.*\)'/\1/" | sort -u | while read n; do echo "#define $n 0" >> /work/auto_defs.h; done
  grep -oE "unknown type name '[A-Za-z_][A-Za-z0-9_]*'" /work/gcc.err | sed "s/.*'\(.*\)'/\1/" | sort -u | while read n; do echo "typedef long $n;" >> /work/auto_defs.h; done
  after=$(wc -l < /work/auto_defs.h)
  [ "$before" = "$after" ] && break
done
if [ "$ok" != 1 ]; then echo PF_COMPILE_FAIL; head -c 1500 /work/gcc.err; exit 0; fi
timeout -s KILL @TIMEOUT@ cbmc /work/h.gb --function __pf_harness_main --unwind @UNWIND@ --unwinding-assertions --trace @FLAGS@
'''


# property family -> CBMC flags (mirrors cbmc_driver.flag_map; leak/cleanup
# deliberately omitted — they false-confirm on allocators).
_FLAGS = {
    "no-oob": ["--bounds-check", "--pointer-check", "--pointer-overflow-check"],
    "no-uaf": ["--pointer-check"],
    "no-overflow": ["--signed-overflow-check", "--unsigned-overflow-check",
                    "--conversion-check"],
}


def signature(source_root: Path, tu_rel: str, func: str):
    fp = source_root / tu_rel
    ext = extract_function_body(fp, func)
    if not ext:
        return None
    _raw, start = ext
    body = _clean_body(fp, start)
    if not body:
        return None
    sig = body.split("{", 1)[0].strip()
    return sig, parse_params(sig)


def _setup(params: list[tuple[str, str]]) -> tuple[list[str], set[str]]:
    """Sound whole-TU param model: byte buffers via buffer_model; every other
    pointer param gets one valid heap object (malloc(sizeof(*p)), assumed
    non-null) so a deref of the param is never a spurious 'bug'."""
    bufset, modeled = buffer_model(params)
    extra = []
    for ty, nm in params:
        if nm in modeled:
            continue
        if ty.strip().endswith("*"):
            extra.append(f"{nm} = malloc(sizeof(*{nm})); __CPROVER_assume({nm} != 0);")
            modeled.add(nm)
    return bufset + extra, modeled


def gen_harness(tu_container_path: str, func: str,
                params: list[tuple[str, str]]) -> str:
    decls = "\n    ".join(f"{ty} {nm};" for ty, nm in params)
    setup, _ = _setup(params)
    setup_s = "\n    ".join(setup)
    args = ", ".join(nm for _, nm in params)
    return f"""#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include "{tu_container_path}"

int __pf_harness_main(void) {{
    {decls}
    {setup_s}
    {func}({args});
    return 0;
}}
"""


def _include_dirs(root: Path, cap: int = 300) -> list[str]:
    dirs: set[Path] = set()
    for h in root.rglob("*.h"):
        dirs.add(h.parent)
        if len(dirs) >= cap:
            break
    return [str(d.resolve().relative_to(root.resolve())) for d in sorted(dirs)]


def run_whole_tu(source_root: Path, tu_rel: str, func: str, *,
                 property: str, extra_flags: list[str] | None,
                 unwind: int, timeout_s: int, out_dir: Path):
    unit = f"{tu_rel}::{func}"
    sigp = signature(source_root, tu_rel, func)
    if not sigp:
        return SimpleNamespace(verdict="inconclusive", wall_ms=0, pov_path=None,
                               target_location=None,
                               evidence_excerpt="signature-parse-failed")
    _sig, params = sigp

    root = source_root.resolve()
    work = (out_dir / f"wt_{func}").resolve()
    work.mkdir(parents=True, exist_ok=True)
    (work / "config.h").write_text("")          # permissive stub if project lacks one
    tu_in = f"/src/{tu_rel}"
    (work / "harness.c").write_text(gen_harness(tu_in, func, params))

    idirs = [f"-I/src/{d}" for d in _include_dirs(root)] + ["-I/src", "-I/work"]
    flags = _FLAGS.get(property, _FLAGS["no-oob"]) + list(extra_flags or [])
    inner = (_REPAIR_TMPL
             .replace("@IDIRS@", " ".join(idirs))
             .replace("@TIMEOUT@", str(timeout_s))
             .replace("@UNWIND@", str(unwind))
             .replace("@FLAGS@", " ".join(flags)))
    container = f"cbmcwt-{func[:20]}-{int(time.monotonic()*1e6)}"
    cmd = (shlex.split(_stage_b.DOCKER)
           + ["run", "--rm", "--name", container,
              "--memory", CBMC_MEM_LIMIT, "--memory-swap", CBMC_MEM_LIMIT,
              "-v", f"{root}:/src:ro", "-v", f"{work}:/work",
              _stage_b.CBMC_IMG, "sh", "-c", inner])

    t0 = time.monotonic()
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout_s + 30)
        out = (r.stdout or "") + "\n" + (r.stderr or "")
        killed = r.returncode in (124, 137)
    except subprocess.TimeoutExpired as e:
        subprocess.run(shlex.split(_stage_b.DOCKER) + ["kill", container],
                       capture_output=True)
        out = ((e.stdout or b"").decode(errors="replace") if isinstance(e.stdout, bytes)
               else (e.stdout or "")) + "\n(outer-timeout)"
        killed = True
    wall_ms = int((time.monotonic() - t0) * 1000)

    if "PF_COMPILE_FAIL" in out:
        err = out.split("PF_COMPILE_FAIL", 1)[1].strip()[:300]
        return SimpleNamespace(verdict="inconclusive", wall_ms=wall_ms, pov_path=None,
                               target_location=None,
                               evidence_excerpt=f"compile-failed: {err}")

    pov_path = None
    target = None
    if killed:
        verdict = "inconclusive"
    elif _stage_b._CBMC_OK.search(out):
        verdict = "safe"
    elif _stage_b._CBMC_UNWIND_FAIL.search(out):
        verdict = "inconclusive"
    elif _stage_b._CBMC_VIOLATED.search(out):
        verdict = "unsafe"
        target = _extract_target_location(out)
        pov = _extract_pov(out)
        pf = out_dir / f"{func}.cbmc-pov.json"
        pf.write_text(json.dumps({"engine": "cbmc", "source": unit,
                                  "function": func, "property": property,
                                  "unwind": unwind, "target_location": target,
                                  "assignment": pov}, indent=2))
        pov_path = str(pf)
    else:
        verdict = "inconclusive"

    tail = "\n".join(ln for ln in out.splitlines() if ln.strip())[-4000:]
    return SimpleNamespace(verdict=verdict, wall_ms=wall_ms, pov_path=pov_path,
                           target_location=target, evidence_excerpt=tail)


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Whole-TU per-function CBMC (P0)")
    ap.add_argument("source_root")
    ap.add_argument("tu_rel")
    ap.add_argument("func")
    ap.add_argument("--property", default="no-oob")
    ap.add_argument("--unwind", type=int, default=16)
    ap.add_argument("--timeout-s", type=int, default=60)
    ap.add_argument("--out", default="run-logs/perfn-wt")
    a = ap.parse_args()
    od = Path(a.out)
    od.mkdir(parents=True, exist_ok=True)
    v = run_whole_tu(Path(a.source_root), a.tu_rel, a.func,
                     property=a.property, extra_flags=None, unwind=a.unwind,
                     timeout_s=a.timeout_s, out_dir=od)
    print(f"verdict={v.verdict} wall_ms={v.wall_ms} target={v.target_location} "
          f"pov={v.pov_path}")
    if v.verdict not in ("safe", "unsafe"):
        print("evidence:", v.evidence_excerpt[:400])
