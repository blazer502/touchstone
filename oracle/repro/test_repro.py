"""R1 validation — local synthetic positive control (no docker).

Builds the deterministic heap-OOB libFuzzer harness, scores reproducibility,
and checks the pipeline:
  - repro_rate == 1.0 (deterministic crash)
  - verdict == 'reproducible'
  - minimization shrinks a 4096-byte trigger toward the 17-byte minimum while
    preserving the crash signature

Run:  python3 -m oracle.repro.test_repro
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

from oracle.tier1_fuzz.userspace import build_libfuzzer
from oracle.repro.pipeline import run_userspace_local

HARNESS_SRC = Path(__file__).resolve().parents[1] / "tier1_fuzz" / "harnesses" / "synthetic_heap_oob.c"


def main() -> int:
    work = Path(tempfile.mkdtemp(prefix="repro-test-"))
    harness_bin = work / "synthetic_heap_oob.bin"
    build_libfuzzer(HARNESS_SRC, harness_bin, "ASan")

    # 4096-byte trigger: size >= 17 fires buf[size-1] past a malloc(16) chunk.
    poc = work / "poc"
    poc.write_bytes(b"\x41" * 4096)

    v = run_userspace_local(harness_bin, poc, sanitizer="ASan", runs=8,
                            minimize=True, unit="synthetic_heap_oob", out_dir=work)

    print(f"verdict={v.verdict} repro_rate={v.repro_rate} sig={v.signature}")
    r = v.reproducer
    assert v.verdict == "reproducible", f"expected reproducible, got {v.verdict}"
    assert v.repro_rate == 1.0, f"expected repro_rate 1.0, got {v.repro_rate}"
    assert "heap-buffer-overflow" in v.signature, f"unexpected signature {v.signature}"
    assert r is not None and r.minimized, "expected minimization to succeed"
    print(f"minimized {r.original_size_bytes} -> {r.minimized_size_bytes} bytes "
          f"(min crashing size is 17)")
    assert r.minimized_size_bytes < r.original_size_bytes, "minimization did not shrink"
    print("PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
