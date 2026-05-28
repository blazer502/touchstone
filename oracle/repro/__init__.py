"""Crash-reproducer pipeline (R-track).

Turns a raw crash signal into a reproducibility-scored, minimized, portable
reproducer. See ``schemas/reproducer.py`` for the data model and
``oracle/repro/pipeline.py`` for the orchestrator + CLI.

R1 (this drop) implements the userspace backend (libFuzzer-shaped harnesses:
local binary + in-container CyberGym OSS-Fuzz). The kernel backend (syz-repro
-> prog2c -> N-times VM re-run) is R2/R3.
"""
