"""Tier-3 BMC oracle (PLAN §3 Tier-3).

CBMC/ESBMC return a definite bounded yes/no on a hypothesis when Tiers 1-2 are
inconclusive. Engine is shared with Stage B (`surface/stage_b.py`); the Tier-3
wrapper repackages the verdict for the oracle pipeline and extracts the
counterexample assignment as a PoV when the verdict is `unsafe`.
"""
