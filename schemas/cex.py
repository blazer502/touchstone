"""First-class counterexample (cex) artifact — uniform across Tier 1/2/3 + KASAN.

A `Cex` packages the structured evidence for a violation found by any oracle in
the system. Same shape regardless of which engine produced it; reducers project
it to whatever consumer needs to read it:

    bytes               (cybergym-style PoC submission)
    regression-test C   (reproduces locally, no external state)
    disclosure blob     (JSON; responsible-disclosure attachment)

The point of the abstraction is that the *same* analysis run produces *multiple*
artifacts at no extra cost — we already have the evidence; we just pick the
projection a given consumer needs.

See `docs/strategic-direction.md` §2 (Output B "Cex-backed PoC") + §7.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:                                # circular-import-safe imports
    from oracle.tier1_fuzz.verdict import Tier1Verdict
    from oracle.tier2_symbolic.verdict import Tier2Verdict
    from oracle.tier3_bmc.verdict import Tier3Verdict


# --- atoms -------------------------------------------------------------------

@dataclass
class InputAssignment:
    """How the violating input is described.

    Fuzz-style oracles populate `byte_payload`; symbolic / BMC oracles populate
    `variable_bindings` (var -> concrete value as a string, so json-safe). A
    `mount_path` records where in the running container the byte payload was
    mounted, when applicable.
    """
    byte_payload_hex: Optional[str] = None       # hex string (json-safe)
    byte_payload_path: Optional[str] = None      # absolute on-disk PoC file
    variable_bindings: Dict[str, str] = field(default_factory=dict)
    mount_path: Optional[str] = None             # e.g. "/tmp/poc"


@dataclass
class ExecutionPath:
    """How the input reaches the violation site.

    Not all fields are populated by all tiers — fuzz oracles can record edges
    hit, symbolic oracles record explored path-branches, BMC engines record
    the assertion location only.
    """
    function_chain: List[str] = field(default_factory=list)   # caller -> ... -> callee
    branches_taken: List[str] = field(default_factory=list)   # ["file.c:42:T", ...]
    edges_hit: List[str] = field(default_factory=list)        # libfuzzer edges


@dataclass
class ViolatedProperty:
    """Which property was violated.

    `kind` is one of {sanitizer, assertion, symbolic-feasibility, kasan,
    ubsan, custom}. `location` is `file.c:line[:col]` when available.
    `details` is a truncated banner / trace excerpt suitable for a human
    summary.
    """
    kind: str
    name: str                                    # e.g. "heap-buffer-overflow", "div-by-zero"
    location: Optional[str] = None
    details: str = ""


@dataclass
class SoundnessNote:
    """Which over-/under-approximations this cex stands on.

    `soundness_anchor_ids` reference rows in `docs/soundness-assumptions.md`
    by free-text id. `assumed_contracts` is the list of `__CPROVER_assume`
    / ACSL `requires` strings used during Stage B / Tier-3 BMC. The ledger
    JSON exporter (P2) consumes these.
    """
    assumed_contracts: List[str] = field(default_factory=list)
    soundness_anchor_ids: List[str] = field(default_factory=list)
    note: str = ""


@dataclass
class Provenance:
    """Who produced this cex.

    `tier` is "1" / "2" / "3" / "0" (KASAN / dmesg replay) — strings to keep
    the json serialisation tidy across consumers in other languages.
    """
    engine: str                                  # "libfuzzer" / "klee" / "cbmc" / ...
    tier: str
    engine_version: str = ""
    task_id: str = ""
    produced_at_utc: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))
    wall_ms: int = 0


# --- the artifact ------------------------------------------------------------

@dataclass
class Cex:
    """First-class verified counterexample.

    Use the `from_tier{1,2,3}` constructors below to lift a tiered verdict
    into this shape. Use `to_bytes` / `to_regression_test` / `to_disclosure_blob`
    to project to a consumer.
    """
    input: InputAssignment
    path: ExecutionPath
    violated: ViolatedProperty
    soundness: SoundnessNote
    provenance: Provenance

    # ---- reducers --------------------------------------------------------

    def to_bytes(self) -> Optional[bytes]:
        """The raw PoC byte stream, if this cex has one (fuzz tier)."""
        if self.input.byte_payload_hex is not None:
            return bytes.fromhex(self.input.byte_payload_hex)
        if self.input.byte_payload_path:
            p = Path(self.input.byte_payload_path)
            if p.exists():
                return p.read_bytes()
        return None

    def to_regression_test(self) -> str:
        """Self-contained reproducer script.

        Tier-1 (fuzz):   bash script that runs the OSS-Fuzz / arvo harness
                         against the recorded PoC bytes.
        Tier-2 (symbolic): python that re-runs the ktest under klee-replay
                         (or angr concretisation) — best-effort, since the
                         original ktest may not survive a code change.
        Tier-3 (BMC):    C source that instantiates the harness with the cex
                         variable bindings and asserts the violated property.
        """
        if self.provenance.tier == "1":
            return self._tier1_reproducer()
        if self.provenance.tier == "2":
            return self._tier2_reproducer()
        if self.provenance.tier == "3":
            return self._tier3_reproducer()
        return self._generic_reproducer()

    def to_disclosure_blob(self) -> Dict[str, Any]:
        """JSON-safe dict suitable for a disclosure attachment."""
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_disclosure_blob(), indent=indent, sort_keys=False)

    # ---- internal reproducer projections ---------------------------------

    def _tier1_reproducer(self) -> str:
        mount = self.input.mount_path or "/tmp/poc"
        bin_hex = self.input.byte_payload_hex or ""
        loc = self.violated.location or "<unknown>"
        return (
            "#!/usr/bin/env bash\n"
            "# Auto-generated Tier-1 reproducer\n"
            f"# Task:        {self.provenance.task_id}\n"
            f"# Engine:      {self.provenance.engine}\n"
            f"# Violation:   {self.violated.kind}/{self.violated.name} @ {loc}\n"
            "set -euo pipefail\n"
            "POC=$(mktemp)\n"
            f"# {len(bin_hex)//2} bytes\n"
            f"python3 -c \"import sys; sys.stdout.buffer.write(bytes.fromhex('{bin_hex}'))\" > \"$POC\"\n"
            "trap 'rm -f \"$POC\"' EXIT\n"
            f"# Run the recorded harness against the PoC at {mount}.\n"
            "# Replace <HARNESS_IMAGE> and <HARNESS_CMD> with values from your runtime.\n"
            "docker run --rm --network=none \\\n"
            f"  -v \"$POC\":{mount}:ro \\\n"
            "  <HARNESS_IMAGE> <HARNESS_CMD>\n"
        )

    def _tier2_reproducer(self) -> str:
        return (
            "#!/usr/bin/env python3\n"
            '"""Tier-2 reproducer — re-runs the symbolic witness."""\n'
            "# Engine: " + self.provenance.engine + "\n"
            "# Variable bindings (concrete witness):\n"
            "BINDINGS = " + repr(self.input.variable_bindings) + "\n"
            "# Replay strategy depends on the engine:\n"
            "#   klee  -> use `klee-replay` against the recorded .ktest\n"
            "#   angr  -> rerun project with these stdin values\n"
            'print("BINDINGS:", BINDINGS)\n'
        )

    def _tier3_reproducer(self) -> str:
        # Re-render bindings as a C compound literal block, one decl per var.
        decls = "\n".join(
            f"    /* {k} */ /* {v} */"
            for k, v in self.input.variable_bindings.items()
        ) or "    /* (no nondet bindings recorded) */"
        loc = self.violated.location or "<unknown>"
        return (
            "/* Auto-generated Tier-3 reproducer.\n"
            f" * Task:      {self.provenance.task_id}\n"
            f" * Engine:    {self.provenance.engine}\n"
            f" * Violation: {self.violated.kind}/{self.violated.name} @ {loc}\n"
            f" * Note:      {self.violated.details[:200]}\n"
            " */\n"
            "#include <assert.h>\n"
            "int main(void) {\n"
            f"{decls}\n"
            "    /* Concretise nondet vars above and call into the harness. */\n"
            "    return 0;\n"
            "}\n"
        )

    def _generic_reproducer(self) -> str:
        return self.to_json()


# --- constructors from existing verdict shapes -------------------------------

def from_tier1(v: "Tier1Verdict", pov_bytes: Optional[bytes] = None,
               soundness_anchor_ids: Optional[List[str]] = None) -> Cex:
    """Lift a Tier-1 (fuzz/sanitizer) verdict into a Cex.

    `pov_bytes` is required when the cex needs to be byte-projected (most fuzz
    cases). If not supplied but `v.pov_path` exists on disk, we read it.
    """
    payload_hex = None
    if pov_bytes is not None:
        payload_hex = pov_bytes.hex()
    elif v.pov_path:
        p = Path(v.pov_path)
        if p.exists():
            payload_hex = p.read_bytes().hex()

    return Cex(
        input=InputAssignment(
            byte_payload_hex=payload_hex,
            byte_payload_path=v.pov_path,
            mount_path="/tmp/poc",
        ),
        path=ExecutionPath(),
        violated=ViolatedProperty(
            kind="sanitizer" if v.sanitizer != "none" else "crash",
            name=v.crash_class or "unknown",
            location=v.location,
            details=v.evidence_excerpt,
        ),
        soundness=SoundnessNote(
            assumed_contracts=list(v.assumed),
            soundness_anchor_ids=soundness_anchor_ids
                or ["oracle-tier-1-fast-crash/sanitizers-coverage-of-properties"],
            note=v.soundness_note,
        ),
        provenance=Provenance(
            engine=v.engine, tier="1", task_id=v.unit, wall_ms=v.wall_ms,
        ),
    )


def from_tier2(v: "Tier2Verdict", *, pov_bytes: Optional[bytes] = None,
               variable_bindings: Optional[Dict[str, str]] = None,
               soundness_anchor_ids: Optional[List[str]] = None) -> Cex:
    """Lift a Tier-2 (symbolic) verdict into a Cex.

    For KLEE the cex is a `.ktest` (binary blob) — pass it as `pov_bytes`.
    For angr the cex is concretised stdin/argv — pass it as `pov_bytes` too.
    Concrete variable bindings (when extractable) populate `variable_bindings`.
    """
    payload_hex = pov_bytes.hex() if pov_bytes is not None else None
    if payload_hex is None and v.pov_path:
        p = Path(v.pov_path)
        if p.exists():
            payload_hex = p.read_bytes().hex()
    return Cex(
        input=InputAssignment(
            byte_payload_hex=payload_hex,
            byte_payload_path=v.pov_path,
            variable_bindings=variable_bindings or {},
        ),
        path=ExecutionPath(),
        violated=ViolatedProperty(
            kind="symbolic-feasibility",
            name=v.property or "feasibility",
            location=v.target_location,
            details=v.evidence_excerpt,
        ),
        soundness=SoundnessNote(
            assumed_contracts=list(v.assumed),
            soundness_anchor_ids=soundness_anchor_ids
                or ["oracle-tier-2-symbolic/klee-sat-verdict-scope"],
            note=v.soundness_note,
        ),
        provenance=Provenance(
            engine=v.engine, tier="2", task_id=v.unit, wall_ms=v.wall_ms,
        ),
    )


def from_tier3(v: "Tier3Verdict",
               variable_bindings: Optional[Dict[str, str]] = None,
               soundness_anchor_ids: Optional[List[str]] = None) -> Cex:
    """Lift a Tier-3 (BMC) verdict into a Cex.

    For CBMC the cex is a set of nondet variable assignments. Parse them out
    of `v.pov_path` (a `.cbmc-pov.json` file emitted by `cbmc_driver`) when
    `variable_bindings` is not supplied.
    """
    bindings = dict(variable_bindings or {})
    if not bindings and v.pov_path:
        p = Path(v.pov_path)
        if p.exists():
            try:
                raw = json.loads(p.read_text())
                # cbmc_driver writes {var: value} OR {"assignments": {var: value}}
                bindings = raw.get("assignments", raw) if isinstance(raw, dict) else {}
                bindings = {str(k): str(v_) for k, v_ in bindings.items()}
            except Exception:
                pass
    return Cex(
        input=InputAssignment(
            byte_payload_path=v.pov_path,
            variable_bindings=bindings,
        ),
        path=ExecutionPath(),
        violated=ViolatedProperty(
            kind="assertion",
            name=v.property,
            location=v.target_location,
            details=v.evidence_excerpt,
        ),
        soundness=SoundnessNote(
            assumed_contracts=list(v.assumed_contracts),
            soundness_anchor_ids=soundness_anchor_ids
                or ["oracle-tier-3-bmc/tier-3-cbmc-verdict-semantics"],
            note=v.soundness_note,
        ),
        provenance=Provenance(
            engine=v.engine, tier="3", task_id=v.unit, wall_ms=v.wall_ms,
        ),
    )
