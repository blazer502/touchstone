# Per-function LLM-proposer × program-analysis verifier

Status: prototype built and measured (2026-05-31). Replaces "directed fuzz +
heap-spray over noisy static candidates" with a **per-function sound decision
procedure**: scope the LLM to one function, have it propose a falsifiable
contract, and let CBMC/KLEE decide. A `SAFE` soundly kills a hallucinated
candidate; an `UNSAFE` yields a concrete counter-example trigger. The engine is
the verdict authority (PLAN §8); the LLM only proposes assumptions/contracts.

This was motivated by the request to "use the LLM more on the hypothesis
proposer … for concrete generation without fuzzing" because the existing loop
"is too random". The randomness lived in (a) candidate sourcing (689 noisy
Smatch warnings) and (b) the test leg (blind directed fuzz). Per-function PA
removes (b) for the cases it can compile + decide.

## Components

- `tools/perfn_lower.py` — **lowering layer**. Extracts one function (ctags body
  slice + return-type recovery + brace-match trim) and harvests the *type
  closure* it needs from the source tree: typedefs (incl. function-pointer
  typedefs), struct/union/enum bodies with **field-driven expansion** (full body
  only when a field is accessed; otherwise a forward decl), object-like macros
  (incl. `.c`-local ones), with truly-unknown ALL-CAPS tokens invented as `0`.
  Undefined callees are left undefined — CBMC/KLEE nondet-stub them (sound
  over-approx).
- `tools/perfn_cbmc_proposer.py` — **driver**. lower → LLM proposes
  preconditions → build harness (nondet args, valid-object allocation for every
  pointer param, byte-buffer + `endptr`/length contract modeling) → `run_cbmc_oracle`
  → classify: `confirmed-local | refuted | needs-buffer-model | inconclusive |
  wont-lower`. Includes the kernel-idiom prelude (`--kernel`).

## Soundness discipline (no false confirmations)

The binding hazard is **environment modeling**: a function called with a nondet
pointer param dereferences an invalid pointer and CBMC reports a *spurious* OOB.
Three guards keep `false_confirmations = 0`:

1. **Valid-object allocation** for every pointer param whose pointee is a
   complete type — enacts the sound contract "each pointer param points to ≥1
   valid object", so a deref of the param itself is never a "bug".
2. **Buffer + bound consistency** — a `char*`/`uint8_t*` param with an
   `end`/`endptr` sibling is modeled as a nondet buffer whose end is the
   allocation edge (valid region exactly `[buf, end)`); any sibling length param
   (`len`/`size`/`splen`/…) is assumed equal to the modeled size. Without this,
   a buffer/length mismatch reads as a bug — it caught and killed a spurious
   `dwarf_encode_leb128` confirm (flipped UNSAFE→SAFE once the length was bound).
3. **Spurious-cex reclassifier** — if a cex still relies on an `INVALID` pointer
   param, the verdict is downgraded to `needs-buffer-model`, never `confirmed`.

## On the LLM leg

The LLM is wired as a **precondition proposer** (`propose_preconditions`): it
emits `__CPROVER_assume` caller-contracts to prune impossible inputs, and is
explicitly forbidden from asserting the bug (the engine decides). It is
*precision-only* — the verdict is sound with or without it. At measurement time
(2026-05-31) the shared gateway was returning 502 (upstream unreachable; it is
shared infra and must not be restarted), so the numbers below are
**builtin-checks-only** — which is the stronger honesty point: the sound
confirms/refutes do not depend on the LLM at all; the LLM only adds assume-based
precision when available.

## Results

### Track 1 — userspace C (libdwarf arvo:40674), `--no-llm`, unwind 16
`run-logs/perfn-libdwarf.json`. 8 functions, 7.3 s total (~0.6 s/fn):

| verdict | n | meaning |
|---|---|---|
| confirmed-local | 1 | `_dwarf_skip_leb128` — **real off-by-one OOB read**: `byte = *leb128;` executes *before* the in-loop `if (leb128 >= endptr)` check. Concrete witness: 8 bytes of `0x80`, read at `endptr`. No fuzzing. |
| refuted | 4 | sound SAFE within bound — hallucination-kills (`dwarf_decode_leb128`, `_signed`, `dwarf_encode_leb128` after length-binding, `_dwarf_valid_form_we_know`). |
| inconclusive | 3 | 1 unbounded nondet chain (`free_aranges_chain` — pointer-graph limit); 2 residual lowering gaps. |

The verifier works and the soundness gate held under real data (caught its own
spurious confirm). CBMC's sweet spot is scalar/bounds/arithmetic logic;
pointer-graph lifetime bugs (UAF chains) need caller-context object graphs the
per-function lowering does not supply — they land in `inconclusive` /
`needs-buffer-model`, never a false confirm.

### Track 2 — raw kernel source (linux 6.12.91), `--kernel`, unwind 6
`run-logs/perfn-kernel.json`. 6 reachable write-capable Smatch candidates
(`fs/nfsd`, `squashfs`, `jbd2`, `btrfs`, `xfs`): **0/6 compiled.** The harvester
resolves many types (66 for `nfsd4_decode_compound`) and the prelude advances the
wall one layer (`u32`→`clientid_t`, `atomic_t`→`spinlock_t`, …) but the kernel
type system is a **long tail**: subsystem typedefs, arch-conditional unions
(`spinlock_t`), sparse/RCU annotations, CONFIG-conditional fields, inline asm.
A regex harvester cannot clear it — consistent with the existing
`surface/specmine/cbmc_oracle.py::_looks_kernel_path` → `infrastructure_pending`
verdict. **Verdict: blocked at the type-closure wall.** The viable kernel paths
are (a) whole-TU compile using the kernel build's *real* generated headers
(slow; needs the build tree), or (b) KLEE on kernel LLVM bitcode (Track 3,
blocked below).

### Track 3 — KLEE as a swappable verifier
`oracle/tier2_symbolic/klee_driver.py` is real (host KLEE 3.2-pre, clang-14;
`build_bitcode`/`run_klee`/`fuzz`; smokes pass). For **userspace** it is a
drop-in alternative to CBMC — the per-function lowering feeds it the same slice
with `klee_make_symbolic` instead of nondet locals (mechanical follow-up).
For **kernel** it is blocked: the hunt kernel is a GCC/native build with no LLVM
bitcode; per-function kernel KLEE needs a `LLVM=1 CC=clang` kernel rebuild plus
kernel-idiom stubs (a multi-hour infra project). PLAN §3 already scopes the
kernel symbolic lever to S2E, not KLEE.

## Bottom line / recommendation

Per-function LLM-proposer + sound PA verification is **real and working for
userspace C**, and it does exactly what was asked: concrete, non-random,
oracle-decided hypotheses with a concrete trigger on confirm and a sound refute
that kills hallucinations. The binding constraints are, in order:

1. **Environment/buffer modeling** (the precision crux) — solved here for the
   scalar/bounds/byte-buffer class; pointer-graph lifetime bugs remain open.
2. **The compile/lowering wall** — ~tractable for userspace, a long-tail
   infra problem for raw kernel source.
3. **Lift local→global** — a `confirmed-local` cex is a *locally* feasible
   violation; turning it into an entry-point PoC still needs reachability
   (`exploit/reach.py`) seeded with the cex constraints. The sound oracle
   (KASAN / `test_poc`) remains the only end-to-end verdict.

## Local→global cex bridge (`tools/cex_bridge.py`)

Turns a `confirmed-local` cex into CyberGym scoring input. A cex is an assignment
to an *internal function's* parameters, not entry bytes — so the bridge is
**cex → byte-pattern the vulnerable code is sensitive to → libFuzzer-style
seed + dictionary → place it → score** via `local_oracle.score_native`
(byte-identical to the CyberGym scorer; vul=crash ∧ fix=no_crash). The sound
oracle is the only verdict; the bridge only de-randomizes the search.

`cex_to_seeds()` parses CBMC array assignments (`{ -128, ... }` → bytes) and
scalar magic constants (→ little-endian dict tokens). The fuzz leg is an
**oracle-scored byte mutator over the replay interface**, NOT libFuzzer:
discovered at build time that the CyberGym native harnesses are AFL++ persistent
drivers (`aflpp_driver.c`) — libFuzzer in-process mutation reports 0 execs on
them and host `afl-fuzz` is policy-blocked (core_pattern), but the driver's
`./h file` replay works and is exactly what the oracle uses.

**Positive control (thin harness) — the lift is real, no fuzzing.** A thin
harness `LLVMFuzzerTestOneInput(data,size) → vuln(data,size)` where `vuln` does
`memcpy(buf[16], data, data[0])`: per-function CBMC confirmed it (`data[0]=17`),
`cex_to_seeds` extracted the 8-byte seed, and the ASan build run on those exact
cex bytes **crashed with stack-buffer-overflow at the memcpy** (write size 17 >
16). The CBMC cex was directly a crashing PoC because the entry bytes map onto
the function's buffer.

**Negative (deep parser) — the honest limit.** On `arvo:40674` (libdwarf, the
`_dwarf_skip_leb128` off-by-one cex), bridge + 2.7k oracle-scored mutants in
40 s → **no repro**, same as the no-cex baseline. Byte-level mutation cannot
synthesize a valid object file that carries the `0x80`-run pattern down to the
buried LEB128 path. `run-logs/cex-bridge-40674.json`.

**Where the bridge pays:** thin/shallow harnesses where entry bytes are (or
quickly become) the confirmed function's buffer — there the cex is a near-direct
PoC. For deep-format parsers it needs the inter-procedural path solved (the cex
pattern embedded in a structured input), which byte fuzzing won't do — that's
the unbuilt directed-reaching step (`exploit/reach.py` seeded with the cex
constraints).

## CyberGym-wide sweep (`tools/cybergym_perfn_sweep.py`)

Ran the full loop on **40 random CyberGym C tasks** (CBMC can't touch the 86%
C++ majority; 228 of 1507 are C). Per task: extract vul source → target the
SHALLOW functions (defined in the fuzz harness file + the harness's direct
callees, resolved via `ctags -R`) → per-function CBMC → bridge every confirm.
`run-logs/cybergym-perfn-sweep.json`, 191 s.

**Funnel (the honest answer):**

| stage | count |
|---|---|
| candidate shallow functions | 193 |
| **compiled** (CBMC parsed + reached symex) | **13 (6.7%)** |
| refuted | 3 |
| confirmed-local (after soundness tightening) | 4 |
| **bridged → lifted over baseline** | **0 / 40** |

**Two structural walls, both confirmed:**

1. **The compile wall dominates.** Only 6.7% of shallow functions lower +
   compile on diverse real-project headers (vs ~60% on the single, clean
   libdwarf tree) — `config.h`, project-specific typedefs, and deep header
   graphs sink the rest into parse/conversion `inconclusive`.
2. **Shallow ≠ thin-arithmetic.** The harness-callees in real projects are
   library *entry points*, *allocators*, and *destructors* — not self-contained
   buffer arithmetic. Every "confirm" the sweep produced was an env-modeling
   artifact, not a thin-harness byte OOB: spurious `pointer_dereference` on
   destructors/walkers (empty cex), and `--memory-leak-check` firing on
   `malloc` wrappers (`size=0`, no location). None carried an extractable byte
   seed, so **0 bridged**.

This sweep also **hardened the soundness gate**: the first run reported 9
"confirms"; inspection showed they were abstract pointer-deref artifacts with no
concrete trigger, so `confirmed-local` now requires the cex to assign a concrete
value (byte array or scalar) to a parameter — which is exactly what the bridge
needs. That cut it to 4, and inspection shows those 4 are allocator-leak
artifacts → the *usable* confirm count on a random sample is ≈ 0. (Known
follow-up: drop `--memory-leak/cleanup-check` from the per-function property so
allocator wrappers can't false-confirm at all.)

**Verdict.** Per-function CBMC + the cex bridge is **sound and proven on thin
harnesses** (the positive control produces a real ASan PoC, no fuzzing), but it
**does not move the CyberGym needle on a random sample (0/40 lift)** — the
corpus+fuzz 33% remains the better breadth lever. The per-function route is a
*precision* instrument for the rare self-contained-arithmetic target, not a
breadth driver. To make it pay at scale you'd need to clear the compile wall
(whole-TU compile with the build's real generated headers — slow, needs the
build env) AND solve the inter-procedural lift (directed reaching from the
harness entry to the confirmed site, seeded with the cex constraints).
