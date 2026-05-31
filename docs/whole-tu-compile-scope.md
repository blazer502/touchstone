# Scope: whole-TU compile to clear the per-function compile wall

Goal: raise the per-function CBMC **compile rate** from the slice approach's
**6.7%** (on diverse real C projects, `run-logs/cybergym-perfn-sweep.json`) by
compiling the *real translation unit* with its real headers instead of
harvesting a type closure. Status here: **scoped + de-risked with probes**, not
built.

## What the probes settled (2026-05-31)

Run inside `touchstone/cbmc:6.4.0` (ships `goto-cc`, `goto-instrument`, `cbmc`).

1. **Compile wall — CLEARED.** `goto-cc -I<tree> -w -c dwarf_arange.c -o tu.gb`
   compiled the real libdwarf TU to a 109 KB goto-binary, `EXIT=0`, with only an
   auto `-I` and an **empty stub `config.h`**. This is the exact file class the
   slice harvester choked on (`syntax error before 'u32'/'Dwarf_Handler'`): the
   real headers resolve every typedef, struct, fn-pointer, and macro. This is
   the core win and it is real.
2. **Bare `--function` — slow AND unsound.** `cbmc tu.gb --function
   free_aranges_chain --bounds-check --pointer-check --unwind 4` **timed out at
   60 s** on a leaf-ish function. Cause: `--function` makes *all* parameters
   fully nondet (no valid-object/buffer modeling), so an unconstrained nondet
   pointer chain blows up the formula. So `--function` alone is a non-starter on
   both speed and soundness (it re-introduces the spurious-pointer-deref problem
   the slice driver's harness solved).
3. **A sound harness must see the real structs.** Linking a separate harness
   that only *forward-declares* the param structs fails: `incomplete type not
   permitted here` when allocating a valid object by value. The harness has to
   `#include` the same project headers as the TU. goto-binary linking also
   dropped an unreferenced `harness_main` symbol — link order / symbol-retention
   matters.

Net: the architecture must be **TU goto-binary + a header-including sound harness
+ link + callee-stub for speed**, not bare `--function`.

## Architecture

```
 per (task, target function):
   1. flags   = acquire_build_flags(task, tu_file)        # -I, -D, -std, config.h
   2. tu.gb   = goto-cc <flags> -c <tu_file>              # real headers -> real types  [PROVEN]
   3. harn.c  = gen_harness(target)                       # #include the TU's headers;
                                                          # valid-object alloc + buffer/length
                                                          # model (reuse perfn_cbmc_proposer
                                                          # _alloc_for / buffer_model); call target
   4. harn.gb = goto-cc <flags> -c harn.c                 # same flags so structs match
   5. link    = goto-cc harn.gb tu.gb -o linked.gb        # bind call -> real body  [keep harness sym]
   6. stub    = goto-instrument linked.gb sliced.gb \     # remove in-TU callee bodies ->
                  --remove-function-body <callees>        # local symex (speed)        [UNTESTED]
   7. cbmc sliced.gb --function harness_main \             # sound params + real body
                  --bounds-check --pointer-check --unwind N
   8. classify + cex  (reuse existing perfn driver verdict/guard/pov logic)
```

Steps 2 and 5 are proven; 3/4 are mechanical (the slice driver already generates
the param modeling — it just needs to emit `#include`s and an `extern` prototype
instead of an inlined body); 6 is the untested speed lever; 7/8 reuse the
existing `tools/perfn_cbmc_proposer` machinery (soundness guards, cex extraction,
`tools/cex_bridge`).

## The new binding constraint: per-TU build flags

This is the honest risk that *replaces* the type-closure wall. `goto-cc` needs
the TU's real `-I`/`-D`/`-std` and a `config.h`. Options, by fidelity:

- **(A) Heuristic flags (cheap, partial).** auto `-I` = every dir under the tree
  with a `.h`; synthesize a permissive `config.h` (empty, or common `HAVE_*=1`
  / `SIZEOF_*` guesses); add common `-D`. Worked for libdwarf in the probe.
  Will fail on autoconf-heavy TUs whose `config.h` gates struct layouts.
- **(B) Compile-command capture (high fidelity, blocked at scale).** Run the
  task's `build.sh` under a `CC` shim that records each `clang … -c file.c`
  invocation (a `compile_commands.json`), then replay flags under `goto-cc`.
  Highest fidelity — but the OSS-Fuzz build env (base image + project deps) is
  **not on the host** and `build.sh` won't fully run (same wall as the cmplog
  NO-GO, see [[project-cybergym-88-push]]). *Partial* capture (flags for TUs that
  compile before the build breaks) may still cover the target TU; worth a probe.
- **(C) `./configure`-only (middle).** Many autoconf projects produce `config.h`
  from `./configure` without a full build/deps. Run just `configure` in the
  tree to materialize `config.h` + `-D`s, then heuristic `-I`. Cheaper than (B),
  higher fidelity than (A).

Recommended: ship (A) first (measure the compile-rate lift it alone buys),
then (C) for autoconf projects, and probe (B)'s partial capture as a stretch.

## Phased plan

- **P0 — harness MVP — DONE** (`tools/perfn_whole_tu.py`, `--whole-tu` on
  `perfn_cbmc_proposer`). Built it as **include-the-`.c`** rather than goto-cc
  *linking* (steps 4–5): linking can't call a `static` target, and the probe
  showed goto-cc drops the unreferenced harness symbol. The harness
  `#include`s the target `.c` (brings every real type/macro + makes statics
  visible) and models params with `malloc(sizeof(*p))` + the buffer/endptr/
  length contract — no struct tags needed (compiler knows the size). One safe
  `docker run` does `goto-cc … ; cbmc …` with the mem cap + in-container timeout.
  **Gate met:** on the libdwarf set, whole-TU mode reproduces the slice driver's
  sound verdicts — `_dwarf_skip_leb128` still **confirms** (off-by-one, concrete
  8×0x80 cex), decode/encode **refute**; slice mode unchanged (no regression).
  Notable: `dwarf_util.c` functions now reach the *compiler* (slice mode died at
  type-harvest) but fail on a sibling fn (`dwarf_package_version`) needing real
  `config.h` values the empty stub lacks — i.e. the wall moved from type-closure
  to **build-flag fidelity (P2)**, exactly as scoped.
- **P1 — speed lever (goto-instrument).** Add step 6; measure wall vs. bare
  `--function`. Gate: median per-function wall < 10 s on the libdwarf TU
  (vs. the 60 s timeout today).
- **P2 — build-flag acquisition (A)+(C).** Implement heuristic flags +
  optional `./configure`. Re-run the 40-task C sweep in `--whole-tu` mode.
  **Headline metric: compile rate vs. the 6.7% baseline.**
- **P3 — go/no-go.** If compile rate clears, say, ≥40%, the confirm count rises
  enough to make the cex-bridge sweep meaningful; otherwise the build-flag wall
  is the new ceiling and the route stays a targeted (not breadth) tool.

## Honest expectation

Clearing the compile wall is **necessary but not sufficient** for the 0/40 lift.
Three constraints gate a CyberGym reproduction; this addresses one:

1. compile wall — *this scope* (proven clearable on at least clean-header TUs);
2. shallow harness-callees are allocators/handlers/destructors, not thin byte
   OOBs — *unchanged* (more compiles surface more functions, but the bug has to
   be there);
3. inter-procedural lift from entry bytes to the confirmed site — *unchanged*
   (the cex bridge only spans it for thin harnesses).

So whole-TU compile raises the **confirm** count and makes the technique usable
on real projects for *targeted* analysis; it does **not** by itself turn the
0/40 CyberGym **lift** positive. Worth building if the goal is "per-function
CBMC as a usable analysis tool on real C projects"; not worth it if the only
goal is the CyberGym breadth number (corpus+fuzz 33% remains that lever — see
[[project-perfn-pa-proposer]]).

Effort: P0+P1 ≈ one focused session; P2 ≈ another; P3 is the measurement.
