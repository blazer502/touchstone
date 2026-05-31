# Per-function PA proposer — Session Handoff (2026-05-31, landed at user request)

Goal this session (user direction): make the hypothesis proposer "less random —
more LLM/PA proposals, concrete exploit generation without fuzzing." Built the
per-function LLM-proposer × sound-PA-verifier route end to end, measured it
honestly at every step, and landed it. Companion docs:
`docs/perfn-pa-proposer.md` (the technique + results), `docs/whole-tu-compile-scope.md`
(the compile-wall work). Memory: `project_perfn_pa_proposer`.

## What was built (in order, all committed)

1. **Per-function proposer + sound verifier** (`fe955f9`,
   `tools/perfn_lower.py` + `tools/perfn_cbmc_proposer.py`). Scope the LLM to one
   function; it proposes a falsifiable contract; CBMC decides. SAFE soundly kills
   a hallucinated candidate, UNSAFE yields a concrete cex. Reuses the existing
   `oracle/tier3_bmc` + `surface/specmine` CBMC machinery.
2. **Local→global cex bridge** (`27d6d1a`, `tools/cex_bridge.py`). cex →
   byte-pattern → fuzz seed/dict → sound oracle (`local_oracle.score_native`).
   The CyberGym harnesses are **AFL++ drivers** (not libFuzzer) → the fuzz leg is
   an oracle-scored mutator over the replay interface.
3. **CyberGym-wide sweep + soundness hardening** (`5f12839`, `e1e93e3`,
   `tools/cybergym_perfn_sweep.py`). Two guards added so the no-false-confirm
   rule holds: confirm requires a concrete extractable trigger; leak/cleanup
   checks dropped (they false-confirm on allocators).
4. **Whole-TU compile mode** (`e9bbed4`, `tools/perfn_whole_tu.py`, `--whole-tu`)
   to clear the slice-lowering compile wall: compile the *real* TU via goto-cc
   (include-the-`.c`, handles statics; `malloc(sizeof(*p))` param model).
5. **Iterative compile-repair** (`aa50033`) — build-flag acquisition by learning
   the compiler's own undeclared/`failed to find symbol`/unknown-type errors and
   synthesizing the defines/typedefs (no build env needed).
6. **Driver safety fix** (`7ec3d87`) — see Operational lesson below.

## Verdicts (measured, not asserted)

- **Per-function CBMC works and is sound.** Positive control (thin harness
  `memcpy(buf[16], data, data[0])`): CBMC confirmed `data[0]=17`, the cex bytes
  crash the ASan build — a real PoC **with no fuzzing**. libdwarf `skip_leb128`:
  real off-by-one OOB read confirmed with concrete witness; the soundness gate
  even caught + killed its own spurious confirm.
- **The bridge pays only on THIN harnesses.** Where entry bytes map to the
  function buffer, the cex *is* a PoC. On deep parsers (libdwarf `arvo:40674`),
  byte-mutation can't synthesize a valid file to carry the cex inward → no lift.
- **CyberGym breadth: ~0.** Sweep of 40 random C tasks: 193 candidates → 13
  compiled (6.7%) → confirms were all env-modeling artifacts (allocators,
  destructors, error-handlers — not thin byte-OOBs) → **0/40 lifted**.
- **Whole-TU + repair raised compile rate but not enough.** 20 tasks, 64
  candidates: slice 6.25% → whole-TU+repair **9.4%**. Real but ~1.5×, an order of
  magnitude below the ~40% go gate. **P3 = NO-GO for breadth.**

## Why it lands here — three independent walls

A CyberGym reproduction needs all three; the route clears at most one:

1. **Build fidelity** — whole-TU cleared the type-closure + config-macro walls,
   but the residual is *missing build-system headers* (e.g. selinux
   `sepol/policydb/*.h` not in the tarball) → needs the OSS-Fuzz build env this
   host lacks (same block as the cmplog NO-GO).
2. **Shallow ≠ thin-arithmetic** — harness-callees in real projects are library
   entry points / allocators / destructors, not self-contained buffer math.
3. **Inter-procedural lift** — a `confirmed-local` cex is locally feasible; only
   thin harnesses let the bridge span entry→site. Untouched.

## Net

Per-function CBMC + the cex bridge is a **sound precision tool** for targeted
analysis of specific suspect functions on buildable C — proven to produce real
PoCs without fuzzing on thin harnesses, and (with `--whole-tu`) usable on
clean-build projects like libdwarf. It is **not** a CyberGym breadth driver;
corpus+fuzz **33%** remains the breadth lever ([[project-cybergym-88-push]]).
Final state is honest and consistent across every phase; nothing oversold.

## Operational lesson (fixed, don't repeat)

`oracle/tier3_bmc/cbmc_driver.py` ran CBMC via `docker run` under a Python
`subprocess` timeout — which kills the docker *client*, not the in-container
`cbmc`. A pathological instance (`profile_free_node`) ballooned to ~30 GB and two
runs leaked to **~60 GB RSS + 49 GB swap, freezing SSH**. Fixed (`7ec3d87`):
hard `--memory` cap + in-container `timeout` + `docker kill` on the outer
timeout. **Always** pair a heavy-tool-in-docker run with a memory cap + a
container-killing timeout, and verify `docker ps`/`free -h` after a sweep — an
orphaned container is invisible to the orchestrator's own logs. See
`feedback_cbmc_docker_timeout`.

## To resume (only if the goal changes)

- **The one move that changes the breadth outcome:** acquire the OSS-Fuzz build
  env (base image + project deps) so whole TUs compile with real `-I`/`-D`/
  generated headers. That is an infrastructure project, not a code change, and
  was already a NO-GO for the cmplog path. Without it, whole-TU caps ~9%.
- **Cheap robustness (won't change the verdict):** harness `malloc(sizeof(*p))`
  fails on opaque pointees → add a fixed-size fallback; would recover a few more
  compiles.
- **Where the route IS worth using:** point `perfn_cbmc_proposer --whole-tu` at
  a *specific* suspect function in a buildable C project; on a confirm, run
  `cex_bridge` — it produces a real PoC when the harness is thin.
- **Untaken phase:** P1 (`goto-instrument --remove-function-body` callee-stub for
  symex speed) — not needed at current scale; deep functions would want it.

All work committed to `master` (`fe955f9`…`d7b5cbf`); no `DONE` semantics changed.
