# CLAUDE.md — Autonomous build instructions

You are implementing the system described in `PLAN.md`. Read `PLAN.md` fully before acting.

## How to work
- Work **phase by phase, in the order given** (Phase 0 → 4). Within a phase, do the numbered steps in order.
- **Never advance to the next phase until the current phase's "Done when" criteria actually pass.**
  Verify them by running the relevant command/test, not by assertion.
- Maintain `PROGRESS.md`: a checklist of every phase/sub-step with status
  (TODO / DOING / DONE / BLOCKED) and a one-line note. Update it after every meaningful action.
- When a whole phase's acceptance criteria pass, append a line `PHASE <n> COMPLETE` to `PROGRESS.md`.
- When all phases are complete, write a file named `DONE` at the repo root and stop.
- If you hit a hard blocker you cannot resolve autonomously (missing credential, external data
  download that needs a human, an ambiguous decision not covered by PLAN.md), set the step to
  BLOCKED in `PROGRESS.md`, write the reason to `BLOCKERS.md`, and continue with other unblocked work.

## Hard rules (project-specific, do not violate)
- **Everything stays inside this workspace.** Do not touch anything outside the repo / mounted volume.
- **Final verdict authority = the sound checker, never an LLM.** Do not let any LLM step replace a
  verification/oracle verdict (see PLAN §8).
- **Patch isolation:** in CyberGym eval, the patched build is scoring-only. Never feed the patch to
  the agent except in CyberGym's explicit with-patch setting.
- Pin tool versions in `docs/toolchain.lock`. Containerize tools (PLAN §6 Phase 0.1).
- Respect the budget caps in `config/budget.yaml`. Prefer the cheapest oracle tier that can decide.

## Conventions
- Commit after each completed sub-step with a message referencing the PLAN step (e.g. `phase0.3: ...`).
- Prefer small, verifiable increments. Run builds/tests yourself and read the output before moving on.
- Put new code where PLAN §5 "Repository Layout" says it goes.
