#!/usr/bin/env bash
# Autonomous driver for executing PLAN.md with Claude Code, fully unattended.
#
# PERMISSION MODE:
#   Default is auto mode (--permission-mode auto): no prompts, but a classifier
#   reviews each action and blocks risky ones. Requires Claude Code v2.1.83+,
#   model Sonnet 4.6 / Opus 4.6 / Opus 4.7, and the Anthropic API provider
#   (not Bedrock/Vertex/Foundry). Set PERMISSION_MODE=bypassPermissions to use
#   the no-guardrails mode instead (isolated throwaway sandboxes only).
#
# HEADLESS CAVEAT: in -p mode, auto mode aborts the session after 3 consecutive
# or 20 total classifier blocks (no human to prompt). This loop restarts on a
# non-zero exit and the agent resumes from PROGRESS.md — but to avoid constant
# aborts, PRE-STAGE all heavy "download + execute" work OUTSIDE the agent
# (toolchain install, CyberGym ~10TB data, Docker images, kernel sources) in the
# container image build, so auto-mode Claude only builds/tests/implements against
# already-local files. Register trusted repos/buckets via autoMode.environment and
# add NARROW allow rules (e.g. Bash(npm test)); broad rules like Bash(*) are dropped
# on entering auto mode. Inspect defaults with `claude auto-mode defaults`.
#
# SAFETY: run this ONLY inside an isolated container/VM with no host access and
# no sensitive credentials. This project runs fuzzers, symbolic execution, and
# builds/boots kernels, so the containment boundary is still your real safety
# layer even in auto mode (which is a research preview, not a safety guarantee).
#
# Prereqs in the container:
#   - Node.js + Claude Code CLI installed (`npm i -g @anthropic-ai/claude-code`)
#   - ANTHROPIC_API_KEY exported (required for auto mode; also best for long runs)
#   - PLAN.md and CLAUDE.md present at repo root; heavy assets pre-staged (see above)
set -euo pipefail

PERMISSION_MODE="${PERMISSION_MODE:-auto}"   # auto | bypassPermissions
MODEL="${MODEL:-claude-opus-4-7}"            # pin Opus 4.7
EFFORT="${EFFORT:-high}"                      # low|medium|high|xhigh|max (CC default is xhigh)
MAX_ITERS="${MAX_ITERS:-200}"     # hard cap so it can never loop forever
MAX_CONSEC_FAIL="${MAX_CONSEC_FAIL:-3}"  # bail if this many invocations fail in a row
LOG_DIR="${LOG_DIR:-./run-logs}"
mkdir -p "$LOG_DIR"

# Pin model + effort for EVERY headless invocation. CLAUDE_CODE_EFFORT_LEVEL has the
# highest precedence and applies to each fresh -p session, so effort never drifts.
export ANTHROPIC_MODEL="$MODEL"
export CLAUDE_CODE_EFFORT_LEVEL="$EFFORT"
# Optional: force a fixed thinking ceiling every turn (no adaptive shortcutting).
# export CLAUDE_CODE_DISABLE_ADAPTIVE_THINKING=1

# Guardrail: bypassPermissions refuses to run as root anyway; keep non-root regardless.
if [[ "$(id -u)" -eq 0 ]]; then
  echo "Refusing to run as root." >&2
  exit 1
fi

PROMPT='Read PLAN.md and CLAUDE.md. Look at PROGRESS.md (create it if missing).
Do the NEXT incomplete step of the plan. Verify the relevant "Done when" criteria
by actually running commands. Update PROGRESS.md. If every phase is complete,
create a file named DONE at the repo root. Make steady, verifiable progress; do
not redo completed steps.'

consec_fail=0
for i in $(seq 1 "$MAX_ITERS"); do
  if [[ -f DONE ]]; then
    echo "PLAN complete (DONE present) after $((i-1)) iterations."
    exit 0
  fi
  ts="$(date +%Y%m%d-%H%M%S)"
  echo "=== iteration $i ($ts) ==="
  # One headless turn. stream-json (requires --verbose under -p) keeps token/cost
  # telemetry; tee to a per-iter log. Capture claude's own exit via PIPESTATUS.
  timeout "${ITER_TIMEOUT:-3600}" \
    claude -p "$PROMPT" \
      --model "$MODEL" \
      --permission-mode "$PERMISSION_MODE" \
      --output-format stream-json \
      --verbose \
      2>&1 | tee "$LOG_DIR/iter-$i-$ts.jsonl" || true
  rc="${PIPESTATUS[0]}"

  if [[ "$rc" -ne 0 ]]; then
    consec_fail=$((consec_fail + 1))
    echo "iteration $i: claude exited $rc (consecutive failures: $consec_fail/$MAX_CONSEC_FAIL)." >&2
    if [[ "$consec_fail" -ge "$MAX_CONSEC_FAIL" ]]; then
      echo "Aborting: $MAX_CONSEC_FAIL invocations failed in a row WITHOUT doing work." >&2
      echo "This usually means a config/flag error, auth failure, or auto-mode block-abort." >&2
      echo "Check the last log in $LOG_DIR and PROGRESS.md before re-running." >&2
      exit 4
    fi
  else
    consec_fail=0   # real progress (or at least a clean turn) resets the breaker
  fi

  # Optional: stop early if the agent recorded a blocker it cannot pass.
  if [[ -f BLOCKERS.md ]] && grep -qi 'FATAL' BLOCKERS.md 2>/dev/null; then
    echo "Fatal blocker recorded in BLOCKERS.md; stopping for human review." >&2
    exit 2
  fi
done

echo "Reached MAX_ITERS=$MAX_ITERS without DONE. Inspect PROGRESS.md / run-logs." >&2
exit 3
