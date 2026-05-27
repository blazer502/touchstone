# Verification-grounded CyberGym agent — improvement plan

Drafted after halting the DeepSeek-R1-Distill-Llama-70B 1507 run at task 196
(5 confirms, all from the deterministic seed bank, **zero additional confirms
from the LLM across 188 calls**). This document is a strategic pivot, not yet
a code patch — see §5 for the decision the user owns.

## 1. Honest diagnosis: why we're at 0.33 %

Empirically:
- 5 / 196 (= 2.55 % rate-over-attempted) is upper-bounded by what the
  12-entry deterministic seed bank can hit on the early arvo task range
  (file-format parsers).
- LLM was called on 188 of 196 tasks (96 %), generated thousands of byte
  candidates across the 70B run, and produced **zero additional confirms**.
- This is the same headline as the 3B partial run (5 / 51, all bank, same 5
  task ids). Upgrading 3B → 70B changed only wall time, not score.

The reason is architectural, not model-scale:

| | Leaderboard agents (OpenHands / Cybench / Codex / ENiGMA) | Our `LLMGuidedSeedGenerator` |
|---|---|---|
| **Reads source code** | Yes (multi-file exploration via tool use) | No (only `description.txt`) |
| **Iterates on feedback** | Yes (reads server `output`, retries) | No (one-shot per candidate) |
| **Local oracle for fast pre-flight** | Sometimes (rebuilds harness) | No (always remote, rate-limited) |
| **Multi-turn LLM** | Yes | No (single shot per task) |
| **Tool use (shell, python)** | Yes | No |

The gap is **agent architecture, not model**. OpenHands+DeepSeek-V3 scores
3.58 %; OpenHands+OpenHands-LM-32B scores 1.66 %; OpenHands+SWE-Gym-32B
scores 0.07 %. The harness dominates the result, not the model size.

## 2. What's uniquely ours — our verification stack

The leaderboard agents *do not have* these capabilities. They are our
differentiator and the basis of every improvement below.

| Asset | Phase | What it gives us that OpenHands lacks |
|---|---|---|
| Stage A reachability + dispatcher entrypoints | 1.2 | A *sound* slice of the codebase the bug must be in |
| Stage B contract-driven CBMC/Frama-C | 1.3 | Per-function safe/unsafe verdicts with counterexamples |
| Proof cache | 1.4 | Memoised verdicts keyed by body + assumed contracts |
| Tier-1 libFuzzer + ASan/MSan/UBSan harness | 2.1 | **Local oracle** — same scoring path as CyberGym server, but unlimited iteration |
| Tier-2 KLEE / angr | 2.2 | Symbolic SAT → concrete byte witness |
| Tier-3 CBMC / ESBMC + harness synthesis | 2.3, 3.2 | BMC-generated cex bytes for bounded bug classes |
| Router with class_hint dispatch | 2.4, 3.3 | Picks the cheapest engine that can decide |
| LLM contract / harness / assertion proposer | 3.1, 3.2 | Verifier-filtered LLM output (degenerate-assume rejection) |
| Closed agent loop with refinement | 4.1 | Verdict-driven multi-turn — already exists, just not wired to CyberGym |
| Soundness gate (Juliet 0 missed-bug) | 1.5 | Quality control against over-pruning |

**Key insight**: We have a full multi-tier verification stack. CyberGym
currently uses only `oracle.tier1_fuzz.replay_docker` and *only as a verdict
sink*. The verifier is downstream of our LLM, never upstream.

## 3. Improvement priorities (ranked by expected ROI)

### Tier 1 — close the architecture gap (this is what gets us from 0.3 % to 3-5 %)

**P1. Multi-turn feedback loop with server output**
- Server already returns `output` field with sanitizer banners, stack traces,
  "Executed /tmp/poc in N ms" timing — currently discarded.
- Change `LLMGuidedSeedGenerator` to consume the previous candidate's
  output and produce the next candidate informed by it.
- Effort: ~80 LOC in `seed_generators.py` + adapter return value.
- Expected lift: **2-5×** (this is what OpenHands does and nothing else).

**P2. Source-grounded LLM prompt**
- We pulled all 1507 `repo-vul.tar.gz` already (220 GB on `/mnt/data`).
- `error.txt` (level 2/3) names a `file:line` — extract that file's function
  body + ±20 lines around the line; embed in prompt.
- Effort: ~50 LOC for tarball-extract + line-slice helper; one prompt edit.
- Expected lift: **1.5-2×** (LLM reasons about real code, not prose).

### Tier 2 — leverage our local oracle (3 % → 5-10 %)

**P3. Local Tier-1 libFuzzer pre-flight**
- For each task we have the OSS-Fuzz harness binary already (130 GB
  `cybergym-server-data` on `/mnt/data`).
- Reuse our `oracle.tier1_fuzz.userspace.replay_docker` to run candidates
  locally — same byte-for-byte semantics as server, but no rate limit, no
  HTTP, no `agent_id`-per-task overhead.
- Effect: LLM can iterate **100+ candidates per task** in the same wall as
  current 16. Only submit confirmed local crashes to server (precision near 1).
- Effort: ~30 LOC swap inside `adapter.try_candidate` (use local harness
  binary via docker exec instead of HTTP).
- Expected lift: **3-5×** on top of P1/P2.

**P4. Coverage-guided feedback for the LLM**
- libFuzzer emits coverage per candidate (`cov:`, `ft:`, `corp:` lines in
  the output). Capture per-candidate coverage delta.
- Surface to LLM: "your candidate reached N edges in `{files}`, but
  vulnerable line at `softmagic.c:365` is unreached."
- Effort: ~60 LOC (parse libFuzzer log, compute delta, include in next prompt).
- Expected lift: **1.5-2×** on top of P3.

### Tier 3 — symbolic / BMC drives the candidate (bounded bug subset)

**P5. CBMC-driven cex generation for the bounded subset**
- Triage by description regex: `off-by-one`, `null deref`, `integer over*`,
  `divide by zero`, `out-of-bounds` — these are bounded properties.
- Extract the *target* function from `error.txt`'s `file:line` (reuses P2).
- Reuse `oracle.tier3_bmc.assertions.synthesize()` (already exists, Phase 3.2)
  to synthesize a CBMC harness with the property as `__CPROVER_assert`.
- CBMC outputs cex assignment → PoV bytes.
- Submit to server. Score.
- Effort: ~150 LOC (triage classifier + adapter from `error.txt` → Hypothesis).
- Expected lift: **only on the ~30 % bounded subset, but ~50-70 % hit rate
  on that subset**. Net gain ≈ 15-20 % absolute on those tasks alone.

### Tier 4 — refinements

**P6. Stage A scoping for prompt focus**
- Run `surface/decompose.py` on the unpacked source; show LLM only the
  cluster containing the target function from `error.txt`.
- Smaller context → tighter LLM focus.
- Expected lift: **1.1-1.3×**.

**P7. Static-analyzer priority hints**
- Run smatch / coccinelle / sparse on the unpacked source; surface lines
  near the `error.txt` location to LLM as `[suspect: array-overflow at
  L142]` hints.
- Reuses Phase 0.4 / 1.2 toolchain.
- Expected lift: **1.1-1.3×**.

## 4. Concrete first-cut proposal — "Phase 5.1: Verifier-grounded CyberGym loop"

Compose **P1 + P2 + P3**. This is the minimum architectural change that
closes the gap with OpenHands and lets our verification stack actually
participate.

```
agent/cybergym_agent.py            # new file, sits where seed_generators was
  ├─ Reads description.txt
  ├─ Extracts target function from error.txt + repo-vul.tar.gz   (P2)
  ├─ Pre-builds local Tier-1 oracle using cybergym-server-data binary  (P3)
  ├─ Multi-turn loop:                                            (P1)
  │     for turn in range(MAX_TURNS):
  │         prompt = build_prompt(description, source_excerpt, prior_outputs)
  │         candidates = llm_propose(prompt, n=K)
  │         for c in candidates:
  │             local_verdict = tier1_local.replay(c)
  │             if local_verdict == "crash":
  │                 server_verdict = adapter.try_candidate(c)
  │                 if server_verdict == "crash":
  │                     return CONFIRMED(c)
  │         prior_outputs += [v.evidence_excerpt for v in local_verdicts]
```

Concrete sub-tasks (rough sizing):

| Sub-task | LOC | Risk |
|---|---|---|
| `agent/source_extractor.py` — tarball → function body around `file:line` | ~80 | low |
| `agent/local_oracle.py` — wrap cybergym-server-data binary as a Tier-1 verdict | ~120 | medium (docker exec semantics) |
| `agent/cybergym_agent.py` — multi-turn loop with feedback | ~200 | medium |
| `run_leaderboard.py` — swap `LLMGuidedSeedGenerator` for new agent | ~30 | trivial |
| Soundness sanity (Juliet rerun unchanged, smoke arvo:1065 confirms) | n/a | low |

**Projected score after P1+P2+P3 with DeepSeek-R1-Distill-Llama-70B**:
3-6 % on full 1507 (extrapolating from OpenHands+DeepSeek-V3 at 3.58 % —
similar architecture, comparable open model).

## 5. Decision the user owns

1. **Adopt the Phase-5.1 (P1+P2+P3) pivot now**, before the leaderboard
   submission. Estimated build wall: 1-2 days of focused work. Then re-run
   1507 with same 70B → projected 3-6 %.
2. **Add Phase-5.2 (P5: CBMC-driven)** as a stretch goal — uniquely ours,
   could push into 5-10 % range on the bounded subset.
3. **Submit the current 0.3 % result as-is** (honor-system PR, label
   clearly as "LLM-guided seed generator, no agent harness") and treat
   Phase-5.1 as a follow-up paper.
4. **Hold the submission** until Phase-5.1 is done.

My recommendation: **#4** then **#1+2**. The 0.3 % result is not interesting
to anyone on the leaderboard (sits below SWE-Gym-32B-class agents) and
submitting it now risks looking under-baked. Phase-5.1 is the smallest
diff that makes us competitive with OpenHands-class agents *and* lets us
demonstrate the unique verifier-in-the-loop value proposition that
distinguishes our project from the leaderboard's 13 entries.

## 6. What we keep warm

The following stay up so we can iterate without re-paying setup cost:

- `veri-vllm-smoke` — DeepSeek-R1-Distill-Llama-70B on port 8100 (4× A6000, 99 % util pre-halt)
- `cybergym.server` — binary-only mode on port 8666 (130 GB `cybergym-server-data`)
- `llm.gateway` — port 8000, smoke profile, both roles → 70B
- HF dataset on `/mnt/data/chanyoung/cybergym/cybergym_data/` (1507 / 1507 level-1 assets materialised)
- 70B weights at `/mnt/data/chanyoung/hf-cache/` (~140 GB)

## 7. What was learned that we keep

- Run-log `run-logs/leaderboard-70b-partial-summary.json` — the 196-task partial.
- Run-log `run-logs/leaderboard-qwen3b-partial-summary.json` — the 3B partial baseline (51 tasks).
- Both confirm the **same 5 task ids** confirmed (`arvo:1065 / 67297 / 3938 / 63314 / 67552`),
  all crash on a deterministic bank seed (XML / magic-byte) **without LLM involvement**.
- Cost: ~3 hr GPU wall + ~140 GB disk + ~250 GB HF dataset + 130 GB server-data.
