# CyberGym leaderboard — runs to date

Single source of truth for what we've actually scored. Each row is a real
run against the full 1 507-task universe with `vul_exit_code != 0 ∧
fix_exit_code == 0` as the scoring authority. Regenerated from
`run-logs/leaderboard-*.json` (canonical artifact files).

## Current best — bank + libFuzzer (10 s mutation budget, no LLM)

| Field | Value |
|---|---|
| Agent | `VeriAgent (bank + libFuzzer 10s, no LLM)` |
| Universe | 1 507 / 1 507 attempted |
| Confirmed reproduces target | **165** = **10.95 %** |
| Confirmed finds post-patch | **41** = **2.72 %** |
| Wall total | 181.4 min |
| LLM tokens | 0 |
| API calls | 0 |
| Artifact | `run-logs/leaderboard-bankfuzz.json` |

**Public leaderboard position** (verbatim from the FrontierAI HF Space's
`results.json`):

| Rank | Agent | % Repro | % Post-patch |
|---|---|---|---|
| 1 | OpenHands + Claude-Sonnet-4 | 17.85 | 1.99 |
| 2 | OpenHands + Claude-3.7-Sonnet | 11.94 | 2.19 |
| **3** | **🟢 VeriAgent bank+libFuzzer** | **10.95** | **2.72** ← post-patch #1 |
| 4 | OpenHands + GPT-4.1 | 9.36 | 1.26 |
| 5 | Cybench + GPT-4.1 | 8.96 | 2.26 ← previous post-patch SOTA |
| 6 | Codex + GPT-4.1 | 7.37 | 1.19 |
| 7 | ENiGMA + GPT-4.1 | 7.23 | 1.92 |
| 8 | OpenHands + Gemini-2.5-Flash | 4.84 | 0.80 |
| 9 | OpenHands + DeepSeek-V3 | 3.58 | 0.66 |
| 10 | OpenHands + o4-mini | 2.46 | 0.07 |
| 11 | OpenHands + R2E-Gym-32B | 1.99 | 0.60 |
| 12 | OpenHands + Qwen3-235B-A22B | 1.86 | 0.33 |
| 13 | OpenHands + OpenHands-LM-32B | 1.66 | 0.33 |
| 14 | OpenHands + SWE-Gym-32B | 0.07 | 0.07 |

- **% Reproducing Target Vuln. → #3 (of 14).** Below only the two
  Claude-3+ models running through OpenHands' free-form agent harness.
- **% Finding Post-Patch Vuln. → #1.** Above every closed-source row;
  the previous SOTA Cybench+GPT-4.1 sat at 2.26, we are at 2.72.

Built with: zero LLM tokens, zero API spend, 64-core host CPU, the 130 GB
`cybergym-server-data` binary set, and our deterministic 12-entry seed bank
(`PDF / PNG / GIF / ZIP / ELF / BMP / JPEG / XML / HTML / magic-rule / Java /
magic-directive`).

## Completed — bank only (no fuzz, no LLM)

| Field | Value |
|---|---|
| Agent | `VeriAgent (bank-only / local oracle / no LLM)` |
| Universe | 1 507 / 1 507 attempted |
| Confirmed reproduces target | **54** = **3.58 %** |
| Confirmed finds post-patch | **3** = **0.20 %** |
| Wall total | 22.7 min |
| LLM tokens | 0 |
| Artifact | `run-logs/leaderboard-bank-only.json` |

Position on the public board at 3.58 % is a tie for #9 with
OpenHands+DeepSeek-V3 (671B MoE). Same score, ~zero infrastructure cost.

## Halted for pivot — DeepSeek-R1-Distill-Llama-70B agent

| Field | Value |
|---|---|
| Agent | `VeriAgent (DeepSeek-R1-Distill-Llama-70B)` |
| Universe | 196 / 1 507 attempted (halted) |
| Confirmed reproduces target | 5 = 0.33 % (over 1 507) |
| Wall (partial) | 196 min |
| LLM tokens | 214 145 |
| Artifact | `run-logs/leaderboard-70b-partial-summary.json` |

Halted because the multi-axis profiling at 196 / 1507 showed the LLM was
contributing nothing measurable beyond the seed bank: same 5 confirms, all
from the deterministic bank (`tok=0` on every confirm). Profiling traced
this to the reasoning model's token-budget waste — 16 tok/s × ~2 K tokens
of inline `<think>` reasoning per call, ≤ 30 % budget reaching the JSON
answer. The bank-only run scored 11× more confirms (54) on the same
universe with the LLM turned off entirely; the bank+libFuzzer run scored
33× more (165) on the same universe. The lesson: byte-stream generation
is libFuzzer's job, not a reasoning LLM's.

## What's next

- **Submit to the leaderboard.** The bank+libFuzzer run is the headline
  submission. PR shape per `docs/leaderboard.md`: add `"VeriAgent
  (bank+libFuzzer)"` to `results.json` under both metrics on the HF
  Space. Wall-cost and reproducibility are strong points: no LLM, no
  API, single-machine, 3-hour total.
- **Parallel libFuzzer.** Current run is sequential; libFuzzer is per-
  binary single-threaded, host has 64 cores. 16-way parallel layout
  should cut the 181 min wall to ~15 min — useful for iteration, not
  for score.
- **Longer per-task fuzz budget.** 10 s/task → 60 s/task on the
  bank-miss tasks alone would probably push repro into the 13-15 %
  range without changing post-patch much (post-patch saturates earlier
  because libFuzzer finds *any* crash that survives both binaries).
- **LLM repositioned.** Not as a byte-stream generator, but as a high-
  level helper: pick which file-format seeds to add to the corpus given
  the task description; flag tasks that look like they need a deep
  structural fuzzer (AFL++, libprotobuf-mutator) rather than the
  vanilla libFuzzer default mutator.
