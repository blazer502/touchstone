# CyberGym leaderboard — runs to date

Single source of truth for what we've actually scored. Each row is a real
run against the full 1 507-task universe (or a deliberate partial — labelled
as such) with `vul_exit_code != 0 ∧ fix_exit_code == 0` as the scoring
authority. The dashboard's "Patch verifications" section is a different
artifact class (verified-patch demonstrations); this doc is leaderboard
score rows only.

Regenerated from `run-logs/leaderboard-*.json` (the canonical artifact files).

## Current best — bank + libFuzzer (in progress)

| Field | Value |
|---|---|
| Agent | `VeriAgent (bank + libFuzzer 10s, no LLM)` |
| Universe | 1 507 tasks |
| `% Reproducing Target Vuln.` | **8.49 %** (at 318/1507 checkpoint, projected) |
| `% Finding Post-Patch Vuln.` | **0.5 %** at checkpoint, projected ~1.5 % |
| Wall (projected) | ~165 min |
| LLM tokens | 0 |
| Artifact | `run-logs/leaderboard-bankfuzz.json` |

## Completed — bank only

| Field | Value |
|---|---|
| Agent | `VeriAgent (bank-only / local oracle / no LLM)` |
| Universe | 1 507 / 1 507 attempted |
| Confirmed reproduces target | **54** = **3.58 %** |
| Confirmed finds post-patch | **3** = **0.20 %** |
| Wall total | 22.7 min |
| LLM tokens | 0 |
| Artifact | `run-logs/leaderboard-bank-only.json` |

**Position on the public leaderboard** (verbatim from
`huggingface.co/spaces/FrontierAICybersecurity/Cybersecurity_leaderboard/`
`results.json`):

| Rank | Agent | % Repro |
|---|---|---|
| 1 | OpenHands + Claude-Sonnet-4 | 17.85 |
| 2 | OpenHands + Claude-3.7-Sonnet | 11.94 |
| 3 | OpenHands + GPT-4.1 | 9.36 |
| 4 | Cybench + GPT-4.1 | 8.96 |
| 5 | Codex + GPT-4.1 | 7.37 |
| 6 | ENiGMA + GPT-4.1 | 7.23 |
| 7 | OpenHands + Gemini-2.5-Flash | 4.84 |
| **8 (tied)** | **OpenHands + DeepSeek-V3** (671B MoE) | **3.58** |
| **8 (tied)** | **VeriAgent bank-only** | **3.58** |
| 9 | OpenHands + o4-mini | 2.46 |
| 10 | OpenHands + R2E-Gym-32B | 1.99 |
| 11 | OpenHands + Qwen3-235B-A22B | 1.86 |
| 12 | OpenHands + OpenHands-LM-32B | 1.66 |
| 13 | OpenHands + SWE-Gym-32B | 0.07 |

The other 12 entries all run an LLM agent (OpenHands / Cybench / Codex /
ENiGMA harness with a 32B–671B model). Our bank-only row ties 671B
DeepSeek-V3 via OpenHands using zero LLM calls and 22.7 minutes wall.

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
contributing nothing measurable beyond the seed bank: same 5 confirms,
all from the deterministic bank (`tok=0` on every confirm), zero
additional confirms from the LLM after 188 calls. Profiling traced this
to the reasoning model's token-budget waste — 16 tok/s × 2 K tokens of
inline `<think>` reasoning per call, ≤ 30 % budget reaching the JSON
answer. The bank-only run above used the same task universe and scored
54 confirms in 22.7 min with the LLM turned off entirely.

## What's running / what's next

- `bng9wndx9` — full 1 507 with libFuzzer mutation (10 s/task budget on
  bank-miss tasks). ETA ~165 min from start; trajectory at 318/1507 is
  8.49 % rate (projected ~128 confirms = #4-5 leaderboard band).
- Stretch: extend the bank with format-specific seeds (TIFF, archive
  variants, audio) and re-run — cheaper than longer libFuzzer budgets.
- Bigger pivot: replace the libFuzzer single-process with a 16-way
  parallel layout (host has 64 cores, libFuzzer is per-binary single-
  threaded) — reduces the bank+fuzz wall from ~165 min to ~15 min.
