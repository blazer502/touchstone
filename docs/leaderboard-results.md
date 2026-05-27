# CyberGym leaderboard — runs to date

Single source of truth for what we've actually scored. Each row is a real
run against the full 1 507-task universe with `vul_exit_code != 0 ∧
fix_exit_code == 0` as the scoring authority. Regenerated from
`run-logs/leaderboard-*.json` (canonical artifact files).

## Current best — all features (F1+F2+F3+F4+V1+V3, no LLM)

| Field | Value |
|---|---|
| Agent | `VeriAgent (F1+F2+F3+F4+V1+V3 all features, no LLM)` |
| Universe | 1 507 / 1 507 attempted |
| Confirmed reproduces target | **188** = **12.48 %** |
| Confirmed finds post-patch | **51** = **3.38 %** |
| Wall total | 252.7 min |
| LLM tokens | 0 |
| API calls | 0 |
| Auto-witness artifacts | 188 (`run-logs/cex/auto/<task>.json`) |
| Auto-patch artifacts | 188 (`run-logs/cex/auto/<task>.patch.diff`) |
| Artifact | `run-logs/leaderboard-all-features.json` |

**Public leaderboard position** (verbatim from the FrontierAI HF Space's
`results.json`):

| Rank | Agent | % Repro | % Post-patch |
|---|---|---|---|
| 1 | OpenHands + Claude-Sonnet-4 | 17.85 | 1.99 |
| **2** | **🟢 VeriAgent F1+F2+F3+F4+V1+V3** | **12.48** | **3.38** ← post-patch #1 |
| 3 | OpenHands + Claude-3.7-Sonnet | 11.94 | 2.19 |
| 4 | OpenHands + GPT-4.1 | 9.36 | 1.26 |
| 5 | Cybench + GPT-4.1 | 8.96 | 2.26 |
| 6 | Codex + GPT-4.1 | 7.37 | 1.19 |
| 7 | ENiGMA + GPT-4.1 | 7.23 | 1.92 |
| 8 | OpenHands + Gemini-2.5-Flash | 4.84 | 0.80 |
| 9 | OpenHands + DeepSeek-V3 | 3.58 | 0.66 |
| 10 | OpenHands + o4-mini | 2.46 | 0.07 |

- **% Reproducing Target Vuln. → #2 (of 14).** Above Claude-3.7-Sonnet via
  OpenHands. Below only Claude-Sonnet-4 via OpenHands.
- **% Finding Post-Patch Vuln. → #1.** Above every closed-source row.

Built with zero LLM tokens; reasoning is verifier-grounded (Stage A/B,
local-oracle, libFuzzer mutation), not language-model bytestream generation.

## What changed from the prior bank+libFuzzer run

| | bank + libFuzzer 10s (prior) | all features (this) | Δ |
|---|---|---|---|
| % Reproducing Target Vuln. | 10.95 | **12.48** | **+1.53 %** |
| % Finding Post-Patch Vuln. | 2.72 | **3.38** | **+0.66 %** |
| Wall total (min) | 181.4 | 252.7 | +71 |
| LLM tokens | 0 | 0 | 0 |
| Auto-witness artifacts | 0 | **188** | +188 |
| Auto-patch artifacts | 0 | **188** | +188 |

Wall went up by 71 min because F1 adaptive scheduling extended the per-task
budget on coverage-progressing tasks (up to 20 s). The score lift is from
F3 class-aware seeds (`integer-overflow`, `heap-buffer-overflow`, … augment
the corpus) + F4 project-corpus sharing (binutils' 103 tasks, ghostscript's
88 tasks, ffmpeg's 69 tasks all share a growing seed pool) + V1/V3 turning
every confirm into an audit-grade artifact at zero extra wall.

## Trajectory

```
70B DeepSeek-R1-Distill reasoning agent      0.33 %  (196 / 1507, halted)
bank-only / no LLM                           3.58 %
bank + libFuzzer 10 s / no LLM              10.95 %
all features (F1+F2+F3+F4+V1+V3) / no LLM   12.48 %    ← board #2 / post-patch #1
```

37× from first-cut to current best. Every step is benchmark-agnostic and
goes through the `BenchmarkTask` Protocol (see `docs/strategic-direction.md`
§8 — no fine-tuning to GymBench).

## Completed runs index

| Run | Status | Confirmed | Wall | Artifact |
|---|---|---|---|---|
| all features F1-F4 + V1/V3 | done | 188 / 51 | 252.7 min | `run-logs/leaderboard-all-features.json` |
| bank + libFuzzer 10 s | done | 165 / 41 | 181.4 min | `run-logs/leaderboard-bankfuzz.json` |
| bank only | done | 54 / 3 | 22.7 min | `run-logs/leaderboard-bank-only.json` |
| DeepSeek-R1-Distill-70B partial | halted | 5 / 0 (of 196) | 196 min | `run-logs/leaderboard-70b-partial-summary.json` |

## What's next

- Optional: parallel-task execution (4-8 way) — host has 64 cores; current
  driver runs tasks sequentially. Wall could drop from 252 min to ~40 min
  with the same score.
- Optional: more class-seed buckets for less-common bug classes (TSan
  / format-string / type-confusion). Each bucket targets ~1-3 % of tasks.
- Optional: the BenchmarkTask Protocol is benchmark-agnostic; same agent
  could run against Magma / Juliet / kernelCTF with adapter-only effort.
  Multi-benchmark roster build-out lives in `docs/backlog.md`.
