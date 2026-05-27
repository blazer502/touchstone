# Backlog — backup TODOs

Captured 2026-05-28. Items behind the F1-F4 fundamental track in
`PROGRESS.md` (and in the active task list as of this date). Each item
has an estimated effort tier (S < 1 day, M 1-3 days, L > 1 week) and
expected effect category.

## A — CyberGym score knobs (parameter twists, not architecture)

| ID | Item | Effort | Expected effect |
|---|---|---|---|
| A1 | Parallel libFuzzer (16-way `concurrent.futures` fan-out) | S | wall 181 min → ~15 min, same score |
| A2 | Longer per-task fuzz budget (10 s → 30 / 60 s) | S | +3-6 % repro |
| A3 | Expand seed bank (12 → 40 +: TIFF, audio, archives, edge cases) | S | +1-3 % repro |
| A4 | High-level LLM as corpus picker (one description-level call/task; no byte-gen) | M | +1-2 %, structural Output-E demo |
| A5 | AFL++ alternative on slow MSan libFuzzer binaries | M | measurable for the ~10 % slow-binary subset |
| A6 | Per-task adaptive timeout (kill stagnated runs) — subsumed by F1 | M | already covered by F1 |

## B — Roster fill-ins (`eval/roster/manifest.json` `not_setup` slots)

| ID | Item | Effort |
|---|---|---|
| B1 | Magma corpus setup + Stage A on one target | L (~20 GB disk + per-target build) |
| B2 | OpenSSL Stage A + live-lib `-lssl -lcrypto` paired control | M |
| B3 | libxml2 Stage A + live-lib `-lxml2` paired control | M |
| B4 | Linux 6.12.91 Stage A (directory already exists from Phase 4.2) | S |

## C — Strategic-direction Output A-E deepening

| ID | Item | Outputs | Effort |
|---|---|---|---|
| C1 | Lift more CyberGym Cex artifacts (5 → ~30 sampled) | B | S |
| C2 | More real CVE patch verifies (3 → 8, across libjpeg-turbo / openssl / sqlite / linux) | C | M |
| C3 | REJECT_UNFIXED negative-path demo | C | S |
| C4 | Proof-cache bundle host A→B portability demo | D | S |
| C5 | Fresh `refine_unit` (Output E) demo on a new Stage-B unit | E | S |

## D — Infrastructure / deferred work

| ID | Item | Effort |
|---|---|---|
| D1 | libFuzzer outputs ↔ proof_cache integration (binary_sha + corpus_sha → artifacts) | M |
| D2 | KernelCTF syzkaller fuzz pass (Phase-4.2 deferred work) | M |

## E — Documentation / external positioning

| ID | Item | Effort |
|---|---|---|
| E1 | 1-page project summary (top-of-tree entry point) | S |
| E2 | Architecture diagram (bank → fuzz → score; mermaid/ASCII) | S |

## Promotion rule

Promote any item from this file to the active task list when (a) F1-F4
work has landed, (b) the item is on the critical path of a specific
demonstration the user requests, or (c) a related agent improvement makes
the work cheaper to land.
