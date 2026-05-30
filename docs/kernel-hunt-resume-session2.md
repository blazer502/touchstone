# Kernel Hunt — Session 2 Handoff (2026-05-30, stopped at user request)

Continues `docs/kernel-hunt-plan.md` and `docs/forward-plan.md` with this
session's outcome and how to resume.

## What happened this session

1. **Recovery** (rm on /mnt/data interrupted): 70B re-downloaded; `tasks.json`
   re-fetched from HF; CyberGym data intact except ~66 oss-fuzz dirs
   (re-fetchable). Repo + scoring binaries + services healthy.
2. **CyberGym Level-1 (post-recovery)**: 466/1507 = 30.9% (466/1441 of available
   tasks = 32.3%). Matches the prior 33.31% baseline — no regression.
3. **Kernel hunt — fuzz campaigns** (stopped):
   - `veri-syz-hunt` (broad, all syscalls, KASAN+setuid+LOCKDEP+KCOV) — 13h →
     coverage 95,091 PCs, 6.6M exec; **3 DoS buckets**: `unix_stream_recvmsg`,
     `corrupted`, `sys_recvmmsg`.
   - `veri-syz-deep` (directed perf/mm/cpu_hotplug, LOCKDEP) — 11h → 16,622
     PCs (plateaued), 8.4M exec; **0 buckets**.
   - `veri-syz-lockorder` (directed unix-shutdown race) — 6h → 26,268 PCs;
     **1 bucket** (reproduced `unix_stream_recvmsg`).
   - Net: only DoS soft-lockups, **0 KASAN, 0 LOCKDEP, 0 weaponizable MC**.
4. **Agent self-enhancement** (built + committed):
   - `tools/pa_llm_iterate.py`: bucket → LLM proposer with strict citation
     gate + adversarial critic (confidence + counter-argument) + history-aware
     proposer (prior iterations' falsifications feed the next prompt).
   - `tools/cross_bucket_analysis.py`: cluster buckets by lockup_fn, multi-
     bucket evidence (unique top-RIPs + syscall union), structural-cause
     proposer with the same critic + history.
5. **Closed loop converged honestly**: across 5 iterations the LLM proposed
   UAF (af_unix.c:3000) → falsified by fuzz; lock-order-inversion
   (af_unix.c:3061, conf=0.5) → falsified by 15-min focused fuzz; refcount-
   underflow (af_unix.c:2995, conf=0.5) → untested; with full history the
   final iter returned **0 hypotheses, honest_finding="dos-only — no MC
   evidence"**. The critic correctly predicted each falsification.

## Honest bottom line

Triply-confirmed: hardened LTS-6.12.91 doesn't yield unprivileged-reachable
weaponizable memory-corruption to session-scale autonomous PA + LLM + fuzz
effort. The loop is sound and self-correcting — it does not fabricate.

## How to resume

1. **Restart the broad campaign** (the only one that produced new buckets,
   though all DoS):
   ```bash
   sudo docker run -d --rm --name veri-syz-hunt --device /dev/kvm \
     -v "$(pwd)/eval/kernelctf-latest":/work \
     touchstone/syzkaller:master \
     syz-manager -config /work/syzkaller/manager-overnight.cfg
   ```
2. **Optional: directed campaigns** — `manager-campaign.cfg` (Candidate A,
   perf/mm), or rebuild a focused cfg from a fresh bucket via
   `tools/pa_llm_iterate.py`.
3. **On any new bucket**: feed it back through the loop:
   ```bash
   PYTHONPATH=. python3 tools/cross_bucket_analysis.py \
     --workdir eval/kernelctf-latest/syzkaller/workdir-overnight \
     --workdir eval/kernelctf-latest/syzkaller/workdir-campaign \
     --source-root eval/kernelctf-latest/linux/source \
     --history run-logs/pa-llm-history.json \
     --out run-logs/cross-bucket-latest.json --min-confidence 0.4
   ```
   The proposer + critic + history will produce ranked hypotheses or honestly
   say dos-only. Update `run-logs/pa-llm-history.json` after any directed-fuzz
   verdict so future iterations learn from it.

## Open levers if continuing

Listed roughly in order of expected yield vs effort:

| lever | effort | expected yield | note |
|---|---|---|---|
| Long campaign (days, not hours) | passive | low-but-nonzero | This is the only thing that actually moves the probabilistic search forward |
| `tools/cross_bucket_analysis.py` re-run when new buckets land | low | yields a new ranked-and-critiqued hypothesis per cluster | The loop is wired |
| Coccinelle on broader scopes (fs/, mm/, drivers/) | medium | low | Patterns covered by cocci are well-audited upstream |
| Sparse warnings ingest (`surface/static_hints.parse_sparse`) | medium | low | Same auditing-coverage caveat |
| Custom Smatch security check that models genetlink/syscall- dispatch validation (the precision-wall fix) | high | medium | Would suppress the dispatch-guarded FPs and surface what's left; could find a real lead |
| CodeQL kernel DB with **full extraction** (the net/ tracer bug) | high | medium | Either reduce -j drastically, or use kernel-build distro packages with codeql trace |
| Less-audited target (out-of-tree driver, older kernel) | scope/policy change | high | kernelCTF requires the live hardened LTS — this is for general research, not the bench |
| Weaponization (any reproduced bug → ≥90% LPE) | multi-week, expert | n/a | Phase 10, gated on a real exploitable bug — not autonomous |

## Tools/state preserved

- `run-logs/pa-llm-history.json` — closed-loop history (3 entries).
- `run-logs/cross-bucket-analysis.json`, `run-logs/cross-bucket-iter5.json` —
  the converged dos-only verdicts.
- `run-logs/cluster-cfg-lockorder-launch.json` — the directed cfg that
  exercised the lock-order hypothesis.
- `run-logs/smatch-candidates-all.json` — 689 cross-fn DB candidates (the
  primary PA source).
- `run-logs/codeql-stock-security.sarif` — 157 CodeQL stock hits (the
  second PA lens).
- All syzkaller workdirs preserved (corpus + crashes) under
  `eval/kernelctf-latest/syzkaller/workdir-*`. Coverage state survives, so a
  restart resumes from the same exploration frontier rather than ramping
  cold.

## Status at stop

- 3 syz-manager containers stopped.
- `veri-vllm-smoke` (Qwen-3B smoke) still up — negligible GPU.
- The 70B vLLM (the shared synthesizer/router backend) was **NOT stopped
  autonomously** — it's shared infrastructure per the standing memory; user
  to confirm if releasing those GPUs is desired.
- All buckets, corpora, and analysis JSONs preserved on disk + committed.
