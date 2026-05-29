# Cross-function Smatch DB hunt — run log (2026-05-29, overnight)

Target: `eval/kernelctf-latest/linux/source` (hardened LTS 6.12.91, kernelCTF
threat model = **unprivileged user**, `sandbox=setuid`, no userns/io_uring/nftables).
Goal: test whether a *proper Smatch cross-function security DB* lifts the
candidate-recall bottleneck the forward-plan flagged (style pass = 3 candidates).

## What ran

1. `smatch_scripts/build_kernel_data.sh` over the whole kernel → cross-fn DB
   (`smatch_db.sqlite` 1.9GB: `caller_info` 4.0M rows, `return_states` 2.96M,
   `function_ptr` 77.7k) + `smatch_warns.txt` (700MB, ~253k warn/error lines).
   Both gitignored (regenerable).
2. `tools/smatch_candidates.py` (new) — streams the warns file, classifies each
   warning via `schemas.hypothesis.classify_warning`, emits memory-corruption
   candidates JSON for `agent.hyp_loop`.
3. `agent/hyp_loop.py` end-to-end on the DB candidates (net/netfilter scope,
   reach-gate + LLM-refine) → `run-logs/hyp-loop-xfndb-netfilter.json`.

## Result 1 — RECALL is solved (the gate passes)

Whole-kernel memory-corruption candidates: **689** (vs **3** from the style pass).

| bug_class | count | write-capable |
|---|---|---|
| oob-write | 94 | yes |
| double-free | 2 | yes |
| oob-read | 220 | no |
| uninit | 373 | no |

**96 write-capable**; 67 of them in unprivileged-reachable subsystems
(mm 38, kernel 14, fs 9, net 6). The cross-fn DB (interprocedural param ranges +
`sizeof_param` + `frees_argument`) is what surfaced them.

## Result 2 — PRECISION is the new wall

Raw recall is high but precision on the write-capable set is low. Triage:

- **92 / 96** are bounded-index false positives: the array index is a kernel-internal
  enum / loop / bitfield that smatch couldn't prove bounded, so it reports the
  loose type range (`'X' 30 <= 254`, `16 <= 63`, `<= u32max`) with **no** user
  range. e.g. `mm/memcontrol.c` (38 hits, per-cpu stat arrays indexed by a small
  enum), `kernel/trace/fgraph.c`, `kernel/bpf/verifier.c`. Not reachable OOBs.
- **4 warnings / 3 sites** carry a tracked **user-controlled index** (`user_rl=`) —
  the genuinely weaponizable shape. All 3 source-verified as guarded / privileged:
  - `net/ethtool/netlink.c:614` `ethnl_default_requests[ghdr->cmd]`, `user_rl='0-255'`
    → **FP**: genetlink dispatches `->start()` only after `genl_get_cmd(hdr->cmd,…)`
    matches a *registered* op (`net/netlink/genetlink.c`), so `cmd < 46` always.
    The `WARN_ONCE(!ops)` is a backstop. Smatch can't model the dispatch-table
    validation because it lives in a different TU.
  - `fs/nfsd/nfs4xdr.c:2493` COMPOUND opnum index → needs an NFS server (privileged);
    COMPOUND has its own opnum bound check.
  - `net/sched/sch_prio.c:214/225` `q->queues[bands]`, `user_rl='2-16'` → needs
    **CAP_NET_ADMIN**; `TCQ_PRIO_BANDS` validation upstream.

## Result 3 — the loop works at scale

`hyp_loop` ingested all 689 warnings, scoped to net/netfilter (7 candidates),
reach-gated to **6 unprivileged-reachable**, and the open 70B re-ranked all 7
with the **citation gate holding** (every refined hid matched a real candidate;
procfs-only `ct_seq_show` correctly `unprivileged=False`). 83s wall. This is the
first end-to-end run on *real rich* candidates (prior validation used 3 toy ones).
But netfilter's reachable candidates are all `oob-read` NULL-deref (DoS-class),
**0 write-capable** — corroborating that this subsystem is well-audited.

## Sharpened bottleneck (updates the forward-plan)

Recall is no longer the wall — the cross-fn DB fixed it (3 → 689). The wall moved to
**precision on user-controlled-index warnings**: on a well-audited hardened LTS the
guards that defeat these candidates live in **framework dispatch layers** (genetlink
op-table validation, NFSD COMPOUND decode, qdisc band checks) in a *different*
function/TU than the indexed access, so even cross-fn Smatch reports them as FPs.
No reproduced novel KASAN crash; milestone still unmet on patched LTS.

Honest next levers (unchanged in spirit, sharper in aim):
- A check that models **dispatch-table / syscall-multiplexer bounds** (hard), or
  CodeQL interprocedural taint that follows the dispatch edge.
- Point the loop at a **less-audited target** (older kernel, a fresh driver
  subsystem) where the guards are genuinely missing — that is where converting
  static warnings → reproduced crashes can actually pay off.

## Artifacts
- `tools/smatch_candidates.py` — the cross-fn-DB candidate source.
- `run-logs/smatch-candidates-all.json` (689), `run-logs/smatch-writecap-unpriv.json` (67).
- `run-logs/hyp-loop-xfndb-netfilter.json` — end-to-end loop record.
