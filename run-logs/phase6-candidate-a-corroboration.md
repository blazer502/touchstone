# Phase 6 static corroboration — kernelctf-latest Candidate A

**Status:** static analysis complete; directed-fuzz handoff ready
**Produced by:** Phase 6 pipeline (MLTA 6.2 + spec mining 5.x + directed scorer 6.3)
**Target tree:** Linux `lts-6.12.91`, `eval/kernelctf-latest/linux/source`, scope `kernel/events/`
**Companion:** `run-logs/upstream-reporting-plan.md` (the v1/v2 fuzz findings this corroborates)

---

## Candidate A recap (from the fuzz hunt)

`possible circular locking dependency` — a 10-deep lock chain crossing perf / mm /
cpu-hotplug. **Holder site:** `perf_event_ctx_lock_nested+0x230` (`kernel/events/core.c`)
holds `&cpuctx_mutex`. **Acquire site:** `__might_fault` (`mm/memory.c`) takes
`&mm->mmap_lock`. Reported reachable via `perf_event_open` + the perf fd ops, no
deterministic reproducer (syzkaller's 3 repro attempts all returned `false`).

## What Phase 6 found on the holder side (`kernel/events/`)

Ran decompose → entrypoints → reachability → **6.2 MLTA** → **5.1/5.2 spec mining**
→ **6.3 directed scorer** on the 6.12.91 `kernel/events/` tree (699 functions,
7 attacker entries incl. the `perf_event_open` syscall + `perf_fops` char-device ops).

### 1. Indirect-call resolution (6.2 MLTA)
- Keep-set pruning **44.78% → 54.08%** (65 functions; `reachability.py` default unchanged → sound).
- fp-table: 128 fields / 33 (type,field) slots / 174 callback functions — the perf
  PMU `struct pmu` vtable dispatch is now resolvable rather than collapsed into
  all-address-taken.

### 2. Spec mining confirmed the perf context-lock convention (5.2)
The mined contracts independently recover the lock discipline Candidate A's chain
rests on:

| callee | mined contract | support |
|---|---|---|
| `__heap_add` | `lockdep_assert_held(&cpuctx->ctx.lock)` | 3/3 = 100% |
| `bp_slots_histogram_add` | `lockdep_assert_held_write(&bp_cpuinfo_sem)` | 9/9 = 100% |
| `bp_slots_histogram_add` | `lockdep_assert_held_read(&bp_cpuinfo_sem)` | 8/9 = 89% |

→ The perf context lock (`cpuctx->ctx.lock` / `cpuctx_mutex`) **is** a near-universal
pre-call convention in this subsystem, which is exactly why a chain that holds it
while reaching out to `mmap_lock` is a real ordering hazard, not fuzzer overload.

A *separate* locking outlier also surfaced (a bonus lead, not Candidate A):
`bp_slots_histogram_add` at `hw_breakpoint.c:424` (caller `toggle_bp_slot`) is the
1/9 callsite missing the `bp_cpuinfo_sem` read-lock convention — suspicion 0.889,
worth a look on its own.

### 3. Directed-fuzz targeting plan (6.3 — the reproducer handoff for #1)
Directed scorer toward the holder site `perf_event_ctx_lock[_nested]`:
- **205 reachable callers, 70.53% SelectFuzz prune** (493/699 functions can't reach
  it → no instrumentation / seed-distance needed).
- Closest attacker seed surfaces (this is what a directed syz-manager should
  prioritise instead of blind coverage):

  | seed entry (perf fd op) | call-graph distance to holder |
  |---|---|
  | `perf_read` | 1 |
  | `perf_ioctl` | 1 |
  | `perf_release` | 2 |
  | `perf_compat_ioctl` | 2 |
  | `perf_mmap` | 5 |

  The scorer *independently* re-derived the attack surface the reporting plan named
  (perf_event_open + perf fd ops). `perf_mmap` at distance 5 is the cross-path that
  ties the holder to the `mmap_lock` acquire side — the seed most likely to drive
  the lock chain.

Artifacts: `oracle/tier1_fuzz/directed/linux-6.12.91-kernel-events.perf_event_ctx_lock*.json`.

## How this closes the two fuzz gaps

- **Low yield / blind fuzzing →** the 70.53% prune set + the distance-1 seed surfaces
  let a *directed* syz-manager (Phase 6.3 `run_syz_manager`, now activatable against
  the existing kernelctf image) spend its budget on the ~30% of `kernel/events/` that
  can actually reach the holder, seeded from `perf_read`/`perf_ioctl`.
- **No reproducer →** directed seeding toward `perf_event_ctx_lock_nested` (esp. via
  `perf_mmap`, distance 5, the mmap_lock-crossing path) is precisely the BEACON-style
  drive that blind repro-minimisation couldn't manage.

## Honest limits (what this does NOT yet do)

- **Spec mining finds "missing lock-held-before-callee", not "lock A acquired before
  lock B" ordering inversions.** Candidate A is a lock-*ordering* bug; directly mining
  it needs a pairwise lock-order mining mode (acquire-sequence patterns) — a clean
  Phase-7 / 6.x extension on top of the existing guard extractor. What Phase 6 provides
  today is (a) corroboration that the lock convention is real, and (b) the directed
  seed surface to reproduce it.
- **Only the holder half (`kernel/events/`) was analysed.** The acquire site
  (`__might_fault` → `mmap_lock`) is in `mm/` (125 files) — running the same pipeline
  on `mm/` would let the directed scorer compute the full cross-subsystem distance and
  pick the single best `perf_mmap`-rooted seed.
- **syzlang synthesis on the perf surface fell to prose-leak under the Qwen-3B smoke
  model** (the upstream perf descriptors already exist, so this isn't blocking); the
  production 32B synthesizer is the fix.

## Recommended next action
Activate `oracle/tier1_fuzz/syzlang_synth.run_syz_manager` against the existing
kernelctf-latest syz image with the directed seed set above (perf_read / perf_ioctl /
perf_mmap), targeting `perf_event_ctx_lock_nested`, and run `mm/` through the same
Phase-6 pipeline to complete the cross-subsystem distance picture.
