# Upstream reporting plan — kernelctf-latest v1/v2 fuzz findings

**Status:** draft / not yet executed
**Author:** veri-agent kernelctf-latest hunt, runs v1+v2 (2026-05-27 → 2026-05-28)
**Target tree:** Linux `lts-6.12.91`, commit `57eaf35b03` (gregkh/linux)

---

## What we have

Two findings from the v1+v2 overnight syzkaller runs that *might* deserve upstream attention. Everything else (8 task-hungs, 2 soft-lockups, 2 "no output from test machine", 1 suppressed userspace fault) is syzkaller-typical noise on a triple-sanitizer debug kernel and is not worth filing.

### Candidate A — lockdep circular dependency (perf_event ↔ mmap_lock ↔ cpu_hotplug)

| | |
|---|---|
| syzkaller bucket title (1) | `possible deadlock in perf_event_ctx_lock_nested` |
| syzkaller bucket title (2) | `WARNING: possible circular locking dependency detected` |
| Hashes in workdir-overnight-v2 | `40117f7e0b1725ec0ef475b4359bea945d6366a9`, `798f1c91f6699c64d905bee349ecec50d36fb0c9` |
| Sightings | 2 (different buckets, same root cause: identical 10-deep lock chain) |
| Reproducer | None (syzkaller's `repro*` files report `false`) |
| Acquire site | `__might_fault+0xa6/0x120` (`mm/memory.c:6750`) tries to take `&mm->mmap_lock` |
| Holder site | `perf_event_ctx_lock_nested+0x230/0x4f0` (`kernel/events/core.c:1337`) holds `&cpuctx_mutex` |
| Reverse chain | `cpuctx_mutex → pmus_lock → cpu_hotplug_lock → tracepoint_mutex → static_call_lock → static_call_text_lock → text_mutex → mmap_lock` |
| Sanitizers needed | LOCKDEP only — no KASAN/KMSAN required |
| CAP_SYS_ADMIN needed? | **No** — `perf_event_open` is accessible to unprivileged users (the deployed kernelCTF kernel runs `kernel.perf_event_paranoid=2`, which *restricts* but does not *deny*) |
| Subsystem maintainer | `tools/get_maintainer.pl kernel/events/core.c` → Peter Zijlstra (PMU), Ingo Molnar, Arnaldo Carvalho de Melo, +linux-perf-users |

**Why it's worth a quick check:**

- The chain crosses three subsystems (perf, mm, cpu hotplug). Structural cross-subsystem lock-ordering is exactly the kind of thing lockdep was built for, and it's hard to argue this is fuzzer-overload noise — the chain is sound.
- The acquire/holder split is reproducible at *design level* — the LLM/synthesizer could (in principle) read the two source lines and explain the inversion without running the kernel.
- Even without an unprivileged-user PoC, lockdep deadlocks in established kernel code are typically worth filing.

### Candidate B — rwsem-magic-corruption via memory-failure path

| | |
|---|---|
| syzkaller bucket title | `WARNING in rmap_walk_file` |
| Hash | `8b4322e86609f605f137e898471a0f1c08180f65` |
| Sightings | 1 |
| Reproducer | None (`reproduction failed: context canceled`) |
| Symptom | `DEBUG_RWSEMS_WARN_ON(sem->magic != sem)` — rwsem magic is `0x0` instead of `&sem` |
| Trigger context | `kswapd0 → shrink_folio_list → unmap_poisoned_folio → try_to_unmap → rmap_walk_file → i_mmap_trylock_read` after `Memory failure: 0x5cffb: keeping poisoned page in swap cache` |
| CAP_SYS_ADMIN needed? | **Yes** — `MADV_HWPOISON` requires `CAP_SYS_ADMIN` (verified empirically: unprivileged `pov` user gets `EPERM`) |
| Sanitizers needed | `CONFIG_DEBUG_RWSEMS=y` for the WARN to fire; underlying race may be silent without it |
| Subsystem maintainer | `tools/get_maintainer.pl mm/memory-failure.c mm/rmap.c` → Naoya Horiguchi (memory-failure), Andrew Morton (mm), Matthew Wilcox, +linux-mm |

**Why it's borderline:**

- The `mm/memory-failure.c + MADV_HWPOISON` corner has been hit hundreds of times by syzbot historically. Many are classified as test-mode artifacts because no production workload uses `MADV_HWPOISON` outside fault-injection testing.
- A single sighting + no reproducer + debug-only WARN signature has a high probability of being closed as "not reproducible" within a week.
- *If* the underlying race (inode/address_space teardown vs. memory-failure-pinned page) is real, it's a genuine UAF in an internal kernel struct — but with no repro, we can't demonstrate that.

---

## Phase 1 — Search-before-report (30 min)

**Goal:** don't file duplicates.

```bash
# For each candidate, hit syzbot's dashboard and existing bug lists.
# Open in a browser (no API auth needed for upstream/<term>):
open "https://syzkaller.appspot.com/upstream"

# Then in the dashboard's search bar, paste each of these (one at a time):
"possible deadlock in perf_event_ctx_lock_nested"
"perf_event_ctx_lock_nested mmap_lock"
"circular locking dependency cpuctx_mutex"

"WARNING in rmap_walk_file"
"rmap_walk_file unmap_poisoned_folio"
"i_mmap_trylock_read rwsem magic"
```

Also search:

- **lore.kernel.org** for the same strings (catches mailing-list reports that never made it to syzbot)
- **bugzilla.kernel.org** mm + locking components
- **github.com/torvalds/linux/commits** for recent fixes touching `perf_event_ctx_lock_nested`, `cpuctx_mutex`, `rmap_walk_file`

**Decision matrix after the search:**

| Already filed and OPEN | Already filed and CLOSED | Not filed |
|---|---|---|
| Drop the candidate. Tracked. | Read the close-reason. If it was closed for "no reproducer" and ours is the second sighting, *attach a note* to the existing bug rather than filing new. | Proceed to Phase 2 for that candidate. |

---

## Phase 2 — Try to produce a reproducer (1–4 h per candidate)

A bug without a reproducer is roughly 10× less likely to be triaged. Worth one focused effort per candidate.

### For Candidate A (lockdep) — easier

Lockdep cross-subsystem deadlocks are usually *manifested* even on cold kernels with the right two parallel programs. Strategy:

1. Take the syz program log for the v2 hit (under `workdir-overnight-v2/crashes/40117f7e*/`).
2. Reduce by hand to the two parallel sub-programs that hold the conflicting locks. Likely: thread A does `perf_event_open + ioctl(PERF_EVENT_IOC_SET_FILTER)` (anything that takes `cpuctx_mutex`), thread B does an `mmap` or `madvise` from a different process.
3. Build a small standalone C reproducer that runs both threads in a loop. Run on the hunt kernel under QEMU; expect lockdep to fire within seconds.
4. If it reproduces deterministically → strong case for filing.

Time budget: ~2 h. If no repro by then, abandon for this round.

### For Candidate B (rwsem) — harder

The race needs `MADV_HWPOISON` (root) + concurrent `swap` activity + inode teardown. Three moving parts that have to align in microseconds. syzkaller already burned its repro budget and failed; doing better by hand is unlikely.

**Decision:** *don't* try. Either let v3 / future runs produce a second sighting + a repro, or skip filing this candidate.

---

## Phase 3 — File (Candidate A only, if Phase 1 says novel + Phase 2 produces a repro)

**Channel:** the syzkaller-bugs mailing list `syzkaller-bugs@googlegroups.com` mirrors directly into the syzbot dashboard, and Cc'ing maintainers gets human eyes on it faster than going straight to LKML.

**To:** `syzkaller-bugs@googlegroups.com`
**Cc:** Peter Zijlstra `<peterz@infradead.org>`, Ingo Molnar `<mingo@redhat.com>`, Arnaldo Carvalho de Melo `<acme@kernel.org>`, `linux-perf-users@vger.kernel.org`, `linux-kernel@vger.kernel.org`

**Subject template:**
```
[BUG] possible circular locking dependency: cpuctx_mutex -> ... -> mmap_lock (6.12.91)
```

**Body skeleton:**

```
Hi all,

Local fuzzing with syzkaller against 6.12.91 (gregkh/linux,
commit 57eaf35b03) surfaced a lockdep circular-dependency report.
The chain crosses perf, mm, and cpu hotplug.

Report (trimmed):
<paste from run-logs/crash-archive/v2/40117f7e/report.txt — the
WARNING block + "the existing dependency chain" + the
"->#10 (&cpuctx_mutex)" through "->#0 (&mm->mmap_lock)" blocks>

Reproducer (if Phase 2 succeeded):
<minimal C program, compiled with: gcc -static -pthread repro.c>

Config:
  Linux 6.12.91 with CONFIG_PROVE_LOCKING=y, CONFIG_LOCKDEP=y,
  CONFIG_KASAN=y, CONFIG_DEBUG_RWSEMS=y.
  Full hunt config: <paste a link / or attach>

Sightings:
  Two independent bucket hashes in an 8 h overnight fuzz run:
   - workdir-overnight/crashes/40117f7e0b1725ec0ef475b4359bea945d6366a9
   - workdir-overnight/crashes/798f1c91f6699c64d905bee349ecec50d36fb0c9
  Same 10-deep lock chain in both.

I'm happy to test patches against the same hunt build. The crash
artifacts are preserved at
  run-logs/crash-archive/v2/40117f7e/{description,title-stat,report.txt,log.gz}
  run-logs/crash-archive/v2/798f1c91/{description,title-stat,report.txt,log.gz}

Thanks,
<sign-off>
```

**What NOT to send:**

- Don't send any veri-agent / fuzzer-implementation details unless asked.
- Don't attribute the find to a "novel verifier" or claim any contribution beyond running syzkaller — the maintainers care about the bug, not the tool that found it.
- Don't claim it is a security bug. Lockdep cycles are CWE-833 (deadlock) — let the maintainers tag severity.

---

## Phase 4 — After-report follow-up (optional)

- Reply within 24 h to any clarification questions.
- If a patch is proposed, rebuild the hunt kernel with the patch applied and rerun a short syzkaller hunt focused on the affected syscall set; report Tested-by: on the patch.
- If maintainers close as won't-fix or not-a-bug, accept the call and don't re-litigate. Their judgement is final.

---

## What NOT to file

- **All task-hung / soft-lockup buckets** (`bdev_open`, `sync_bdevs`, `do_coredump`, `iterate_supers`, `corrupted`, `unix_stream_recvmsg`, `no output from test machine`): every one is consistent with a fuzzer-overloaded debug kernel. They will be closed as triage-noise.
- **suppressed report (b83ebc0f, twice)**: this is *exactly* the bucket syzkaller's own heuristics filter out as low-signal (mostly userspace faults from syz-executor itself). Filing this would be embarrassing.
- **rwsem-magic-corruption** (Candidate B): per Phase 2 decision above, skip unless we get a second sighting with a reproducer.

---

## Budget for this whole plan

| Phase | Time | Outcome |
|---|---|---|
| 1 — search syzbot | 30 min | go / no-go per candidate |
| 2 — repro for Candidate A | 0–2 h | repro / abandon |
| 3 — file Candidate A | 30 min | email out |
| 4 — follow-up | sporadic | depends on maintainer reply |

Worst case if both candidates turn out novel: ~3 h total. Realistic case (Candidate B is already filed or won't be filable, Candidate A is new): ~2.5 h.

If you'd rather skip this entirely and not engage the upstream community, that's also fine — there's no obligation. The bugs would presumably be found by syzbot's own infrastructure within weeks anyway.

---

## Cross-references in this repo

- Crash artifacts (gzipped, ~3.9 MB total): `run-logs/crash-archive/v1/`, `run-logs/crash-archive/v2/`
- Specifically: `run-logs/crash-archive/v2/40117f7e/`, `run-logs/crash-archive/v2/798f1c91/`, `run-logs/crash-archive/v2/8b4322e8/`
- Per-run summary: `run-logs/kernelctf-latest-fuzz-run-v2.json`
- Classifier source: `oracle/tier1_fuzz/verdict.py` (`from_kernel_bug_log` and severity tables)
- Maintainer lookup: run `tools/get_maintainer.pl` from inside `eval/kernelctf-latest/linux/source/`
