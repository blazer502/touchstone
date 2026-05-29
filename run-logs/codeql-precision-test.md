# CodeQL interprocedural-taint precision test — outcome (2026-05-30)

Goal: test whether CodeQL's global interprocedural taint can follow the dispatch
edge that Smatch's per-function `user_rl` misses, to confirm/refute the net/
user-controlled-index candidates (ethtool / sch_prio / nfsd) the cross-fn Smatch
DB surfaced (see `run-logs/smatch-xfn-db-hunt.md`).

## What works
- CodeQL CLI 2.25.5 installed in-workspace (`tools/codeql/`, gitignored, pinned
  in `docs/toolchain.lock`). Custom kernel-taint query authored:
  `tools/codeql-queries/KernelUserControlledArrayIndex.ql` (sources:
  copy_from_user/memdup_user + nla_get*/nlmsg_data/genlmsg_data; sinks: array
  index + memcpy/copy_to_user size; global taint, compiles clean).
- The query RUNS correctly and the DB import is clean (no extractor errors).

## The blocker — net/ under-extraction (reproducible, 3 build attempts)
The traced kernel build **under-extracts `net/`**: `fs/` extracts fully (10,432
functions) but `net/` yields only 586, and the candidate functions are ABSENT:
`ethnl_default_start` = 0, `prio_tune` = 0, `net/ethtool/` = 0 functions —
even though the build log shows `net/ethtool/netlink.o` compiling. Extraction
quality correlates with build *time* (early-compiled dirs missed: net/core 16,
net/ethtool/net/sched 0; late dirs caught: net/devlink 80; fs/ last = full),
pointing to a CodeQL build-tracer issue with this kernel's net/ build. Tried:
`-j16` net/+fs/ (prepare chained), prepare-isolated, and `-j1` net/ serial —
all reproduce 586/0 for net/. Not cracked.

## Net result — the net/ CodeQL test is INCONCLUSIVE
Because the net/ candidates aren't in the DB, CodeQL can't be used to confirm/
refute them. **This does not change the conclusion:** the ethtool/sch_prio/nfsd
candidates were already **source-verified as dispatch-guarded false positives**
(ethtool: genl_get_cmd validates cmd before `->start()`; nfsd: COMPOUND opnum
check + privileged; sch_prio: CAP_NET_ADMIN). CodeQL DID run on the extracted
surface and produced 3 copy_from_user→sink flows — 2 are `tools/lib/string.c`
host-tool memcpy/memset artifacts, 1 in `fs/proc/task_mmu.c:604` — i.e., nothing
new/exploitable on the unprivileged surface, consistent with the Smatch finding.

## Disposition
The CodeQL DB is valid for `fs/` (10,432 functions) and usable as a supplementary
candidate source for the kernelCTF hunt's fs/ surface. The net/ extraction issue
is a documented limitation; the cross-fn Smatch DB remains the primary candidate
source. Not worth further build attempts — the precision-wall conclusion stands.
Artifacts: `run-logs/codeql-db/kernel-netfs/` (DB), `run-logs/codeql-kernel-user-index.sarif`.
