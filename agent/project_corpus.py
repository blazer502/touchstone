"""F4: project-level corpus sharing — tasks in the same project pool their
discovered inputs.

When a `BenchmarkTask` exposes `project_group()` (e.g. `libpng`, `openssl`,
`net/netfilter`), the agent can amortise learning across tasks: a candidate
that crashed task A's harness becomes a seed for task B if both are in the
same project. The OSS-Fuzz dataset has heavy project repetition (libpng
has 30+ tasks, openssl 50+, libxml2 20+), so this is real leverage rather
than a synthetic trick.

API:

    pc = ProjectCorpus()             # in-memory across one driver run
    seeds = pc.seeds_for(task)       # returns previously-found inputs for
                                     # task.project_group(), oldest-first
    pc.record(task, poc_bytes)       # add a new input to that project's pool

Persistence is optional (`ProjectCorpus(persist_root=Path(...))`) — a
JSON-per-project record so a re-run of the same benchmark inherits prior
discoveries. Set `max_seeds_per_project` to bound memory.

Benchmark-agnostic: only uses `BenchmarkTask.project_group()`. CyberGym
adapter resolves it via `tasks.json["project_name"]`; future benchmarks
return their own grouping (CWE class for Juliet, target name for Magma,
kernel subsystem for kernelCTF).
"""
from __future__ import annotations

import hashlib
import json
import logging
import threading
from collections import OrderedDict
from pathlib import Path
from typing import Iterable, Optional

from agent.task_interface import BenchmarkTask


log = logging.getLogger("project_corpus")


def _content_id(poc_bytes: bytes) -> str:
    return hashlib.sha256(poc_bytes).hexdigest()[:16]


class ProjectCorpus:
    """Thread-safe project-keyed seed pool. Keeps the K most recent inputs
    per project; older entries fall off LRU-style.

    Most callers want one instance per driver run; pass it to every
    `run_agent` invocation via the orchestrator.
    """

    def __init__(self, *,
                 persist_root: Optional[Path] = None,
                 max_seeds_per_project: int = 64,
                 max_seed_bytes: int = 4096) -> None:
        self._lock = threading.Lock()
        self._by_project: dict[str, "OrderedDict[str, bytes]"] = {}
        self._max = max_seeds_per_project
        self._max_bytes = max_seed_bytes
        self._persist_root = persist_root
        if persist_root is not None:
            persist_root.mkdir(parents=True, exist_ok=True)
            self._load()

    # --- persistence -------------------------------------------------------

    def _load(self) -> None:
        if not self._persist_root:
            return
        for p in self._persist_root.glob("*.json"):
            try:
                blob = json.loads(p.read_text())
            except Exception:
                continue
            project = blob.get("project") or p.stem
            seeds = blob.get("seeds") or []
            od: "OrderedDict[str, bytes]" = OrderedDict()
            for ent in seeds:
                hx = ent.get("hex")
                if not hx:
                    continue
                try:
                    b = bytes.fromhex(hx)
                except ValueError:
                    continue
                if 0 < len(b) <= self._max_bytes:
                    od[_content_id(b)] = b
            if od:
                self._by_project[project] = od

    def _save(self, project: str) -> None:
        if not self._persist_root:
            return
        od = self._by_project.get(project) or OrderedDict()
        safe = project.replace("/", "_").replace(":", "_")
        out = self._persist_root / f"{safe}.json"
        try:
            out.write_text(json.dumps({
                "project": project,
                "seeds": [{"id": cid, "hex": b.hex()} for cid, b in od.items()],
            }))
        except Exception as e:
            log.warning("[%s] project corpus persist failed: %s", project, e)

    # --- API ---------------------------------------------------------------

    def seeds_for(self, task: BenchmarkTask) -> list[bytes]:
        proj = task.project_group()
        if not proj:
            return []
        with self._lock:
            od = self._by_project.get(proj)
            return list(od.values()) if od else []

    def record(self, task: BenchmarkTask, poc_bytes: bytes) -> None:
        proj = task.project_group()
        if not proj or not poc_bytes or len(poc_bytes) > self._max_bytes:
            return
        cid = _content_id(poc_bytes)
        with self._lock:
            od = self._by_project.setdefault(proj, OrderedDict())
            if cid in od:
                od.move_to_end(cid)              # touch
                return
            od[cid] = poc_bytes
            while len(od) > self._max:
                od.popitem(last=False)            # drop oldest
        self._save(proj)

    def record_many(self, task: BenchmarkTask, poc_blobs: Iterable[bytes]) -> int:
        n = 0
        for b in poc_blobs:
            self.record(task, b)
            n += 1
        return n

    def stats(self) -> dict:
        with self._lock:
            return {
                "projects": len(self._by_project),
                "seeds_total": sum(len(od) for od in self._by_project.values()),
                "by_project": {p: len(od) for p, od in self._by_project.items()},
            }


__all__ = ["ProjectCorpus"]
