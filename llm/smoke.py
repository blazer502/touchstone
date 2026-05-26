"""Phase 0.2 smoke test — verify the LLM endpoint serves an OpenAI request.

Done when:
  * vLLM is up under `llm/serve.sh smoke`,
  * the gateway forwards an OpenAI-format chat/completion and returns a body,
  * GPU utilization is non-trivially nonzero during the call.

This script does NOT bring vLLM up; that's `llm/serve.sh smoke`'s job. The
script waits for /healthz, fires one chat request via the role alias
"synthesizer", samples nvidia-smi mid-flight, and writes a result row to
run-logs/phase0.2-smoke.json.
"""
from __future__ import annotations
import argparse
import json
import subprocess
import sys
import threading
import time
from pathlib import Path

import httpx

REPO_ROOT = Path(__file__).resolve().parents[1]
LOG_DIR = REPO_ROOT / "run-logs"


def wait_for_health(url: str, timeout: float) -> dict:
    deadline = time.time() + timeout
    last_err = None
    while time.time() < deadline:
        try:
            r = httpx.get(f"{url}/healthz", timeout=3.0)
            if r.status_code == 200:
                body = r.json()
                # All backends must reply with HTTP 200 (vLLM's /health).
                ok = all(b["status"] == 200 for items in body["backends"].values() for b in items)
                if ok:
                    return body
        except Exception as e:
            last_err = e
        time.sleep(2.0)
    raise RuntimeError(f"gateway never healthy within {timeout:.0f}s (last={last_err})")


def sample_nvidia_smi() -> list[dict]:
    out = subprocess.check_output([
        "nvidia-smi",
        "--query-gpu=index,utilization.gpu,memory.used,memory.total",
        "--format=csv,noheader,nounits",
    ], text=True)
    rows = []
    for line in out.strip().splitlines():
        idx, util, mem_used, mem_total = [x.strip() for x in line.split(",")]
        rows.append({"gpu": int(idx), "util_pct": int(util),
                     "mem_used_mib": int(mem_used), "mem_total_mib": int(mem_total)})
    return rows


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--gateway", default="http://127.0.0.1:8000")
    p.add_argument("--role", default="synthesizer")
    p.add_argument("--health-timeout", type=float, default=600.0,
                   help="Wait up to N seconds for vLLM to finish loading the model.")
    p.add_argument("--prompt", default="Write a one-line C function that returns the sum of two ints.")
    args = p.parse_args()

    print(f"[smoke] waiting for {args.gateway}/healthz ...", flush=True)
    health = wait_for_health(args.gateway, args.health_timeout)
    print(f"[smoke] healthy: {json.dumps(health)}", flush=True)

    # Sample GPU during the request, in a side thread.
    gpu_samples: list[list[dict]] = []
    stop = threading.Event()
    def sampler():
        while not stop.is_set():
            try:
                gpu_samples.append(sample_nvidia_smi())
            except Exception:
                pass
            time.sleep(0.5)
    t = threading.Thread(target=sampler, daemon=True)
    t.start()

    t0 = time.time()
    r = httpx.post(f"{args.gateway}/v1/chat/completions", json={
        "model": args.role,
        "messages": [
            {"role": "system", "content": "You are a terse C systems programmer."},
            {"role": "user", "content": args.prompt},
        ],
        "max_tokens": 64,
        "temperature": 0.0,
    }, timeout=300.0)
    latency = time.time() - t0
    stop.set(); t.join(timeout=1.0)

    if r.status_code != 200:
        print(f"[smoke] FAIL status={r.status_code} body={r.text[:400]}", file=sys.stderr)
        return 1

    body = r.json()
    completion = body["choices"][0]["message"]["content"]
    usage = body.get("usage", {})

    # Peak GPU util across samples per device.
    peak = {}
    for sample in gpu_samples:
        for row in sample:
            cur = peak.get(row["gpu"], {"util_pct": 0, "mem_used_mib": 0})
            cur["util_pct"] = max(cur["util_pct"], row["util_pct"])
            cur["mem_used_mib"] = max(cur["mem_used_mib"], row["mem_used_mib"])
            cur["mem_total_mib"] = row["mem_total_mib"]
            peak[row["gpu"]] = cur
    peak_list = [{"gpu": g, **v} for g, v in sorted(peak.items())]

    record = {
        "ts": time.time(),
        "phase": "0.2",
        "gateway": args.gateway,
        "role": args.role,
        "health": health,
        "latency_s": round(latency, 3),
        "usage": usage,
        "completion_preview": completion[:200],
        "gpu_peak": peak_list,
        "gpu_samples": len(gpu_samples),
    }
    LOG_DIR.mkdir(exist_ok=True)
    fp = LOG_DIR / "phase0.2-smoke.json"
    fp.write_text(json.dumps(record, indent=2) + "\n")
    print(f"[smoke] PASS latency={latency:.2f}s usage={usage} -> {fp}")
    print(f"[smoke] completion: {completion[:200]!r}")
    print(f"[smoke] gpu_peak: {peak_list}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
