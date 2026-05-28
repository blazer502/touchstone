#!/usr/bin/env bash
# Run Stage B verifier overnight on netfilter Stage A surface.
# Bounded by --wall-cap (default 4h). Uses the CPU LLM via gateway.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$ROOT"

# Ensure gateway is up
curl -s http://127.0.0.1:8000/healthz >/dev/null || {
  echo "[stageb-overnight] LLM gateway not running at :8000 — aborting"
  exit 1
}

OUT="run-logs/stageb-overnight/results-$(date +%Y%m%d-%H%M%S).jsonl"
mkdir -p "$(dirname $OUT)" run-logs/stageb-overnight/harnesses

echo "[stageb-overnight] starting at $(date)"
echo "[stageb-overnight] output: $OUT"

DOCKER=docker GATEWAY_PORT=8000 timeout 14400 \
  /tmp/veri-venv/bin/python3 eval/kernelctf-latest/scripts/stageb_overnight.py \
    --tasks-dir surface/tasks/linux-6.12.91-net-netfilter \
    --linux-src eval/kernelctf-latest/linux/source \
    --out "$OUT" \
    --harness-dir run-logs/stageb-overnight/harnesses \
    --limit 60 \
    --cbmc-timeout 180 \
    --unwind 8 \
    --max-refine-iters 3 \
    --wall-cap 14400 \
  2>&1 | tee "${OUT%.jsonl}.log"

echo "[stageb-overnight] done at $(date)"
echo "--- result summary ---"
python3 -c "
import json
from collections import Counter
counts = Counter()
for line in open('$OUT'):
    if not line.strip(): continue
    r = json.loads(line)
    s = r.get('status', 'unknown')
    v = r.get('verdict', '-') if s == 'ok' else s
    counts[v] += 1
print(dict(counts))
"
