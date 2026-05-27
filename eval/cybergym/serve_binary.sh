#!/usr/bin/env bash
# Start the CyberGym submission server in **binary-only** mode against the
# off-repo NVMe data layout. See docs/leaderboard.md §5b.
#
# Layout (defaults):
#   /mnt/data/chanyoung/cybergym/cybergym-server-data/  ← extracted 130 GB tarball
#   /mnt/data/chanyoung/cybergym/cybergym_data/         ← HF dataset (gen_task data-dir)
#   /home/chanyoung/veri-agent/eval/cybergym/server_state/  ← POC db + log dir
#
# Override via env:
#   CYBERGYM_SERVER_DATA_DIR  (path to extracted binary server-data)
#   CYBERGYM_PORT             (default 8666)
#   POC_SAVE_DIR              (default eval/cybergym/server_state)
#
# Usage:
#   bash eval/cybergym/serve_binary.sh            # start in foreground
#   bash eval/cybergym/serve_binary.sh --background
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CYBERGYM_DIR="$REPO_ROOT/eval/cybergym"
PORT="${CYBERGYM_PORT:-8666}"
SAVE_DIR="${POC_SAVE_DIR:-$CYBERGYM_DIR/server_state}"
SERVER_DATA_DIR="${CYBERGYM_SERVER_DATA_DIR:-/mnt/data/chanyoung/cybergym/cybergym-server-data}"
# Mask map is for blind-eval protocol (gen_task masks ids so agents can't look
# up the disclosure ahead of time). For self-evaluation we don't need it —
# scoring is identical and we avoid plumbing the mask through the adapter.
# Set CYBERGYM_USE_MASK_MAP=1 to re-enable.
MASK_MAP="$CYBERGYM_DIR/repo/mask_map.json"
USE_MASK_MAP="${CYBERGYM_USE_MASK_MAP:-0}"
VENV_PY="$CYBERGYM_DIR/venv/bin/python"

if [[ ! -d "$SERVER_DATA_DIR" ]]; then
    echo "ERROR: server data not found at $SERVER_DATA_DIR" >&2
    echo "       extract cybergym-server-data.7z there first." >&2
    exit 2
fi

mkdir -p "$SAVE_DIR"

CMD=(
    sudo -E "$VENV_PY" -m cybergym.server
    --host 127.0.0.1 --port "$PORT"
    --log_dir "$SAVE_DIR"
    --db_path "$SAVE_DIR/poc.db"
    --binary_dir "$SERVER_DATA_DIR"
)
if [[ "$USE_MASK_MAP" == "1" ]]; then
    CMD+=(--mask_map_path "$MASK_MAP")
fi

echo "starting cybergym.server (binary-only):"
printf '  %q' "${CMD[@]}"; echo

if [[ "${1:-}" == "--background" ]]; then
    nohup "${CMD[@]}" > "$SAVE_DIR/server.log" 2>&1 &
    echo "pid=$! → log: $SAVE_DIR/server.log"
else
    exec "${CMD[@]}"
fi
