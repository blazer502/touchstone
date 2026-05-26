#!/usr/bin/env bash
# llm/serve.sh — bring vLLM containers up per config/models.yaml.
#
# Phase 0.2 needs an OpenAI-format endpoint to exist and answer. The same script
# launches either the smoke profile (one small model, one GPU) or the production
# profile (synthesizer + router replicas per config/models.yaml).
#
# Usage:
#   llm/serve.sh smoke           # bring up the smoke profile (default)
#   llm/serve.sh production      # bring up all production replicas
#   llm/serve.sh stop            # stop everything we started
#   llm/serve.sh status          # show running containers + ports
#
# Env:
#   DOCKER       — defaults to `docker`; set to `sudo docker` if not in the docker group.
#   HF_HOME      — defaults to $HOME/.cache/huggingface (mounted into the container).
#   VLLM_IMAGE   — overrides config/models.yaml; falls back to docs/toolchain.lock.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DOCKER="${DOCKER:-docker}"
HF_HOME="${HF_HOME:-$HOME/.cache/huggingface}"

# Read image pin from toolchain.lock unless caller overrides.
if [[ -z "${VLLM_IMAGE:-}" ]]; then
  VLLM_IMAGE="$(grep -E '^VLLM_IMAGE=' "$REPO_ROOT/docs/toolchain.lock" | cut -d= -f2)"
fi

CONTAINER_PREFIX="veri-vllm"

cmd_status() {
  $DOCKER ps --filter "name=${CONTAINER_PREFIX}-" --format 'table {{.Names}}\t{{.Ports}}\t{{.Status}}'
}

cmd_stop() {
  local names
  names=$($DOCKER ps -aq --filter "name=${CONTAINER_PREFIX}-")
  if [[ -n "$names" ]]; then
    $DOCKER rm -f $names >/dev/null
    echo "stopped: $names"
  else
    echo "no veri-vllm containers running"
  fi
}

# launch_one NAME MODEL PORT GPUS TP MAX_LEN MEM_UTIL
launch_one() {
  local name="$1" model="$2" port="$3" gpus="$4" tp="$5" max_len="$6" mem_util="$7"
  local full="${CONTAINER_PREFIX}-${name}"
  $DOCKER rm -f "$full" >/dev/null 2>&1 || true
  echo "launching $full (model=$model port=$port gpus=$gpus tp=$tp)"
  $DOCKER run -d --rm \
    --name "$full" \
    --gpus "\"device=${gpus}\"" \
    --ipc=host \
    -v "$HF_HOME:/root/.cache/huggingface" \
    -p "${port}:8000" \
    "$VLLM_IMAGE" \
      --model "$model" \
      --tensor-parallel-size "$tp" \
      --max-model-len "$max_len" \
      --gpu-memory-utilization "$mem_util" \
      --disable-log-requests
}

cmd_smoke() {
  # Parse the smoke block from config/models.yaml without depending on yq.
  local cfg="$REPO_ROOT/config/models.yaml"
  local model port gpus tp max_len mem
  model=$(python3 -c "import yaml,sys;print(yaml.safe_load(open('$cfg'))['smoke']['model'])")
  port=$(python3 -c "import yaml;print(yaml.safe_load(open('$cfg'))['smoke']['port'])")
  gpus=$(python3 -c "import yaml;print(','.join(map(str, yaml.safe_load(open('$cfg'))['smoke']['gpus'])))")
  tp=$(python3 -c "import yaml;print(yaml.safe_load(open('$cfg'))['smoke']['tensor_parallel'])")
  max_len=$(python3 -c "import yaml;print(yaml.safe_load(open('$cfg'))['smoke']['max_model_len'])")
  mem=$(python3 -c "import yaml;print(yaml.safe_load(open('$cfg'))['smoke']['gpu_memory_utilization'])")
  launch_one smoke "$model" "$port" "$gpus" "$tp" "$max_len" "$mem"
}

cmd_production() {
  local cfg="$REPO_ROOT/config/models.yaml"
  # Synthesizer replicas
  python3 - "$cfg" <<'PY' | while IFS=$'\t' read -r role idx model port gpus tp max_len; do
import sys, yaml
c = yaml.safe_load(open(sys.argv[1]))
for role in ('synthesizer', 'router'):
    r = c['roles'][role]
    for i, rep in enumerate(r['replicas']):
        print('\t'.join([role, str(i), r['model'], str(rep['port']),
                         ','.join(map(str, rep['gpus'])),
                         str(r['tensor_parallel']), str(r['max_model_len'])]))
PY
    launch_one "${role}-${idx}" "$model" "$port" "$gpus" "$tp" "$max_len" 0.85
  done
}

case "${1:-smoke}" in
  smoke)      cmd_smoke ;;
  production) cmd_production ;;
  stop)       cmd_stop ;;
  status)     cmd_status ;;
  *) echo "usage: $0 {smoke|production|stop|status}"; exit 2 ;;
esac
