#!/usr/bin/env bash
# On-demand lifecycle for the FP8 vLLM backend running in the author-recommended Docker image
# (vllm/vllm-openai:v0.24.0). start (launch + wait until healthy) | stop | status | logs.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT="${VLLM_PORT:-8001}"

is_up() { curl -sf "http://127.0.0.1:$PORT/health" >/dev/null 2>&1; }

case "${1:-}" in
  start)
    if is_up; then echo "vLLM(FP8) already up on :$PORT"; exit 0; fi
    echo "starting FP8 vLLM container (v0.24.0, tp=2)... this takes ~4-5 min (compile+warmup+capture)"
    bash "$HERE/run-vllm-docker.sh" >/dev/null
    printf "waiting for model"
    for _ in $(seq 1 180); do            # up to ~6 min
      if is_up; then echo " ready on :$PORT."; exit 0; fi
      if [ "$(docker ps -q -f name=qh-vllm)" = "" ]; then
        echo " CONTAINER EXITED — see: docker logs qh-vllm" >&2; exit 1
      fi
      printf "."; sleep 2
    done
    echo " TIMEOUT — see: docker logs qh-vllm" >&2; exit 1
    ;;
  stop)
    docker rm -f qh-vllm >/dev/null 2>&1 || true
    echo "FP8 vLLM container stopped."
    ;;
  status)
    if is_up; then echo "vLLM(FP8): UP on :$PORT"; else echo "vLLM(FP8): down"; fi
    docker ps -a --filter name=qh-vllm --format '  container: {{.Status}}' 2>/dev/null || true
    ;;
  logs) docker logs "${2:-qh-vllm}" 2>&1 | tail -"${3:-40}" ;;
  *) echo "usage: $0 {start|stop|status|logs}" >&2; exit 2 ;;
esac
