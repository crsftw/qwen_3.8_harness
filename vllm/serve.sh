#!/usr/bin/env bash
# On-demand lifecycle for the vLLM FP8 backend: start (background, wait until healthy) | stop | status.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT="${VLLM_PORT:-8001}"
PIDFILE="$HERE/state/vllm.pid"
LOG="$HERE/state/vllm.log"

is_up() { curl -sf "http://127.0.0.1:$PORT/health" >/dev/null 2>&1; }

case "${1:-}" in
  start)
    if is_up; then echo "vLLM already up on :$PORT"; exit 0; fi
    echo "starting vLLM (FP8, tp=2)... logs -> $LOG"
    nohup bash "$HERE/run-vllm.sh" >"$LOG" 2>&1 &
    echo $! > "$PIDFILE"
    printf "waiting for model load"
    for _ in $(seq 1 180); do          # up to ~6 min for weights to load
      if is_up; then echo " ready."; exit 0; fi
      printf "."; sleep 2
    done
    echo " TIMEOUT — check $LOG" >&2; exit 1
    ;;
  stop)
    if [[ -f "$PIDFILE" ]]; then
      PID="$(cat "$PIDFILE")"
      # kill the process group (vllm spawns workers)
      pkill -TERM -P "$PID" 2>/dev/null || true
      kill -TERM "$PID" 2>/dev/null || true
      sleep 3
      pkill -KILL -P "$PID" 2>/dev/null || true
      kill -KILL "$PID" 2>/dev/null || true
      rm -f "$PIDFILE"
    fi
    pkill -f "vllm serve" 2>/dev/null || true
    echo "vLLM stopped."
    ;;
  status)
    if is_up; then echo "vLLM: UP on :$PORT"; else echo "vLLM: down"; fi
    ;;
  *) echo "usage: $0 {start|stop|status}" >&2; exit 2 ;;
esac
