#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
python3 -m pip install -q -r requirements.txt
export MONITOR_CONFIG="${MONITOR_CONFIG:-./config.yaml}"
exec python3 -m uvicorn "backend.main:get_app" --factory \
  --host "$(python3 -c 'from backend.config import load;print(load().bind_host)')" \
  --port "$(python3 -c 'from backend.config import load;print(load().bind_port)')"
