#!/usr/bin/env bash
# Launch the network/recon tools MCP. Egress-enabled; private targets blocked at the app layer
# (unless ALLOW_PRIVATE=1). No NET_RAW — all tools are unprivileged.
set -euo pipefail
docker network inspect qh-net >/dev/null 2>&1 || docker network create qh-net >/dev/null

exec docker run --rm -i \
  --network qh-net \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --read-only \
  --tmpfs /tmp:rw,size=32m,mode=1777 \
  --pids-limit=128 \
  --memory=256m \
  --cpus=1 \
  -e ALLOW_PRIVATE="${ALLOW_PRIVATE:-0}" \
  qwen-harness/nettools
