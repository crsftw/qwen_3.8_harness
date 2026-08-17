#!/usr/bin/env bash
# Launch the web MCP (egress-enabled, LAN-blocked at the app layer via SSRF filter).
# No shell is exposed by this server, so network access here can't become host execution.
set -euo pipefail
docker network inspect qh-web >/dev/null 2>&1 || docker network create qh-web >/dev/null

exec docker run --rm -i \
  --network qh-web \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --read-only \
  --tmpfs /tmp:rw,size=64m,mode=1777 \
  --pids-limit=128 \
  --memory=512m \
  --cpus=1 \
  -e SEARXNG_URL="${SEARXNG_URL:-http://qh-searxng:8080}" \
  qwen-harness/web
