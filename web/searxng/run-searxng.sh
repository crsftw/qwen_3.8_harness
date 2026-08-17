#!/usr/bin/env bash
# Start (or restart) the self-hosted SearXNG search service on the qh-web network.
# Generates a runtime settings file with a fresh secret_key (not committed).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
RUNTIME="$HERE/runtime"
mkdir -p "$RUNTIME"

if [ ! -f "$RUNTIME/settings.yml" ]; then
  SECRET="$(openssl rand -hex 32)"
  sed "s/__SECRET_KEY__/$SECRET/" "$HERE/settings.template.yml" > "$RUNTIME/settings.yml"
  echo "generated $RUNTIME/settings.yml with a fresh secret_key"
fi

docker network inspect qh-web >/dev/null 2>&1 || docker network create qh-web >/dev/null
docker rm -f qh-searxng >/dev/null 2>&1 || true

docker run -d --name qh-searxng \
  --network qh-web \
  -p 127.0.0.1:8888:8080 \
  -v "$RUNTIME/settings.yml:/etc/searxng/settings.yml:ro" \
  --memory=512m --cpus=1 \
  searxng/searxng >/dev/null

echo "SearXNG starting on the qh-web network (name: qh-searxng:8080; host: http://127.0.0.1:8888)"
