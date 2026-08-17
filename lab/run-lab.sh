#!/usr/bin/env bash
# Stand up the practice range: the qh-lab network + a vulnerable target.
# NOTE: qh-lab is now a normal bridge (egress + DNS) per request — kali on it can reach the
# internet as well as this target (qh-target). The target is still NOT published to the host.
set -euo pipefail
docker network inspect qh-lab >/dev/null 2>&1 || docker network create qh-lab >/dev/null
docker rm -f qh-target >/dev/null 2>&1 || true

docker run -d --name qh-target \
  --network qh-lab \
  --memory=4g --cpus=4 \
  bkimminich/juice-shop >/dev/null

echo "lab target 'qh-target' (OWASP Juice Shop, port 3000) is up on qh-lab (bridge)."
echo "Reachable by name as qh-target from kali; not published to the host."
