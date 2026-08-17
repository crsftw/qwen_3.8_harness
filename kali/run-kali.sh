#!/usr/bin/env bash
# Launch the Kali tools MCP on qh-lab. NOTE: qh-lab is now a normal bridge (egress + DNS) per
# request, so kali tools can reach the internet AND the lab target (qh-target) by name.
# Security posture: containment is NO LONGER the network — it is the HIGH-tier per-call approval
# gate. kali can also reach your LAN/host on a bridge; approve each scan target deliberately.
# gVisor-ready: `export SANDBOX_RUNTIME=runsc` for kernel-level isolation.
set -euo pipefail
docker network inspect qh-lab >/dev/null 2>&1 || docker network create qh-lab >/dev/null

RUNTIME_ARG=()
[[ -n "${SANDBOX_RUNTIME:-}" ]] && RUNTIME_ARG=(--runtime "$SANDBOX_RUNTIME")

exec docker run --rm -i \
  "${RUNTIME_ARG[@]}" \
  --network qh-lab \
  --sysctl net.ipv4.ping_group_range="0 2147483647" \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --read-only \
  --tmpfs /tmp:rw,size=128m,mode=1777 \
  --tmpfs /home/kali:rw,size=32m,uid=1000,gid=1000 \
  --pids-limit=512 \
  --memory=2g \
  --cpus=2 \
  qwen-harness/kali
