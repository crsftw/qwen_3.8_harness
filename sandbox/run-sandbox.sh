#!/usr/bin/env bash
# Launch the hardened sandbox container running the MCP server on stdio.
# This is the ONE audited place holding the isolation flags. Goose's extension
# calls this script; the container is ephemeral (--rm) and dies when Goose closes stdio.
set -euo pipefail

# Persistent, sandboxed workspace — the ONLY writable path the agent can touch.
WORKSPACE="${SANDBOX_WORKSPACE:-$HOME/qwen_harness/workspace}"
mkdir -p "$WORKSPACE"

# Optional gVisor runtime: `export SANDBOX_RUNTIME=runsc` once gVisor is installed
# (Phase 6 prerequisite). Defaults to the standard runtime for now.
RUNTIME_ARG=()
if [[ -n "${SANDBOX_RUNTIME:-}" ]]; then
  RUNTIME_ARG=(--runtime "$SANDBOX_RUNTIME")
fi

# Networked shell: egress + DNS on a dedicated bridge. ping works via the ping_group_range
# sysctl (ICMP datagram sockets for the non-root user) so caps stay fully dropped (no NET_RAW).
# NOTE: a raw shell on a bridge can also reach your LAN and host services — see docs for the
# optional DOCKER-USER rules that restrict it to internet-only.
docker network inspect qh-shell >/dev/null 2>&1 || docker network create qh-shell >/dev/null

exec docker run --rm -i \
  "${RUNTIME_ARG[@]}" \
  --network qh-shell \
  --sysctl net.ipv4.ping_group_range="0 2147483647" \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --read-only \
  --tmpfs /tmp:rw,size=64m,mode=1777 \
  --tmpfs /home/sandbox:rw,size=16m,uid=1000,gid=1000 \
  --pids-limit=256 \
  --memory=1g \
  --cpus=2 \
  -v "$WORKSPACE:/work:rw" \
  qwen-harness/sandbox
