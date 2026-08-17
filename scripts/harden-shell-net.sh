#!/usr/bin/env bash
# OPTIONAL: restrict the networked sandbox (qh-shell) to INTERNET-ONLY — block your LAN,
# other docker networks, and host services (e.g. Ollama). Needs sudo (edits iptables).
# Run `--remove` to undo. DNS still works (Docker embedded resolver at 127.0.0.11).
set -euo pipefail
SUBNET="$(docker network inspect qh-shell -f '{{ (index .IPAM.Config 0).Subnet }}')"
GW="$(docker network inspect qh-shell -f '{{ (index .IPAM.Config 0).Gateway }}')"
PRIV=(10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16)
ACTION="${1:-add}"

if [ "$ACTION" = "--remove" ]; then
  for dst in "${PRIV[@]}"; do sudo iptables -D DOCKER-USER -s "$SUBNET" -d "$dst" -j DROP 2>/dev/null || true; done
  sudo iptables -D INPUT -s "$SUBNET" -d "$GW" -j DROP 2>/dev/null || true
  echo "removed qh-shell egress restrictions"; exit 0
fi

# container -> LAN / other docker nets (FORWARD path): drop private destinations, allow public
for dst in "${PRIV[@]}"; do
  sudo iptables -C DOCKER-USER -s "$SUBNET" -d "$dst" -j DROP 2>/dev/null \
    || sudo iptables -I DOCKER-USER -s "$SUBNET" -d "$dst" -j DROP
done
# container -> host services on the bridge gateway (INPUT path): drop (blocks host Ollama etc.)
sudo iptables -C INPUT -s "$SUBNET" -d "$GW" -j DROP 2>/dev/null \
  || sudo iptables -I INPUT -s "$SUBNET" -d "$GW" -j DROP

echo "qh-shell ($SUBNET) is now internet-only: LAN, other docker nets, and host ($GW) are blocked; DNS + internet still work."
echo "undo with: bash scripts/harden-shell-net.sh --remove"
