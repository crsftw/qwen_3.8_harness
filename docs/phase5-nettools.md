# Phase 5 — Network / recon tools (DONE)

Egress-enabled recon, with your LAN/host protected at the **application layer** (no host-firewall
changes needed) and **no elevated capabilities** (unprivileged tools, `--cap-drop=ALL` kept).

## Tools (`nettools/net_mcp.py`)
| Tool | Tier | Connects to target? | Notes |
|---|---|---|---|
| `net_dig` | LOW | no | DNS lookup via default resolver |
| `net_whois` | LOW | no (whois servers) | domain/IP whois |
| `net_tracepath` | MEDIUM | yes → validated | unprivileged path trace (no NET_RAW) |
| `net_openssl` | MEDIUM | yes → validated | TLS handshake / server cert |
| `net_nc` | MEDIUM | yes → validated | TCP connect, optional send, banner |

Connect-tools resolve the target and **refuse private / loopback / link-local IPs** (protects LAN, the
docker host, cloud metadata). Toggle with `ALLOW_PRIVATE=1` for an isolated lab (Phase 6). All commands
run as argv arrays (`shell=false`) — host-side command-injection safe (ANTI_PATTERNS P2).

## Container (`nettools/`)
`debian:stable-slim` + dnsutils/whois/iputils-tracepath/openssl/netcat-openbsd. Non-root, read-only
rootfs, `--cap-drop=ALL`, resource-limited, on the `qh-net` network. `run-net.sh` is the launcher.

## Gateway
Registered in `policy.json` under server `net`. Because tools are already named `net_*`, the gateway
exposes them un-double-prefixed (fixed for all servers: `sandbox_*`, `web_*`, `net_*`).

## Verified (2026-08-15)
- `net_dig example.com` → A records; `net_openssl example.com:443` → cert CN + TLS1.3;
  `net_nc example.com:80` → HTTP banner
- `net_tracepath 192.168.1.1` → **blocked** (LAN protection) with `ALLOW_PRIVATE=0`
- agent-driven: Qwen ran dig+openssl via gateway, reported IPs/CN/TLS correctly; calls logged with tiers

## Why unprivileged tools
`tracepath` (not `traceroute`) and connect-only `nc` avoid needing `NET_RAW`, so the container keeps all
caps dropped. ICMP `ping` is intentionally omitted for the same reason.
