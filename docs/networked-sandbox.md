# Networked sandbox (change to Phase 2)

`sandbox_bash` was changed from `--network=none` to a networked shell on a dedicated `qh-shell` bridge,
per request, so DNS + internet + `ping` work.

## What changed (`sandbox/run-sandbox.sh`)
- `--network=none` → `--network qh-shell` (bridge: egress + Docker embedded DNS at 127.0.0.11)
- added `--sysctl net.ipv4.ping_group_range="0 2147483647"` so the non-root user can send ICMP
  **without** `NET_RAW` — container keeps `--cap-drop=ALL`.
- everything else unchanged: non-root, read-only rootfs, resource limits, workspace-only RW mount.

## Verified
`ping google.com` (replies), DNS resolution, and `curl https://example.com` (200) all work from
`sandbox_bash`.

## Security tradeoff (important)
Unlike `web`/`net` (whose targets are parsed and SSRF-filtered), `sandbox_bash` runs arbitrary commands,
so on a normal bridge it can reach **your LAN, router, and host services** — confirmed it can hit the
host **Ollama** on `172.22.0.1:11434`. Compensating control: `sandbox_bash` stays **HIGH tier**, so every
command needs human approval and is audited.

## Optional: make it internet-only
`scripts/harden-shell-net.sh` (needs sudo) blocks the `qh-shell` subnet from RFC1918 + the host gateway
while keeping DNS + internet:
```bash
bash scripts/harden-shell-net.sh            # apply (internet-only)
bash scripts/harden-shell-net.sh --remove   # undo (full network)
```
Alternative to iptables: bind host services you don't want exposed (e.g. Ollama) to localhost instead of
0.0.0.0, or run the shell on an `--internal` network + an egress proxy.
