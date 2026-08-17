# Phase 6 — Kali / offensive tools (DONE)

Real security tooling, fully contained, every action human-approved and audited.

## Containment model
> **Changed (per request): `qh-lab` is now a normal bridge (egress + DNS), not `--internal`.** Kali
> tools can reach the **internet, the lab target (by name), and also your LAN/host**. The network is no
> longer the containment boundary — **the HIGH-tier per-call approval gate is.** Approve each scan
> target deliberately (that approval = you authorizing that target). To restore full isolation, put
> `--internal` back in `kali/run-kali.sh` + `lab/run-lab.sh` and recreate the network.

1. **Approval (primary control)** — all `kali_*` tools are **HIGH**: human approval per call + audit.
2. **Container** — `--cap-drop=ALL`, `--security-opt=no-new-privileges`, read-only rootfs, non-root,
   resource limits. nmap uses **connect scan (`-sT`)** so no raw-socket capability is needed.
   `ping_group_range` sysctl allows ICMP without `NET_RAW`.
3. **Parameterized tools** — no free-form flags (no arg injection); targets validated `^[A-Za-z0-9._-]+$`.
4. **gVisor-ready** — flip `SANDBOX_RUNTIME=runsc` for a kernel-isolation layer (install below).

## Components
- **`kali/kali_mcp.py`** — parameterized tools (no free-form flags → no arg injection, ANTI_PATTERNS P2):
  `kali_nmap(target, top_ports?, service_scan?)`, `kali_nikto(host, port?, ssl?)`,
  `kali_gobuster(host, port?, ssl?, wordlist?)`, `kali_whatweb(host, port?, ssl?)`.
  Targets validated `^[A-Za-z0-9._-]+$`.
- **`kali/Dockerfile`** — `kalilinux/kali-rolling` + nmap/nikto/gobuster/whatweb/dirb/wordlists, non-root.
- **`kali/run-kali.sh`** — hardened launcher on `qh-lab`, gVisor-ready.
- **`lab/run-lab.sh`** — creates the internal net + starts **OWASP Juice Shop** as `qh-target`
  (reachable only inside `qh-lab`, not published to the host).

## Start the range
```bash
bash lab/run-lab.sh            # internal net + vulnerable target 'qh-target'
docker build -t qwen-harness/kali kali/
# kali MCP is launched on demand by the gateway (policy.json server 'kali', all HIGH)
```

## Verified (2026-08-15)
- `kali_nmap qh-target` (by name) → lab target reachable; `kali_whatweb` → OWASP Juice Shop
- `kali_nmap scanme.nmap.org` → resolves + scans over the **internet** (DNS + egress working)
- **agent-driven**: Qwen ran nmap+whatweb, each **HIGH call blocked for approval**, human approved via
  `approve.py`, ran in the lab, produced a recon report; both logged `APPROVED:human:…`

## Optional hardening: install gVisor (runsc)
Run these (need sudo); authoritative docs: https://gvisor.dev/docs/user_guide/install
```bash
sudo apt-get install -y apt-transport-https ca-certificates gnupg
curl -fsSL https://gvisor.dev/archive.key | sudo gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" \
  | sudo tee /etc/apt/sources.list.d/gvisor.list
sudo apt-get update && sudo apt-get install -y runsc
sudo runsc install            # adds the 'runsc' runtime to /etc/docker/daemon.json
sudo systemctl reload docker
```
Then enable it for the sandbox + kali containers:
```bash
export SANDBOX_RUNTIME=runsc   # picked up by run-sandbox.sh and run-kali.sh
```

## Scaling the toolset
Add tools by extending `kali_mcp.py` with more parameterized wrappers (keep them parameterized, never
free-form). For hundreds of tools, this thin server can later be swapped for / combined with an existing
Dockerized Kali-MCP as a second downstream — the gateway's tier+approval+audit still wraps it.
