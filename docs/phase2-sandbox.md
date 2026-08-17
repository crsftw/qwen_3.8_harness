# Phase 2 — Hardened sandbox + Shell/Filesystem MCP (DONE)

The reusable security foundation. Every later tool container is a variation of this template.

## Components (`sandbox/`)
- **`sandbox_mcp.py`** — stdlib-only MCP stdio server (JSON-RPC 2.0, newline-delimited). Tools:
  `bash`, `read_file`, `write_file`, `list_dir`, all confined to `/work`. A *full* shell is intentional —
  the container is the boundary, so command-injection has nothing to injure inside (see §3.5 of the spec).
- **`Dockerfile`** — `debian:stable-slim` + python3/bash/coreutils (+ curl/ping/dig for isolation tests).
  Non-root `sandbox` user (uid 1000). No secrets baked in.
- **`run-sandbox.sh`** — the ONE audited place holding the isolation flags. Ephemeral `docker run --rm -i`
  on stdio; gVisor-ready via `SANDBOX_RUNTIME=runsc`.

## Isolation flags (in `run-sandbox.sh`)
`--network=none` · `--cap-drop=ALL` · `--security-opt=no-new-privileges` · `--read-only` rootfs ·
`--tmpfs /tmp,/home/sandbox` · `--pids-limit=256` · `--memory=1g --cpus=2` ·
only writable path = `-v $WORKSPACE:/work:rw` (default `~/qwen_harness/workspace`).

## Wiring
Goose `~/.config/goose/config.yaml`: built-in `developer` extension **disabled**; `sandbox` stdio
extension enabled (`cmd: bash run-sandbox.sh`). The model can act ONLY through the sandbox.

## Verified (2026-08-15)
Agent-driven (`goose run`, Qwen 3.8:27b) confirmed all of:
- runs as non-root `sandbox` (uid 1000), container hostname ≠ host
- `--network=none`: `curl` fails (DNS unresolvable)
- host filesystem not reachable (host paths absent)
- read-only rootfs (`touch /opt/evil` → *Read-only file system*)
- workspace RW mount persists files back to the host

## Build / re-verify
```bash
cd sandbox && docker build -t qwen-harness/sandbox .
# protocol/isolation smoke test:
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{}}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' | bash run-sandbox.sh
```

## Later
- Flip `SANDBOX_RUNTIME=runsc` once gVisor is installed (Phase 6 prerequisite).
- This template is the parent for the network-tools (Phase 5) and Kali (Phase 6) containers, which get
  different `--network`/`--cap-add` per tier — always launched behind the gateway (Phase 3).
