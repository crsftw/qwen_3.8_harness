# qwen_3.8_harness

**A self-hosted, sandboxed Linux / security agent for a locally-run LLM — with real containment, tiered permissions, human approval, and a live activity-monitoring dashboard.**

`qwen_harness` lets a local Qwen model (served by Ollama or vLLM) act as a capable Linux and security/pen-testing agent that can use many real tools — a shell, web fetch/search, network recon, and a Kali toolbox (nmap, nikto, gobuster, whatweb) — **without trusting the model**. Every tool runs inside an ephemeral, locked-down container behind a policy gateway that tiers each call (LOW / MEDIUM / HIGH), requires human approval for dangerous operations, and writes a redacted audit log. A companion **web dashboard** turns that activity into a live, filterable security-operations view.

> ⚠️ **Authorized use only.** This is offensive-security tooling. Run it only against systems you own or are explicitly authorized to test. The bundled model is uncensored — the security guarantees come from the sandbox and the approval gate, **not** from the model.

---

## What it achieves

- **The model is untrusted; the environment is the control.** Containers (non-root, read-only rootfs, all caps dropped, resource-limited, network-isolated) + a per-call trust tier + human approval on HIGH-tier actions + a redacted audit trail. The uncensored model can *ask* to do anything; it can only *do* what the gate allows.
- **Model-agnostic.** Everything below the agent loop speaks OpenAI-compatible `/v1`. Swap Ollama (Q4, always-on) and vLLM (FP8, on-demand) per session without touching the tools.
- **Extensible via MCP.** Adding a capability means adding an MCP tool server + a policy entry — no changes to the agent.
- **Observable.** A read-only dashboard shows, live, every session, tool call, argument, response, error, external connection, approval tier, and any reverse-shell / MITRE ATT&CK classification — without ever writing to or interfering with the agent.

## How it works

```
User → Goose (agent loop, MCP client)
          └→ Policy / Approval Gateway   ← the one custom trust component
                 tier check (LOW/MED/HIGH) → HIGH needs human approval → redacted JSONL audit
                 └→ MCP tool servers, each a fresh `docker run --rm` per call:
                      ├ sandbox/  hardened shell + filesystem (confined to /work)
                      ├ web/      web_search (SearXNG) + SSRF-guarded web_fetch
                      ├ nettools/ dig / whois / tracepath / openssl / nc
                      └ kali/     nmap / nikto / gobuster / whatweb   (all HIGH-tier)

model backend (switchable):  Ollama  qwen  (:11434)   |   vLLM  qwen-fp8  (Docker, :8001)

              ┌─────────────────────────────────────────────┐
Goose sessions │  →  reads Goose's sessions.db (read-only)   │  →  Activity Monitor
gateway audit  │  →  tails gateway/state/audit.log           │      dashboard (:8787)
              └─────────────────────────────────────────────┘
```

- **Agent:** [Goose](https://github.com/block/goose) (MCP-native, has approval modes). Not hand-rolled.
- **The only custom trust component** is the gateway (`gateway/`): it re-exposes downstream tools as `<server>_<tool>`, tiers each call from `policy.json`, gates HIGH-tier calls on human approval, spawns a fresh ephemeral container per call, and appends a redacted audit record.
- **The dashboard** (`monitor/`) is a separate, read-only observer — see below.

## The Activity Monitor dashboard

A live, dark security-operations dashboard that **watches** the agent — it opens Goose's session store read-only and tails the gateway's audit log, correlates them, and streams a normalized event feed to the browser over WebSocket. It never writes to or influences the agent.

- **Session sidebar** with `id_keyword` labels and live status (ACTIVE / IDLE / COMPLETED / ERROR).
- **Event table:** timestamp, command, a plain-English explanation, **MITRE ATT&CK tactic:technique** (e.g. *Reconnaissance: Active Scanning*), response, errors, and external connections — with per-column wildcard filters, quick filters, expand/collapse, resizable/persisted columns, and a detail view.
- **Reverse-shell detection:** multi-indicator weighted scoring that flags suspected reverse shells (tuned to not false-positive on ordinary recon), shown as pulsing alerts.
- **Security-first:** LAN-bound + HTTP Basic Auth on every route, model chain-of-thought never stored or shown, optional secret redaction.

Full details: [`monitor/README.md`](monitor/README.md).

## Quickstart

**Prerequisites:** Linux host, **Docker**, **Python 3.10+**, an **[Ollama](https://ollama.com)** install serving a tool-calling-capable Qwen chat model, and **[Goose](https://github.com/block/goose)**. (The FP8 / vLLM path is optional and needs specific GPU hardware — see below.)

```bash
# 1. Clone
git clone https://github.com/crsftw/qwen_3.8_harness.git && cd qwen_3.8_harness

# 2. Model backend: pull a tool-capable Qwen model into Ollama
#    (this repo used qwen3.8:27b; substitute any Ollama chat model with tool support)
ollama pull qwen2.5:32b            # example substitute

# 3. Build the tool-server container images (each has a Dockerfile)
#    See docs/phase2-sandbox.md … phase6-kali.md for per-tool build/run details.
docker build -t qh-sandbox sandbox/    # repeat for web/, nettools/, kali/ as documented

# 4. Point Goose at the gateway extension
#    Use configs/goose-config.yaml as a template for ~/.config/goose/config.yaml;
#    register `gateway/run-gateway.sh` as an stdio MCP extension. The gateway is
#    self-locating (no path edits needed) — it resolves the repo via $QH_ROOT.

# 5. Start an agent session (the gateway launches tool servers on demand)
goose session

# 6. Run the dashboard (in another terminal)
cd monitor
cp config.example.yaml config.yaml     # then set basic_auth.password
./run-monitor.sh                        # installs deps + serves on http://<host>:8787
```

Then open `http://<host>:8787` and log in with the credentials from `monitor/config.yaml`.

Step-by-step setup for each component lives in [`docs/`](docs/) (`phase1-goose-setup.md` → `phase7-observability.md`) and the full design is in [`docs/spec-qwen-agent-architecture.md`](docs/spec-qwen-agent-architecture.md).

## Repository layout

| Path | What it is |
|---|---|
| `gateway/` | Policy/approval gateway (tiering, human approval, redacted audit) — the trust core |
| `sandbox/` `web/` `nettools/` `kali/` `lab/` | MCP tool servers (each: Dockerfile + `*_mcp.py` + `run-*.sh`) |
| `monitor/` | The read-only Activity Monitor dashboard (FastAPI + vanilla-JS + SQLite) |
| `vllm/` | Optional FP8 vLLM launcher + Ollama⇄vLLM switch scripts |
| `configs/` | Goose config template |
| `scripts/` | Setup/verification helpers (`phase0_verify_tools.py`, host hardening) |
| `docs/` | Design spec, secure-coding baseline (`ANTI_PATTERNS.md`), and per-phase setup guides |

## Security model (real vs. theater)

**Real containment:** containers only (the host runs Ollama/Goose/gateway), network isolation, `cap-drop=ALL`, read-only rootfs, non-root, resource limits, ephemeral per-call containers, and a redacted audit log. Code follows [`docs/ANTI_PATTERNS.md`](docs/ANTI_PATTERNS.md): **argv arrays, never shell strings**; **no secrets in code**; audit **redacts** secrets; parameterized Kali tools (no free-form flags → no argument injection). **The HIGH-tier approval gate is the containment — not the model.** ("Theater if alone": command allow/deny lists and metacharacter stripping — present as defense-in-depth, never relied on by themselves.)

## Replication notes

- **Excluded from this repo (regenerated at runtime):** the vLLM virtualenv, the `workspace/` scratch/target artifacts, runtime state (`gateway/state/`, `vllm/state/`), the monitor's `events.db` and `config.yaml`, and all logs. See `.gitignore`.
- **Paths are portable:** the gateway resolves tool-server paths from `$QH_ROOT` (auto-derived from the repo location), so a fresh clone runs without editing paths. A few prose examples in `docs/` still show the original author's absolute paths — those are illustrative only.
- **The FP8 / vLLM backend is optional and hardware-specific** (built for 2× RTX PRO 4000 Blackwell, no NVLink, via the `vllm/vllm-openai` Docker image). The Ollama (Q4) path is the portable default; the FP8 gotchas are documented in `vllm/run-vllm-docker.sh` and `docs/OVERVIEW.md`.
- The exact original model build (`qwen3.8:27b` / a gated FP8 Qwen) may not be publicly pullable — substitute any tool-calling-capable chat model in Ollama.

## Docs

- [`docs/OVERVIEW.md`](docs/OVERVIEW.md) — detailed architecture & rationale (the original project README)
- [`docs/spec-qwen-agent-architecture.md`](docs/spec-qwen-agent-architecture.md) — full design spec
- [`docs/ANTI_PATTERNS.md`](docs/ANTI_PATTERNS.md) — the secure-coding baseline this project holds to
- [`docs/phase1-goose-setup.md`](docs/) … `phase7-observability.md` — step-by-step build-up
- [`monitor/README.md`](monitor/README.md) — the dashboard

## License

Licensed under the **Apache License 2.0** — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).

Copyright 2026 Cristian Cornea.

## Disclaimer

For research and **authorized** security testing only. You are responsible for how you use it. The authors provide no warranty and accept no liability for misuse or damage.
