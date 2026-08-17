# Design: Qwen Local Linux/Security Agent — Architecture & Roadmap

## Context

You have Ollama + Open WebUI + **Qwen 3.8:27b** (released 2026‑08‑14) locally and want Qwen to
behave like an **extensible Linux/security agent** that can safely use hundreds of tools through a
standardized interface, while staying self‑hosted and controllable. Goal: request a tool, get
output, reason, continue — with real sandboxing, tiered permissions, and human approval for
dangerous operations. Use case today is **learning / no specific targets**; you prefer reusing
mature components but will build a real harness *if warranted*.

**Verdict up front:** building a bespoke agent loop is **not** warranted — mature MCP‑native harnesses
already do it. The one piece worth building is a thin **policy/approval gateway**. Everything else is
assembly of existing, maintained components. This is deliverable = "recommendation + spec in one pass";
in plan mode this file **is** the spec (on approval it can be copied to
`docs/superpowers/specs/2026-08-15-qwen-agent-architecture-design.md` and committed).

**Security baseline adopted:** `ANTI_PATTERNS.md` (from `~/Desktop/LLM2user-social-network/9_coding_best_practices/`)
is adopted as the secure-coding guide for all code we write in this project. Phase 0 copies it into the
repo (`./docs/ANTI_PATTERNS.md`) as the standing reference. Its top-7 patterns are mapped to concrete
rules in **§3.5** below. The load-bearing realization: this whole system is, by design, a machine that
lets an LLM build and run shell commands — so **Pattern 2 (command injection)**, **Pattern 1 (secrets)**,
and **Pattern 7 (dependency/slopsquatting)** are not hypothetical for us; they are the core threat.

---

## 1. Research findings (what's true vs. inferred)

| Component | Status | Finding |
|---|---|---|
| **Qwen 3.8:27b** | Official (Ollama page) | 256K context; `vision tools thinking`; native tool calling; thinking on-by-default, tunable via `reasoning_effort`; `preserve_thinking`. 18GB quant. Strong agentic benchmarks. |
| **Ollama tool calling** | Official | Exposes OpenAI‑compatible `/v1/chat/completions` with `tools`/`tool_calls`. This is the interface every harness below uses. |
| **Open WebUI** | Official | Chat UI + model gateway; Tools/Functions/Pipelines; MCP via **mcpo** (MCP→OpenAPI proxy). Its agentic loop is chat-driven and **weaker** for long multi-step tool use. |
| **Goose** (Block/LF) | Official + community | MCP-native CLI/desktop agent; works with **Ollama**; ~70 MCP servers; approval/permission modes. Best off-the-shelf harness for local model + custom tools. Caveat: reliability tracks model quality. |
| **OpenHands** | Official | Docker-sandboxed agent control-center; heavier, coding/team-oriented. Good fallback, overkill for phase 1. |
| **Kali-MCP servers** | Community | Multiple maintained Dockerized servers (k3nn3dy-ai=35 tools/SSE, zebbern=130, TriV3, pabpereza). Weaknesses: **no human approval, root-in-container, metacharacter-stripping only**. Reuse the container; wrap it with our gateway. |
| **Web browsing** | Official (MS/community) | Playwright MCP (accessibility-tree, ~2–5KB/interaction vs 500KB screenshots) = real browsing; SearXNG = self-hosted meta-search; Jina/markdown fetch = cheap read. |
| **Sandboxing** | Community consensus 2026 | Defense-in-depth: never raw Docker for untrusted code; use gVisor (or microVM) runtime + **network isolation** + ephemeral containers + dropped caps + resource limits. Command allow/deny lists are a **tripwire, not a boundary**. |

**HTTP request vs. real browsing:** `curl/wget` fetches bytes — no JavaScript, no session, no DOM, no
clicking. **Real browsing** = a headless Chromium that renders JS, keeps cookies/session, follows
links, fills forms, and returns structured page state. Qwen needs both: fetch (cheap reads) + Playwright
(interactive/JS sites) + SearXNG (discovery).

---

## 2. Recommended architecture

```
 User
  │
  ▼
 Open WebUI ──────────────► Ollama (Qwen 3.8:27b)      [host]
  │  (chat UI, RAG, models)        ▲
  │                                │ OpenAI-compatible /v1
  ▼                                │
 Goose  ── agent loop / MCP client ┘                    [host]
  │
  ▼
 Policy / Approval Gateway  (thin custom MCP proxy)     [host]  ← THE piece we build
  │   • tiers LOW/MED/HIGH  • human-approval for HIGH  • audit log  • rate/timeout
  ▼
 MCP tool servers (grouped by capability + trust tier)
  ├── Filesystem MCP ........ hardened container, scoped RO/RW mount, no net
  ├── Shell/Sandbox MCP ..... gVisor container, non-root, resource limits, no host net
  ├── Web MCP (Playwright + Fetch) .. container, egress-only to internet, no LAN
  ├── Search MCP (SearXNG) .. container, egress-only
  └── Kali/Security MCP ...... reuse Dockerized kali-mcp, isolated "lab" net, HIGH tier
```

**Why this shape**
- **MCP is the right tool layer** — one standardized contract; adding a tool = adding/registering an
  MCP server, no harness changes. Extensible and maintainable, which is your stated priority.
- **Goose is the harness** — mature agent loop + MCP client + Ollama + approval modes. No reason to
  reimplement retries, tool-schema plumbing, and multi-step orchestration.
- **Open WebUI stays the human front-door** (chat, model management, RAG, optionally a *curated
  low-risk* toolset via mcpo for quick tasks). It is **not** the primary agent loop for serious
  multi-step/offensive work.
- **The gateway is the only custom code** — because no off-the-shelf component enforces *your*
  LOW/MED/HIGH tiers + human approval + unified audit across a heterogeneous tool set.

### MCP server structuring decision
**Group by capability AND trust tier, each in its own sandbox.** Not one-per-tool (unmanageable), not
one-giant-server (bad blast radius, mixes trust levels). The existing Kali-MCP is already "one server /
many tools" — acceptable *because* it lives in its own isolated container behind the gateway.

---

## 3. Security model (and what's theater)

**Real boundaries (do these):**
- Model-executed code runs **only in containers**, never on host. Host runs Ollama, Open WebUI, Goose,
  gateway.
- **Runtime isolation**: gVisor (`runsc`) for shell/kali; microVM (Firecracker/Kata) if you later run
  fully untrusted payloads.
- **Network isolation** (most important): dedicated Docker networks with **no route to host or LAN**.
  Web/search containers get internet-only egress; Kali gets a separate "lab" network only.
- **Filesystem**: read-only rootfs + tmpfs workdir; at most one scoped, mostly-RO bind mount.
- **Capabilities/limits**: `--cap-drop=ALL` (add back only what a tool needs, e.g. `NET_RAW` for
  Kali raw sockets), `--pids-limit`, `--memory`, `--cpus`, per-command timeouts, ephemeral containers.
- **Audit logging** at the gateway: every tool call, args, tier, approval decision, exit code, output
  hash.
- **Secrets** never in the sandbox env; injected per-call by the gateway only when required.

**Security theater / weak-alone (don't rely on):**
- Command **allow/deny lists** as the primary boundary — trivially bypassed via shell; keep as a
  UX tripwire + tier classifier, not the wall.
- **Metacharacter stripping** (what kali-mcp does) — defense-in-depth at best, not isolation.
- Default seccomp/AppArmor **alone** — helpful layer, insufficient by itself.
- Running the LLM as the trust boundary ("just prompt it not to") — not a control.

---

## 3.5 Secure-coding rules for code WE write (from `ANTI_PATTERNS.md`)

The gateway, MCP adapters, and any control-plane UI are ordinary software and must follow the guide.
**Treat every string the LLM emits as hostile user input** — the model is an untrusted input source, so
the same rules that stop attacker payloads stop a mis-firing or prompt-injected model.

| Pattern (guide) | Applies to | Rule for this project |
|---|---|---|
| **2 — Command injection** | gateway → tool execution | **Never build a shell string.** Execute via **argv arrays** (`["nmap","-sV",host]`), `shell=false`. Metacharacter stripping (what off-the-shelf Kali-MCPs do) is defense-in-depth, **not** the boundary. Guard against **argument injection** too (e.g. `curl -o`, `git --upload-pack`, `tar --checkpoint-action`) via per-tool arg allowlists + `--` where the tool honors it. |
| **1 — Hardcoded secrets** | gateway, compose, images | No secrets in code, `docker-compose.yml`, Dockerfiles, or image layers. Use env / Docker secrets / a mount injected per-call. Secrets never enter a sandbox's env unless that call needs them. |
| **logging leaks (P1 edge)** | audit log | The audit log **redacts** sensitive fields (password/token/key/secret/auth) and never logs full secret values or secret-bearing URLs. Correlation IDs, not secrets, in errors. |
| **7 — Dependency slopsquatting** | MEDIUM tier `pip`/`apt`/`npm` | Qwen can hallucinate package names → installs malware. Require the model to justify each package; prefer pinned/known packages; the network isolation (egress-restricted, no default internet in build) is the real mitigation against Shai-Hulud-style supply-chain payloads. |
| **6 — Input validation** | gateway tool schemas | Validate/normalize tool args server-side against each tool's schema **before** dispatch; validate after any decode/normalize, not before. |
| **3/4 — XSS & auth** | approval/observability UI | If the gateway exposes a web approval or log UI, apply context-aware output encoding + real auth/session handling. Simplest safe default: keep it localhost-only / CLI to avoid the web attack surface entirely. |

---

## 4. Permission model (enforced by the gateway)

| Tier | Examples | Sandbox | Network | Approval |
|---|---|---|---|---|
| **LOW** | date, pwd, ls, cat, grep, find, dig, ping, whois, read-file | shared long-lived container | none / read-only | auto |
| **MEDIUM** | curl, wget, git, python, pip/apt install, write-file | ephemeral container | internet-only egress | auto, logged |
| **HIGH** | nmap, masscan, nikto, gobuster, ffuf, sqlmap, hydra, metasploit, tcpdump, netcat, arbitrary shell | isolated gVisor/kali container | "lab" net only | **human approval required** |

Approval = gateway pauses the tool call and surfaces a prompt (Goose approval mode / Open WebUI message
/ CLI). Tier is decided by the target MCP server + a per-tool classification table, not by parsing the
model's free text.

---

## 5. Staged roadmap

Each phase is independently useful and testable. **Build the sandbox pattern once (Phase 2), reuse it.**

- **Phase 0 — Baseline + security guide.** (a) Copy `ANTI_PATTERNS.md` → `./docs/ANTI_PATTERNS.md` as the
  repo's standing secure-coding reference (deferred from this session because plan mode only permits
  editing the plan file). (b) Confirm `qwen3.8:27b` does reliable tool calls via Ollama `/v1`.
  Software: existing Ollama. Test: a 2-tool script (get_time, add) round-trips.
- **Phase 1 — Harness.** Install **Goose**, point at Ollama, enable an approval mode. Host-only, no
  dangerous tools yet. Deliverable: Goose completes a multi-step task using 1–2 built-in MCP tools.
- **Phase 2 — Sandbox pattern + Shell/FS MCP.** Stand up the **hardened container template**
  (gVisor runtime, cap-drop, RO rootfs, resource limits, isolated net) and a **filesystem + sandboxed
  shell MCP** inside it. This template is reused by every later tool container.
- **Phase 3 — Policy/Approval Gateway.** Thin MCP proxy between Goose and the tool servers: tier table,
  human-approval for HIGH, unified audit log, timeouts/rate limits. *This is the only substantial code.*
- **Phase 4 — Web browsing.** Playwright MCP + a fetch/markdown MCP + **SearXNG** container, all
  internet-egress-only. Gives Qwen genuine browsing + search.
- **Phase 5 — Network/recon tools (MEDIUM).** dig, whois, traceroute, openssl, nc (client) in a
  network-tools container on the lab net.
- **Phase 6 — Kali/security (HIGH).** Reuse a Dockerized Kali-MCP (e.g. k3nn3dy-ai) behind the gateway,
  on an isolated lab network, all calls approval-gated + audited. Add a deliberate lab target
  (e.g. a vulnerable-app container) so "no targets yet" becomes a safe practice range.
- **Phase 7 — Observability + custom tools.** Ship gateway logs to a viewer; document the
  "add-a-tool = add-an-MCP-server + tier entry" recipe so extension stays a 10-minute job.

For every phase: tools run in containers; **host runs only** Ollama, Open WebUI, Goose, gateway.
Communication: Goose ⇄ gateway ⇄ MCP servers over stdio/SSE/HTTP; Open WebUI ⇄ Ollama over `/v1`;
optional curated low-risk tools exposed to Open WebUI via **mcpo**.

---

## 6. Final recommendation (the concise verdict)

- **Harness:** **Goose** (MCP-native, Ollama-ready, approval modes). OpenHands only if you later want a
  team/multi-agent control center.
- **Use MCP?** **Yes** — it's the standardized tool layer that makes "hundreds of tools, easy to add"
  achievable.
- **Open WebUI Functions/Tools/Pipelines?** Keep Open WebUI as **chat UI + model gateway + optional
  curated low-risk tools via mcpo**; do **not** make it the primary agent/tool layer.
- **Existing agent framework?** Yes — Goose. Don't hand-roll LangChain/AutoGen glue.
- **Build anything yourself?** Only the **policy/approval gateway** + the **hardened sandbox
  container template** + tier config. Not the agent loop, not Kali wrappers.
- **First three components:** (1) Goose ⇄ Ollama/Qwen with approval on; (2) hardened sandbox template +
  shell/filesystem MCP; (3) web browsing (Playwright + SearXNG) to validate the pattern at MEDIUM risk
  before touching offensive tooling.
- **Architecture I'd choose:** Open WebUI (front-door) + Goose (harness) + MCP (tool layer) + a thin
  custom policy gateway + capability/trust-tiered sandboxed tool containers — reusing existing Kali-MCP
  and browser/search MCP servers, network-isolated, human-approval on HIGH.

---

## 7. Verification (how we'll know each phase works)

- **Phase 0/1:** Ask Goose (on Qwen) a task requiring ≥2 sequential tool calls; confirm correct
  tool_calls, output ingestion, and a coherent final answer. Disable thinking and re-test to compare
  tool-call reliability.
- **Phase 2:** From inside the shell MCP container, attempt `curl http://<host-LAN-IP>` and a host
  filesystem read — both must **fail** (network + mount isolation proven). Confirm gVisor runtime
  (`runsc`) is active and caps are dropped.
- **Phase 3:** Trigger a HIGH-tier tool; confirm the call **blocks pending approval**, is denied
  cleanly on "no", executes on "yes", and every call appears in the audit log with tier + exit code.
  **Command-injection test:** have the model pass an arg like `127.0.0.1; cat /etc/passwd` to ping —
  confirm it is treated as one literal argv token (single failed lookup), not two commands.
  **Secret-redaction test:** route a call carrying a token; confirm the audit log shows `[REDACTED]`,
  not the value.
- **Phase 4:** Have Qwen search (SearXNG) then open a JS-heavy page (Playwright) and extract content a
  raw `curl` cannot; confirm egress reaches internet but **not** the LAN.
- **Phase 6:** Run nmap against the **lab target container only**; confirm it cannot reach the host/LAN,
  runs approval-gated, and is fully logged.

## Open decisions to confirm at implementation time
- Sandbox runtime: start with **gVisor** (good enough for learning); escalate to microVM only if
  running untrusted exploit payloads.
- Approval UX surface: Goose's native approval vs. routing approvals through Open WebUI chat — pick when
  wiring Phase 3.

## Sources
- Ollama Qwen3.8: https://ollama.com/library/qwen3.8
- Open WebUI MCP/mcpo: https://docs.openwebui.com/features/extensibility/plugin/tools/openapi-servers/mcp/ · https://github.com/open-webui/mcpo
- Goose: https://blog.marcnuri.com/goose-on-machine-ai-agent-cli-introduction
- Kali-MCP: https://github.com/k3nn3dy-ai/kali-mcp · https://github.com/zebbern/zebbern-kali-mcp · https://github.com/TriV3/MCP-Kali-Server · https://github.com/pabpereza/kali-mcp
- Web/browse/search: https://medium.com/@bluudit/playwright-mcp-comprehensive-guide-to-ai-powered-browser-automation-in-2025-712c9fd6cffa · https://mcp.directory/servers/searxng-public
- Sandboxing: https://northflank.com/blog/how-to-sandbox-ai-agents · https://zylos.ai/research/2026-04-04-ai-agent-sandboxing-security-isolation/
