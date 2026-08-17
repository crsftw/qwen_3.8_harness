# qwen_harness

An extensible, self-hosted Linux/security **agent environment** for a locally-run Qwen model.
Goal: Qwen behaves like an extensible Linux/security agent that can safely use many tools through a
standardized interface (MCP), while staying self-hosted and controllable — with real sandboxing,
tiered permissions, and human approval for dangerous operations.

## Architecture (summary)

```
User → Open WebUI ─┐
                   ├→ model backend (switchable):
                   │     • Ollama    → qwen3.8:27b  (Q4_K_M GGUF, always-on default)   :11434
                   │     • vLLM (Docker) → qwen3.8-fp8 (FP8, on-demand)                 :8001
                   │
                   └→ Goose (agent loop / MCP client)
                          └→ Policy/Approval Gateway  ← the only custom component
                                 └→ MCP tool servers (grouped by capability + trust tier)
                                      ├ Filesystem/Shell Sandbox (hardened container, networked, non-root)
                                      ├ Web (fetch) + Search (SearXNG)   (egress-only)
                                      ├ Network/recon (dig/whois/tracepath/openssl/nc)
                                      └ Kali/Security (nmap/nikto/gobuster/whatweb, isolated lab net, HIGH tier)
```

- **Harness:** Goose (MCP-native, approval modes). Not hand-rolled.
- **Tool layer:** MCP — adding a tool = adding/registering an MCP server, no harness changes.
- **Model layer is swappable:** everything below Goose is model-agnostic. Ollama (Q4) and vLLM (FP8)
  both expose an OpenAI-compatible `/v1`; Goose points at one per session. See **Model backends** below.
- **We build only:** the policy/approval gateway + hardened sandbox template + tier config + the
  FP8 vLLM launcher/switcher.
- Full design & rationale: `docs/spec-qwen-agent-architecture.md`.

## Security baseline

All code we write follows `docs/ANTI_PATTERNS.md`. Load-bearing rules (this system's job is letting an
LLM build & run commands, so these are the core threat, not edge cases):

- **Command injection (P2):** never build shell strings — execute via **argv arrays**, `shell=false`;
  guard argument injection (`curl -o`, `git --upload-pack`, `tar --checkpoint-action`) with per-tool
  arg allowlists.
- **Secrets (P1):** none in code/compose/images; inject per-call; audit log **redacts** secrets.
- **Slopsquatting (P7):** the model can hallucinate package names — pin/justify installs; egress
  restriction is the real mitigation.

> **Posture note:** the FP8 model is *uncensored* (refusal alignment removed). That's often desirable
> for legitimate recon, and it fits this system's design — **the model is untrusted; containment is the
> HIGH-tier approval gate, not the model.** It makes the approval gate more load-bearing, not less.
> Only approve scans against hosts you own or are authorized to test.

## Container fleet — access & capabilities

Each MCP tool server runs in its own container on its own `qh-` (**q**wen-**h**arness) bridge network.
The tables below describe the **current** posture (before any per-tool escalation).

### What each one is

| Container / image | Name stands for | What it does | Network (subnet) |
|---|---|---|---|
| **sandbox** `qwen-harness/sandbox` | the confined shell/FS | Hardened general-purpose shell: `bash`, read/write/list confined to `/work` | `qh-shell` (172.22.0.0/16) |
| **web** `qwen-harness/web` | web tools | `web_search` (via SearXNG) + SSRF-guarded `web_fetch`. **No shell exposed** | `qh-web` (172.19.0.0/16) |
| **nettools** `qwen-harness/net` | network/recon tools | `dig`/`whois`/`tracepath`/`openssl`/`nc` — unprivileged recon | `qh-net` (172.20.0.0/16) |
| **kali** `qwen-harness/kali` | Kali Linux pentest tools | Full **`kali-linux-large`** toolset via 4 typed wrappers (`nmap -sT`/`nikto`/`gobuster`/`whatweb`) + free-form **`kali_shell(cmd)`** — all HIGH-tier | `qh-lab` (172.21.0.0/16) |
| **qh-target** `bkimminich/juice-shop` | the practice target | OWASP Juice Shop — the vulnerable app kali practices against | `qh-lab` (172.21.0.0/16) |
| **qh-searxng** | SearXNG meta-search | Search engine the `web` MCP queries at `qh-searxng:8080` | `qh-web` |

### What access each one has

| Container | Runs as | Caps | Egress (outbound) | Ingress (inbound) | Send ICMP (ping) | DNS | L2 (MAC/ARP) |
|---|---|---|---|---|---|---|---|
| **sandbox** | non-root (uid 1000) | `cap-drop=ALL` | ✅ NAT → LAN + internet | ❌ no `-p`; only same-bridge peers | ✅ via `ping_group_range` sysctl (datagram ICMP, no NET_RAW) | ✅ | ❌ no NET_RAW |
| **web** | non-root (nologin) | `cap-drop=ALL` | ✅ NAT out, **SSRF filter blocks private/LAN at app layer** | ❌ | ❌ | ✅ | ❌ |
| **nettools** | non-root (nologin) | `cap-drop=ALL` | ✅ NAT out, **private blocked unless `ALLOW_PRIVATE=1`** | ❌ | ❌ (`tracepath` uses UDP) | ✅ | ❌ |
| **kali** | non-root (nologin) | `cap-drop=ALL` | ✅ NAT → LAN + internet + `qh-target` | ❌ no `-p`; only `qh-lab` peers | ✅ via `ping_group_range` | ✅ | ❌ no NET_RAW → `-sT` connect scans only |
| **qh-target** | image default (root inside) | default | ✅ NAT out | ✅ from `qh-lab` peers; **not** published to host/LAN | image-dependent | ✅ | ❌ |

Three properties hold across the whole fleet today:

- **Egress is broad.** Every bridge NATs through the host (`192.168.50.133/24`), so sandbox/kali can already
  reach the LAN (`192.168.50.0/24`) and internet at L3. `web`/`nettools` block private targets only in
  *application code* (SSRF filter / `ALLOW_PRIVATE`), which is softer than a network block.
- **Ingress is closed.** Nothing publishes a port (`-p`), so no container is reachable from the host or LAN —
  only from peers on the same `qh-` bridge.
- **L2 is impossible.** `cap-drop=ALL` (no `NET_RAW`/`NET_ADMIN`) means no ARP/MAC checks or spoofing, no raw
  SYN scans, no LLMNR/mDNS poisoning anywhere. ICMP echo works only on sandbox/kali, via the unprivileged
  `ping_group_range` sysctl — never raw sockets.

### `--cap-drop=ALL` — what it means

Linux **capabilities** split the old all-or-nothing "root" into ~40 distinct privileges. Docker grants a
container ~14 by default; `--cap-drop=ALL` removes **all** of them, so even a root process is stripped of the
powers that make root dangerous. The ones that matter here:

| Capability | Grants | Impact of dropping it |
|---|---|---|
| `CAP_NET_RAW` | Raw sockets; craft/inject/sniff packets at L2 | **The key one.** No ARP/MAC spoofing, no raw ICMP, no SYN scan, no `responder`/`arpspoof`/`bettercap` — this is why the fleet is L2-incapable |
| `CAP_NET_ADMIN` | Configure interfaces/routes/firewall, promiscuous mode | No network reconfiguration, no promisc sniffing |
| `CAP_NET_BIND_SERVICE` | Bind ports < 1024 | Can't listen on privileged ports |
| `CAP_CHOWN` / `CAP_FOWNER` / `CAP_DAC_OVERRIDE` | Bypass file ownership/permission checks | Can't sidestep filesystem permissions |
| `CAP_SETUID` / `CAP_SETGID` | Change process UID/GID | Can't switch users / escalate via setuid |
| `CAP_SYS_ADMIN` | Mount + many privileged syscalls ("the new root") | Large escape-surface reduction |
| `CAP_SYS_PTRACE` | Attach to/inspect other processes | Can't ptrace out |
| `CAP_MKNOD` / `CAP_SYS_MODULE` | Create device nodes, load kernel modules | Can't reach the kernel/devices |

**Why it matters:** capabilities are a **kernel/host-isolation** control (blast-radius reducer) — even with code
execution inside a container, the privileged syscalls used to escape or attack the network at a low level are
simply absent. It composes with non-root for defense in depth: even if something became root inside, the
dangerous powers are gone. Note it is **orthogonal to network reachability** — a `cap-drop=ALL` container still
reaches the LAN via NAT egress; capabilities don't firewall it.

> **Escalation note:** running kali tools as **root** with **L2/raw** capability (SYN scans, `responder`,
> `arpspoof`) is incompatible with `cap-drop=ALL`. It requires re-granting named powers —
> `--cap-drop=ALL --cap-add=NET_RAW --cap-add=NET_ADMIN` at minimum — each one a specific privilege handed back
> to an untrusted-model-driven container. Do this deliberately, per the approval-gate containment model.

### Reaching the LAN + docker networks — three options

Bridges today: `qh-lab` 172.21, `qh-web` 172.19, `qh-net` 172.20, `qh-shell` 172.22 (host is `192.168.50.133`
on `enp39s0`). Reaching those internal networks **plus** the LAN `192.168.50.0/24` can be done three ways, and
they differ in **what tools actually work**:

| Option | Reaches LAN `192.168.50.x` | Reaches docker bridges | **L2 attacks** (`responder`/`arpspoof`/`bettercap`, LLMNR/mDNS/DHCP) | Isolation left |
|---|---|---|---|---|
| **A. Bridge (NAT), multi-attached** | ✅ via host routing | ✅ `docker network connect` kali to each `qh-*` | ❌ NAT'd behind host IP, no broadcast/L2 | Own netns; caps mostly droppable |
| **B. macvlan on `enp39s0`** (+ connect to `qh-*` bridges) | ✅ own IP on the LAN, L2-adjacent | ✅ | ✅ full | Own netns, but a first-class device on your LAN |
| **C. `--network host`** | ✅ | ✅ (host routes to all) | ✅ full | **None** — shares host stack; container ≈ host on the network |

The catch: **root is only worth it if raw/L2 works** — otherwise root wasn't needed. Option A defeats half the
ask (`responder`, `bettercap`, `arpspoof` need L2), leaving **B or C**. **B (macvlan)** is recommended: full L2
surface + own LAN IP, while keeping a separate network namespace (Option C's `--network host` collapses that,
and the container reaches host services like Ollama as `localhost` — strictly worse).

### Approval modes (`GOOSE_MODE`)

The HIGH-tier approval gate **is** the containment (the model is untrusted). Goose owns the approval UI; the
gateway defers to it (`GATEWAY_APPROVAL=auto_approve`), so **Goose's mode is the whole story** — set it to
`auto` and nothing gates. Set in `~/.config/goose/config.yaml` (persistent) or per-session
(`GOOSE_MODE=auto goose session`, self-reverting). Read at session start.

| Mode | Behavior | When |
|---|---|---|
| `approve` | Asks before **every** tool call | Max caution / debugging tool calls |
| `smart_approve` | *(default)* Asks only for calls Goose judges risky | Everyday use |
| `auto` | Runs **everything**, never asks | Hands-off lab run you babysit — **no containment left** |
| `chat` | No tools at all | Plain chat |

> **Warning:** `auto` + the uncensored FP8 model + free-form `kali_shell` = unsupervised arbitrary command
> execution that can reach the LAN (`192.168.50.0/24`, this host included). To cut per-step prompts *without*
> going fully ungated, keep `smart_approve` and downgrade only the structured wrappers in `gateway/policy.json`
> (e.g. `kali_nmap`/`kali_nikto`/`kali_gobuster`/`kali_whatweb` → `MEDIUM`) while leaving `kali_shell` **HIGH** —
> recon flows freely, the arbitrary shell still needs sign-off. (Don't combine Goose `approve` with gateway
> `queue` — two prompts fight.)

## Status

| Phase | What | State |
|---|---|---|
| 0 | Baseline: security guide in repo + verify Qwen tool calling | ✅ done — `scripts/phase0_verify_tools.py` → **PASS** |
| 1 | Install Goose, point at a backend, enable approval mode | ✅ done — Goose 1.46.0, `config.yaml` (`smart_approve`), multi-step probe PASS |
| 2 | Hardened sandbox template + Shell/Filesystem MCP | ✅ done — `sandbox/` image + stdlib MCP server. **Networked** (DNS+internet+ping) per request — see `docs/networked-sandbox.md` |
| 3 | Policy/Approval Gateway (tiers, approval, audit) | ✅ done — MCP proxy in `gateway/`, tiers+approval+redacted audit, live-verified |
| 4 | Web browsing — fetch + search | ✅ done — `web/` egress MCP (SSRF-guarded fetch) + SearXNG. Playwright deferred until a JS site needs it |
| 5 | Network/recon tools (MEDIUM) | ✅ done — `nettools/` (dig/whois/tracepath/openssl/nc), LAN-blocked at app layer |
| 6 | Kali/security tools (HIGH, approval-gated) | ✅ done — `kali/`+`lab/` (nmap/nikto/gobuster/whatweb). Internet+DNS (qh-lab = bridge); containment = HIGH approval |
| 7 | Observability + custom-tool recipe | ✅ done — `gateway/audit_view.py` (terminal timeline + local HTML report) + add-a-tool recipe |
| 8 | **FP8 model backend + switching** | ✅ done — `vllm/` runs `qwen3.8-fp8` via Docker vLLM 0.24.0; `switch-model.sh` toggles Ollama↔FP8. See below |

### Verified environment (2026-08-16)
- **GPUs:** 2× RTX PRO 4000 Blackwell (24 GB each, sm_120, **no NVLink** — GPU0↔GPU1 over PCIe host bridge)
- Ollama 0.32.13; `qwen3.8:27b` — 27.3B **Q4_K_M** GGUF, 262k ctx, `[completion, tools, thinking, vision]`
- FP8: `orcarouter/Qwen3.8-27B-Uncensored-FP8` (Qwen3.5 hybrid attention+GDN, gated repo) via
  `vllm/vllm-openai:v0.24.0` Docker image, tensor-parallel across both GPUs
- Python 3.10.12, Docker 29.1.3, nvidia-container-toolkit present

## Model backends

Two interchangeable local backends, both OpenAI-compatible; Goose binds one per session.

| | Ollama (default) | vLLM FP8 (on-demand) |
|---|---|---|
| Model | `qwen3.8:27b` (Q4_K_M GGUF) | `qwen3.8-fp8` (FP8 uncensored) |
| Runtime | Ollama (always on) `:11434` | Docker `vllm/vllm-openai:v0.24.0` `:8001` |
| VRAM | ~19 GB (1 model, both GPUs) | ~40 GB (weights+KV across both GPUs) |
| Startup | instant | ~4–5 min first time (compile+warmup+capture); fast after (cache volume) |

You **cannot run both at once** (48 GB total). `switch-model.sh fp8` unloads Ollama's model first.

### Switching
```bash
vllm/switch-model.sh fp8       # start FP8 container + point Goose at it (unloads Ollama's model)
vllm/switch-model.sh ollama    # tear FP8 down + point Goose back at Ollama
vllm/switch-model.sh status    # which provider is active + container health
```
Start a **fresh `goose session`** after switching — the provider binds at session start.

### `vllm/` layout
- `run-vllm-docker.sh` — **the working launcher** (all Blackwell fixes baked in; see Fixes below)
- `serve-docker.sh` — lifecycle: `start` (launch + wait-until-healthy) / `stop` / `status` / `logs`
- `switch-model.sh` — flips Goose's provider (`config.yaml`) and the container up/down
- (`install-vllm.sh`, `run-vllm.sh`, `serve.sh` — an abandoned **pip-venv** vLLM path, kept for
  reference; it hits a Blackwell kernel deadlock the Docker image avoids — see Fixes)

## FP8 on Blackwell — issues, fixes, best practices

Getting a brand-new FP8 model (Qwen3.5, hybrid attention + Gated-DeltaNet) onto brand-new Blackwell
GPUs took a long chain of fixes. Each is a specific error with a specific remedy — recorded here so a
future retry is minutes, not hours.

### Issues encountered → fixes
| Symptom | Root cause | Fix |
|---|---|---|
| pip vLLM 0.27.x (stable **and** nightly) hangs forever at warm-up (100% GPU / 0% mem) | `reshape_and_cache_flash` KV-cache CUDA kernel **deadlocks on sm_120** (regression after 0.24.0) | Use the model authors' **Docker image `vllm/vllm-openai:v0.24.0`** — doesn't have the bug, and bundles a matched CUDA/torch stack |
| `Repository not found` on download | Gated HF repo | Accept the license on the model page once, then `hf download` |
| `Invalid repository ID or local directory '/model'` | HF cache uses `../../blobs/` **symlinks**; mounting only the snapshot dir breaks them | Mount the **whole repo** → `/model_repo`, point `--model` at `/model_repo/snapshots/<hash>` |
| OOM at startup | `--speculative-config mtp` loads an extra draft model | Drop MTP (`VLLM_SPEC=1` to opt back in); use `--language-model-only` |
| `DeepGemm ... Unknown recipe` | DeepGemm FP8 GEMM path broken on Blackwell | `-e VLLM_USE_DEEP_GEMM=0` (falls back to CUTLASS) |
| Worker spins in the **GDN linear-attention** layer under `--enforce-eager` | GDN eager path hangs on Blackwell | **Use graph mode** (torch.compile), *not* eager; `--compilation-config {"cudagraph_mode":"PIECEWISE"}` |
| Worker dies at graph capture: `custom_all_reduce.cuh:455 'invalid argument'` (looked like OOM) | vLLM **custom all-reduce** needs GPU-P2P, unavailable over the PHB link | **`--disable-custom-all-reduce`** (NCCL all-reduce works) ← the final unlock |
| NCCL init hang on TP start | No NVLink; P2P over PCIe host bridge unreliable | `-e NCCL_P2P_DISABLE=1` (route through host shared memory) |
| Goose `401 Unauthorized` | Goose reads its API key from its own secret store, not `config.yaml`; mismatch with server `--api-key` | Drop server-side `--api-key` (endpoint is `127.0.0.1`-only) |

### Best practices observed
- **Prefer the model author's recommended runtime/version.** The model card pinned vLLM 0.24.0 for a
  reason; newer ≠ better on bleeding-edge hardware. That single choice avoided the fatal kernel bug.
- **Use the vendor Docker image over a host venv** for bleeding-edge GPU stacks — it ships a matched,
  tested CUDA/torch/flashinfer set and sidesteps host `nvcc`/dependency drift entirely.
- **Read the actual error, don't pattern-match "OOM".** The decisive failure *looked* like OOM but was
  a CUDA all-reduce error; `py-spy dump --pid <worker>` on the hung process pinpointed each real cause.
- **On a no-NVLink multi-GPU box, disable the P2P fast paths** (`NCCL_P2P_DISABLE=1`,
  `--disable-custom-all-reduce`) — they assume peer memory access you don't have.
- **Run the server detached** (`docker run -d`), not attached — an attached client dies with its shell
  and takes the container down mid-init. Persist `/root/.cache/vllm` (named volume) so recompiles are
  one-time.
- **Keep the model layer swappable.** Because the gateway/MCP/sandbox stack is model-agnostic, proving
  a new backend only required Goose's provider to change — zero tool-side edits.
- **Size for the hardware, not the model card.** The card's `--max-model-len 262144` / MTP assume a
  bigger GPU; on 2×24 GB, 32k context + `--max-num-seqs 32` + FP8 KV cache fits with ~243k-token KV.

## Quick starts
```bash
# tool-calling sanity (Phase 0)
python3 scripts/phase0_verify_tools.py

# use the FP8 model
vllm/switch-model.sh fp8 && goose session      # then a fresh session

# back to the default Q4 model
vllm/switch-model.sh ollama && goose session
```
