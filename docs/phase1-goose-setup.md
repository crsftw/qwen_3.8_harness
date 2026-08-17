# Phase 1 — Install Goose (harness) + wire it to Ollama

**Decisions:** inference engine = **Ollama** (kept; swappable later via base-URL). Harness = **Goose CLI**,
installed by you. Approval mode on from the start (matches the plan's human-in-the-loop requirement).

> Provenance verified 2026-08-15: `github.com/block/goose` now 301-redirects (GitHub-native) to
> `github.com/aaif-goose/goose` (52.8k★, active, docs `goose-docs.ai`) — a legitimate transfer, not a
> typosquat. Install script inspected (440 lines, sha256 `ab5ae405…6013f0`): downloads the release
> binary to `~/.local/bin`, no secondary pipes/obfuscation.

## 1. Install (you run this)

Standard glibc build, skip the interactive wizard (we configure declaratively below):

```bash
curl -fsSL https://github.com/aaif-goose/goose/releases/download/stable/download_cli.sh \
  | CONFIGURE=false GOOSE_LINUX_VARIANT=standard bash
```

Ensure it's on PATH (installer targets `~/.local/bin`, already in your PATH per env check):

```bash
goose --version
```

*Prefer not to pipe to bash?* The inspected copy is at
`…/scratchpad/goose_download_cli.sh` — run `CONFIGURE=false GOOSE_LINUX_VARIANT=standard bash <that file>`.

## 2. Configure the Ollama provider + approval mode

Run the wizard (authoritative — its schema is version-stable):

```bash
goose configure
```
- **Provider:** `Ollama`  → host: accept default `localhost:11434` (your Ollama binds `0.0.0.0`, so localhost works)
- **Model:** `qwen3.8:27b`
- Uncheck "requires an API key" (local, no key)

Then set the safety mode (asks before risky/edit actions instead of auto-running):

```bash
goose configure          # → Goose Settings → Mode → "Smart Approval" (smart_approve)
```

Equivalent declarative config (`~/.config/goose/config.yaml`) — template in
`configs/goose-config.yaml`; the wizard is the source of truth if the schema differs:

```yaml
GOOSE_PROVIDER: ollama
GOOSE_MODEL: qwen3.8:27b
GOOSE_MODE: smart_approve      # human approval for risky actions (plan requirement)
OLLAMA_HOST: localhost:11434
```

Context window is already handled at the Ollama server level (`OLLAMA_CONTEXT_LENGTH=32768`), so agent
runs won't silently truncate. Raise to 65536 later if long runs need it — you have the VRAM (2×24GB).

## 3. Phase 1 verification (definition of done)

A multi-step task that requires sequential tool use and ends coherently:

```bash
goose run -t "Create a file /tmp/goose_probe.txt containing the current date, then read it back and tell me its exact contents and byte count."
```

**Pass =** Goose (on Qwen) makes the tool calls, the approval prompt appears for the write, the file is
created & read, and the final message reports the contents + byte count. This proves harness ↔ Ollama ↔
tool-loop works end-to-end before we add sandboxed/dangerous tools in Phase 2+.

> Note: at this phase Goose uses its **built-in developer tools on the host** (no sandbox yet). Keep the
> probe to harmless paths like `/tmp`. Real isolation arrives in Phase 2 (hardened container + shell/FS
> MCP); dangerous tools stay behind the gateway (Phase 3) and never run un-sandboxed.
