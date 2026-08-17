# Phase 3 — Policy / Approval Gateway (DONE)

The security spine. An MCP **proxy**: Goose is its client; it is a client to the downstream tool
servers. Every tool call passes through tier enforcement + audit.

```
Goose ──MCP──▶ gateway ──MCP──▶ sandbox (and later: web, network, kali)
                  │
                  ├ tier check (LOW/MEDIUM/HIGH from policy.json)
                  ├ HIGH ⇒ human approval (queue / tty; fail-closed)
                  └ redacted JSONL audit log
```

## Components (`gateway/`)
- **`gateway_mcp.py`** — stdlib MCP proxy. Aggregates downstream tools, re-exposes them as
  `<server>_<tool>`, tags each with a tier, enforces it, forwards approved calls, logs everything.
- **`policy.json`** — the tier map. Per-tool LOW/MEDIUM/HIGH + `default_tier` per server, and
  `tier_actions` (LOW/MEDIUM=`auto`, HIGH=`approve`). Editing this re-tiers instantly.
- **`approve.py`** — CLI to list/approve/deny pending HIGH calls (`approve.py <id> yes|no [reason]`).
- **`run-gateway.sh`** — launcher (what Goose's extension calls).
- **`state/`** — `audit.log` (JSONL), `pending/`, `decided/`.

## Approval modes (env `GATEWAY_APPROVAL`)
- `queue` (default): HIGH call blocks; writes `state/pending/<id>.json`; a human runs `approve.py`;
  gateway proceeds on decision. Timeout (`GATEWAY_APPROVAL_TIMEOUT`, default 120s) ⇒ **DENY** (fail-closed).
- `tty`: prompt on `/dev/tty` (for interactive `goose session`).
- `auto_approve` / `auto_deny`: **test only**, logged loudly.

## Secret redaction (ANTI_PATTERNS P1)
Audit args are redacted before logging: keys matching `pass|secret|token|key|auth|cred` → `[REDACTED]`,
and value patterns (Bearer, `sk_live_…`, `ghp_…`, AWS `AKIA…`, `api_key=…`) masked. The tool still
executes with real values — only the *log* is scrubbed.

## Wiring
Goose `config.yaml`: `developer` disabled; single `gateway` stdio extension
(`cmd: bash gateway/run-gateway.sh`). The gateway launches downstream servers per `policy.json`.

## Verified (2026-08-15)
- tiers enforced: LOW/MEDIUM auto-run; HIGH blocked under `auto_deny`, ran under `auto_approve`
- **live queue approval**: HIGH call blocked → `approve.py` approved → call proceeded; audit shows
  `APPROVED:human:cristi:…`; timeout denies
- redaction confirmed (`Bearer sk_live_…` → `[REDACTED]` in audit while tool got the real value)
- **agent-driven**: Qwen called `sandbox_bash` (HIGH) via the gateway; blocked for approval; approved
  out-of-band; ran in a fresh sandbox container; Qwen reported the result
- no container leaks

## Startup, lifecycle & approval integration (important)
- `initialize` answers **immediately**; the registry builds lazily on first `tools/list` (spawning
  everything before the handshake made Goose time out and disable the extension as servers grew).
- **Ephemeral per-call containers**: each tool call runs in its OWN short-lived `docker run --rm`
  container that is torn down right after. Nothing long-lived is held — so containers never leak even
  though Goose keeps the gateway *process* alive across a session. (Enumeration for `tools/list` is
  likewise ephemeral.)
- **Approval integration with Goose**: two interactive approval UIs can't coexist (the gateway's `tty`
  prompt would fight Goose's TUI). So in `goose session` **Goose provides the human approval**
  (`GOOSE_MODE=smart_approve`) and the gateway defers (`GATEWAY_APPROVAL=auto_approve`, set in
  `run-gateway.sh`) while still applying tiers + writing the audit log. For **unattended** runs, set
  `GATEWAY_APPROVAL=queue` to get the gateway's own fail-closed HIGH gate (approve via `approve.py`).

## Note on current tiering
`sandbox_bash` is set HIGH in `policy.json` to exercise the approval gate. A no-network sandbox shell is
really MEDIUM — retier it there once genuinely-HIGH tools (Kali, Phase 6) exist. The mechanism is
tool-name based and config-driven, so it scales as servers are added.
