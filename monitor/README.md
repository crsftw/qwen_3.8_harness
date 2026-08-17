# Goose Activity Monitor

A read-only, self-hosted dashboard that watches a Goose agent's sessions and
the sandbox gateway's audit log, and streams a normalized, correlated event
feed to a browser over a live WebSocket.

## Data sources (read-only)

The monitor never writes to Goose or the gateway. It only reads:

- **`sessions.db`** — Goose's own SQLite session store (default:
  `~/.local/share/goose/sessions/sessions.db`). Polled for new messages;
  tool-call/tool-response pairs and text messages are turned into events.
- **`audit.log`** — the sandbox gateway's audit log (default:
  `/home/cristi/qwen_harness/gateway/state/audit.log`). Tailed for new lines;
  each audit record is correlated (by tool name + key argument + a time
  window) to the matching tool-call event to attach its approval **tier**
  and **decision**.

Both sources are opened read-only; the monitor keeps its own cursor/offset so
restarts resume from where they left off instead of re-scanning from zero
(the audit tailer does re-read from the start of the file on process
restart, but the sessions.db cursor is persisted).

## How to start

```bash
./run-monitor.sh
```

This installs `requirements.txt`, exports `MONITOR_CONFIG` (default
`./config.yaml`), and launches uvicorn against the `backend.main:get_app`
factory, binding host/port read live from the config file.

Open the dashboard at:

```
http://<bind_host>:8787
```

(`bind_host`/`bind_port` come from `config.yaml`; the default is
`0.0.0.0:8787`, i.e. reachable on the LAN at `http://<this-machine-ip>:8787`).
Log in with the HTTP Basic Auth username/password set in `config.yaml`.

## Using the dashboard (browser UI)

The UI is a single dark, dependency-free page (`web/index.html` + `app.js` +
`styles.css`) served by the backend. It updates live over the WebSocket — no
manual refresh.

- **Header** — a ● LIVE / ● RECONNECTING indicator (the socket auto-reconnects
  and replays any events missed while disconnected), plus session and total
  alert counters.
- **Session sidebar (left)** — one clickable tab per Goose session, labeled
  `<session_id>_<keyword>` (the keyword is slugified from the session name,
  e.g. `20260816_11_asus_router_pentest`). Each tab shows a colored status dot
  — **ACTIVE** (green) / **IDLE** (grey) / **COMPLETED** (blue) / **ERROR**
  (red, when the session has a security alert) — and per-session counts
  (events / errors / external connections / alerts). New sessions appear
  automatically; statuses and counts refresh every ~10s from `/api/sessions`.
  Click a tab to load that session's events. A **`☰ Sessions`** button in the
  toolbar hides the sidebar to maximize the event table; the hidden/shown
  state persists in `localStorage`.
- **Event table** — columns **Date** (browser-local time, millisecond
  precision) · **Command Executed** · **Command Explained** · **Command
  Response** · **Error Encountered** · **External Connection**.
  - Long commands/responses collapse behind a `▶` expander. Expanding a
    command shows the full text (and, for structured tool calls, the tool name
    + pretty-printed JSON arguments); expanding a response lazily renders the
    full stdout/stderr, exit code, and HTTP status only on demand (so a
    14k-char response doesn't cost anything until opened).
  - **External Connection** shows `host:port` with an **INTERNAL** / **EXTERNAL**
    / **UNKNOWN** badge; a destination only *referenced* in a shell command
    (not proven to have been contacted) is shown dimmed/italic to distinguish
    it from a connection an actual network tool made.
  - A tool call with a reverse-shell alert **pulses red** with a
    `⚠ REVERSE SHELL SUSPECTED` badge (severity + matched reasons +
    destination). This is the only animated element in the UI.
  - Click any row to open a **detail modal** with every field — event/session
    ids, timestamp, tool, full command, full arguments, stdout, stderr, exit
    code, HTTP status, destinations, security detections, and the raw event
    JSON — each with a copy button.
- **Filtering** (all client-side, applied instantly with no reload, and
  AND-combined):
  - a **global search** box;
  - **quick-filter** buttons — ALL / COMMANDS / MODEL / TOOLS / NETWORK /
    ERRORS / ALERTS;
  - a **per-column filter row** under the headers. Each box supports
    **wildcards** — `*` (any run) and `?` (one char), anchored when present,
    otherwise a case-insensitive substring — e.g. `*nmap*`, `nmap*`, `*:443`.
- **Resizable / reorderable columns** — drag a header's **right-edge divider**
  (highlights blue on hover) to resize a column; drag a header body to reorder
  columns. **Column widths and order are saved to `localStorage`** and restored
  on load, so they survive a tab refresh, closing the tab, and restarting the
  browser. **Reset columns** in the toolbar restores the defaults.
- **Redaction toggle** — masks likely secrets (`Authorization:`/`Bearer`
  values, and `api_key`/`token`/`password` in both query-string and JSON
  `"key": "value"` forms) in the displayed command/response/JSON. This is a
  display-only mask; full text is always kept in `events.db`.

## How the collector works

`backend/collector.py`'s `Collector.run()` loop, once per
`poll_interval_ms` (default 500ms):

1. Tails `audit.log` for new lines and indexes them (`AuditIndex`) for
   correlation.
2. Reads new rows from `sessions.db` since the last processed message id
   (`Store` persists this cursor across restarts).
3. Registers any newly-seen sessions (`session` events, with a generated
   `{session_id}_{slug(name)}` label, e.g. `abc123_my_project`) and pushes
   them to the store and to connected clients.
4. Normalizes each new message (`backend/normalizer.py`): pairs
   `toolRequest`/`toolResponse` content into a single `tool_call` event, and
   turns plain text content into `assistant_message`/`user_message` events.
   **`thinking`-type content is dropped before normalization and is never
   stored or transmitted.**
5. For each `tool_call` event, matches it against the audit index to attach
   `tier`/`approval_decision`; a `DENIED`/`BLOCK*` decision without another
   error is also flagged with `error: "Tool call blocked"`.
6. Runs detection (external-connection classification, error classification,
   command explanation, and reverse-shell scoring — see below) as part of
   normalization, then inserts the event into the events database and
   publishes it to the WebSocket hub so all connected browsers get it live.
7. Prunes old events per the retention settings after each poll.

## Events database

Events and session metadata are stored in a local SQLite database at the
path given by `events_db` in `config.yaml` (default `./events.db`, i.e.
`monitor/events.db` when run from the `monitor/` directory). This database
is the monitor's own storage — separate from and independent of Goose's
`sessions.db` and the gateway's `audit.log`.

## Config options (`config.yaml`)

| Key | Default | Meaning |
|---|---|---|
| `bind_host` | `0.0.0.0` | Interface the server binds to |
| `bind_port` | `8787` | Port the server binds to |
| `basic_auth.username` | `admin` | HTTP Basic Auth username |
| `basic_auth.password` | *(required)* | HTTP Basic Auth password; server refuses to start if empty (can also be supplied via the `MONITOR_PASSWORD` env var, which overrides the config file value) |
| `sources.sessions_db` | `~/.local/share/goose/sessions/sessions.db` | Path to Goose's session database (read-only) |
| `sources.audit_log` | `/home/cristi/qwen_harness/gateway/state/audit.log` | Path to the gateway's audit log (read-only, tailed) |
| `events_db` | `./events.db` | Path to the monitor's own SQLite events database |
| `poll_interval_ms` | `500` | Collector poll interval in milliseconds |
| `status.active_window_s` | `60` | Seconds of recent activity before a session is considered "active" |
| `status.idle_window_s` | `1800` | Seconds of inactivity before a session is considered "idle" |
| `retention.max_age_days` | `30` | Events older than this many days are pruned after each poll (set to `0` to disable age-based pruning) |
| `retention.max_events` | `500000` | Events beyond this count are also pruned (oldest first) after each poll |
| `redaction.enabled` | `true` | Exposed to the client via `GET /api/config` as `redaction_enabled`, for the frontend to decide whether to mask likely secrets in displayed command/output text |
| `llm_explain.enabled` | `false` | Reserved flag, exposed for future optional LLM-based explanation of events; not otherwise used by the current backend |

See `config.example.yaml` for a template.

## Reverse-shell detection

`backend/detection.py::scan_reverse_shell()` runs on every tool call's
command + stdout + stderr text. It checks the text against the weighted
rules in `backend/rules.py::REVERSE_SHELL_RULES` — a shell fd-merge redirect
into `/dev/tcp` (`>& /dev/tcp/…`, `… 0>&1`, `exec N<>/dev/tcp/…`), `nc -e` /
`ncat -c`, `mkfifo` + `nc`, `socat … EXEC:`/`SYSTEM:`, language-specific
socket-to-shell patterns (python `socket`+`pty`/`subprocess`/`dup2`, php
`fsockopen`+exec, PowerShell `TCPClient`, perl/ruby socket+exec), an
interactive `bash -i`/`sh -i`, and a base64-decode-piped-to-a-shell pattern.
Each matched rule contributes its `weight` to a total score, and rules marked
`standalone: True` represent a single mechanism that is reverse-shell-like on
its own.

Severity is then derived from the score and the standalone matches:

- **CRITICAL** — score ≥ 6, or 2+ standalone indicators matched
- **HIGH** — 1+ standalone indicator matched, or (score ≥ 4 and 2+ rules matched)
- **MEDIUM** — score ≥ 2 (but doesn't meet HIGH/CRITICAL)
- **LOW** — any match below that (currently unreachable given the rule
  weights, but defined for future lower-weight rules)
- no alert at all if no rule matches (score == 0)

This escalation exists so that a single decisive indicator (e.g. a genuine
`/dev/tcp` redirect or `nc -e`) is flagged HIGH/CRITICAL on its own, while
weaker, easily-false-positive indicators (like a bare `bash -i` or a
base64-to-shell pipe) only escalate once combined with something else.

A matched alert also carries a best-effort `destination` (`host:port`)
extracted from `/dev/tcp/HOST/PORT`-style redirects, `connect((...))`-style
calls, or a loose `IP PORT` pattern, falling back to any external connection
already detected for that tool call.

**Precision tuning.** The rules are deliberately tightened so ordinary
pentest recon does not false-positive as a reverse shell — this was validated
against real Goose pentest sessions:

- The **`nc exec flag`** rule only matches when `-e`/`-c` is netcat's *own*
  argument (the match span stops at a pipe/redirect/semicolon). So netcat used
  as a probe client — e.g. `echo | nc HOST PORT | head -c 300` — does **not**
  match (the `-c` there belongs to `head`), while a genuine
  `nc -e /bin/sh HOST PORT` does.
- A **bare `/dev/tcp` mention does not alert** on its own. Standard bash port
  checks like `echo > /dev/tcp/HOST/PORT` (a single `>`) are ignored; only the
  reverse-shell fd-merge signature (`>& /dev/tcp/…`, `… 0>&1`, or
  `exec N<>/dev/tcp/…`) fires.

See `tests/test_detection.py` and `tests/test_detection_precision.py` for the
locked-in positive (real reverse shells still fire) and negative (benign recon
stays quiet) cases.

### How to add a detection rule

Append a dict to `REVERSE_SHELL_RULES` in `backend/rules.py`:

```python
{"name": "my new rule", "weight": 2, "pattern": re.compile(r"some-regex")}
```

- `name` — shown in the event's `security_alerts[].reasons` list.
- `weight` — added to the total score if the regex matches the command +
  stdout + stderr text.
- `pattern` — a compiled `re.Pattern` (use `re.I`/`re.S` flags as needed).
- `standalone: True` (optional) — mark this if the pattern by itself is a
  definitive, single-mechanism reverse-shell indicator (not just a weak
  signal); this lets it escalate severity to HIGH/CRITICAL on its own
  instead of requiring corroboration from another rule.

No other code changes are needed — `scan_reverse_shell()` iterates
`REVERSE_SHELL_RULES` automatically.

## Security posture

- **LAN-bound, not internet-facing**: the default `bind_host` is `0.0.0.0`
  (all interfaces) — run it behind a firewall/VPN or set `bind_host` to a
  specific LAN/loopback address if broader exposure is not desired.
- **HTTP Basic Auth** protects every route, including the REST API, the
  static UI files, and the `/ws` WebSocket handshake (checked via
  `secrets.compare_digest`, a constant-time comparison, before the socket is
  accepted).
- **Read-only with respect to Goose and the gateway**: the monitor only
  reads `sessions.db` and tails `audit.log`; it never writes to either, and
  has no ability to approve/deny/replay tool calls.
- **Thinking / chain-of-thought content is never stored or transmitted**:
  `backend/normalizer.py::iter_content()` filters out any content item with
  `type == "thinking"` before any event is constructed, so it never reaches
  `events.db` or a connected browser.
- **Optional secret redaction**: `redaction.enabled` in `config.yaml`
  (default `true`) is surfaced to the client at `GET /api/config` as
  `redaction_enabled`, for the frontend UI to mask likely secrets in
  displayed text; the backend itself stores full event text in `events.db`
  regardless of this setting (redaction is a display-layer concern, not a
  storage-layer one).
