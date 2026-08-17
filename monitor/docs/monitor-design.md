# Goose Activity Monitor — Design Spec

**Date:** 2026-08-17
**Status:** Approved for planning
**Scope:** A read-only, real-time web dashboard that **observes** the existing Goose 1.46.0 + Qwen 3.8 red-team infrastructure. It does **not** modify, replace, or reconfigure Goose, the gateway, vLLM/Ollama, or Qwen. Entirely additive under `monitor/`.

---

## 1. Goal & non-goals

**Goal:** An observability/auditing console showing, per Goose session: tool calls, arguments, responses, errors, external connections, security tier/approval, and reverse-shell alerts — updating live.

**Non-goals (hard constraints):**
- No changes to Goose, gateway, vLLM, Ollama, or Qwen config.
- No new agent framework, tool-execution layer, or command execution from the dashboard.
- No cloud, no external telemetry, no analytics, no data sent off-box.
- Read-only with respect to all Goose data (open SQLite `mode=ro`; never write Goose files).
- Do not capture, infer, or display hidden chain-of-thought.

---

## 2. Data sources (verified by inspection)

Goose exposes **no event stream/webhook**; it persists to disk. The collector is a **file observer**.

### 2.1 Primary — `~/.local/share/goose/sessions/sessions.db` (SQLite)
- **`sessions`**: `id` (real, e.g. `20260816_11`), `name` (auto-generated human label, e.g. `ASUS Router Pentest`), `working_dir`, `created_at`, `updated_at`, `session_type`, token counts, `provider_name`, `goose_mode`.
- **`messages`**: `id` (autoincrement, used as ingest cursor), `session_id`, `role`, `created_timestamp` (epoch), `timestamp`, `content_json`.
- **`content_json` item types:**
  - `toolRequest` (role=assistant): `toolCall.value.name` (e.g. `shell`, `sandbox_bash`, `kali_nmap`), `toolCall.value.arguments` (object), `_meta.goose_extension`, and a correlation `id` (e.g. `call_6nlqwzfg`).
  - `toolResponse` (role=user): same `id`; `toolResult.value.structuredContent = {stdout, stderr, exit_code}`, `toolResult.value.isError`, `toolResult.value.content[].text`.
  - `text` (assistant/user): user prompts, assistant messages.
  - `thinking` (assistant/user): **hidden chain-of-thought — DROPPED at ingest, never stored or shown.**

### 2.2 Enrichment — `/home/cristi/qwen_harness/gateway/state/audit.log` (JSONL, append-only, live)
Each line: `{ts, tool ("<server>_<tool>"), tier (LOW|MEDIUM|HIGH), decision (AUTO|APPROVED:...|DENIED...), outcome (ok|isError|null), args}`.
This is the **only** source of the security **tier** and **approval decision**; `sessions.db` lacks both. Correlated to tool events by `(tool, args, ±time window)`.

### 2.3 Not used (this version)
`~/.local/state/goose/logs/llm_request.*.jsonl` (raw Qwen payloads) — large, not cleanly session-tagged. Out of scope; may be added later behind a flag.

---

## 3. Architecture

```
sessions.db (mode=ro) ──poll new messages.id──┐
audit.log (JSONL) ──inode/offset tail─────────┤
                                              ▼
        Collector → Normalizer → Detection → Store (events.db, SQLite)
                                              │
                                     async Hub (pub/sub)
                                              ▼
   FastAPI (uvicorn) ── WebSocket (live) + REST (history) + static UI ──▶ Browser
                        HTTP Basic Auth · bind 0.0.0.0:8787
```

### 3.1 Backend components (isolated units)
| Unit | Responsibility | Depends on |
|------|----------------|-----------|
| `sources/sessions_db.py` | RO poll of `messages WHERE id > cursor`; detect new `sessions` rows. WAL-safe. Emits raw records. | sqlite3 |
| `sources/audit_log.py` | Inode+offset-aware tail of `audit.log` (survives truncation/rotation). Emits audit records. | — |
| `collector.py` | Orchestrates both sources on the async loop; persists ingest cursors. | sources |
| `normalizer.py` | Pair `toolRequest`↔`toolResponse` by call `id` → one event; extract stdout/stderr/exit_code/isError/http_status; **drop `thinking`**; attach audit `tier`+`decision`; build `command_explained`, `external_connections`. | detection |
| `detection.py` | Pure functions: reverse-shell scoring, error classification, external-connection extraction/classification, command explanation. | — |
| `store.py` | SQLite `events.db`; write events (full `raw_json`); indexed queries with pagination + per-column/wildcard filters; retention. | sqlite3 |
| `hub.py` | asyncio pub/sub; fan-out new events to WS clients. | — |
| `config.py` | Load `config.yaml` + env overrides. | pyyaml |
| `app.py` | FastAPI routes, WebSocket, static serving, basic-auth middleware. | all |

### 3.2 Frontend (`web/`, no build step)
`index.html` + vanilla `app.js` + `styles.css`. Dark SOC theme, monospace for commands/output.

---

## 4. Normalized event schema

One event row = one tool call merged with its response (matches the table layout).

```json
{
  "event_id": "<session_id>:<msg_id>:<call_id>",
  "seq": 12345,                       // global monotonic (assigned by store)
  "session_id": "20260816_11",
  "timestamp_ms": 1786950042641,      // from created_timestamp; ms precision
  "event_type": "tool_call",          // session_started | tool_call | error | security_alert | session_completed
  "tool": "sandbox_bash",
  "extension": "gateway",             // _meta.goose_extension
  "command": "curl -s https://example.com ...",   // full, never truncated in storage
  "arguments": { "command": "..." },  // full structured args
  "command_explained": "HTTP GET via curl to example.com.",
  "stdout": "...", "stderr": "...", "exit_code": 0,
  "http_status": null,
  "error": null,                      // null OR classified error string
  "tier": "HIGH",                     // from audit.log; null if uncorrelated
  "approval_decision": "APPROVED:auto_approve",
  "external_connections": [
    {"host":"example.com","port":443,"proto":"https","classification":"EXTERNAL","source":"referenced"}
  ],
  "security_alerts": [
    {"type":"reverse_shell","severity":"HIGH","score":5,"reasons":["/dev/tcp/","bash -i"],"destination":"10.0.0.5:4444"}
  ],
  "raw_json": { ... }                 // original Goose message(s), thinking removed
}
```

**Event types actually emitted** (only what telemetry supports):
- `session_started` — synthesized from a new `sessions` row.
- `user_message` — a user `text` block (the prompt / instructions).
- `assistant_message` — an assistant `text` block (the model's **visible** response; this is the observable Qwen output that, with `tool_call`, reconstructs the User→Goose→Qwen→Tool sequence). **`thinking` blocks are never emitted.**
- `tool_call` — the workhorse: merged `toolRequest`+`toolResponse`.
- `session_completed` — synthesized when a session crosses the inactivity threshold.

`error` is a field on any event (set by the classifier), and `security_alert` objects attach to the event that triggered them — neither is a standalone row. The **MODEL** quick filter selects `user_message` + `assistant_message`; **COMMANDS/TOOLS** select `tool_call`; **NETWORK** selects events with `external_connections`; **ERRORS** selects `error != null`; **ALERTS** selects events with `security_alerts`.

---

## 5. Sessions & status

- **Tab label:** `<real_session_id>_<slug(name)>` — e.g. `20260816_11_asus_router_pentest`, `20260816_10_owasp_juice_shop_pentest`, `20260816_2_subnet_host_discovery`. Uses Goose's own generated `name` (deterministic, no LLM, real ID preserved). Fallback: slug of first user `text` message. Slug = lowercase, non-alnum→`_`, collapse repeats, cap ~40 chars.
- **Status (inactivity-inferred; thresholds configurable):**
  - `ACTIVE` — last event within `active_window` (default 60 s).
  - `IDLE` — last event within `idle_window` (default 1800 s) but not active.
  - `COMPLETED` — no activity beyond `idle_window` (inferred; UI marks it "inferred", since Goose has no explicit end event).
  - `ERROR` — latest event errored, or an unacknowledged HIGH/CRITICAL alert exists. Takes precedence for the badge color.
- **Per-tab counters:** events, errors, external connections, security alerts.
- **New sessions appear live** (pushed over WS; sidebar updates without refresh).

---

## 6. Detection engine (`detection.py`)

### 6.1 Reverse-shell scoring (multi-indicator, not a single regex)
Scan `command`, `stdout`, `stderr`, and `external_connections`. Weighted indicators (declarative rule list):

| Indicator | Weight |
|-----------|-------:|
| `/dev/tcp/` or `/dev/udp/` redirection | 3 |
| `nc`/`ncat` with `-e` or `-c` (exec) | 3 |
| `mkfifo` + `nc` pipeline | 3 |
| `socat ... EXEC:` / `SYSTEM:` | 3 |
| python `socket` + (`pty.spawn`\|`subprocess`\|`os.dup2`) | 3 |
| php `fsockopen` + exec | 3 |
| powershell `New-Object System.Net.Sockets.TCPClient` | 3 |
| perl `Socket`/`IO::Socket` + `exec`/`system` | 2 |
| ruby `TCPSocket` + `exec` | 2 |
| `bash -i` / `sh -i` interactive shell | 2 |
| base64 blob that decodes to any of the above | 2 |
| shell keyword + outbound connection to non-standard high port | 2 |

**Severity:** `score>=6 CRITICAL`, `4–5 HIGH`, `2–3 MEDIUM`, `1 LOW`. **HIGH+ requires >=2 distinct indicators** (guards against single-token false positives). Alert records: `severity`, `score`, matched `reasons`, `command`, `destination` (ip:port if parseable). Adding a rule = one entry in the rule list.

### 6.2 Error classification (not every stderr is an error)
`error` is set when ANY of: `exit_code != 0`; `isError == true`; audit `decision` starts with `DENIED`/blocked; parsed HTTP `4xx`/`5xx`; a known network-failure token (`Connection refused`, `timed out`, `Could not resolve`, `No route to host`) **in a network-tool result**. Plain stderr with `exit_code==0` is **not** an error. Message is a short classified string (e.g. `exit code: 1`, `HTTP 403 Forbidden`, `Tool call blocked`, `Connection refused`).

### 6.3 External-connection extraction & classification (no fabrication)
- **Dedicated network tools** (`net_*`, `web_fetch`, `kali_*`): the tool's purpose is to connect → emit connection with `source: "tool"`. Classify `INTERNAL` if host is RFC1918 / loopback / lab (`qh-target`, `*.lab`, `192.168.*`, `10.*`, `172.16–31.*`), else `EXTERNAL`; `UNKNOWN` if unresolvable/undetermined.
- **Shell commands** (`bash`/`shell`/curl/wget with a URL or `host:port`): a destination is *referenced* but the connection is not proven → emit with `source: "referenced"`, classification defaults to `UNKNOWN` unless the host is clearly private/public, and the UI shows it visually distinct ("referenced, not observed").
- Never invent a connection when no host/URL token is present.

### 6.4 Command explanation (deterministic, local)
Parse by tool: for structured tools use `tool` + key args (e.g. `kali_nmap{top_ports,service_scan}` → "TCP-connect scan, top N ports, with version detection"). For `shell`/`bash`, parse the **leading binary + notable flags** of each pipeline segment (argv-aware — avoids matching keywords inside grep patterns / here-docs, the earlier false-positive class). Optional LLM explanation endpoint exists but is **OFF by default and never auto-invoked** (no overhead, no recursive monitoring events).

---

## 7. API (FastAPI)

All endpoints behind HTTP Basic Auth.

- `GET /` → dashboard (static).
- `GET /api/sessions` → list: id, label, status, counts, start/last-activity.
- `GET /api/sessions/{id}/events?after_seq=&limit=&<filters>` → paginated events (history load; never full-session dump).
- `GET /api/events/{event_id}` → full event incl. `raw_json` (detail modal).
- `GET /api/search?...` → cross-session filtered query.
- `WS /ws?after_seq=<n>` → on connect, replay events with `seq > n` from `events.db`, then stream live. Enables **missed-event recovery after reconnect**. Server also pushes new-session and status-change messages.
- Filtering params (REST + applied client-side too): `session`, `tool`, `command`, `ip`, `domain`, `port`, `url`, `event_type`, `http_status`, `error`, `severity`, `time_from`, `time_to`, plus **per-column keyword** and **wildcard** (`*`/`?`) support.

---

## 8. Frontend behavior

### 8.1 Layout
Left sidebar = session tabs (live). Right = header (title + ● LIVE / ● RECONNECTING + session/alert counters) over the event table.

### 8.2 Event table
Columns: **Date · Command Executed · Command Explained · Command Response · Error Encountered · External Connection**.
- **Date:** `YYYY-MM-DD HH:MM:SS.mmm`, browser-local tz for display; stored as UTC ms.
- **Command:** collapsed preview with `▶`; expand shows full command / formatted-JSON arguments (monospace). Never truncated in storage.
- **Response:** long output shown as `▶ N characters`; expand lazy-loads full stdout/stderr/exit code/http status/metadata; virtualized for very large outputs.
- **Error / External Connection:** classified badges (INTERNAL/EXTERNAL/UNKNOWN; error type).
- **Reverse-shell rows:** pulse red + red indicator + `⚠ REVERSE SHELL SUSPECTED` + reason + destination; links to the event detail. (Alerts are the only pulsing UI.)
- Sticky headers; expand/collapse arrows; smooth session switching.

### 8.3 Filtering (per user request)
- **Global search bar** + **quick filters** (ALL / COMMANDS / MODEL / TOOLS / NETWORK / ERRORS / ALERTS).
- **Per-column filter row** beneath the sticky headers — an input per column; each filters its own column. All active filters combine with AND (and with global search + quick filter).
- **Wildcards** everywhere text is matched: `*` = any run, `?` = one char (e.g. `*something*`, `nmap*`, `*:443`). Bare text = case-insensitive substring. Filters apply without page reload.

### 8.4 Column resizing persistence (per user request)
Columns are drag-resizable. Widths **and order** persist to `localStorage` and restore across refresh / tab close / browser close. A "Reset columns" control clears the saved layout.

### 8.5 Detail modal
Event ID, session ID, timestamp, parent event id (if any), event type, tool, full command, full arguments, stdout, stderr, exit code, HTTP req/resp, destination(s), security detections, raw event JSON. Copy buttons on useful fields.

### 8.6 Connection handling
WebSocket with auto-reconnect (exponential backoff). Client tracks max `seq`; on reconnect sends `after_seq` → server replays the gap. ● LIVE when connected, ● RECONNECTING otherwise.

---

## 9. Storage & performance

- **`events.db`** (SQLite) under `monitor/`. Tables: `sessions`, `events` (full `raw_json` preserved), `ingest_cursor`. Indexes: `session_id`, `timestamp_ms`, `event_type`, `severity`, and a `destination` index (derived column) for network filtering.
- **Retention:** configurable by max age and/or max rows; a periodic prune task.
- **Performance:** incremental WS delivery (only new events); REST pagination via `after_seq`/`limit`; lazy-loaded large responses; client-side virtualization for long tables/outputs; indexed queries. Never resend a whole session on a single new event.

---

## 10. Security

- Bind `0.0.0.0:8787` (LAN) behind **HTTP Basic Auth** (credentials from `config.yaml`/env; no default password — startup fails if unset).
- Optional **UI secret redaction** toggle: regex-mask `Authorization:` headers, `api[_-]?key`, `token`, bearer values in displayed command/response (raw remains in DB; redaction is display-side; default ON).
- No external network calls from the backend; no telemetry/analytics.
- Read-only: `sessions.db` opened `mode=ro`; audit.log read-only; **no endpoint mutates or executes anything** in Goose.

---

## 11. Configuration (`config.yaml`)

```yaml
bind_host: 0.0.0.0
bind_port: 8787
basic_auth: { username: admin, password: "" }   # required; empty -> refuse start
sources:
  sessions_db: ~/.local/share/goose/sessions/sessions.db
  audit_log:   /home/cristi/qwen_harness/gateway/state/audit.log
poll_interval_ms: 500
status: { active_window_s: 60, idle_window_s: 1800 }
retention: { max_age_days: 30, max_events: 500000 }
redaction: { enabled: true }
llm_explain: { enabled: false }   # optional, never auto-invoked
```

---

## 12. Testing plan

- **Unit:** `detection.py` (reverse-shell corpus: known RS one-liners across bash/python/perl/php/powershell/socat **+** benign lookalikes from this env's real pentest commands to check false-positive rate), error classifier, external-connection classifier, normalizer (thinking-drop + request/response pairing + audit correlation), slug generation, wildcard matcher.
- **Integration/UI:** `tests/feeder.py` synthesizes a controlled event stream to exercise: multiple sessions, long commands, long responses, errors, HTTP 4xx/5xx, external destinations, session switching, live updates, browser reconnect, reverse-shell alert rendering, large event volumes.
- **Real-data verification:** run the collector against the actual `sessions.db` (11 real sessions incl. the 599-message `20260816_11` ASUS run with large outputs) and live `audit.log`; confirm columns, virtualization, and correlation on real activity.

---

## 13. File layout (all new, additive)

```
monitor/
  backend/
    app.py  collector.py  normalizer.py  detection.py  store.py  hub.py  config.py
    sources/{sessions_db.py, audit_log.py}
  web/{index.html, app.js, styles.css}
  tests/{test_detection.py, test_normalizer.py, test_external.py, test_wildcard.py, feeder.py}
  docs/monitor-design.md   config.yaml   requirements.txt   run-monitor.sh   README.md
```

Dependencies (`requirements.txt`): `fastapi`, `uvicorn[standard]`, `pyyaml`. No changes anywhere outside `monitor/`.

---

## 14. Deliverable summary (to report at completion)

Goose data source used · files created · how to start · URL/port · how the collector works · DB location · config options · how reverse-shell detection works · how to add detection rules.
