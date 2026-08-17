"use strict";
/*
 * Goose Activity Monitor — frontend shell (Task 11).
 *
 * Scope: page shell, session sidebar, live WebSocket feed with
 * auto-reconnect. Event table rendering, filters, and the detail modal
 * are Task 12 — `renderEvents(sessionId)` below is the seam it fills in.
 *
 * Auth: the browser caches the HTTP Basic credentials after the initial
 * page load (GET /), so plain same-origin fetch()/WebSocket calls below
 * do not need to attach an Authorization header explicitly.
 */

// ---------------------------------------------------------------------
// State
// ---------------------------------------------------------------------

const state = {
  config: null,
  sessions: new Map(),        // session_id -> session object (server fields + client-tracked counters)
  events: new Map(),          // session_id -> array of event objects, ordered by seq ascending
  selectedSessionId: null,
  maxSeq: 0,                  // highest event seq observed (REST or WS) — drives WS resume point
  ws: null,
  wsReconnectAttempts: 0,
  wsReconnectTimer: null,
  sessionPollTimer: null,     // periodic GET /api/sessions refresh (guards against stacking)

  // -- Task 12 additions --
  redactionOverride: null,    // null = follow config.redaction_enabled; true/false = user toggle wins
  filters: {
    columns: { date: "", command: "", explained: "", response: "", error: "", external: "" },
    global: "",
    quick: "ALL",              // ALL|COMMANDS|MODEL|TOOLS|NETWORK|ERRORS|ALERTS
  },
  columns: { order: [], widths: {} }, // populated by loadColumnPrefs()
  view: { sessionId: null, filtered: [], shown: 0 }, // current table render window (desc by seq)
};

const SESSION_POLL_MS = 10000;
const HISTORY_FETCH_LIMIT = 1000;   // per-session REST fetch cap (DOM rendering is virtualized separately)
const PAGE_SIZE = 150;              // rows added per virtualization page
const MAX_RENDERED_ROWS = 3000;     // DOM row cap for the live-append path (state.events itself is never trimmed)
const COLUMN_STORAGE_KEY = "monitor.columns";
const DEFAULT_COL_ORDER = ["date", "command", "explained", "attack", "response", "error", "external"];
const DEFAULT_COL_WIDTHS = { date: 170, command: 340, explained: 220, attack: 230, response: 240, error: 170, external: 220 };

const STATUS_ORDER = { ACTIVE: 0, IDLE: 1, ERROR: 2, COMPLETED: 3 };

// ---------------------------------------------------------------------
// DOM refs
// ---------------------------------------------------------------------

const dom = {
  sidebar: document.getElementById("sidebar"),
  layout: document.getElementById("layout"),
  toggleSidebarBtn: document.getElementById("toggle-sidebar"),
  indicator: document.getElementById("live-indicator"),
  counterSessions: document.querySelector("#counter-sessions .counter-value"),
  counterAlerts: document.querySelector("#counter-alerts .counter-value"),
  counterFindings: document.querySelector("#counter-findings .counter-value"),
  eventsBody: document.getElementById("events-body"),
  tableWrap: document.getElementById("table-wrap"),
  colgroup: document.getElementById("col-group"),
  headerRow: document.querySelector("#events thead tr.col-headers"),
  filterRow: document.getElementById("filter-row"),
  searchGlobal: document.getElementById("search-global"),
  quickFilters: document.getElementById("quick-filters"),
  redactionToggle: document.getElementById("redaction-toggle"),
  resetColumnsBtn: document.getElementById("reset-columns"),
  detail: document.getElementById("detail"),
};

// ---------------------------------------------------------------------
// REST helpers
// ---------------------------------------------------------------------

async function apiGet(path) {
  const res = await fetch(path, { credentials: "same-origin" });
  if (!res.ok) {
    throw new Error(`GET ${path} failed: ${res.status}`);
  }
  return res.json();
}

// ---------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------

async function loadConfig() {
  try {
    state.config = await apiGet("/api/config");
  } catch (err) {
    console.error("failed to load /api/config", err);
    state.config = null;
  }
}

async function loadSessions() {
  let sessions = [];
  try {
    sessions = await apiGet("/api/sessions");
  } catch (err) {
    console.error("failed to load /api/sessions", err);
  }
  for (const s of sessions) {
    state.sessions.set(s.id, normalizeSession(s));
  }
  renderSidebar();
  updateHeaderCounters();
}

// The WS only pushes {kind:"session"} for brand-new sessions (id/label/
// created_ms) — status transitions (ACTIVE -> IDLE -> COMPLETED) are
// time-based and computed server-side, so there is no live push for them.
// This periodic REST refresh is the authoritative source for status and
// counts; it complements (does not replace) the WS event stream, which
// still drives immediate per-event counter bumps between polls.
async function refreshSessionsPeriodic() {
  let sessions;
  try {
    sessions = await apiGet("/api/sessions");
  } catch (err) {
    console.error("periodic /api/sessions refresh failed", err);
    return;
  }
  for (const s of sessions) {
    ensureSession(s.id, s); // server values win for every recognized field present
  }
  renderSidebar();
  updateHeaderCounters();
}

function startSessionPolling() {
  if (state.sessionPollTimer) return; // already running — never stack timers
  state.sessionPollTimer = setInterval(refreshSessionsPeriodic, SESSION_POLL_MS);
}

function normalizeSession(s) {
  return {
    id: s.id,
    label: s.label || s.name || s.id,
    name: s.name || null,
    status: s.status || "ACTIVE",
    created_ms: s.created_ms || null,
    last_activity_ms: s.last_activity_ms || null,
    event_count: s.event_count || 0,
    error_count: s.error_count || 0,
    conn_count: s.conn_count || 0,
    alert_count: s.alert_count || 0,
    working_dir: s.working_dir || null,
  };
}

// Fields ensureSession() is willing to merge from a partial payload — a WS
// "session" message (id/label/created_ms only) or a full /api/sessions row
// (all of these). Kept as a whitelist so unrecognized/extra keys never leak
// onto the session object.
const SESSION_MERGE_FIELDS = [
  "label", "name", "status", "created_ms", "last_activity_ms",
  "event_count", "error_count", "conn_count", "alert_count", "working_dir",
];

// Get-or-create a session entry from partial data (e.g. a WS "session"
// message, an /api/sessions refresh row, or an event arriving for a
// session we haven't seen via REST yet). Any recognized field present
// (non-null/undefined) in `partial` overwrites the existing value — this
// is what lets the periodic /api/sessions refresh (see
// refreshSessionsPeriodic) push authoritative status/count updates,
// since ACTIVE/IDLE/COMPLETED/ERROR transitions are time-based and
// computed server-side, not pushed over the WS.
function ensureSession(id, partial) {
  let existing = state.sessions.get(id);
  if (!existing) {
    existing = normalizeSession({ id, ...partial });
    state.sessions.set(id, existing);
  } else if (partial) {
    for (const key of SESSION_MERGE_FIELDS) {
      if (partial[key] !== undefined && partial[key] !== null) {
        existing[key] = partial[key];
      }
    }
  }
  return existing;
}

// ---------------------------------------------------------------------
// Sidebar rendering
// ---------------------------------------------------------------------

function renderSidebar() {
  const sidebar = dom.sidebar;
  sidebar.textContent = "";

  const sessions = Array.from(state.sessions.values()).sort((a, b) => {
    const aRank = a.status in STATUS_ORDER ? STATUS_ORDER[a.status] : 9;
    const bRank = b.status in STATUS_ORDER ? STATUS_ORDER[b.status] : 9;
    if (aRank !== bRank) return aRank - bRank;
    return (b.created_ms || 0) - (a.created_ms || 0);
  });

  if (sessions.length === 0) {
    const empty = document.createElement("div");
    empty.className = "sidebar-empty";
    empty.textContent = "No sessions yet.";
    sidebar.appendChild(empty);
    return;
  }

  for (const s of sessions) {
    sidebar.appendChild(buildSessionTab(s));
  }
}

function buildSessionTab(s) {
  const tab = document.createElement("button");
  tab.type = "button";
  tab.className = "session-tab" + (s.id === state.selectedSessionId ? " selected" : "");
  tab.dataset.status = s.status;
  tab.dataset.sessionId = s.id;
  tab.setAttribute("aria-pressed", s.id === state.selectedSessionId ? "true" : "false");

  const dot = document.createElement("span");
  dot.className = "status-dot";

  const body = document.createElement("span");
  body.className = "session-tab-body";

  const label = document.createElement("div");
  label.className = "session-tab-label";
  label.textContent = s.label;
  label.title = s.label;

  const meta = document.createElement("div");
  meta.className = "session-tab-meta";

  const mEvents = document.createElement("span");
  mEvents.className = "m-events";
  mEvents.textContent = `${s.event_count} ev`;

  const mErrors = document.createElement("span");
  mErrors.className = "m-err" + (s.error_count ? "" : " zero");
  mErrors.textContent = `${s.error_count} err`;

  const mConns = document.createElement("span");
  mConns.className = "m-conn";
  mConns.textContent = `${s.conn_count} conn`;

  const mAlerts = document.createElement("span");
  mAlerts.className = "m-alert" + (s.alert_count ? "" : " zero");
  mAlerts.textContent = `${s.alert_count} alert`;

  meta.append(mEvents, mErrors, mConns, mAlerts);
  body.append(label, meta);
  tab.append(dot, body);

  tab.addEventListener("click", () => selectSession(s.id));

  return tab;
}

function updateHeaderCounters() {
  let alertTotal = 0, findingTotal = 0;
  for (const s of state.sessions.values()) {
    alertTotal += s.alert_count || 0;
    findingTotal += s.finding_count || 0;
  }
  dom.counterSessions.textContent = String(state.sessions.size);
  dom.counterAlerts.textContent = String(alertTotal);
  if (dom.counterFindings) dom.counterFindings.textContent = String(findingTotal);
}

// ---------------------------------------------------------------------
// Session selection + history fetch
// ---------------------------------------------------------------------

async function selectSession(id) {
  state.selectedSessionId = id;
  renderSidebar();

  if (!state.events.has(id)) state.events.set(id, []);

  try {
    const data = await apiGet(buildEventsUrl(id));
    mergeEvents(id, data.events || []);
    // Note: data.max_seq is the *global* store max_seq, not just this
    // session's. We deliberately do NOT fold it into state.maxSeq here —
    // doing so would make a future WS reconnect resume past events for
    // other sessions we have not fetched yet, silently dropping them.
    // state.maxSeq only advances from events we have actually seen
    // (via WS, or a per-session fetch that we've merged in).
  } catch (err) {
    console.error("failed to load events for session", id, err);
  }

  renderEvents(id);
}

// Build the GET /api/sessions/{id}/events URL, forwarding any active
// per-column filters as f_<col> query params so the server can prefilter
// (the local buffer may not hold every historical event for a large
// session — this lets a column filter reach further back than what we've
// already fetched).
function buildEventsUrl(sessionId, limit) {
  const params = new URLSearchParams();
  params.set("after_seq", "0");
  params.set("limit", String(limit || HISTORY_FETCH_LIMIT));
  for (const [key, val] of Object.entries(state.filters.columns)) {
    if (val) params.set(`f_${key}`, val);
  }
  return `/api/sessions/${encodeURIComponent(sessionId)}/events?${params.toString()}`;
}

// Re-fetch a session's history with the current per-column filters applied
// server-side, merge into the local buffer, and re-render if still selected.
// Debounced caller lives in setupFilterUI().
async function reloadHistoryWithFilters(sessionId) {
  let data;
  try {
    data = await apiGet(buildEventsUrl(sessionId));
  } catch (err) {
    console.error("failed to reload filtered history for session", sessionId, err);
    return;
  }
  mergeEvents(sessionId, data.events || []);
  if (state.selectedSessionId === sessionId) renderEvents(sessionId);
}

// Merge a batch of events into the per-session buffer, de-duplicating by
// event_id and keeping ascending seq order. Bumps state.maxSeq for any
// event we now hold, since we've genuinely observed it.
function mergeEvents(sessionId, incoming) {
  const existing = state.events.get(sessionId) || [];
  const byId = new Map(existing.map((e) => [e.event_id, e]));
  for (const e of incoming) {
    byId.set(e.event_id, e);
    if (typeof e.seq === "number" && e.seq > state.maxSeq) {
      state.maxSeq = e.seq;
    }
  }
  const merged = Array.from(byId.values()).sort((a, b) => (a.seq || 0) - (b.seq || 0));
  state.events.set(sessionId, merged);
}

// ---------------------------------------------------------------------
// WebSocket
// ---------------------------------------------------------------------

function wsUrl(afterSeq) {
  const scheme = location.protocol === "https:" ? "wss:" : "ws:";
  return `${scheme}//${location.host}/ws?after_seq=${encodeURIComponent(afterSeq)}`;
}

function connectWS() {
  if (state.wsReconnectTimer) {
    clearTimeout(state.wsReconnectTimer);
    state.wsReconnectTimer = null;
  }

  let ws;
  try {
    ws = new WebSocket(wsUrl(state.maxSeq));
  } catch (err) {
    console.error("failed to open WebSocket", err);
    scheduleReconnect();
    return;
  }
  state.ws = ws;

  ws.addEventListener("open", () => {
    state.wsReconnectAttempts = 0;
    setLiveIndicator(true);
  });

  ws.addEventListener("message", (ev) => {
    let msg;
    try {
      msg = JSON.parse(ev.data);
    } catch (err) {
      console.error("unparseable WS message", err, ev.data);
      return;
    }
    handleWsMessage(msg);
  });

  ws.addEventListener("close", () => {
    setLiveIndicator(false);
    scheduleReconnect();
  });

  ws.addEventListener("error", () => {
    // The subsequent 'close' event drives reconnect; just make sure the
    // socket is actually closed so we don't leak a half-open connection.
    try { ws.close(); } catch (_err) { /* already closing */ }
  });
}

function scheduleReconnect() {
  if (state.wsReconnectTimer) return;
  state.wsReconnectAttempts += 1;
  const base = 500; // ms
  const cap = 10000; // ms
  const delay = Math.min(cap, base * 2 ** (state.wsReconnectAttempts - 1));
  state.wsReconnectTimer = setTimeout(() => {
    state.wsReconnectTimer = null;
    connectWS();
  }, delay);
}

function setLiveIndicator(isLive) {
  const el = dom.indicator;
  const label = el.querySelector(".indicator-label");
  if (isLive) {
    el.classList.remove("is-reconnecting");
    el.classList.add("is-live");
    label.textContent = "LIVE";
  } else {
    el.classList.remove("is-live");
    el.classList.add("is-reconnecting");
    label.textContent = "RECONNECTING";
  }
}

function handleWsMessage(msg) {
  if (!msg || typeof msg !== "object") return;
  if (msg.kind === "session" && msg.session) {
    handleSessionMessage(msg.session);
  } else if (msg.kind === "event" && msg.event) {
    handleEventMessage(msg.event);
  }
}

function handleSessionMessage(session) {
  ensureSession(session.id, session);
  renderSidebar();
  updateHeaderCounters();
}

function handleEventMessage(event) {
  if (typeof event.seq === "number" && event.seq > state.maxSeq) {
    state.maxSeq = event.seq;
  }

  const sid = event.session_id;
  if (!sid) return;

  if (!state.events.has(sid)) state.events.set(sid, []);
  const buf = state.events.get(sid);
  // Guard against duplicate delivery (e.g. replay overlap) by event_id.
  if (!buf.some((e) => e.event_id === event.event_id)) {
    buf.push(event);
  }

  const session = ensureSession(sid, { id: sid });
  session.event_count = (session.event_count || 0) + 1;
  if (event.error) session.error_count = (session.error_count || 0) + 1;
  if (Array.isArray(event.external_connections) && event.external_connections.length) {
    session.conn_count = (session.conn_count || 0) + event.external_connections.length;
  }
  if (Array.isArray(event.security_alerts) && event.security_alerts.length) {
    session.alert_count = (session.alert_count || 0) + event.security_alerts.length;
  }
  if (typeof event.timestamp_ms === "number") {
    session.last_activity_ms = event.timestamp_ms;
  }

  renderSidebar();
  updateHeaderCounters();

  if (state.selectedSessionId === sid) {
    onLiveEvent(sid, event);
  }
}

// ---------------------------------------------------------------------
// Client wildcard matcher — port of backend/wildcard.py's matches()
// ---------------------------------------------------------------------
//   empty pattern -> true; '*'/'?' present -> glob anchored to the whole
//   string ('*' -> '.*', '?' -> '.'); otherwise a case-insensitive
//   substring test. Null-safe on both pattern and text.
function matches(pattern, text) {
  if (pattern === null || pattern === undefined || pattern === "") return true;
  const t = text === null || text === undefined ? "" : String(text);
  if (pattern.indexOf("*") !== -1 || pattern.indexOf("?") !== -1) {
    return globToRegExp(pattern).test(t);
  }
  return t.toLowerCase().indexOf(String(pattern).toLowerCase()) !== -1;
}

const REGEX_SPECIAL = /[.*+?^${}()|[\]\\]/;
function globToRegExp(pattern) {
  let out = "";
  for (const ch of String(pattern)) {
    if (ch === "*") out += ".*";
    else if (ch === "?") out += ".";
    else out += REGEX_SPECIAL.test(ch) ? "\\" + ch : ch;
  }
  return new RegExp("^" + out + "$", "i");
}

// ---------------------------------------------------------------------
// Redaction — display-only masking, never mutates stored events
// ---------------------------------------------------------------------

function effectiveRedactionEnabled() {
  if (state.redactionOverride !== null) return state.redactionOverride;
  return !!(state.config && state.config.redaction_enabled);
}

function redact(text) {
  if (!text) return text;
  let out = String(text);
  // URL-query / header style: key=value, Authorization: value, Bearer value.
  out = out.replace(/Authorization:\s*[^\r\n]+/gi, "Authorization: [REDACTED]");
  out = out.replace(/\bapi[_-]?key=[^\s&"'<>]+/gi, (m) => m.slice(0, m.indexOf("=") + 1) + "[REDACTED]");
  out = out.replace(/\btoken=[^\s&"'<>]+/gi, (m) => m.slice(0, m.indexOf("=") + 1) + "[REDACTED]");
  out = out.replace(/\bBearer\s+[^\s"'<>]+/gi, "Bearer [REDACTED]");
  // JSON-style "key": "value" pairs — catches secrets embedded in structured
  // arguments / raw event JSON, keeping the key visible and masking only
  // the value.
  out = out.replace(/("authorization"\s*:\s*")([^"]*)(")/gi, (_m, p1, _v, p3) => p1 + "[REDACTED]" + p3);
  out = out.replace(/("api[_-]?key"\s*:\s*")([^"]*)(")/gi, (_m, p1, _v, p3) => p1 + "[REDACTED]" + p3);
  out = out.replace(/("token"\s*:\s*")([^"]*)(")/gi, (_m, p1, _v, p3) => p1 + "[REDACTED]" + p3);
  out = out.replace(/("password"\s*:\s*")([^"]*)(")/gi, (_m, p1, _v, p3) => p1 + "[REDACTED]" + p3);
  return out;
}

function maybeRedact(text) {
  return effectiveRedactionEnabled() ? redact(text) : text;
}

// ---------------------------------------------------------------------
// Date formatting — browser-local timezone, YYYY-MM-DD HH:MM:SS.mmm
// ---------------------------------------------------------------------

function pad(n, width) {
  return String(n).padStart(width || 2, "0");
}

function formatLocalTs(ms) {
  if (typeof ms !== "number" || !isFinite(ms)) return "";
  const d = new Date(ms);
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ` +
    `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${pad(d.getMilliseconds(), 3)}`;
}

function truncateText(text, n) {
  const s = text || "";
  return s.length > n ? s.slice(0, n) + "…" : s;
}

// ---------------------------------------------------------------------
// Filtering
// ---------------------------------------------------------------------

function externalText(e) {
  return (e.external_connections || []).map((c) => `${c.host}:${c.port}`).join(" ");
}

function quickFilterPredicate(kind) {
  switch (kind) {
    case "COMMANDS":
    case "TOOLS":
      return (e) => e.event_type === "tool_call";
    case "MODEL":
      return (e) => e.event_type === "user_message" || e.event_type === "assistant_message";
    case "NETWORK":
      return (e) => Array.isArray(e.external_connections) && e.external_connections.length > 0;
    case "ERRORS":
      return (e) => e.error != null;
    case "ALERTS":
      return (e) => Array.isArray(e.security_alerts) && e.security_alerts.length > 0;
    case "FINDINGS":
      return (e) => Array.isArray(e.findings) && e.findings.length > 0;
    case "ALL":
    default:
      return () => true;
  }
}

function matchesAllFilters(e) {
  if (!quickFilterPredicate(state.filters.quick)(e)) return false;

  const cols = state.filters.columns;
  if (cols.date && !matches(cols.date, formatLocalTs(e.timestamp_ms))) return false;
  if (cols.command && !matches(cols.command, e.command)) return false;
  if (cols.explained && !matches(cols.explained, e.command_explained)) return false;
  if (cols.attack && !matches(cols.attack, e.attack)) return false;
  if (cols.response && !matches(cols.response, `${e.stdout || ""} ${e.stderr || ""}`)) return false;
  if (cols.error && !matches(cols.error, e.error)) return false;
  if (cols.external && !matches(cols.external, externalText(e))) return false;

  if (state.filters.global) {
    const hay = [e.command, e.command_explained, e.attack, e.finding_category, e.stdout, e.stderr, e.error, e.tool, e.extension, externalText(e)]
      .filter(Boolean).join(" \n ");
    if (!matches(state.filters.global, hay)) return false;
  }
  return true;
}

// ---------------------------------------------------------------------
// Event table rendering
// ---------------------------------------------------------------------
//
// Rows render newest-first (descending seq). state.view holds the
// filtered result set for the currently-selected session plus how many
// rows are currently materialized in the DOM (`shown`) — only `shown`
// rows are ever built, and scrolling near the bottom of #table-wrap
// grows it by PAGE_SIZE (see loadMoreRows/onTableScroll). New live
// events for the selected session are spliced in and prepended to the
// DOM directly (onLiveEvent) rather than triggering a full rebuild.

function severityRank(s) {
  const r = { LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 };
  return s in r ? r[s] : -1;
}

function topAlert(alerts) {
  return alerts.slice().sort((a, b) =>
    (severityRank(b.severity) - severityRank(a.severity)) || ((b.score || 0) - (a.score || 0))
  )[0];
}

function rebuildFiltered(sessionId) {
  const all = state.events.get(sessionId) || [];
  const filtered = all.filter(matchesAllFilters).slice().sort((a, b) => (b.seq || 0) - (a.seq || 0));
  state.view = { sessionId, filtered, shown: Math.min(PAGE_SIZE, filtered.length) };
}

function renderEvents(sessionId) {
  if (sessionId !== state.selectedSessionId) return; // stale/late call — ignore
  rebuildFiltered(sessionId);

  const body = dom.eventsBody;
  body.textContent = "";
  dom.tableWrap.scrollTop = 0;

  if (state.view.filtered.length === 0) {
    const row = document.createElement("tr");
    row.className = "placeholder-row";
    const cell = document.createElement("td");
    cell.colSpan = state.columns.order.length || 6;
    const total = (state.events.get(sessionId) || []).length;
    cell.textContent = total ? "No events match the current filters." : "No events buffered yet for this session.";
    row.appendChild(cell);
    body.appendChild(row);
    return;
  }

  const frag = document.createDocumentFragment();
  for (let i = 0; i < state.view.shown; i++) frag.appendChild(buildRow(state.view.filtered[i]));
  body.appendChild(frag);
}

function loadMoreRows() {
  const prevShown = state.view.shown;
  state.view.shown = Math.min(state.view.shown + PAGE_SIZE, state.view.filtered.length);
  if (state.view.shown === prevShown) return;
  const frag = document.createDocumentFragment();
  for (let i = prevShown; i < state.view.shown; i++) frag.appendChild(buildRow(state.view.filtered[i]));
  dom.eventsBody.appendChild(frag);
}

function onTableScroll() {
  const el = dom.tableWrap;
  if (!state.view || !state.view.filtered.length) return;
  if (state.view.shown >= state.view.filtered.length) return;
  if (el.scrollHeight - (el.scrollTop + el.clientHeight) < 300) loadMoreRows();
}

// Called for a freshly-arrived WS event on the currently selected
// session. Avoids a full table rebuild: if the event passes the active
// filters it is spliced into state.view.filtered (it is always the
// newest event, so it belongs at index 0 in our descending-seq view)
// and its row is prepended directly.
function onLiveEvent(sessionId, event) {
  if (sessionId !== state.selectedSessionId) return;
  if (!state.view || state.view.sessionId !== sessionId) {
    renderEvents(sessionId);
    return;
  }
  if (!matchesAllFilters(event)) return;

  const placeholder = dom.eventsBody.querySelector(".placeholder-row");
  if (placeholder) placeholder.remove();

  state.view.filtered.unshift(event);
  state.view.shown += 1;
  dom.eventsBody.insertBefore(buildRow(event), dom.eventsBody.firstChild);

  // Bound DOM growth for continuously-running sessions: drop the oldest
  // rendered row(s) once we exceed MAX_RENDERED_ROWS. The underlying
  // state.events / state.view.filtered buffers are untouched — this only
  // trims what's materialized in the DOM, keeping `shown` consistent with
  // "DOM rows == filtered[0..shown)".
  while (dom.eventsBody.children.length > MAX_RENDERED_ROWS) {
    dom.eventsBody.removeChild(dom.eventsBody.lastElementChild);
    state.view.shown -= 1;
  }
}

function buildRow(e) {
  const tr = document.createElement("tr");
  tr.dataset.eventId = e.event_id;
  const hasAlerts = Array.isArray(e.security_alerts) && e.security_alerts.length > 0;
  if (hasAlerts) tr.classList.add("alert-row");
  if (Array.isArray(e.findings) && e.findings.length > 0) tr.classList.add("finding-row");

  for (const col of state.columns.order) {
    tr.appendChild(buildCell(col, e));
  }

  tr.addEventListener("click", (ev) => {
    if (ev.target.closest(".no-row-click")) return;
    openDetail(e);
  });

  return tr;
}

function attackUrl(id) {
  if (!id) return null;
  const m = /^T(\d+)(?:\.(\d+))?$/.exec(id);
  if (!m) return null;
  return "https://attack.mitre.org/techniques/T" + m[1] + (m[2] ? "/" + m[2] : "") + "/";
}

function buildAttackCell(e) {
  const td = document.createElement("td");
  td.className = "cell-attack";
  const label = e.attack;
  if (!label) return td;
  const url = attackUrl(e.attack_id);
  if (url) {
    const a = document.createElement("a");
    a.className = "attack-link no-row-click";
    a.href = url;
    a.target = "_blank";
    a.rel = "noopener noreferrer";
    a.textContent = label;
    a.title = label + (e.attack_id ? " (" + e.attack_id + ")" : "") + " — open on attack.mitre.org";
    td.appendChild(a);
  } else {
    td.textContent = label;
  }
  return td;
}

function buildCell(col, e) {
  switch (col) {
    case "date": return buildDateCell(e);
    case "command": return buildCommandCell(e);
    case "explained": {
      const td = document.createElement("td");
      td.className = "cell-explained";
      td.textContent = maybeRedact(e.command_explained || "");
      return td;
    }
    case "attack": return buildAttackCell(e);
    case "response": return buildResponseCell(e);
    case "error": return buildErrorCell(e);
    case "external": return buildExternalCell(e);
    default: return document.createElement("td");
  }
}

function buildDateCell(e) {
  const td = document.createElement("td");
  td.className = "cell-date";
  if (Array.isArray(e.security_alerts) && e.security_alerts.length) {
    const dot = document.createElement("span");
    dot.className = "alert-dot";
    td.appendChild(dot);
  }
  const span = document.createElement("span");
  span.textContent = formatLocalTs(e.timestamp_ms);
  td.appendChild(span);
  return td;
}

function buildCommandCell(e) {
  const td = document.createElement("td");
  td.className = "cell-command";

  const full = e.command || "";
  if (!full && !(e.arguments && Object.keys(e.arguments).length)) return td;

  const displayFull = maybeRedact(full);
  const wrap = document.createElement("div");
  wrap.className = "expandable";

  const toggle = document.createElement("span");
  toggle.className = "toggle no-row-click";
  toggle.textContent = "▶";
  toggle.setAttribute("role", "button");
  toggle.tabIndex = 0;

  const preview = document.createElement("span");
  preview.className = "preview";
  // Full text; the .preview CSS ellipsizes it to the current column width, so
  // widening the column reveals more of the command instead of dead space.
  preview.textContent = displayFull;

  const fullDiv = document.createElement("div");
  fullDiv.className = "full-content";
  fullDiv.hidden = true;

  const hasArgs = e.event_type === "tool_call" && e.arguments && Object.keys(e.arguments).length;
  if (hasArgs) {
    const toolLine = document.createElement("div");
    toolLine.className = "tool-line";
    toolLine.textContent = `Tool: ${e.tool || ""}`;
    const pre = document.createElement("pre");
    pre.className = "json-pre";
    pre.textContent = maybeRedact(JSON.stringify(e.arguments, null, 2));
    fullDiv.append(toolLine, pre);
  } else {
    const pre = document.createElement("pre");
    pre.className = "cmd-pre";
    pre.textContent = displayFull;
    fullDiv.appendChild(pre);
  }

  toggle.addEventListener("click", (ev) => {
    ev.stopPropagation();
    const willShow = fullDiv.hidden;
    fullDiv.hidden = !willShow;
    preview.hidden = willShow;
    toggle.textContent = willShow ? "▼" : "▶";
  });

  wrap.append(toggle, preview, fullDiv);
  td.appendChild(wrap);
  return td;
}

function buildResponseDetail(container, e) {
  container.textContent = "";
  if (e.exit_code !== null && e.exit_code !== undefined) {
    const p = document.createElement("div");
    p.className = "meta-line";
    p.textContent = `exit_code: ${e.exit_code}`;
    container.appendChild(p);
  }
  if (e.http_status !== null && e.http_status !== undefined) {
    const p = document.createElement("div");
    p.className = "meta-line";
    p.textContent = `http_status: ${e.http_status}`;
    container.appendChild(p);
  }
  if (e.stdout) {
    const h = document.createElement("div");
    h.className = "sub-label";
    h.textContent = "stdout:";
    const pre = document.createElement("pre");
    pre.className = "resp-pre";
    pre.textContent = maybeRedact(e.stdout);
    container.append(h, pre);
  }
  if (e.stderr) {
    const h = document.createElement("div");
    h.className = "sub-label";
    h.textContent = "stderr:";
    const pre = document.createElement("pre");
    pre.className = "resp-pre";
    pre.textContent = maybeRedact(e.stderr);
    container.append(h, pre);
  }
}

function buildResponseCell(e) {
  const td = document.createElement("td");
  td.className = "cell-response";

  const stdout = e.stdout || "";
  const stderr = e.stderr || "";
  const combinedLen = stdout.length + stderr.length;
  const hasMeta = (e.exit_code !== null && e.exit_code !== undefined) ||
    (e.http_status !== null && e.http_status !== undefined);
  if (combinedLen === 0 && !hasMeta) return td;

  const wrap = document.createElement("div");
  wrap.className = "expandable";

  const toggle = document.createElement("span");
  toggle.className = "toggle no-row-click";
  toggle.textContent = `▶ ${combinedLen} characters`;
  toggle.setAttribute("role", "button");
  toggle.tabIndex = 0;

  const fullDiv = document.createElement("div");
  fullDiv.className = "full-content";
  fullDiv.hidden = true;

  let built = false; // lazy: only build the (possibly huge) text nodes on first expand
  toggle.addEventListener("click", (ev) => {
    ev.stopPropagation();
    if (!built) {
      buildResponseDetail(fullDiv, e);
      built = true;
    }
    const willShow = fullDiv.hidden;
    fullDiv.hidden = !willShow;
    toggle.textContent = `${willShow ? "▼" : "▶"} ${combinedLen} characters`;
  });

  wrap.append(toggle, fullDiv);
  td.appendChild(wrap);
  return td;
}

function buildAlertBadge(alerts) {
  const top = topAlert(alerts);
  const wrap = document.createElement("div");
  wrap.className = "alert-badge";

  const title = document.createElement("span");
  title.className = "alert-badge-title";
  title.textContent = "⚠ REVERSE SHELL SUSPECTED";

  const chip = document.createElement("span");
  chip.className = `chip chip-${top.severity || ""}`;
  chip.textContent = top.severity || "";

  const reasons = document.createElement("span");
  reasons.className = "alert-reasons";
  reasons.textContent = (top.reasons || []).join("; ");

  const dest = document.createElement("span");
  dest.className = "alert-dest";
  dest.textContent = top.destination ? `→ ${top.destination}` : "";

  wrap.append(title, chip, reasons, dest);
  return wrap;
}

function buildFindingBadge(findings) {
  const top = findings[0] || {};
  const wrap = document.createElement("div");
  wrap.className = "finding-badge";

  const title = document.createElement("span");
  title.className = "finding-badge-title";
  title.textContent = "★ FINDING";

  const chip = document.createElement("span");
  chip.className = `chip chip-${top.severity || ""}`;
  chip.textContent = top.severity || "";

  const cat = document.createElement("span");
  cat.className = "finding-cat";
  cat.textContent = top.category || "";

  const ev = document.createElement("span");
  ev.className = "finding-evidence";
  if (top.evidence) { ev.textContent = `“${top.evidence}”`; ev.title = top.evidence; }

  wrap.append(title, chip, cat, ev);
  return wrap;
}

function buildErrorCell(e) {
  const td = document.createElement("td");
  td.className = "cell-error";
  if (Array.isArray(e.findings) && e.findings.length) {
    td.appendChild(buildFindingBadge(e.findings));
  }
  if (Array.isArray(e.security_alerts) && e.security_alerts.length) {
    td.appendChild(buildAlertBadge(e.security_alerts));
  }
  if (e.error) {
    const span = document.createElement("span");
    span.className = "error-text";
    span.textContent = maybeRedact(e.error);
    td.appendChild(span);
  }
  return td;
}

function buildExternalCell(e) {
  const td = document.createElement("td");
  td.className = "cell-external";
  const conns = e.external_connections || [];
  for (const c of conns) {
    const badge = document.createElement("span");
    const cls = c.classification || "UNKNOWN";
    badge.className = `conn-badge conn-${cls}` + (c.source === "referenced" ? " conn-referenced" : "");

    const hostPort = document.createElement("span");
    hostPort.className = "conn-hostport";
    hostPort.textContent = `${c.host}:${c.port}`;

    const clsSpan = document.createElement("span");
    clsSpan.className = "conn-class";
    clsSpan.textContent = cls;

    badge.append(hostPort, clsSpan);

    if (c.source === "referenced") {
      const ref = document.createElement("span");
      ref.className = "conn-ref-marker";
      ref.textContent = "ref";
      badge.appendChild(ref);
    }
    td.appendChild(badge);
  }
  return td;
}

// ---------------------------------------------------------------------
// Detail modal
// ---------------------------------------------------------------------

function addDetailField(dl, label, value) {
  const dt = document.createElement("dt");
  dt.textContent = label;
  const dd = document.createElement("dd");
  dd.textContent = (value === undefined || value === null || value === "") ? "—" : String(value);
  dl.append(dt, dd);
}

function buildCopyableBlock(label, text, showCopy) {
  const section = document.createElement("div");
  section.className = "detail-section";

  const head = document.createElement("div");
  head.className = "detail-section-head";
  const h = document.createElement("h3");
  h.textContent = label;
  head.appendChild(h);

  if (showCopy) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "copy-btn";
    btn.textContent = "Copy";
    btn.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(text || "");
        btn.textContent = "Copied";
      } catch (err) {
        console.error("clipboard write failed", err);
        btn.textContent = "Failed";
      }
      setTimeout(() => { btn.textContent = "Copy"; }, 1200);
    });
    head.appendChild(btn);
  }

  section.appendChild(head);
  const pre = document.createElement("pre");
  pre.className = "detail-pre";
  pre.textContent = text || "(empty)";
  section.appendChild(pre);
  return section;
}

function openDetail(e) {
  const dlg = dom.detail;
  dlg.textContent = "";

  const wrapper = document.createElement("div");
  wrapper.className = "detail-content";

  const header = document.createElement("div");
  header.className = "detail-header";
  const title = document.createElement("h2");
  title.textContent = "Event Detail";
  const closeBtn = document.createElement("button");
  closeBtn.type = "button";
  closeBtn.className = "detail-close";
  closeBtn.textContent = "✕";
  closeBtn.addEventListener("click", () => dlg.close());
  header.append(title, closeBtn);
  wrapper.appendChild(header);

  const grid = document.createElement("dl");
  grid.className = "detail-grid";
  addDetailField(grid, "Event ID", e.event_id);
  addDetailField(grid, "Session ID", e.session_id);
  addDetailField(grid, "Timestamp", formatLocalTs(e.timestamp_ms));
  addDetailField(grid, "Event Type", e.event_type);
  addDetailField(grid, "Tool", e.tool);
  addDetailField(grid, "Extension", e.extension);
  addDetailField(grid, "Tier", e.tier);
  addDetailField(grid, "Approval Decision", e.approval_decision);
  addDetailField(grid, "MITRE ATT&CK", e.attack);
  addDetailField(grid, "Finding", e.finding_severity ? `${e.finding_severity} — ${e.finding_category}` : null);
  addDetailField(grid, "Exit Code", e.exit_code);
  addDetailField(grid, "HTTP Status", e.http_status);
  wrapper.appendChild(grid);

  if (Array.isArray(e.findings) && e.findings.length) {
    const f = e.findings[0];
    wrapper.appendChild(buildCopyableBlock(
      `★ Finding — ${f.severity} ${f.category} [${(f.reasons || []).join(", ")}]`,
      maybeRedact(f.evidence || ""), true));
  }

  wrapper.appendChild(buildCopyableBlock("Command", maybeRedact(e.command || ""), true));
  wrapper.appendChild(buildCopyableBlock("Arguments (JSON)", maybeRedact(JSON.stringify(e.arguments || {}, null, 2)), true));
  wrapper.appendChild(buildCopyableBlock("stdout", maybeRedact(e.stdout || ""), true));
  wrapper.appendChild(buildCopyableBlock("stderr", maybeRedact(e.stderr || ""), true));
  wrapper.appendChild(buildCopyableBlock("Error", maybeRedact(e.error || ""), true));

  const destSection = document.createElement("div");
  destSection.className = "detail-section";
  const destTitle = document.createElement("h3");
  destTitle.textContent = "External Destinations";
  destSection.appendChild(destTitle);
  const conns = e.external_connections || [];
  if (!conns.length) {
    const p = document.createElement("div");
    p.className = "empty-note";
    p.textContent = "none";
    destSection.appendChild(p);
  } else {
    const list = document.createElement("ul");
    list.className = "detail-conn-list";
    for (const c of conns) {
      const li = document.createElement("li");
      li.textContent = `${c.host}:${c.port} [${c.proto || ""}] ${c.classification || "UNKNOWN"} (${c.source || "?"})`;
      list.appendChild(li);
    }
    destSection.appendChild(list);
  }
  wrapper.appendChild(destSection);

  const alertSection = document.createElement("div");
  alertSection.className = "detail-section";
  const alertTitle = document.createElement("h3");
  alertTitle.textContent = "Security Detections";
  alertSection.appendChild(alertTitle);
  const alerts = e.security_alerts || [];
  if (!alerts.length) {
    const p = document.createElement("div");
    p.className = "empty-note";
    p.textContent = "none";
    alertSection.appendChild(p);
  } else {
    const list = document.createElement("ul");
    list.className = "detail-alert-list";
    for (const a of alerts) {
      const li = document.createElement("li");
      const chip = document.createElement("span");
      chip.className = `chip chip-${a.severity || ""}`;
      chip.textContent = a.severity || "";
      li.appendChild(chip);
      const txt = document.createElement("span");
      const scoreText = (a.score === undefined || a.score === null) ? "" : String(a.score);
      txt.textContent = ` ${a.type || ""} score=${scoreText} — ${(a.reasons || []).join("; ")} → ${a.destination || ""}`;
      li.appendChild(txt);
      list.appendChild(li);
    }
    alertSection.appendChild(list);
  }
  wrapper.appendChild(alertSection);

  wrapper.appendChild(buildCopyableBlock("Raw Event JSON", maybeRedact(JSON.stringify(e, null, 2)), true));

  dlg.appendChild(wrapper);
  dlg.showModal();
}

function setupDetailDialog() {
  // Click on the ::backdrop area (outside the dialog's own box) closes it.
  dom.detail.addEventListener("click", (ev) => {
    if (ev.target !== dom.detail) return;
    const r = dom.detail.getBoundingClientRect();
    const inside = ev.clientX >= r.left && ev.clientX <= r.right && ev.clientY >= r.top && ev.clientY <= r.bottom;
    if (!inside) dom.detail.close();
  });
}

// ---------------------------------------------------------------------
// Column persistence (drag-resize + reorder, localStorage-backed)
// ---------------------------------------------------------------------

function loadColumnPrefs() {
  let saved = null;
  try {
    const raw = localStorage.getItem(COLUMN_STORAGE_KEY);
    if (raw) saved = JSON.parse(raw);
  } catch (err) {
    console.error("failed to parse stored column prefs", err);
  }
  const validOrder = saved && Array.isArray(saved.colOrder) &&
    saved.colOrder.length === DEFAULT_COL_ORDER.length &&
    DEFAULT_COL_ORDER.every((c) => saved.colOrder.includes(c));
  const order = validOrder ? saved.colOrder.slice() : DEFAULT_COL_ORDER.slice();
  const widths = Object.assign({}, DEFAULT_COL_WIDTHS, (saved && saved.colWidths) || {});
  state.columns = { order, widths };
}

function saveColumnPrefs() {
  try {
    localStorage.setItem(COLUMN_STORAGE_KEY, JSON.stringify({
      colOrder: state.columns.order,
      colWidths: state.columns.widths,
    }));
  } catch (err) {
    console.error("failed to persist column prefs", err);
  }
}

function reorderRow(tr) {
  if (!tr) return;
  const byKey = new Map(Array.from(tr.children).map((th) => [th.dataset.col, th]));
  for (const key of state.columns.order) {
    const th = byKey.get(key);
    if (th) tr.appendChild(th);
  }
}

function applyColumnLayout() {
  const cols = Array.from(dom.colgroup.children);
  const byKey = new Map(cols.map((c) => [c.dataset.col, c]));
  for (const key of state.columns.order) {
    const col = byKey.get(key);
    if (col) {
      dom.colgroup.appendChild(col);
      col.style.width = (state.columns.widths[key] || DEFAULT_COL_WIDTHS[key] || 150) + "px";
    }
  }
  reorderRow(dom.headerRow);
  reorderRow(dom.filterRow);
}

function resetColumnPrefs() {
  try {
    localStorage.removeItem(COLUMN_STORAGE_KEY);
  } catch (err) {
    console.error("failed to clear column prefs", err);
  }
  state.columns = { order: DEFAULT_COL_ORDER.slice(), widths: Object.assign({}, DEFAULT_COL_WIDTHS) };
  applyColumnLayout();
  if (state.selectedSessionId) renderEvents(state.selectedSessionId);
}

function setupColumnInteractions() {
  for (const th of Array.from(dom.headerRow.children)) {
    const key = th.dataset.col;
    const handle = th.querySelector(".col-resize-handle");

    if (handle) {
      handle.addEventListener("mousedown", (ev) => {
        ev.preventDefault();
        ev.stopPropagation();
        const startX = ev.clientX;
        const col = dom.colgroup.querySelector(`col[data-col="${key}"]`);
        if (!col) return;
        // Read the start width from the header cell (reliable) rather than the
        // <col> element, whose getBoundingClientRect can report 0 in some browsers.
        const startWidth = th.getBoundingClientRect().width ||
          (state.columns.widths[key] || DEFAULT_COL_WIDTHS[key] || 150);
        handle.classList.add("is-resizing");

        function onMove(mv) {
          const newW = Math.max(60, Math.round(startWidth + (mv.clientX - startX)));
          col.style.width = newW + "px";
        }
        function onUp() {
          document.removeEventListener("mousemove", onMove);
          document.removeEventListener("mouseup", onUp);
          handle.classList.remove("is-resizing");
          state.columns.widths[key] = parseInt(col.style.width, 10) || startWidth;
          saveColumnPrefs();
        }
        document.addEventListener("mousemove", onMove);
        document.addEventListener("mouseup", onUp);
      });
    }

    // Drag-to-reorder: mousedown anywhere else on the th header. A small
    // movement threshold distinguishes a drag from an incidental click.
    th.addEventListener("mousedown", (ev) => {
      if (ev.target.closest(".col-resize-handle")) return;
      const startX = ev.clientX;
      let dragging = false;

      function onMove(mv) {
        if (!dragging && Math.abs(mv.clientX - startX) > 6) {
          dragging = true;
          th.classList.add("th-dragging");
        }
      }
      function onUp(mv) {
        document.removeEventListener("mousemove", onMove);
        document.removeEventListener("mouseup", onUp);
        th.classList.remove("th-dragging");
        if (!dragging) return;

        let targetKey = null;
        for (const t of Array.from(dom.headerRow.children)) {
          const r = t.getBoundingClientRect();
          if (mv.clientX >= r.left && mv.clientX <= r.right) { targetKey = t.dataset.col; break; }
        }
        if (targetKey && targetKey !== key) {
          const order = state.columns.order.slice();
          const from = order.indexOf(key);
          const to = order.indexOf(targetKey);
          order.splice(from, 1);
          order.splice(to, 0, key);
          state.columns.order = order;
          applyColumnLayout();
          saveColumnPrefs();
          if (state.selectedSessionId) renderEvents(state.selectedSessionId);
        }
      }
      document.addEventListener("mousemove", onMove);
      document.addEventListener("mouseup", onUp);
    });
  }
}

// ---------------------------------------------------------------------
// Filter / redaction UI wiring
// ---------------------------------------------------------------------

function debounce(fn, waitMs) {
  let timer = null;
  return function debounced(...args) {
    if (timer) clearTimeout(timer);
    timer = setTimeout(() => fn.apply(this, args), waitMs);
  };
}

function setupFilterUI() {
  for (const key of DEFAULT_COL_ORDER) {
    const th = dom.filterRow.querySelector(`th[data-col="${key}"]`);
    if (!th) continue;
    const input = document.createElement("input");
    input.type = "text";
    input.className = "col-filter-input";
    input.placeholder = "filter…";
    input.dataset.col = key;
    input.addEventListener("input", debounce(() => {
      state.filters.columns[key] = input.value;
      if (state.selectedSessionId) {
        renderEvents(state.selectedSessionId);
        reloadHistoryWithFilters(state.selectedSessionId);
      }
    }, 250));
    th.appendChild(input);
  }

  dom.searchGlobal.addEventListener("input", debounce(() => {
    state.filters.global = dom.searchGlobal.value;
    if (state.selectedSessionId) renderEvents(state.selectedSessionId);
  }, 150));

  dom.quickFilters.addEventListener("click", (ev) => {
    const btn = ev.target.closest(".quick-btn");
    if (!btn) return;
    for (const b of dom.quickFilters.querySelectorAll(".quick-btn")) b.classList.toggle("active", b === btn);
    state.filters.quick = btn.dataset.quick;
    if (state.selectedSessionId) renderEvents(state.selectedSessionId);
  });

  dom.resetColumnsBtn.addEventListener("click", resetColumnPrefs);
}

function setupRedactionToggle() {
  dom.redactionToggle.addEventListener("change", () => {
    state.redactionOverride = dom.redactionToggle.checked;
    if (state.selectedSessionId) renderEvents(state.selectedSessionId);
  });
}

const SIDEBAR_STORAGE_KEY = "monitor.sidebarHidden";

function applySidebarState(hidden) {
  dom.layout.classList.toggle("sidebar-collapsed", hidden);
  dom.toggleSidebarBtn.classList.toggle("is-active", hidden);
  dom.toggleSidebarBtn.setAttribute("aria-pressed", hidden ? "true" : "false");
}

function setupSidebarToggle() {
  let hidden = false;
  try { hidden = localStorage.getItem(SIDEBAR_STORAGE_KEY) === "1"; } catch (e) { /* ignore */ }
  applySidebarState(hidden);
  dom.toggleSidebarBtn.addEventListener("click", () => {
    hidden = !dom.layout.classList.contains("sidebar-collapsed");
    applySidebarState(hidden);
    try { localStorage.setItem(SIDEBAR_STORAGE_KEY, hidden ? "1" : "0"); } catch (e) { /* ignore */ }
  });
}

// ---------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------

async function init() {
  loadColumnPrefs();
  applyColumnLayout();
  setupColumnInteractions();
  setupFilterUI();
  setupRedactionToggle();
  setupSidebarToggle();
  setupDetailDialog();
  dom.tableWrap.addEventListener("scroll", onTableScroll);

  await loadConfig();
  dom.redactionToggle.checked = !!(state.config && state.config.redaction_enabled);

  await loadSessions();
  connectWS();
  startSessionPolling();
}

document.addEventListener("DOMContentLoaded", init);
