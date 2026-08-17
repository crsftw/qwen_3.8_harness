import re, shlex
from urllib.parse import urlparse

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

def _explain_shell(command):
    cmd = (command or "").strip()
    # Drop heredoc body before tokenizing
    head = cmd.split("<<", 1)[0]

    # Tokenize respecting shell quoting—this prevents regex-split from breaking inside quoted strings
    try:
        tokens = shlex.split(head)
    except ValueError:
        tokens = head.split()

    # Split token stream on shell separators to extract command sequences
    separators = {'|', '||', '&&', ';', '&'}
    commands = []
    current = []

    for token in tokens:
        if token in separators:
            if current:
                commands.append(current)
                current = []
        else:
            current.append(token)

    if current:
        commands.append(current)

    # Find the first non-trivial command (skip cd, export, etc.)
    trivial = {'cd', 'export', 'source', '.', 'pwd', 'pushd', 'popd'}
    binv = None

    for cmd_tokens in commands:
        if cmd_tokens:
            candidate = cmd_tokens[0].split("/")[-1]
            if candidate not in trivial:
                binv = candidate
                break

    # Fallback: use first command if all were trivial
    if binv is None:
        for cmd_tokens in commands:
            if cmd_tokens:
                binv = cmd_tokens[0].split("/")[-1]
                break

    if not binv:
        binv = ""

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

def _safe_urlparse(s):
    # urlparse() itself raises ValueError on some malformed URLs (e.g. an
    # unclosed IPv6 bracket: "http://[::1"). Never let that propagate -- a
    # malformed URL should just yield no connection for that URL, not abort
    # the whole event.
    try:
        return urlparse(s)
    except ValueError:
        return None

def _safe_port(u):
    # u.port raises ValueError on a malformed or out-of-range port string.
    # Degrade to None (never crash) instead of falling back to the scheme's
    # default port -- a malformed port is not the same as "no port given".
    try:
        p = u.port
    except ValueError:
        return None
    return p or _PORT_BY_SCHEME.get(u.scheme)

def _conn(host, port=None, proto=None, source="tool"):
    return {"host":host,"port":port,"proto":proto,
            "classification":_classify_host(host),"source":source}

def external_connections(tool, arguments, command):
    a = arguments or {}
    t = (tool or "").lower()
    out = []
    if any(t.endswith(x) for x in _NET_TOOLS):
        if "url" in a:
            u = _safe_urlparse(a["url"])
            if u is not None:
                out.append(_conn(u.hostname, _safe_port(u), u.scheme, "tool"))
        else:
            host = a.get("target") or a.get("host") or a.get("name") or a.get("query")
            if host:
                proto = "https" if a.get("ssl") else None
                out.append(_conn(host, a.get("port") or (443 if a.get("ssl") else None), proto, "tool"))
        return [c for c in out if c["host"]]
    # shell: referenced-only
    text = command or a.get("command") or ""
    for m in re.finditer(r"https?://[^\s\"']+", text):
        u = _safe_urlparse(m.group(0))
        if u is None:
            continue
        c = _conn(u.hostname, _safe_port(u), u.scheme, "referenced")
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
    matched = [r for r in _rules.REVERSE_SHELL_RULES if r["pattern"].search(text)]
    reasons = [r["name"] for r in matched]
    score = sum(r["weight"] for r in matched)
    strong = [r for r in matched if r.get("standalone")]
    if score == 0:
        return []
    if score >= 6 or len(strong) >= 2:
        sev = "CRITICAL"
    elif len(strong) >= 1 or (score >= 4 and len(reasons) >= 2):
        sev = "HIGH"
    elif score >= 2:
        sev = "MEDIUM"
    else:
        sev = "LOW"
    return [{"type":"reverse_shell","severity":sev,"score":score,
             "reasons":reasons,"destination":_destination(text, connections)}]
