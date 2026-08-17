#!/usr/bin/env python3
"""
Web MCP server (stdlib only) — runs in an egress-enabled but LAN-blocked container.
Exposes ONLY:
  * web_search(query, count?)  -> self-hosted SearXNG JSON API (trusted endpoint)
  * web_fetch(url, max_bytes?) -> fetch a PUBLIC url, return cleaned text

SSRF defense (ANTI_PATTERNS / input-validation): web_fetch resolves the host and refuses any
private / loopback / link-local / reserved IP (blocks LAN, the docker host, and cloud metadata
169.254.169.254). Redirects are followed manually and each hop is re-validated. No shell is exposed
here — this container has network, so it must not offer arbitrary execution.

Known limitation (documented, to harden later): DNS rebinding TOCTOU between validation and connect.
Lightweight-first accepts this; IP-pinning is a later hardening.
"""
import html.parser
import ipaddress
import json
import os
import socket
import sys
import urllib.parse
import urllib.request

SEARXNG_URL = os.environ.get("SEARXNG_URL", "http://qh-searxng:8080")
DEFAULT_MAX_BYTES = 500_000
FETCH_TIMEOUT = 20
MAX_REDIRECTS = 5
SERVER_INFO = {"name": "qwen-harness-web", "version": "0.1.0"}

# ---- SSRF guard ----------------------------------------------------------
def _ip_is_public(ip_str):
    ip = ipaddress.ip_address(ip_str)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or
                ip.is_reserved or ip.is_multicast or ip.is_unspecified)

def _assert_public_url(url):
    p = urllib.parse.urlparse(url)
    if p.scheme not in ("http", "https"):
        raise ValueError(f"scheme not allowed: {p.scheme!r} (only http/https)")
    host = p.hostname
    if not host:
        raise ValueError("no host in URL")
    infos = socket.getaddrinfo(host, p.port or (443 if p.scheme == "https" else 80),
                               proto=socket.IPPROTO_TCP)
    ips = {i[4][0] for i in infos}
    if not ips:
        raise ValueError(f"could not resolve {host}")
    for ip in ips:
        if not _ip_is_public(ip):
            raise ValueError(f"blocked non-public address {ip} for host {host} (SSRF protection)")
    return url

# ---- minimal HTML -> text -----------------------------------------------
class _TextExtractor(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts = []
        self.skip = 0
    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style", "noscript"):
            self.skip += 1
    def handle_endtag(self, tag):
        if tag in ("script", "style", "noscript") and self.skip:
            self.skip -= 1
    def handle_data(self, data):
        if not self.skip:
            t = data.strip()
            if t:
                self.parts.append(t)

def _html_to_text(s):
    ex = _TextExtractor()
    try:
        ex.feed(s)
    except Exception:
        pass
    return "\n".join(ex.parts)

# ---- tools ---------------------------------------------------------------
def tool_web_fetch(args):
    url = args["url"]
    max_bytes = int(args.get("max_bytes", DEFAULT_MAX_BYTES))
    for _ in range(MAX_REDIRECTS + 1):
        _assert_public_url(url)
        req = urllib.request.Request(url, headers={"User-Agent": "qwen-harness/0.1"})
        opener = urllib.request.build_opener(_NoRedirect())
        resp = opener.open(req, timeout=FETCH_TIMEOUT)
        if resp.status in (301, 302, 303, 307, 308):
            loc = resp.headers.get("Location")
            if not loc:
                raise ValueError("redirect without Location")
            url = urllib.parse.urljoin(url, loc)  # re-validated next loop
            continue
        ctype = resp.headers.get("Content-Type", "")
        raw = resp.read(max_bytes)
        text = raw.decode("utf-8", errors="replace")
        if "html" in ctype.lower():
            text = _html_to_text(text)
        return f"[{resp.status}] {ctype}\nURL: {url}\n\n{text}"
    raise ValueError("too many redirects")

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None  # we handle redirects manually to re-validate each hop

def tool_web_search(args):
    query = args["query"]
    count = int(args.get("count", 5))
    qs = urllib.parse.urlencode({"q": query, "format": "json"})
    req = urllib.request.Request(f"{SEARXNG_URL}/search?{qs}",
                                 headers={"User-Agent": "qwen-harness/0.1"})
    resp = urllib.request.urlopen(req, timeout=FETCH_TIMEOUT)  # trusted endpoint, no SSRF check
    data = json.loads(resp.read().decode("utf-8", errors="replace"))
    out = []
    for r in (data.get("results") or [])[:count]:
        out.append(f"- {r.get('title','')}\n  {r.get('url','')}\n  {(r.get('content','') or '')[:200]}")
    return "\n".join(out) or "(no results)"

TOOLS = {
    "web_search": {
        "impl": tool_web_search,
        "description": "Search the web via self-hosted SearXNG. Returns top results (title, url, snippet).",
        "schema": {"type": "object",
                   "properties": {"query": {"type": "string"}, "count": {"type": "integer"}},
                   "required": ["query"]},
    },
    "web_fetch": {
        "impl": tool_web_fetch,
        "description": "Fetch a PUBLIC http(s) URL and return cleaned text. Private/LAN/metadata addresses are refused.",
        "schema": {"type": "object",
                   "properties": {"url": {"type": "string"}, "max_bytes": {"type": "integer"}},
                   "required": ["url"]},
    },
}

# ---- MCP plumbing (identical shape to the sandbox server) -----------------
def send(m): sys.stdout.write(json.dumps(m) + "\n"); sys.stdout.flush()
def reply(rid, result): send({"jsonrpc": "2.0", "id": rid, "result": result})

def handle(msg):
    method = msg.get("method"); rid = msg.get("id")
    if method == "initialize":
        proto = (msg.get("params") or {}).get("protocolVersion", "2024-11-05")
        reply(rid, {"protocolVersion": proto, "capabilities": {"tools": {}}, "serverInfo": SERVER_INFO})
    elif method == "notifications/initialized":
        pass
    elif method == "ping":
        if rid is not None: reply(rid, {})
    elif method == "tools/list":
        reply(rid, {"tools": [{"name": n, "description": t["description"], "inputSchema": t["schema"]}
                              for n, t in TOOLS.items()]})
    elif method == "tools/call":
        p = msg.get("params") or {}
        name = p.get("name"); args = p.get("arguments") or {}
        tool = TOOLS.get(name)
        if not tool:
            reply(rid, {"content": [{"type": "text", "text": f"unknown tool: {name}"}], "isError": True}); return
        try:
            reply(rid, {"content": [{"type": "text", "text": tool["impl"](args)}], "isError": False})
        except Exception as e:
            reply(rid, {"content": [{"type": "text", "text": f"{type(e).__name__}: {e}"}], "isError": True})
    else:
        if rid is not None:
            send({"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": f"method not found: {method}"}})

def main():
    for line in sys.stdin:
        line = line.strip()
        if not line: continue
        try: msg = json.loads(line)
        except json.JSONDecodeError: continue
        try: handle(msg)
        except Exception as e:
            if msg.get("id") is not None:
                send({"jsonrpc": "2.0", "id": msg["id"], "error": {"code": -32603, "message": str(e)}})

if __name__ == "__main__":
    main()
