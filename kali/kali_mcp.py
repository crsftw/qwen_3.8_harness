#!/usr/bin/env python3
"""
Kali tools MCP server (stdlib only) — runs in a gVisor-ready container on the `qh-lab` bridge
(egress + DNS: reaches the internet, the lab target, and — via host NAT — the LAN 192.168.50.0/24).
Backed by the full `kali-linux-large` toolset. Exposes two kinds of tools:

  PARAMETERIZED (no free-form flags → argument-injection impossible, ANTI_PATTERNS P2):
    kali_nmap(target, top_ports?, service_scan?)
    kali_nikto(host, port?, ssl?)
    kali_gobuster(host, port?, ssl?, wordlist?)
    kali_whatweb(host, port?, ssl?)

  FREE-FORM (arbitrary command line — the whole kali-linux-large toolset):
    kali_shell(cmd, timeout?)

Containment model: containment is the HIGH-tier per-call APPROVAL GATE, not app-layer filtering and
not the network (qh-lab is a normal bridge). `kali_shell` is deliberately NOT argument-filtered — the
human operator reviews and approves every call. It still runs non-root with cap-drop=ALL on the bridge,
so L2/raw tools (responder, SYN scans, ...) are inert until that runtime is escalated. Every tool here
is HIGH tier at the gateway (human approval required per call).
"""
import json
import os
import re
import subprocess
import sys

TIMEOUT = int(os.environ.get("KALI_TIMEOUT", "300"))
MAXOUT = 200_000
HOST_RE = re.compile(r"^[A-Za-z0-9._-]+$")   # no spaces/flags/colons -> no arg injection
WORDLISTS = {
    "common": "/usr/share/wordlists/dirb/common.txt",
    "big": "/usr/share/wordlists/dirb/big.txt",
    "small": "/usr/share/wordlists/dirb/small.txt",
}
SERVER_INFO = {"name": "qwen-harness-kali", "version": "0.1.0"}

def _host(h):
    if not HOST_RE.match(h or ""):
        raise ValueError(f"invalid target {h!r} (allowed: letters, digits, . _ -)")
    return h

def _url(host, port, ssl):
    scheme = "https" if ssl else "http"
    return f"{scheme}://{_host(host)}:{int(port)}/"

def _run(argv):
    p = subprocess.run(argv, capture_output=True, text=True, timeout=TIMEOUT)
    out = (p.stdout or "")[:MAXOUT]; err = (p.stderr or "")[:MAXOUT]
    return f"$ {' '.join(argv)}\nexit={p.returncode}\n{out}" + (f"\n[stderr]\n{err}" if err.strip() else "")

# ---- tools ---------------------------------------------------------------
def tool_nmap(a):
    target = _host(a["target"])
    top = int(a.get("top_ports", 100))
    # -sT connect scan: needs no raw sockets, so the container keeps --cap-drop=ALL +
    # no-new-privileges and runs non-root. Stealth/speed of -sS is irrelevant in a lab.
    # NOTE: requires the Dockerfile's `setcap -r /usr/lib/nmap/nmap` -- Kali's nmap ships with
    # file caps (cap_net_admin=eip) that the kernel refuses to execve under cap-drop=ALL (EPERM).
    argv = ["nmap", "-Pn", "-sT"]
    if a.get("service_scan", True):
        argv.append("-sV")
    argv += ["--top-ports", str(top), target]
    return _run(argv)

def tool_nikto(a):
    url = _url(a["host"], a.get("port", 80), a.get("ssl", False))
    return _run(["nikto", "-ask", "no", "-maxtime", "120", "-h", url])

def tool_gobuster(a):
    url = _url(a["host"], a.get("port", 80), a.get("ssl", False))
    wl = WORDLISTS.get(a.get("wordlist", "common"), WORDLISTS["common"])
    return _run(["gobuster", "dir", "-q", "-u", url, "-w", wl, "-t", "20"])

def tool_whatweb(a):
    url = _url(a["host"], a.get("port", 80), a.get("ssl", False))
    return _run(["whatweb", "--color=never", url])

def tool_shell(a):
    # FREE-FORM shell over the full kali-linux-large toolset. Intentionally NOT sanitized:
    # containment is the HIGH-tier approval gate (every call is human-approved), NOT input
    # filtering — so P2's arg-injection guarantee does not apply here by design. Runs non-root
    # with cap-drop=ALL on the qh-lab bridge (L2/raw tools inert until the runtime is escalated).
    cmd = a.get("cmd")
    if not isinstance(cmd, str) or not cmd.strip():
        raise ValueError("cmd (non-empty string) is required")
    timeout = min(int(a.get("timeout", TIMEOUT)), 1800)
    p = subprocess.run(["bash", "-lc", cmd], capture_output=True, text=True, timeout=timeout)
    out = (p.stdout or "")[:MAXOUT]; err = (p.stderr or "")[:MAXOUT]
    return f"$ {cmd}\nexit={p.returncode}\n{out}" + (f"\n[stderr]\n{err}" if err.strip() else "")

TOOLS = {
    "kali_nmap":     {"impl": tool_nmap, "description": "nmap port/service scan of a lab target.",
                      "schema": {"type": "object", "properties": {"target": {"type": "string"}, "top_ports": {"type": "integer"}, "service_scan": {"type": "boolean"}}, "required": ["target"]}},
    "kali_nikto":    {"impl": tool_nikto, "description": "nikto web-server vulnerability scan.",
                      "schema": {"type": "object", "properties": {"host": {"type": "string"}, "port": {"type": "integer"}, "ssl": {"type": "boolean"}}, "required": ["host"]}},
    "kali_gobuster": {"impl": tool_gobuster, "description": "gobuster directory brute-force (dirb wordlists).",
                      "schema": {"type": "object", "properties": {"host": {"type": "string"}, "port": {"type": "integer"}, "ssl": {"type": "boolean"}, "wordlist": {"type": "string", "enum": ["common", "big", "small"]}}, "required": ["host"]}},
    "kali_whatweb":  {"impl": tool_whatweb, "description": "whatweb technology fingerprint of a web target.",
                      "schema": {"type": "object", "properties": {"host": {"type": "string"}, "port": {"type": "integer"}, "ssl": {"type": "boolean"}}, "required": ["host"]}},
    "kali_shell":    {"impl": tool_shell, "description": "Run an ARBITRARY shell command in the Kali container (full kali-linux-large toolset). Free-form, no sanitization; HIGH tier — every call requires human approval.",
                      "schema": {"type": "object", "properties": {"cmd": {"type": "string", "description": "Shell command line to execute via bash -lc."}, "timeout": {"type": "integer", "description": "Optional timeout in seconds (default 300, max 1800)."}}, "required": ["cmd"]}},
}

# ---- MCP plumbing --------------------------------------------------------
def send(m): sys.stdout.write(json.dumps(m) + "\n"); sys.stdout.flush()
def reply(rid, r): send({"jsonrpc": "2.0", "id": rid, "result": r})

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
        p = msg.get("params") or {}; name = p.get("name"); args = p.get("arguments") or {}
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
