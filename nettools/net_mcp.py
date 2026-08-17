#!/usr/bin/env python3
"""
Network/recon MCP server (stdlib only) — egress-enabled, LAN-blocked at the app layer.

Tools (each takes an explicit target; tools that CONNECT validate the target is public):
  net_dig(name, rtype?)        - DNS lookup (default public resolver; does not connect to target)
  net_whois(query)             - whois lookup
  net_tracepath(host)          - unprivileged path trace (no NET_RAW needed)   [validates target]
  net_openssl(host, port?)     - TLS handshake / show server cert               [validates target]
  net_nc(host, port, data?)    - TCP connect, optional send, capture banner     [validates target]

By default, connect-tools refuse private / loopback / link-local targets (protects your LAN, host,
and cloud metadata). Set ALLOW_PRIVATE=1 to permit them (e.g. an isolated lab network in Phase 6).
All commands run as argv arrays (shell=false) — host-side command-injection safe (ANTI_PATTERNS P2).
"""
import ipaddress
import json
import os
import socket
import subprocess
import sys

ALLOW_PRIVATE = os.environ.get("ALLOW_PRIVATE", "0") == "1"
TIMEOUT = 30
MAXOUT = 100_000
SERVER_INFO = {"name": "qwen-harness-nettools", "version": "0.1.0"}

def _ip_public(ip_str):
    ip = ipaddress.ip_address(ip_str)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or
                ip.is_reserved or ip.is_multicast or ip.is_unspecified)

def _assert_public_host(host):
    if ALLOW_PRIVATE:
        return
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        raise ValueError(f"cannot resolve {host}: {e}")
    for info in infos:
        if not _ip_public(info[4][0]):
            raise ValueError(f"blocked non-public target {info[4][0]} for {host} "
                             f"(set ALLOW_PRIVATE=1 for lab targets)")

def _run(argv, inp=None):
    p = subprocess.run(argv, capture_output=True, text=True, timeout=TIMEOUT, input=inp)
    out = (p.stdout or "")[:MAXOUT]
    err = (p.stderr or "")[:MAXOUT]
    return f"exit={p.returncode}\n{out}" + (f"\n[stderr]\n{err}" if err.strip() else "")

# ---- tools ---------------------------------------------------------------
def tool_dig(a):
    name = a["name"]; rtype = a.get("rtype", "A")
    return _run(["dig", "+noall", "+answer", name, rtype])

def tool_whois(a):
    return _run(["whois", a["query"]])

def tool_tracepath(a):
    host = a["host"]; _assert_public_host(host)
    return _run(["tracepath", "-n", host])

def tool_openssl(a):
    host = a["host"]; port = int(a.get("port", 443)); _assert_public_host(host)
    return _run(["openssl", "s_client", "-connect", f"{host}:{port}",
                 "-servername", host, "-brief"], inp="")

def tool_nc(a):
    host = a["host"]; port = int(a["port"]); _assert_public_host(host)
    data = a.get("data", "")
    return _run(["nc", "-w", "5", host, str(port)], inp=(data + "\n") if data else "")

TOOLS = {
    "net_dig":       {"impl": tool_dig, "description": "DNS lookup (dig).",
                      "schema": {"type": "object", "properties": {"name": {"type": "string"}, "rtype": {"type": "string"}}, "required": ["name"]}},
    "net_whois":     {"impl": tool_whois, "description": "whois lookup for a domain/IP.",
                      "schema": {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]}},
    "net_tracepath": {"impl": tool_tracepath, "description": "Trace network path to a public host (unprivileged).",
                      "schema": {"type": "object", "properties": {"host": {"type": "string"}}, "required": ["host"]}},
    "net_openssl":   {"impl": tool_openssl, "description": "TLS handshake / inspect a public server's certificate.",
                      "schema": {"type": "object", "properties": {"host": {"type": "string"}, "port": {"type": "integer"}}, "required": ["host"]}},
    "net_nc":        {"impl": tool_nc, "description": "TCP connect to host:port (public), optional send data, capture banner.",
                      "schema": {"type": "object", "properties": {"host": {"type": "string"}, "port": {"type": "integer"}, "data": {"type": "string"}}, "required": ["host", "port"]}},
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
