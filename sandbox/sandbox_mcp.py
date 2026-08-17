#!/usr/bin/env python3
"""
Sandbox MCP server (stdlib only) — runs INSIDE a hardened, network-less,
non-root, read-only container. Exposes a shell + file tools confined to /work.

Security rationale (see docs/ANTI_PATTERNS.md):
- A FULL shell is intentional here: the container itself is the boundary
  (no network, non-root, read-only rootfs, dropped caps, ephemeral). There is
  nothing valuable inside to injure, so command-injection is moot IN HERE.
- The argv-array discipline from the guide applies to HOST-side code that
  launches this container, not to commands the model runs inside the sandbox.
- File tools refuse to escape /work (defense-in-depth; the RO rootfs already
  blocks writes elsewhere).

MCP: newline-delimited JSON-RPC 2.0 over stdin/stdout (stdio transport).
Implements: initialize, notifications/initialized, tools/list, tools/call, ping.
"""
import json
import os
import subprocess
import sys

WORK = "/work"
DEFAULT_TIMEOUT = 120
MAX_OUTPUT = 200_000  # bytes, truncate huge outputs

def _within_work(path):
    """Resolve `path` (relative to /work) and ensure it stays under /work."""
    p = path if os.path.isabs(path) else os.path.join(WORK, path)
    rp = os.path.realpath(p)
    if rp != WORK and not rp.startswith(WORK + os.sep):
        raise ValueError(f"path escapes {WORK}: {path}")
    return rp

# ---- tool implementations ------------------------------------------------
def tool_bash(args):
    command = args["command"]
    timeout = int(args.get("timeout", DEFAULT_TIMEOUT))
    proc = subprocess.run(
        ["bash", "-c", command],
        cwd=WORK, capture_output=True, text=True, timeout=timeout,
    )
    out = (proc.stdout or "")[:MAX_OUTPUT]
    err = (proc.stderr or "")[:MAX_OUTPUT]
    return f"exit={proc.returncode}\n--- stdout ---\n{out}\n--- stderr ---\n{err}"

def tool_read_file(args):
    rp = _within_work(args["path"])
    with open(rp, "r", errors="replace") as f:
        return f.read()[:MAX_OUTPUT]

def tool_write_file(args):
    rp = _within_work(args["path"])
    os.makedirs(os.path.dirname(rp), exist_ok=True)
    with open(rp, "w") as f:
        n = f.write(args["content"])
    return f"wrote {n} chars to {rp}"

def tool_list_dir(args):
    rp = _within_work(args.get("path", "."))
    entries = []
    for name in sorted(os.listdir(rp)):
        full = os.path.join(rp, name)
        kind = "d" if os.path.isdir(full) else "f"
        size = os.path.getsize(full) if os.path.isfile(full) else 0
        entries.append(f"{kind} {size:>10}  {name}")
    return "\n".join(entries) or "(empty)"

TOOLS = {
    "bash": {
        "impl": tool_bash,
        "description": "Run a bash command inside the sandbox (cwd=/work). Full shell WITH network access — DNS, internet, curl/wget, and ping all work. Use this for ping and general networked shell tasks. Non-root, ephemeral; can only write /work.",
        "schema": {
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "bash command line"},
                "timeout": {"type": "integer", "description": "seconds (default 120)"},
            },
            "required": ["command"],
        },
    },
    "read_file": {
        "impl": tool_read_file,
        "description": "Read a UTF-8 text file under /work.",
        "schema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]},
    },
    "write_file": {
        "impl": tool_write_file,
        "description": "Write text to a file under /work (creates parent dirs).",
        "schema": {
            "type": "object",
            "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
            "required": ["path", "content"],
        },
    },
    "list_dir": {
        "impl": tool_list_dir,
        "description": "List a directory under /work (default: /work root).",
        "schema": {"type": "object", "properties": {"path": {"type": "string"}}},
    },
}

SERVER_INFO = {"name": "qwen-harness-sandbox", "version": "0.1.0"}

# ---- JSON-RPC / MCP plumbing --------------------------------------------
def send(msg):
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()

def reply(req_id, result):
    send({"jsonrpc": "2.0", "id": req_id, "result": result})

def error(req_id, code, message):
    send({"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}})

def handle(msg):
    method = msg.get("method")
    req_id = msg.get("id")
    is_request = req_id is not None

    if method == "initialize":
        # Echo the client's protocol version for maximum compatibility.
        proto = (msg.get("params") or {}).get("protocolVersion", "2024-11-05")
        reply(req_id, {
            "protocolVersion": proto,
            "capabilities": {"tools": {}},
            "serverInfo": SERVER_INFO,
        })
    elif method == "notifications/initialized":
        pass  # notification, no reply
    elif method == "ping":
        if is_request:
            reply(req_id, {})
    elif method == "tools/list":
        tools = [{"name": n, "description": t["description"], "inputSchema": t["schema"]}
                 for n, t in TOOLS.items()]
        reply(req_id, {"tools": tools})
    elif method == "tools/call":
        params = msg.get("params") or {}
        name = params.get("name")
        args = params.get("arguments") or {}
        tool = TOOLS.get(name)
        if not tool:
            reply(req_id, {"content": [{"type": "text", "text": f"unknown tool: {name}"}], "isError": True})
            return
        try:
            text = tool["impl"](args)
            reply(req_id, {"content": [{"type": "text", "text": text}], "isError": False})
        except Exception as e:  # tool errors are returned, not fatal
            reply(req_id, {"content": [{"type": "text", "text": f"{type(e).__name__}: {e}"}], "isError": True})
    else:
        if is_request:
            error(req_id, -32601, f"method not found: {method}")

def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        try:
            handle(msg)
        except Exception as e:
            # never crash the server on a single bad message
            if msg.get("id") is not None:
                error(msg["id"], -32603, f"internal error: {e}")

if __name__ == "__main__":
    main()
