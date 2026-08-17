#!/usr/bin/env python3
"""
Policy / Approval Gateway — an MCP proxy (stdlib only).

  Goose  ──MCP──▶  gateway  ──MCP──▶  downstream tool servers (sandbox, later kali/web/...)

Responsibilities:
  * Aggregate downstream tools, re-expose them prefixed as `<server>_<tool>`.
  * Enforce a per-tool trust tier (LOW/MEDIUM/HIGH) from policy.json.
      LOW/MEDIUM -> run (logged). HIGH -> require human approval (fail-closed).
  * Write a redacted JSONL audit log of every call, decision, and outcome.

Approval modes (env GATEWAY_APPROVAL):
  queue (default) : write state/pending/<id>.json, block until approve.py decides (or timeout->deny)
  tty             : prompt on /dev/tty
  auto_approve    : TEST ONLY — approve everything (logged loudly)
  auto_deny       : TEST ONLY — deny everything
"""
import json
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
POLICY_PATH = os.environ.get("GATEWAY_POLICY", os.path.join(HERE, "policy.json"))
STATE_DIR = os.environ.get("GATEWAY_STATE", os.path.join(HERE, "state"))
AUDIT_PATH = os.path.join(STATE_DIR, "audit.log")
PENDING_DIR = os.path.join(STATE_DIR, "pending")
DECIDED_DIR = os.path.join(STATE_DIR, "decided")
APPROVAL_MODE = os.environ.get("GATEWAY_APPROVAL", "queue")
APPROVAL_TIMEOUT = int(os.environ.get("GATEWAY_APPROVAL_TIMEOUT", "120"))
SERVER_INFO = {"name": "qwen-harness-gateway", "version": "0.1.0"}

for d in (STATE_DIR, PENDING_DIR, DECIDED_DIR):
    os.makedirs(d, exist_ok=True)

# ---- logging to stderr (shows up in Goose logs; never to stdout=MCP channel) ----
def log(*a):
    print("[gateway]", *a, file=sys.stderr, flush=True)

# ---- secret redaction (ANTI_PATTERNS P1) ---------------------------------
SENSITIVE_KEY = re.compile(r"(pass|secret|token|key|auth|cred)", re.I)
SECRET_PATTERNS = [
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]+"),
    re.compile(r"(?i)(sk|pk|rk)_(live|test)_[A-Za-z0-9]+"),
    re.compile(r"(?i)(ghp|gho|github_pat)_[A-Za-z0-9_]+"),
    re.compile(r"AKIA[0-9A-Z]{12,}"),
    re.compile(r"(?i)(api[_-]?key|password|token)\s*[=:]\s*\S+"),
]

def _mask_str(s):
    for pat in SECRET_PATTERNS:
        s = pat.sub("[REDACTED]", s)
    return s

def redact(args):
    out = {}
    for k, v in (args or {}).items():
        if SENSITIVE_KEY.search(k):
            out[k] = "[REDACTED]"
        elif isinstance(v, str):
            out[k] = _mask_str(v)
        else:
            out[k] = v
    return out

def audit(entry):
    entry = {"ts": round(time.time(), 3), **entry}
    with open(AUDIT_PATH, "a") as f:
        f.write(json.dumps(entry) + "\n")

# ---- downstream MCP client ------------------------------------------------
class Downstream:
    def __init__(self, name, cmd):
        self.name = name
        self.cmd = cmd
        self.reqid = 0
        self.proc = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=sys.stderr, text=True, bufsize=1,
        )

    def _send(self, msg):
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()

    def request(self, method, params=None):
        self.reqid += 1
        rid = self.reqid
        self._send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}})
        while True:
            line = self.proc.stdout.readline()
            if not line:
                raise RuntimeError(f"downstream '{self.name}' closed the connection")
            line = line.strip()
            if not line:
                continue
            m = json.loads(line)
            if m.get("id") == rid:
                return m
            # ignore any downstream notifications

    def notify(self, method, params=None):
        self._send({"jsonrpc": "2.0", "method": method, "params": params or {}})

    def initialize(self):
        self.request("initialize", {"protocolVersion": "2024-11-05", "capabilities": {},
                                     "clientInfo": {"name": "gateway", "version": "0.1.0"}})
        self.notify("notifications/initialized")

    def list_tools(self):
        return (self.request("tools/list").get("result") or {}).get("tools", [])

    def close(self):
        """Close stdin so `docker run --rm` tears the container down; force-kill as last resort."""
        try: self.proc.stdin.close()
        except Exception: pass
        try: self.proc.wait(timeout=8)
        except Exception:
            try: self.proc.kill()
            except Exception: pass

# ---- registry: enumerate downstream tools ONCE (ephemeral), then run each call
# in its OWN short-lived container. Nothing long-lived is held, so containers never
# leak even though Goose keeps the gateway process alive across a session.
POLICY = json.load(open(POLICY_PATH))
TIER_ACTIONS = POLICY.get("tier_actions", {"LOW": "auto", "MEDIUM": "auto", "HIGH": "approve"})
SERVERS = POLICY["servers"]          # name -> {cmd, default_tier, tools}
# Portable paths: policy.json references tool servers via ${QH_ROOT} (the repo
# root). Default it to this repo's location so a fresh clone runs without edits;
# override by exporting QH_ROOT. Expand it in every server command.
os.environ.setdefault("QH_ROOT", os.path.dirname(HERE))
for _s in SERVERS.values():
    _s["cmd"] = [os.path.expandvars(a) for a in _s.get("cmd", [])]
REGISTRY = {}                        # exposed_name -> {"ds","tool","tier","schema","description"}

def build_registry():
    for sname, scfg in SERVERS.items():
        ds = Downstream(sname, scfg["cmd"])
        try:
            ds.initialize()
            tools = ds.list_tools()
        finally:
            ds.close()               # ephemeral: enumeration container is gone immediately
        default_tier = scfg.get("default_tier", "MEDIUM")
        tier_map = scfg.get("tools", {})
        for t in tools:
            tool = t["name"]
            tier = tier_map.get(tool, default_tier)
            # avoid double-prefix when tools are already named after their server (net_dig, web_search)
            exposed = tool if tool.startswith(sname + "_") else f"{sname}_{tool}"
            REGISTRY[exposed] = {
                "ds": sname, "tool": tool, "tier": tier,
                "schema": t.get("inputSchema", {"type": "object"}),
                "description": f"[{tier}] {t.get('description','')}",
            }
        log(f"loaded server '{sname}': {list(tier_map) or 'defaults'}")
    log(f"exposing {len(REGISTRY)} tools: {sorted(REGISTRY)}")

_REGISTRY_READY = False
def ensure_registry():
    """Build the registry lazily so `initialize` is answered instantly (before spawning
    any downstream containers) — avoids Goose's handshake timeout as servers grow."""
    global _REGISTRY_READY
    if not _REGISTRY_READY:
        build_registry()
        _REGISTRY_READY = True

# ---- approval -------------------------------------------------------------
def approve(call_id, exposed, args):
    detail = {"id": call_id, "tool": exposed, "args": redact(args)}
    if APPROVAL_MODE == "auto_approve":
        log(f"AUTO-APPROVE (test mode) {exposed} #{call_id}")
        return True, "auto_approve"
    if APPROVAL_MODE == "auto_deny":
        return False, "auto_deny"
    if APPROVAL_MODE == "tty":
        try:
            with open("/dev/tty", "r+") as tty:
                tty.write(f"\n[APPROVAL] HIGH-risk call {exposed} #{call_id}\n  args: {json.dumps(detail['args'])}\n  approve? [y/N] ")
                tty.flush()
                ans = tty.readline().strip().lower()
                return (ans in ("y", "yes")), f"tty:{ans or 'empty'}"
        except OSError:
            log("no /dev/tty; falling back to queue")
    # queue mode (default)
    pend = os.path.join(PENDING_DIR, f"{call_id}.json")
    with open(pend, "w") as f:
        json.dump(detail, f)
    log(f"APPROVAL REQUIRED for {exposed} #{call_id} — run: python3 gateway/approve.py {call_id} yes|no")
    deadline = time.time() + APPROVAL_TIMEOUT
    decided = os.path.join(DECIDED_DIR, f"{call_id}.json")
    while time.time() < deadline:
        if os.path.exists(decided):
            d = json.load(open(decided))
            try: os.remove(pend)
            except OSError: pass
            return bool(d.get("approved")), f"human:{d.get('by','?')}:{d.get('reason','')}"
        time.sleep(0.5)
    try: os.remove(pend)
    except OSError: pass
    return False, "timeout"   # fail closed

# ---- MCP server side (to Goose) ------------------------------------------
def send(msg):
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()

def reply(rid, result):
    send({"jsonrpc": "2.0", "id": rid, "result": result})

def tool_result(text, is_error=False):
    return {"content": [{"type": "text", "text": text}], "isError": is_error}

def handle_call(rid, params):
    exposed = params.get("name")
    args = params.get("arguments") or {}
    reg = REGISTRY.get(exposed)
    if not reg:
        reply(rid, tool_result(f"unknown tool: {exposed}", True)); return
    tier = reg["tier"]
    action = TIER_ACTIONS.get(tier, "approve")
    call_id = f"{int(time.time()*1000)}"

    if action == "approve":
        ok, reason = approve(call_id, exposed, args)
        if not ok:
            audit({"tool": exposed, "tier": tier, "decision": "DENIED", "reason": reason, "args": redact(args)})
            reply(rid, tool_result(f"DENIED by policy ({tier}): {reason}", True)); return
        decision = f"APPROVED:{reason}"
    else:
        decision = "AUTO"

    # forward to a fresh, ephemeral downstream container for this one call
    ds = Downstream(reg["ds"], SERVERS[reg["ds"]]["cmd"])
    try:
        ds.initialize()
        res = ds.request("tools/call", {"name": reg["tool"], "arguments": args}).get("result", {})
    except Exception as e:
        audit({"tool": exposed, "tier": tier, "decision": decision, "outcome": "ERROR", "error": str(e), "args": redact(args)})
        reply(rid, tool_result(f"downstream error: {e}", True)); return
    finally:
        ds.close()

    is_err = bool(res.get("isError"))
    audit({"tool": exposed, "tier": tier, "decision": decision,
           "outcome": "isError" if is_err else "ok", "args": redact(args)})
    reply(rid, res)

def handle(msg):
    method = msg.get("method")
    rid = msg.get("id")
    if method == "initialize":
        proto = (msg.get("params") or {}).get("protocolVersion", "2024-11-05")
        reply(rid, {"protocolVersion": proto, "capabilities": {"tools": {}}, "serverInfo": SERVER_INFO})
    elif method == "notifications/initialized":
        pass
    elif method == "ping":
        if rid is not None: reply(rid, {})
    elif method == "tools/list":
        ensure_registry()
        tools = [{"name": n, "description": r["description"], "inputSchema": r["schema"]}
                 for n, r in REGISTRY.items()]
        reply(rid, {"tools": tools})
    elif method == "tools/call":
        ensure_registry()
        handle_call(rid, msg.get("params") or {})
    else:
        if rid is not None:
            send({"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": f"method not found: {method}"}})

def main():
    log(f"approval mode = {APPROVAL_MODE}; audit -> {AUDIT_PATH} (registry builds lazily on first tools/list)")
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
            log(f"handler error: {e}")
            if msg.get("id") is not None:
                send({"jsonrpc": "2.0", "id": msg["id"], "error": {"code": -32603, "message": str(e)}})

if __name__ == "__main__":
    main()
