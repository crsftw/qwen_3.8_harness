#!/usr/bin/env python3
"""
Phase 0 verification: does qwen3.8:27b reliably do multi-step tool calling
through Ollama's OpenAI-compatible /v1 endpoint?

Stdlib only (no pip installs — see docs/ANTI_PATTERNS.md Pattern 7).

It exposes two trivial tools (get_time, add), asks a question that needs both,
runs the tool-call loop, and checks the model reaches the correct final answer.

Usage:
    python3 scripts/phase0_verify_tools.py [--model qwen3.8:27b] [--base http://localhost:11434]
"""
import argparse
import json
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone

# --- local tool implementations (the "real work") -------------------------
def tool_get_time(_args):
    return {"utc_iso": datetime.now(timezone.utc).replace(microsecond=0).isoformat()}

def tool_add(args):
    return {"sum": float(args["a"]) + float(args["b"])}

TOOL_IMPLS = {"get_time": tool_get_time, "add": tool_add}

TOOLS_SPEC = [
    {
        "type": "function",
        "function": {
            "name": "get_time",
            "description": "Return the current UTC time as ISO-8601.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "add",
            "description": "Add two numbers and return the sum.",
            "parameters": {
                "type": "object",
                "properties": {"a": {"type": "number"}, "b": {"type": "number"}},
                "required": ["a", "b"],
            },
        },
    },
]

def post(url, payload):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=180) as r:
        return json.loads(r.read().decode())

def run(model, base):
    url = base.rstrip("/") + "/v1/chat/completions"
    messages = [
        {"role": "system", "content": "You are a tool-using assistant. Use the provided tools to get facts; do not guess numbers."},
        {"role": "user", "content": "Add 21 and 21 using the add tool, then tell me the current UTC time using get_time. Report both results."},
    ]
    called = set()
    for turn in range(6):
        resp = post(url, {"model": model, "messages": messages, "tools": TOOLS_SPEC, "temperature": 0})
        msg = resp["choices"][0]["message"]
        # normalize: strip any reasoning-only content, keep tool_calls
        messages.append({k: v for k, v in msg.items() if k in ("role", "content", "tool_calls")})
        tool_calls = msg.get("tool_calls") or []
        if not tool_calls:
            final = (msg.get("content") or "").strip()
            print(f"\n[final answer]\n{final}\n")
            ok = ("42" in final) and called >= {"add", "get_time"}
            print(f"tools called: {sorted(called)}")
            return ok
        for tc in tool_calls:
            name = tc["function"]["name"]
            raw = tc["function"].get("arguments") or "{}"
            args = json.loads(raw) if isinstance(raw, str) else raw
            impl = TOOL_IMPLS.get(name)
            result = impl(args) if impl else {"error": f"unknown tool {name}"}
            called.add(name)
            print(f"[tool] {name}({args}) -> {result}")
            messages.append({
                "role": "tool",
                "tool_call_id": tc.get("id", name),
                "content": json.dumps(result),
            })
    print("gave up after 6 turns without a final answer", file=sys.stderr)
    return False

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="qwen3.8:27b")
    ap.add_argument("--base", default="http://localhost:11434")
    args = ap.parse_args()
    try:
        ok = run(args.model, args.base)
    except urllib.error.URLError as e:
        print(f"ERROR reaching Ollama at {args.base}: {e}", file=sys.stderr)
        sys.exit(2)
    print("\nRESULT:", "PASS ✅" if ok else "FAIL ❌")
    sys.exit(0 if ok else 1)

if __name__ == "__main__":
    main()
