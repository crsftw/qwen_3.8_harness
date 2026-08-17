#!/usr/bin/env python3
"""Approve/deny pending HIGH-risk gateway calls.

Usage:
  python3 gateway/approve.py                 # list pending requests
  python3 gateway/approve.py <id> yes|no [reason]
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
STATE = os.environ.get("GATEWAY_STATE", os.path.join(HERE, "state"))
PENDING = os.path.join(STATE, "pending")
DECIDED = os.path.join(STATE, "decided")
os.makedirs(DECIDED, exist_ok=True)

def list_pending():
    items = sorted(os.listdir(PENDING)) if os.path.isdir(PENDING) else []
    if not items:
        print("(no pending approvals)"); return
    print("Pending approvals:")
    for fn in items:
        d = json.load(open(os.path.join(PENDING, fn)))
        print(f"  id={d['id']}  tool={d['tool']}  args={json.dumps(d['args'])}")

def decide(call_id, yes, reason):
    out = {"id": call_id, "approved": yes, "by": os.environ.get("USER", "user"), "reason": reason}
    with open(os.path.join(DECIDED, f"{call_id}.json"), "w") as f:
        json.dump(out, f)
    print(f"recorded: {call_id} -> {'APPROVED' if yes else 'DENIED'} ({reason})")

if __name__ == "__main__":
    if len(sys.argv) == 1:
        list_pending()
    else:
        cid = sys.argv[1]
        yes = len(sys.argv) > 2 and sys.argv[2].lower() in ("y", "yes", "approve", "1")
        reason = " ".join(sys.argv[3:]) if len(sys.argv) > 3 else ""
        decide(cid, yes, reason)
