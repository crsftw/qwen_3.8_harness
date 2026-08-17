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

def _goose_db_blocked(path):
    db = sqlite3.connect(path)
    db.execute("CREATE TABLE sessions(id TEXT PRIMARY KEY,name TEXT,working_dir TEXT,created_at TIMESTAMP)")
    db.execute("CREATE TABLE messages(id INTEGER PRIMARY KEY AUTOINCREMENT,message_id TEXT,session_id TEXT,role TEXT,content_json TEXT,created_timestamp INTEGER)")
    db.execute("INSERT INTO sessions VALUES('s1','ASUS Router Pentest','/w','2026-08-16 23:19:25')")
    req=[{"type":"toolRequest","id":"c1","toolCall":{"value":{"name":"sandbox_bash","arguments":{"command":"cat /etc/shadow"}}},"_meta":{"goose_extension":"gateway"}}]
    # response is NOT itself an error (exit_code 0, isError False) -- the block
    # only shows up via the audit-log decision, which the collector must surface
    resp=[{"type":"toolResponse","id":"c1","toolResult":{"value":{"structuredContent":{"stdout":"","stderr":"","exit_code":0},"isError":False}}}]
    db.execute("INSERT INTO messages(session_id,role,content_json,created_timestamp) VALUES('s1','assistant',?,1000)",(json.dumps(req),))
    db.execute("INSERT INTO messages(session_id,role,content_json,created_timestamp) VALUES('s1','user',?,1001)",(json.dumps(resp),))
    db.commit(); db.close()

def test_collector_flags_blocked_decision_as_error(tmp_path):
    gpath=str(tmp_path/"g.db"); _goose_db_blocked(gpath)
    apath=tmp_path/"audit.log"
    apath.write_text(json.dumps({"ts":1000.0,"tool":"sandbox_bash","tier":"HIGH","decision":"DENIED:policy","outcome":"blocked","args":{"command":"cat /etc/shadow"}})+"\n")
    cfg=Config(sessions_db=gpath, audit_log=str(apath), events_db=str(tmp_path/"e.db"), auth_password="x")
    store=Store(cfg.events_db); hub=Hub()
    col=Collector(cfg, store, hub)
    col.poll_once()
    evs=store.query_events(session_id="s1")
    tool_ev=[e for e in evs if e["event_type"]=="tool_call"][0]
    assert tool_ev["error"] == "Tool call blocked"
    assert tool_ev["approval_decision"].startswith("DENIED")

def _goose_db_two_self_contained_calls(path, bad_command, good_command):
    # Each row carries BOTH the toolRequest and its toolResponse in the same
    # content_json list, so the pairing is self-contained per-row and doesn't
    # depend on a neighboring row -- lets us force one row to fail downstream
    # without corrupting MessageState's pending-request bookkeeping for the
    # other row.
    db = sqlite3.connect(path)
    db.execute("CREATE TABLE sessions(id TEXT PRIMARY KEY,name TEXT,working_dir TEXT,created_at TIMESTAMP)")
    db.execute("CREATE TABLE messages(id INTEGER PRIMARY KEY AUTOINCREMENT,message_id TEXT,session_id TEXT,role TEXT,content_json TEXT,created_timestamp INTEGER)")
    db.execute("INSERT INTO sessions VALUES('s1','Mixed Batch','/w','2026-08-16 23:19:25')")
    def _combined(cid, command):
        return [
            {"type":"toolRequest","id":cid,"toolCall":{"value":{"name":"sandbox_bash","arguments":{"command":command}}},"_meta":{"goose_extension":"gateway"}},
            {"type":"toolResponse","id":cid,"toolResult":{"value":{"structuredContent":{"stdout":"ok","stderr":"","exit_code":0},"isError":False}}},
        ]
    db.execute("INSERT INTO messages(session_id,role,content_json,created_timestamp) VALUES('s1','assistant',?,1000)",
               (json.dumps(_combined("bad1", bad_command)),))
    db.execute("INSERT INTO messages(session_id,role,content_json,created_timestamp) VALUES('s1','assistant',?,1001)",
               (json.dumps(_combined("good1", good_command)),))
    db.commit(); db.close()

def test_collector_poll_once_survives_one_bad_row_and_advances_cursor(tmp_path):
    gpath=str(tmp_path/"g.db")
    _goose_db_two_self_contained_calls(gpath, bad_command="boom trigger", good_command="echo good")
    apath=tmp_path/"audit.log"; apath.write_text("")
    cfg=Config(sessions_db=gpath, audit_log=str(apath), events_db=str(tmp_path/"e.db"), auth_password="x")
    store=Store(cfg.events_db); hub=Hub()
    col=Collector(cfg, store, hub)

    # Force a downstream (store) failure for the first row's event only,
    # simulating an unpredictable per-message crash (bad data, db constraint,
    # detection bug, etc). The second row must still be processed and stored.
    real_insert = store.insert_event
    def guarded_insert(ev):
        if ev.get("command") == "boom trigger":
            raise RuntimeError("simulated downstream failure")
        return real_insert(ev)
    store.insert_event = guarded_insert

    col.poll_once()  # must not raise

    evs = store.query_events(session_id="s1")
    tool_evs = [e for e in evs if e["event_type"] == "tool_call"]
    assert len(tool_evs) == 1
    assert tool_evs[0]["command"] == "echo good"
    # cursor advanced past BOTH rows (including the one that errored), so the
    # permanently-malformed row is never retried forever
    assert store.get_cursor("messages") == 2
    assert col.error_count == 1

def test_collector_poll_once_ingests_and_correlates(tmp_path):
    gpath=str(tmp_path/"g.db"); _goose_db(gpath)
    apath=tmp_path/"audit.log"
    apath.write_text(json.dumps({"ts":1000.0,"tool":"sandbox_bash","tier":"HIGH","decision":"APPROVED:auto","outcome":"ok","args":{"command":"nmap x"}})+"\n")
    cfg=Config(sessions_db=gpath, audit_log=str(apath), events_db=str(tmp_path/"e.db"), auth_password="x")
    store=Store(cfg.events_db); hub=Hub()
    col=Collector(cfg, store, hub)
    col.poll_once()
    evs=store.query_events(session_id="s1")
    tool_ev=[e for e in evs if e["event_type"]=="tool_call"][0]
    assert tool_ev["tier"]=="HIGH" and tool_ev["command"]=="nmap x"
    sess=store.list_sessions()[0]
    assert sess["label"].startswith("s1_asus_router")
