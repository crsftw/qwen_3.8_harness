import json, sqlite3, time, calendar, os
from backend.sources.sessions_db import SessionsReader
from backend.sources.audit_log import AuditTailer

def _make_goose_db(path):
    db = sqlite3.connect(path)
    db.execute("CREATE TABLE sessions(id TEXT PRIMARY KEY, name TEXT, working_dir TEXT, created_at TIMESTAMP)")
    db.execute("""CREATE TABLE messages(id INTEGER PRIMARY KEY AUTOINCREMENT, message_id TEXT,
                 session_id TEXT, role TEXT, content_json TEXT, created_timestamp INTEGER)""")
    db.execute("INSERT INTO sessions VALUES('s1','ASUS Router Pentest','/w','2026-08-16 23:19:25')")
    db.execute("INSERT INTO messages(session_id,role,content_json,created_timestamp) VALUES('s1','user',?,1)",
               (json.dumps([{"type":"text","text":"hi"}]),))
    db.commit(); db.close()

def test_sessions_reader_reads_new(tmp_path):
    p = str(tmp_path/"g.db"); _make_goose_db(p)
    r = SessionsReader(p)
    sessions, msgs = r.read_new(after_message_id=0)
    assert sessions[0]["name"] == "ASUS Router Pentest"
    assert msgs[0]["session_id"] == "s1" and msgs[0]["id"] == 1
    # second read after id=1 returns nothing new
    _, msgs2 = r.read_new(after_message_id=1)
    assert msgs2 == []

def test_sessions_reader_normalizes_timestamps(tmp_path):
    p = str(tmp_path/"g2.db")
    db = sqlite3.connect(p)
    db.execute("CREATE TABLE sessions(id TEXT PRIMARY KEY, name TEXT, working_dir TEXT, created_at TIMESTAMP)")
    db.execute("""CREATE TABLE messages(id INTEGER PRIMARY KEY AUTOINCREMENT, message_id TEXT,
                 session_id TEXT, role TEXT, content_json TEXT, created_timestamp INTEGER)""")
    db.execute("INSERT INTO sessions VALUES('s1','ASUS Router Pentest','/w','2026-08-16 23:19:25')")
    # 10-digit epoch seconds -> must be normalized to ms (x1000)
    db.execute("INSERT INTO messages(session_id,role,content_json,created_timestamp) VALUES('s1','user',?,1786958049)",
               (json.dumps([{"type":"text","text":"seconds"}]),))
    # 13-digit already-ms value -> must pass through unchanged
    db.execute("INSERT INTO messages(session_id,role,content_json,created_timestamp) VALUES('s1','user',?,1786958049000)",
               (json.dumps([{"type":"text","text":"millis"}]),))
    db.commit(); db.close()

    r = SessionsReader(p)
    sessions, msgs = r.read_new(after_message_id=0)

    seconds_row = next(m for m in msgs if "seconds" in m["content_json"])
    millis_row = next(m for m in msgs if "millis" in m["content_json"])
    assert seconds_row["created_timestamp"] == 1786958049000
    assert millis_row["created_timestamp"] == 1786958049000

    expected_ms = calendar.timegm(time.strptime("2026-08-16 23:19:25", "%Y-%m-%d %H:%M:%S")) * 1000
    assert sessions[0]["created_ms"] == expected_ms

def test_audit_tailer_incremental(tmp_path):
    p = tmp_path/"audit.log"
    p.write_text(json.dumps({"ts":1,"tool":"sandbox_bash","tier":"HIGH","decision":"APPROVED","outcome":"ok","args":{"command":"x"}})+"\n")
    t = AuditTailer(str(p))
    first = t.read_new()
    assert len(first) == 1 and first[0]["tier"] == "HIGH"
    assert t.read_new() == []                       # nothing new
    with open(p,"a") as f: f.write(json.dumps({"ts":2,"tool":"kali_nmap","tier":"HIGH","decision":"APPROVED","outcome":"ok","args":{}})+"\n")
    more = t.read_new()
    assert len(more) == 1 and more[0]["tool"] == "kali_nmap"

def test_audit_tailer_resets_offset_on_truncation(tmp_path):
    p = tmp_path/"audit2.log"
    p.write_text(json.dumps({"ts":1,"tool":"sandbox_bash","tier":"HIGH","decision":"APPROVED","outcome":"ok","args":{}})+"\n")
    t = AuditTailer(str(p))
    first = t.read_new()
    assert len(first) == 1 and first[0]["tool"] == "sandbox_bash"
    assert t.read_new() == []                       # fully consumed, offset at EOF

    # truncate the file (same inode, smaller size) and write a single new, shorter line
    with open(p, "w") as f:
        f.write(json.dumps({"ts":3,"tool":"short","tier":"LOW","decision":"APPROVED","outcome":"ok","args":{}})+"\n")

    after_truncate = t.read_new()
    assert len(after_truncate) == 1 and after_truncate[0]["tool"] == "short"

def test_audit_tailer_resets_offset_on_inode_change(tmp_path):
    p = tmp_path/"audit3.log"
    p.write_text(json.dumps({"ts":1,"tool":"first_file","tier":"HIGH","decision":"APPROVED","outcome":"ok","args":{}})+"\n")
    t = AuditTailer(str(p))
    first = t.read_new()
    assert len(first) == 1 and first[0]["tool"] == "first_file"

    # simulate realistic log rotation: rename the old file aside (its inode stays
    # allocated under the new name) then create a fresh file at the original path.
    # This guarantees a genuinely new inode, unlike remove+recreate which can have
    # the freed inode number reused immediately by some filesystems.
    rotated_aside = tmp_path/"audit3.log.1"
    os.rename(p, rotated_aside)
    p.write_text(json.dumps({"ts":2,"tool":"rotated_file","tier":"HIGH","decision":"APPROVED","outcome":"ok","args":{}})+"\n")
    assert os.stat(p).st_ino != os.stat(rotated_aside).st_ino  # sanity: genuinely new inode

    after_rotate = t.read_new()
    assert len(after_rotate) == 1 and after_rotate[0]["tool"] == "rotated_file"
