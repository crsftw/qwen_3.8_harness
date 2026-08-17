import calendar, time
from backend.store import Store

def _ev(eid, sid, seqless=True, **kw):
    # Recent by default (not epoch=1) -- prune() now does age-based deletion
    # too, and callers that don't care about age shouldn't accidentally have
    # their fixture events swept by it.
    e = {"event_id":eid,"session_id":sid,"timestamp_ms":int(time.time()*1000),"event_type":"tool_call",
         "tool":"sandbox_bash","command":"nmap -sV 192.168.50.1","command_explained":"scan",
         "stdout":"open","stderr":"","exit_code":0,"http_status":None,"error":None,
         "tier":"HIGH","approval_decision":"APPROVED","external_connections":[],
         "security_alerts":[],"arguments":{"command":"x"},"raw_json":{"a":1},"extension":"gateway"}
    e.update(kw); return e

def test_insert_and_seq_monotonic(tmp_path):
    s = Store(str(tmp_path/"e.db"))
    a = s.insert_event(_ev("e1","s1"))
    b = s.insert_event(_ev("e2","s1"))
    assert b > a
    assert s.max_seq() == b

def test_idempotent_on_event_id(tmp_path):
    s = Store(str(tmp_path/"e.db"))
    s.insert_event(_ev("dup","s1")); s.insert_event(_ev("dup","s1"))
    assert len(s.query_events(session_id="s1")) == 1

def test_events_after(tmp_path):
    s = Store(str(tmp_path/"e.db"))
    s.insert_event(_ev("e1","s1")); mid=s.max_seq(); s.insert_event(_ev("e2","s1"))
    got = s.events_after(mid, 10)
    assert [e["event_id"] for e in got] == ["e2"]

def test_percolumn_wildcard_filter(tmp_path):
    s = Store(str(tmp_path/"e.db"))
    s.insert_event(_ev("e1","s1", command="nmap -sV 192.168.50.1"))
    s.insert_event(_ev("e2","s1", command="curl https://example.com"))
    got = s.query_events(session_id="s1", filters={"command":"nmap*"})
    assert [e["event_id"] for e in got] == ["e1"]
    got = s.query_events(session_id="s1", filters={"command":"*example*"})
    assert [e["event_id"] for e in got] == ["e2"]

def test_prune_by_max_events(tmp_path):
    s = Store(str(tmp_path/"e.db"))
    for i in range(5): s.insert_event(_ev(f"e{i}","s1"))
    removed = s.prune(max_age_days=3650, max_events=2)
    assert removed == 3 and len(s.query_events(session_id="s1")) == 2

def test_prune_by_max_age_days(tmp_path):
    s = Store(str(tmp_path/"e.db"))
    s.insert_event(_ev("old","s1", timestamp_ms=1000))
    recent_ts = int(time.time()*1000)
    s.insert_event(_ev("recent","s1", timestamp_ms=recent_ts))
    removed = s.prune(max_age_days=1, max_events=10_000)
    assert removed == 1
    ids = [e["event_id"] for e in s.query_events(session_id="s1")]
    assert ids == ["recent"]

def test_date_filter_matches_formatted_timestamp(tmp_path):
    s = Store(str(tmp_path/"e.db"))
    ts_ms = calendar.timegm((2026,8,17,12,0,0,0,0,0)) * 1000
    s.insert_event(_ev("e1","s1", timestamp_ms=ts_ms))
    got = s.query_events(session_id="s1", filters={"date":"2026-08-17*"})
    assert [e["event_id"] for e in got] == ["e1"]
    got = s.query_events(session_id="s1", filters={"date":"1999-*"})
    assert got == []

def test_insert_event_creates_session_row(tmp_path):
    s = Store(str(tmp_path/"e.db"))
    s.insert_event(_ev("e1","s1"))
    sessions = {r["id"]: r for r in s.list_sessions()}
    assert "s1" in sessions
    assert sessions["s1"]["event_count"] == 1

def test_duplicate_event_id_does_not_double_count_session(tmp_path):
    s = Store(str(tmp_path/"e.db"))
    s.insert_event(_ev("dup","s1"))
    s.insert_event(_ev("dup","s1"))
    sessions = {r["id"]: r for r in s.list_sessions()}
    assert sessions["s1"]["event_count"] == 1
