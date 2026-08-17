from backend.audit_index import AuditIndex

def test_match_by_tool_and_command():
    ix = AuditIndex(window_ms=5000)
    ix.add({"ts":1.0,"tool":"sandbox_bash","tier":"HIGH","decision":"APPROVED","args":{"command":"nmap x"}})
    m = ix.match("sandbox_bash", {"command":"nmap x"}, ts_ms=1000)
    assert m["tier"] == "HIGH" and m["decision"] == "APPROVED"
    # consumed: second match returns None
    assert ix.match("sandbox_bash", {"command":"nmap x"}, ts_ms=1000) is None

def test_tool_name_normalization():
    ix = AuditIndex(window_ms=5000)
    ix.add({"ts":1.0,"tool":"kali_nmap","tier":"HIGH","decision":"APPROVED","args":{"target":"192.168.50.1"}})
    assert ix.match("kali_nmap", {"target":"192.168.50.1"}, ts_ms=900)["tier"] == "HIGH"

def test_records_bounded_by_max_records():
    # count-based bound, not time-based: a backlog re-read on restart can
    # span far more than window_ms, so eviction must be by count only.
    # Override the 20000 default on the instance to keep the test fast.
    ix = AuditIndex(window_ms=60000)
    ix.MAX_RECORDS = 20
    for i in range(70):
        ix.add({"ts": float(i), "tool":"sandbox_bash","tier":"LOW",
                 "decision":"APPROVED", "args":{"command": f"cmd{i}"}})
    assert len(ix.recs) <= 20
    # the most-recently-added record is retained (recent, not oldest, kept)
    assert ix.match("sandbox_bash", {"command":"cmd69"}, ts_ms=69000)["tier"] == "LOW"

def test_used_records_dropped_on_next_add():
    ix = AuditIndex(window_ms=60000)
    ix.add({"ts":1.0,"tool":"sandbox_bash","tier":"HIGH","decision":"APPROVED","args":{"command":"a"}})
    assert ix.match("sandbox_bash", {"command":"a"}, ts_ms=1000)["tier"] == "HIGH"
    assert ix.recs[0]["used"] is True
    # adding a new record must drop the already-used one
    ix.add({"ts":2.0,"tool":"sandbox_bash","tier":"LOW","decision":"APPROVED","args":{"command":"b"}})
    assert all(not r["used"] for r in ix.recs)
    assert len(ix.recs) == 1
