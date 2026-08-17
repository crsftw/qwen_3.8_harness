from backend.config import Config
from backend.store import Store
from backend.hub import Hub
from backend.collector import Collector
from tests import feeder


def _run(tmp_path):
    g = str(tmp_path / "g.db")
    a = str(tmp_path / "audit.log")
    feeder.populate(g, a)
    cfg = Config(sessions_db=g, audit_log=a, events_db=str(tmp_path / "e.db"), auth_password="x")
    store = Store(cfg.events_db)
    Collector(cfg, store, Hub()).poll_once()
    return store.query_events(session_id=feeder.SESSION_ID, limit=1000)


def test_reverse_shell_end_to_end(tmp_path):
    evs = _run(tmp_path)
    assert evs

    alerted = [e for e in evs if e["security_alerts"]]
    assert alerted, "expected at least one event with a security alert"
    alert = alerted[0]["security_alerts"][0]
    assert alert["severity"] in ("HIGH", "CRITICAL")
    assert alert["destination"] == "10.0.0.5:4444"

    assert any(e["error"] == "exit code: 1" for e in evs)


def test_external_curl_classified_referenced(tmp_path):
    evs = _run(tmp_path)
    curl_events = [e for e in evs if e.get("command") == "curl https://example.com"]
    assert curl_events
    conns = curl_events[0]["external_connections"]
    assert conns
    assert conns[0]["classification"] == "EXTERNAL"
    assert conns[0]["source"] == "referenced"


def test_large_response_len(tmp_path):
    evs = _run(tmp_path)
    big = [e for e in evs if e.get("command") == "cat bigfile.txt"]
    assert big
    assert len(big[0]["stdout"] or "") == feeder.BIG_RESPONSE_LEN
