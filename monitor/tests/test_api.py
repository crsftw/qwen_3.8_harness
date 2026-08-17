import base64
import pytest
from fastapi.testclient import TestClient
from fastapi import WebSocketDisconnect
from backend.config import Config
from backend.store import Store
from backend.hub import Hub
from backend.app import create_app
from backend import status as st

def _auth(u="admin", p="x"):
    return {"Authorization": "Basic "+base64.b64encode(f"{u}:{p}".encode()).decode()}

def _client(tmp_path):
    cfg = Config(events_db=str(tmp_path/"e.db"), auth_username="admin", auth_password="x")
    store = Store(cfg.events_db)
    store.upsert_session("s1","ASUS Router Pentest","s1_asus_router_pentest",1000,"/w")
    store.insert_event({"event_id":"s1:1:c1","session_id":"s1","timestamp_ms":1000,
        "event_type":"tool_call","tool":"kali_nmap","command":"nmap x","command_explained":"scan",
        "stdout":"open","stderr":"","exit_code":0,"error":None,"tier":"HIGH",
        "approval_decision":"APPROVED","external_connections":[],"security_alerts":[],
        "arguments":{"target":"x"},"raw_json":{}})
    return TestClient(create_app(cfg, store, Hub()))

def test_requires_auth(tmp_path):
    c = _client(tmp_path)
    assert c.get("/api/sessions").status_code == 401
    assert c.get("/api/sessions", headers=_auth()).status_code == 200

def test_sessions_and_events(tmp_path):
    c = _client(tmp_path)
    s = c.get("/api/sessions", headers=_auth()).json()
    assert s[0]["label"] == "s1_asus_router_pentest" and "status" in s[0]
    evs = c.get("/api/sessions/s1/events", headers=_auth()).json()
    assert evs["events"][0]["command"] == "nmap x"

def test_event_detail(tmp_path):
    c = _client(tmp_path)
    e = c.get("/api/events/s1:1:c1", headers=_auth()).json()
    assert e["tier"] == "HIGH"

def test_column_filter_wildcard(tmp_path):
    c = _client(tmp_path)
    r = c.get("/api/sessions/s1/events?f_command=nmap*", headers=_auth()).json()
    assert len(r["events"]) == 1
    r = c.get("/api/sessions/s1/events?f_command=zzz*", headers=_auth()).json()
    assert r["events"] == []

def test_status_transitions():
    assert st.compute_status(10_000, 20_000, 60, 1800, False, False) == "ACTIVE"
    assert st.compute_status(10_000, 100_000, 60, 1800, False, False) == "IDLE"
    assert st.compute_status(10_000, 10_000_000, 60, 1800, False, False) == "COMPLETED"
    assert st.compute_status(10_000, 20_000, 60, 1800, True, False) == "ERROR"

def test_static_requires_auth(tmp_path):
    c = _client(tmp_path)
    assert c.get("/static/whatever.js").status_code == 401
    assert c.get("/static/whatever.js", headers=_auth()).status_code == 404

def test_ws_replays_and_rejects_unauthenticated(tmp_path):
    c = _client(tmp_path)
    with c.websocket_connect("/ws?after_seq=0", headers=_auth()) as ws:
        msg = ws.receive_json()
        assert msg["kind"] == "event"
        assert msg["event"]["event_id"] == "s1:1:c1"
    with pytest.raises(WebSocketDisconnect):
        with c.websocket_connect("/ws?after_seq=0") as ws:
            ws.receive_json()
