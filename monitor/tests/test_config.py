import os, textwrap, pytest
from backend import config

def _write(tmp_path, body):
    p = tmp_path / "c.yaml"; p.write_text(textwrap.dedent(body)); return str(p)

def test_load_expands_paths_and_types(tmp_path):
    p = _write(tmp_path, """
        bind_host: 127.0.0.1
        bind_port: 9000
        basic_auth: {username: u, password: pw}
        sources: {sessions_db: ~/x.db, audit_log: /tmp/a.log}
        events_db: ./e.db
        poll_interval_ms: 250
        status: {active_window_s: 30, idle_window_s: 600}
        retention: {max_age_days: 7, max_events: 100}
        redaction: {enabled: false}
        llm_explain: {enabled: true}
    """)
    c = config.load(p)
    assert c.bind_port == 9000
    assert c.auth_username == "u" and c.auth_password == "pw"
    assert c.sessions_db == os.path.expanduser("~/x.db")
    assert c.active_window_s == 30 and c.idle_window_s == 600
    assert c.redaction_enabled is False and c.llm_explain_enabled is True

def test_empty_password_refused(tmp_path):
    p = _write(tmp_path, """
        basic_auth: {username: u, password: ""}
        sources: {sessions_db: ~/x.db, audit_log: /tmp/a.log}
    """)
    with pytest.raises(config.ConfigError):
        config.load(p)
