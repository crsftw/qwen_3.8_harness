import os
from dataclasses import dataclass
import yaml

class ConfigError(Exception): ...

@dataclass
class Config:
    bind_host: str = "0.0.0.0"
    bind_port: int = 8787
    auth_username: str = "admin"
    auth_password: str = ""
    sessions_db: str = "~/.local/share/goose/sessions/sessions.db"
    audit_log: str = "../gateway/state/audit.log"
    events_db: str = "./events.db"
    poll_interval_ms: int = 500
    active_window_s: int = 60
    idle_window_s: int = 1800
    retention_max_age_days: int = 30
    retention_max_events: int = 500000
    redaction_enabled: bool = True
    llm_explain_enabled: bool = False

def _abs(p): return os.path.abspath(os.path.expanduser(p))

def load(path=None):
    path = path or os.environ.get("MONITOR_CONFIG", "config.yaml")
    with open(path) as f:
        d = yaml.safe_load(f) or {}
    auth = d.get("basic_auth", {})
    src = d.get("sources", {})
    st = d.get("status", {})
    ret = d.get("retention", {})
    c = Config(
        bind_host=d.get("bind_host", "0.0.0.0"),
        bind_port=int(d.get("bind_port", 8787)),
        auth_username=auth.get("username", "admin"),
        auth_password=str(auth.get("password", "")),
        sessions_db=_abs(src.get("sessions_db", Config.sessions_db)),
        audit_log=_abs(src.get("audit_log", Config.audit_log)),
        events_db=_abs(d.get("events_db", "./events.db")),
        poll_interval_ms=int(d.get("poll_interval_ms", 500)),
        active_window_s=int(st.get("active_window_s", 60)),
        idle_window_s=int(st.get("idle_window_s", 1800)),
        retention_max_age_days=int(ret.get("max_age_days", 30)),
        retention_max_events=int(ret.get("max_events", 500000)),
        redaction_enabled=bool(d.get("redaction", {}).get("enabled", True)),
        llm_explain_enabled=bool(d.get("llm_explain", {}).get("enabled", False)),
    )
    if os.environ.get("MONITOR_PASSWORD"):
        c.auth_password = os.environ["MONITOR_PASSWORD"]
    if not c.auth_password:
        raise ConfigError("basic_auth.password is empty; refusing to start")
    return c
