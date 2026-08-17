import json, sqlite3, threading, time
from backend.wildcard import matches

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions(
  id TEXT PRIMARY KEY, name TEXT, label TEXT, created_ms INTEGER,
  working_dir TEXT, last_activity_ms INTEGER,
  event_count INTEGER DEFAULT 0, error_count INTEGER DEFAULT 0,
  conn_count INTEGER DEFAULT 0, alert_count INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS events(
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id TEXT UNIQUE, session_id TEXT, timestamp_ms INTEGER,
  event_type TEXT, tool TEXT, extension TEXT, command TEXT,
  command_explained TEXT, stdout TEXT, stderr TEXT, exit_code INTEGER,
  http_status INTEGER, error TEXT, tier TEXT, approval_decision TEXT,
  severity TEXT, destination TEXT, attack TEXT, attack_id TEXT,
  arguments_json TEXT, connections_json TEXT, alerts_json TEXT, raw_json TEXT);
CREATE INDEX IF NOT EXISTS ix_ev_session ON events(session_id, seq);
CREATE INDEX IF NOT EXISTS ix_ev_ts ON events(timestamp_ms);
CREATE INDEX IF NOT EXISTS ix_ev_type ON events(event_type);
CREATE INDEX IF NOT EXISTS ix_ev_sev ON events(severity);
CREATE INDEX IF NOT EXISTS ix_ev_dest ON events(destination);
CREATE INDEX IF NOT EXISTS ix_ev_attack ON events(attack);
CREATE TABLE IF NOT EXISTS cursors(name TEXT PRIMARY KEY, value INTEGER);
"""

_COLMAP = {  # per-column filter key -> event field(s) to test
  "date":"timestamp_ms","command":"command","explained":"command_explained",
  "response":"_response","error":"error","external":"_external",
  "attack":"attack","tool":"tool","tier":"tier","severity":"severity"}

class Store:
    def __init__(self, path):
        self._lock = threading.Lock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(_SCHEMA); self.db.commit()

    def _row_to_event(self, r):
        e = dict(r)
        for k_json, k in (("arguments_json","arguments"),("connections_json","external_connections"),
                          ("alerts_json","security_alerts"),("raw_json","raw_json")):
            e[k] = json.loads(e.pop(k_json) or "null")
        return e

    def insert_event(self, ev):
        conns = ev.get("external_connections") or []
        alerts = ev.get("security_alerts") or []
        severity = alerts[0].get("severity") if alerts else None
        dest = (alerts[0].get("destination") if alerts else None) or \
               (f'{conns[0].get("host")}:{conns[0].get("port")}' if conns else None)
        with self._lock:
            cur = self.db.execute(
              """INSERT OR IGNORE INTO events(event_id,session_id,timestamp_ms,event_type,tool,
                 extension,command,command_explained,stdout,stderr,exit_code,http_status,error,
                 tier,approval_decision,severity,destination,attack,attack_id,arguments_json,connections_json,
                 alerts_json,raw_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
              (ev["event_id"],ev["session_id"],ev["timestamp_ms"],ev["event_type"],ev.get("tool"),
               ev.get("extension"),ev.get("command"),ev.get("command_explained"),ev.get("stdout"),
               ev.get("stderr"),ev.get("exit_code"),ev.get("http_status"),ev.get("error"),
               ev.get("tier"),ev.get("approval_decision"),severity,dest,
               ev.get("attack"),ev.get("attack_id"),
               json.dumps(ev.get("arguments")),json.dumps(conns),json.dumps(alerts),
               json.dumps(ev.get("raw_json"))))
            if cur.rowcount:
                seq = cur.lastrowid
                self.db.execute(
                  """INSERT INTO sessions(id, last_activity_ms, event_count, error_count, conn_count, alert_count)
                     VALUES(?,?,1,?,?,?)
                     ON CONFLICT(id) DO UPDATE SET
                       last_activity_ms=MAX(COALESCE(last_activity_ms,0), excluded.last_activity_ms),
                       event_count=event_count+1,
                       error_count=error_count+excluded.error_count,
                       conn_count=conn_count+excluded.conn_count,
                       alert_count=alert_count+excluded.alert_count""",
                  (ev["session_id"], ev["timestamp_ms"], 1 if ev.get("error") else 0, len(conns), len(alerts)))
                self.db.commit()
                return seq
            row = self.db.execute("SELECT seq FROM events WHERE event_id=?", (ev["event_id"],)).fetchone()
            return row["seq"] if row else -1

    def upsert_session(self, session_id, name, label, created_ms, working_dir):
        with self._lock:
            self.db.execute("""INSERT INTO sessions(id,name,label,created_ms,working_dir,last_activity_ms)
              VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,label=excluded.label,
                created_ms=COALESCE(excluded.created_ms, created_ms),
                working_dir=COALESCE(excluded.working_dir, working_dir)""",
              (session_id,name,label,created_ms,working_dir,created_ms))
            self.db.commit()

    def list_sessions(self):
        return [dict(r) for r in self.db.execute("SELECT * FROM sessions ORDER BY created_ms")]

    def max_seq(self):
        r = self.db.execute("SELECT COALESCE(MAX(seq),0) m FROM events").fetchone(); return r["m"]

    def events_after(self, seq, limit):
        rows = self.db.execute("SELECT * FROM events WHERE seq>? ORDER BY seq LIMIT ?", (seq,limit))
        return [self._row_to_event(r) for r in rows]

    def get_event(self, event_id):
        r = self.db.execute("SELECT * FROM events WHERE event_id=?", (event_id,)).fetchone()
        return self._row_to_event(r) if r else None

    def _match_filters(self, e, filters):
        for key, pat in (filters or {}).items():
            field = _COLMAP.get(key, key)
            if field == "_response":
                text = f'{e.get("stdout") or ""} {e.get("stderr") or ""}'
            elif field == "_external":
                text = " ".join(f'{c.get("host")}:{c.get("port")}' for c in e.get("external_connections") or [])
            elif field == "timestamp_ms":
                # Format for human date-pattern matching (e.g. "2026-08-*").
                # UTC -- the client formats/filters in local tz for display;
                # this server-side match only needs to be internally
                # consistent, not local, since client-side filtering already
                # covers local display.
                ts = e.get("timestamp_ms")
                text = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(ts/1000)) if ts is not None else None
            else:
                text = e.get(field)
            if not matches(pat, text):
                return False
        return True

    def query_events(self, session_id=None, after_seq=0, limit=200, filters=None):
        sql = "SELECT * FROM events WHERE seq>?"
        args = [after_seq]
        if session_id: sql += " AND session_id=?"; args.append(session_id)
        sql += " ORDER BY seq LIMIT ?"; args.append(max(limit*5, limit))  # overfetch for py filter
        out = []
        for r in self.db.execute(sql, args):
            e = self._row_to_event(r)
            if self._match_filters(e, filters):
                out.append(e)
                if len(out) >= limit: break
        return out

    def prune(self, max_age_days, max_events):
        removed = 0
        with self._lock:
            if max_age_days and max_age_days > 0:
                cutoff = int((time.time() - max_age_days*86400) * 1000)
                removed += self.db.execute("DELETE FROM events WHERE timestamp_ms < ?", (cutoff,)).rowcount
            n = self.db.execute("SELECT COUNT(*) c FROM events").fetchone()["c"]
            if n > max_events:
                cut = self.db.execute("SELECT seq FROM events ORDER BY seq DESC LIMIT 1 OFFSET ?",
                                      (max_events-1,)).fetchone()
                if cut:
                    removed += self.db.execute("DELETE FROM events WHERE seq < ?", (cut["seq"],)).rowcount
            self.db.commit()
        return removed

    def get_cursor(self, name):
        r = self.db.execute("SELECT value FROM cursors WHERE name=?", (name,)).fetchone()
        return r["value"] if r else 0
    def set_cursor(self, name, val):
        with self._lock:
            self.db.execute("INSERT INTO cursors(name,value) VALUES(?,?) ON CONFLICT(name) DO UPDATE SET value=?",
                            (name,val,val)); self.db.commit()
