import sqlite3, calendar, time

class SessionsReader:
    def __init__(self, db_path):
        self.db_path = db_path

    def _connect(self):
        c = sqlite3.connect(f"file:{self.db_path}?mode=ro", uri=True, check_same_thread=False)
        c.row_factory = sqlite3.Row
        return c

    @staticmethod
    def _to_ms(ts):
        if ts is None: return 0
        try:
            return int(calendar.timegm(time.strptime(str(ts)[:19], "%Y-%m-%d %H:%M:%S")) * 1000)
        except Exception:
            try: return int(float(ts) * (1000 if float(ts) < 1e12 else 1))
            except Exception: return 0

    def read_new(self, after_message_id):
        c = self._connect()
        try:
            sessions = [{"id":r["id"],"name":r["name"],"working_dir":r["working_dir"],
                         "created_ms":self._to_ms(r["created_at"])}
                        for r in c.execute("SELECT id,name,working_dir,created_at FROM sessions ORDER BY created_at")]
            msgs = [dict(r) for r in c.execute(
                "SELECT id,session_id,role,content_json,created_timestamp FROM messages WHERE id>? ORDER BY id",
                (after_message_id,))]
            # created_timestamp may be seconds or ms; normalize to ms
            for m in msgs:
                ct = m.get("created_timestamp") or 0
                m["created_timestamp"] = int(ct if ct > 1e12 else ct*1000)
            return sessions, msgs
        finally:
            c.close()
