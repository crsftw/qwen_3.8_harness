import asyncio, json, sys
from backend.sources.sessions_db import SessionsReader
from backend.sources.audit_log import AuditTailer
from backend.audit_index import AuditIndex
from backend.normalizer import MessageState, slug

class Collector:
    def __init__(self, config, store, hub, loop=None):
        self.cfg=config; self.store=store; self.hub=hub; self.loop=loop
        self.reader=SessionsReader(config.sessions_db)
        self.tailer=AuditTailer(config.audit_log)
        self.audit=AuditIndex()
        self.state=MessageState()
        self.known_sessions=set()
        self.error_count=0
        # event_ids already ingested this process lifetime. Goose rewrites its
        # messages table constantly (renumbering rows), so the id-cursor re-reads
        # the whole history after every rewrite; this set lets the normalizer skip
        # re-detecting content we've already stored. Persistence-level dedup is
        # still guaranteed by the UNIQUE(event_id) constraint in the store.
        self.seen=set()

    def poll_once(self):
        for rec in self.tailer.read_new():
            self.audit.add(rec)
        cursor=self.store.get_cursor("messages")
        sessions, msgs = self.reader.read_new(after_message_id=cursor)
        for s in sessions:
            if s["id"] not in self.known_sessions:
                self.known_sessions.add(s["id"])
                label=f"{s['id']}_{slug(s['name'])}"
                self.store.upsert_session(s["id"], s["name"], label, s["created_ms"], s["working_dir"])
                self._emit({"kind":"session","session":{"id":s["id"],"label":label,
                            "created_ms":s["created_ms"]}})
        max_id=cursor
        for row in msgs:
            row_id = row["id"]
            try:
                for ev in self.state.feed(row, self.seen):
                    if ev["event_type"]=="tool_call":
                        m=self.audit.match(ev["tool"], ev.get("arguments"), ev["timestamp_ms"])
                        if m:
                            ev["tier"]=m["tier"]; ev["approval_decision"]=m["decision"]
                            decision = (m["decision"] or "")
                            if decision.upper().startswith(("DENIED","BLOCK")) and ev.get("error") is None:
                                ev["error"] = "Tool call blocked"
                    seq=self.store.insert_event(ev)
                    self.seen.add(ev["event_id"])
                    ev_out=dict(ev); ev_out["seq"]=seq
                    self._emit({"kind":"event","event":ev_out})
            except Exception as e:
                # One bad message (normalizer/detection/store) must never halt
                # ingestion of the rest of the batch. Skip it, but still count
                # its id toward the cursor below so we don't reprocess it
                # forever -- a permanently-malformed message must not wedge us.
                self.error_count += 1
                print(f"[collector] error processing message id={row_id}: {e!r}", file=sys.stderr)
            finally:
                max_id=max(max_id, row_id)
        if max_id != cursor:
            self.store.set_cursor("messages", max_id)

    def _emit(self, msg):
        if self.loop:
            asyncio.run_coroutine_threadsafe(self.hub.publish(msg), self.loop)

    async def run(self):
        self.loop=asyncio.get_running_loop()
        while True:
            try:
                self.poll_once()
                self.store.prune(self.cfg.retention_max_age_days, self.cfg.retention_max_events)
            except Exception as e:
                # A single poll failure must not kill the ingestion loop --
                # log it and retry on the next tick.
                print(f"[collector] poll_once failed: {e!r}", file=sys.stderr)
            await asyncio.sleep(self.cfg.poll_interval_ms/1000)
