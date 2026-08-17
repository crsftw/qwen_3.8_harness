import asyncio, json, secrets, time, os
from fastapi import FastAPI, Depends, HTTPException, WebSocket, WebSocketDisconnect, Request
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.responses import FileResponse
from backend import status as status_mod

WEB_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "web")
security = HTTPBasic()

def create_app(config, store, hub, collector=None):
    app = FastAPI()

    def check(cred: HTTPBasicCredentials = Depends(security)):
        u_ok = secrets.compare_digest(cred.username, config.auth_username)
        p_ok = secrets.compare_digest(cred.password, config.auth_password)
        if not (u_ok and p_ok):
            raise HTTPException(status_code=401, detail="unauthorized",
                                headers={"WWW-Authenticate":"Basic"})
        return True

    def _now_ms(): return int(time.time()*1000)

    def _decorate_session(s):
        # last_error/open_alert approximation via counts of recent events omitted; use flags on session row
        s = dict(s)
        s["status"] = status_mod.compute_status(
            s.get("last_activity_ms"), _now_ms(),
            config.active_window_s, config.idle_window_s,
            last_error=False, has_open_alert=(s.get("alert_count",0) > 0))
        return s

    def _filters(request: Request):
        return {k[2:]: v for k,v in request.query_params.items() if k.startswith("f_")}

    @app.get("/api/config")
    def client_config(_: bool = Depends(check)):
        return {"redaction_enabled": config.redaction_enabled,
                "active_window_s": config.active_window_s,
                "idle_window_s": config.idle_window_s}

    @app.get("/api/sessions")
    def sessions(_: bool = Depends(check)):
        return [_decorate_session(s) for s in store.list_sessions()]

    @app.get("/api/sessions/{sid}/events")
    def events(sid: str, request: Request, after_seq: int = 0, limit: int = 200, _: bool = Depends(check)):
        evs = store.query_events(session_id=sid, after_seq=after_seq, limit=limit, filters=_filters(request))
        return {"events": evs, "max_seq": store.max_seq()}

    @app.get("/api/search")
    def search(request: Request, after_seq: int = 0, limit: int = 200, _: bool = Depends(check)):
        return {"events": store.query_events(after_seq=after_seq, limit=limit, filters=_filters(request))}

    @app.get("/api/events/{event_id}")
    def event_detail(event_id: str, _: bool = Depends(check)):
        e = store.get_event(event_id)
        if not e: raise HTTPException(404)
        return e

    @app.websocket("/ws")
    async def ws(sock: WebSocket):
        # validate basic-auth header on handshake
        auth = sock.headers.get("authorization","")
        import base64
        try:
            u,p = base64.b64decode(auth.split(" ",1)[1]).decode().split(":",1)
        except Exception:
            await sock.close(code=1008); return
        if not (secrets.compare_digest(u,config.auth_username) and secrets.compare_digest(p,config.auth_password)):
            await sock.close(code=1008); return
        await sock.accept()
        after = int(sock.query_params.get("after_seq", "0"))
        q = await hub.subscribe()                     # subscribe FIRST (buffer live events)
        try:
            last_seq = after
            # Drain loop: page through backlog until caught up, so a client that
            # was disconnected long enough to accumulate >1000 events never loses
            # the middle chunk waiting for a reload. Events published while this
            # drain is running are already buffered on q (we subscribed first),
            # and are deduped below by seq<=last_seq.
            while True:
                batch = store.events_after(last_seq, 1000)
                if not batch:
                    break
                for e in batch:
                    await sock.send_text(json.dumps({"kind":"event","event":e}, default=str))
                    last_seq = max(last_seq, e.get("seq", last_seq))
            while True:
                msg = await q.get()
                # dedupe: skip any live event already covered by the replay snapshot
                if msg.get("kind") == "event" and (msg.get("event") or {}).get("seq", last_seq+1) <= last_seq:
                    continue
                await sock.send_text(json.dumps(msg, default=str))
        except WebSocketDisconnect:
            pass
        finally:
            hub.unsubscribe(q)

    @app.get("/")
    def index(_: bool = Depends(check)):
        return FileResponse(os.path.join(WEB_DIR, "index.html"))

    @app.get("/static/{path:path}")
    def static_files(path: str, _: bool = Depends(check)):
        full = os.path.normpath(os.path.join(WEB_DIR, path))
        # prevent path traversal outside WEB_DIR
        if not full.startswith(os.path.abspath(WEB_DIR) + os.sep):
            raise HTTPException(404)
        if not os.path.isfile(full):
            raise HTTPException(404)
        return FileResponse(full)

    if collector is not None:
        @app.on_event("startup")
        async def _start():
            asyncio.create_task(collector.run())
    return app
