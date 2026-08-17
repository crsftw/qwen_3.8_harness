import json, re
from backend import detection
from backend import attack as attack_mod

def slug(name, fallback=""):
    base = (name or "").strip() or (fallback or "").strip()
    s = re.sub(r"[^a-z0-9]+", "_", base.lower()).strip("_")
    return (s[:40] or "session")

def iter_content(content_json):
    try:
        cj = json.loads(content_json)
    except Exception:
        return []
    items = cj if isinstance(cj, list) else [cj]
    return [it for it in items if isinstance(it, dict) and it.get("type") != "thinking"]

def _mk_event(row, etype, **kw):
    e = {"session_id":row["session_id"], "timestamp_ms":int(row["created_timestamp"]),
         "event_type":etype, "tool":None, "extension":None, "command":None,
         "arguments":None, "command_explained":None, "stdout":None, "stderr":None,
         "exit_code":None, "http_status":None, "error":None, "tier":None,
         "approval_decision":None, "external_connections":[], "security_alerts":[],
         "attack":None, "attack_id":None, "raw_json":None}
    e.update(kw); return e

class MessageState:
    def __init__(self):
        self.pending = {}   # call_id -> (row, request_item)

    def feed(self, row):
        events = []
        for it in iter_content(row["content_json"]):
            typ = it.get("type")
            if typ == "toolRequest":
                self.pending[it.get("id")] = (row, it)
            elif typ == "toolResponse":
                events += self._pair(row, it)
            elif typ == "text":
                etype = "assistant_message" if row["role"] == "assistant" else "user_message"
                e = _mk_event(row, etype, command=it.get("text"), raw_json=it)
                e["event_id"] = f"{row['session_id']}:{row['id']}:msg"
                events.append(e)
        return events

    def _pair(self, resp_row, resp_it):
        cid = resp_it.get("id")
        req = self.pending.pop(cid, None)
        if not req:
            return []
        req_row, req_it = req
        val = (req_it.get("toolCall") or {}).get("value") or {}
        tool = val.get("name"); args = val.get("arguments") or {}
        ext = (req_it.get("_meta") or {}).get("goose_extension")
        rv = (resp_it.get("toolResult") or {}).get("value") or {}
        sc = rv.get("structuredContent") or {}
        stdout, stderr = sc.get("stdout"), sc.get("stderr")
        exit_code = sc.get("exit_code")
        is_error = bool(rv.get("isError"))
        if stdout is None:
            texts = [c.get("text","") for c in rv.get("content",[]) if c.get("type")=="text"]
            stdout = "\n".join(texts) if texts else None
        command = args.get("command") if isinstance(args, dict) else None
        if command is None:
            command = json.dumps(args) if args else tool
        conns = detection.external_connections(tool, args, command)
        err = detection.classify_error(exit_code, is_error, None, stdout, stderr, tool)
        alerts = detection.scan_reverse_shell(command, stdout or "", stderr or "", conns)
        explained = detection.explain(tool, args)
        atk = attack_mod.classify(tool, args, command, explained)
        etype = "tool_call"
        return [_mk_event(req_row, etype, tool=tool, extension=ext,
                          command=command, arguments=args,
                          command_explained=explained,
                          stdout=stdout, stderr=stderr, exit_code=exit_code,
                          error=err, external_connections=conns,
                          security_alerts=alerts,
                          attack=(atk or {}).get("label"),
                          attack_id=(atk or {}).get("technique_id"),
                          event_id=f"{req_row['session_id']}:{req_row['id']}:{cid}",
                          raw_json={"request":req_it,"response":resp_it})]
