import hashlib, json, re
from backend import detection
from backend import attack as attack_mod
from backend import findings as findings_mod

def _hash(*parts):
    # Short, stable digest of content -- used to build event_ids that survive
    # Goose renumbering its message rows. Never derive an id from the row id.
    raw = "\x1f".join("" if p is None else str(p) for p in parts)
    return hashlib.sha1(raw.encode("utf-8", "replace")).hexdigest()[:16]

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
         "attack":None, "attack_id":None,
         "findings":[], "finding_severity":None, "finding_category":None,
         "raw_json":None}
    e.update(kw); return e

class MessageState:
    def __init__(self):
        self.pending = {}   # call_id -> (row, request_item)

    def feed(self, row, seen=None):
        # `seen` (optional set of already-ingested event_ids) lets the caller
        # short-circuit re-ingested content after a Goose table rewrite before
        # the expensive detection pass runs -- see Collector.
        events = []
        for it in iter_content(row["content_json"]):
            typ = it.get("type")
            if typ == "toolRequest":
                self.pending[it.get("id")] = (row, it)
            elif typ == "toolResponse":
                events += self._pair(row, it, seen)
            elif typ == "text":
                etype = "assistant_message" if row["role"] == "assistant" else "user_message"
                text = it.get("text")
                eid = f"{row['session_id']}:m:{int(row['created_timestamp'])}:{_hash(row['role'], text)}"
                if seen is not None and eid in seen:
                    continue
                e = _mk_event(row, etype, command=text, raw_json=it)
                e["event_id"] = eid
                events.append(e)
        return events

    def _pair(self, resp_row, resp_it, seen=None):
        cid = resp_it.get("id")
        req = self.pending.pop(cid, None)
        if not req:
            return []
        req_row, req_it = req
        # The model's tool call-id (cid) is stable across Goose rewrites; the
        # row id is not. Prefer cid; skip the detection pass if already seen.
        eid = f"{req_row['session_id']}:{cid}" if cid else None
        if eid and seen is not None and eid in seen:
            return []
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
        finds = findings_mod.scan_findings(command, stdout, stderr,
                                           http_status=None, exit_code=exit_code,
                                           connections=conns, security_alerts=alerts, tool=tool)
        etype = "tool_call"
        if eid is None:  # no cid -> fall back to a content-stable digest
            eid = f"{req_row['session_id']}:t:{_hash(int(resp_row['created_timestamp']), tool, command, stdout)}"
        return [_mk_event(req_row, etype, tool=tool, extension=ext,
                          command=command, arguments=args,
                          command_explained=explained,
                          stdout=stdout, stderr=stderr, exit_code=exit_code,
                          error=err, external_connections=conns,
                          security_alerts=alerts,
                          attack=(atk or {}).get("label"),
                          attack_id=(atk or {}).get("technique_id"),
                          findings=finds,
                          finding_severity=(finds[0]["severity"] if finds else None),
                          finding_category=(finds[0]["category"] if finds else None),
                          event_id=eid,
                          raw_json={"request":req_it,"response":resp_it})]
