MAX_RECORDS = 20000

class AuditIndex:
    MAX_RECORDS = MAX_RECORDS  # class attribute, overridable per instance for tests

    def __init__(self, window_ms=60000):
        self.window_ms = window_ms
        self.recs = []   # list of dicts with ts_ms, tool(norm), key, tier, decision, used

    @staticmethod
    def _norm_tool(t): return (t or "").split("__")[-1].lower()

    @staticmethod
    def _key(args):
        a = args or {}
        for k in ("command","target","host","name","url","query"):
            if a.get(k): return str(a[k])
        return ""

    def add(self, rec):
        self.recs.append({"ts_ms":int(float(rec.get("ts",0))*1000),
                          "tool":self._norm_tool(rec.get("tool")),
                          "key":self._key(rec.get("args")),
                          "tier":rec.get("tier"),"decision":rec.get("decision"),"used":False})
        # drop consumed records and bound memory (count-based, no time eviction:
        # a backlog re-read on restart can span far more than window_ms, and
        # time-based eviction would drop still-pending records before they can
        # correlate within the same poll cycle)
        if len(self.recs) > self.MAX_RECORDS or any(r["used"] for r in self.recs):
            self.recs = [r for r in self.recs if not r["used"]][-self.MAX_RECORDS:]

    def match(self, tool, arguments, ts_ms):
        nt=self._norm_tool(tool); key=self._key(arguments); best=None
        for r in self.recs:
            if r["used"] or r["tool"]!=nt: continue
            if r["key"] and key and r["key"]!=key: continue
            if abs(r["ts_ms"]-ts_ms) > self.window_ms: continue
            if best is None or abs(r["ts_ms"]-ts_ms) < abs(best["ts_ms"]-ts_ms):
                best=r
        if best:
            best["used"]=True
            return {"tier":best["tier"],"decision":best["decision"]}
        return None
