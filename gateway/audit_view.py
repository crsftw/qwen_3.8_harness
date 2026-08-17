#!/usr/bin/env python3
"""
Audit viewer — makes the gateway's security spine legible.

  python3 gateway/audit_view.py            # colored timeline + summary in the terminal
  python3 gateway/audit_view.py --html      # also write a self-contained HTML report (local)

Reads gateway/state/audit.log (JSONL). The report stays LOCAL by design — it reveals exactly what the
agent ran, so it is not published anywhere.
"""
import html
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
STATE = os.environ.get("GATEWAY_STATE", os.path.join(HERE, "state"))
AUDIT = os.path.join(STATE, "audit.log")
REPORT = os.path.join(STATE, "audit_report.html")

TIER_COLOR = {"LOW": "\033[32m", "MEDIUM": "\033[33m", "HIGH": "\033[31m"}
RESET = "\033[0m"

def load():
    if not os.path.exists(AUDIT):
        return []
    rows = []
    for line in open(AUDIT):
        line = line.strip()
        if line:
            try: rows.append(json.loads(line))
            except json.JSONDecodeError: pass
    return rows

def fmt_ts(ts):
    try: return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
    except Exception: return str(ts)

def decision_mark(d):
    if d.startswith("DENIED"): return "✗ DENIED"
    if d.startswith("APPROVED:human"): return "✓ APPROVED (human)"
    if d.startswith("APPROVED"): return "✓ APPROVED"
    return "· auto"

def terminal(rows):
    if not rows:
        print("(audit log empty)"); return
    print(f"{'TIME':19}  {'TIER':7} {'TOOL':22} {'DECISION':22} OUTCOME  ARGS")
    print("-" * 110)
    for r in rows:
        tier = r.get("tier", "?")
        c = TIER_COLOR.get(tier, "")
        args = json.dumps(r.get("args", {}))
        if len(args) > 40: args = args[:39] + "…"
        print(f"{fmt_ts(r.get('ts')):19}  {c}{tier:7}{RESET} {r.get('tool',''):22} "
              f"{decision_mark(r.get('decision','')):22} {r.get('outcome','-'):7}  {args}")
    # summary
    n = len(rows)
    by_tier = {}
    approvals = denials = errors = 0
    for r in rows:
        by_tier[r.get("tier", "?")] = by_tier.get(r.get("tier", "?"), 0) + 1
        d = r.get("decision", "")
        if d.startswith("APPROVED"): approvals += 1
        if d.startswith("DENIED"): denials += 1
        if r.get("outcome") in ("ERROR", "isError"): errors += 1
    print("-" * 110)
    tiers = "  ".join(f"{TIER_COLOR.get(t,'')}{t}={c}{RESET}" for t, c in sorted(by_tier.items()))
    print(f"total calls: {n}   {tiers}   approvals(HIGH): {approvals}   denials: {denials}   errored: {errors}")

def to_html(rows):
    css = """
    :root{--bg:#fff;--fg:#1a1a1a;--mut:#666;--line:#e2e2e2;--low:#1a7f37;--med:#9a6700;--high:#cf222e;--card:#f6f8fa}
    :root:not([data-theme=light]) @media (prefers-color-scheme:dark){}
    @media (prefers-color-scheme:dark){:root{--bg:#0d1117;--fg:#e6edf3;--mut:#8b949e;--line:#30363d;--low:#3fb950;--med:#d29922;--high:#f85149;--card:#161b22}}
    body{background:var(--bg);color:var(--fg);font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;margin:0;padding:24px}
    h1{font-size:18px;margin:0 0 4px}.sub{color:var(--mut);margin:0 0 20px}
    .cards{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:20px}
    .card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 16px;min-width:110px}
    .card .n{font-size:22px;font-weight:600}.card .l{color:var(--mut);font-size:12px}
    .wrap{overflow-x:auto}table{border-collapse:collapse;width:100%;min-width:760px}
    th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);white-space:nowrap}
    th{color:var(--mut);font-weight:600;font-size:12px;text-transform:uppercase}
    td.args{white-space:normal;color:var(--mut);font-family:ui-monospace,monospace;font-size:12px;max-width:420px}
    .pill{display:inline-block;padding:1px 8px;border-radius:20px;font-size:12px;font-weight:600}
    .LOW{color:var(--low);border:1px solid var(--low)}.MEDIUM{color:var(--med);border:1px solid var(--med)}.HIGH{color:var(--high);border:1px solid var(--high)}
    .deny{color:var(--high);font-weight:600}.appr{color:var(--low);font-weight:600}.auto{color:var(--mut)}
    """
    by_tier = {}; approvals = denials = 0
    for r in rows:
        by_tier[r.get("tier","?")]=by_tier.get(r.get("tier","?"),0)+1
        if r.get("decision","").startswith("APPROVED"): approvals+=1
        if r.get("decision","").startswith("DENIED"): denials+=1
    cards = "".join(f'<div class="card"><div class="n">{v}</div><div class="l">{k} calls</div></div>'
                    for k,v in sorted(by_tier.items()))
    cards += f'<div class="card"><div class="n">{approvals}</div><div class="l">HIGH approved</div></div>'
    cards += f'<div class="card"><div class="n">{denials}</div><div class="l">denied</div></div>'
    trs = []
    for r in rows:
        tier = r.get("tier","?"); d = r.get("decision","")
        dc = "deny" if d.startswith("DENIED") else ("appr" if d.startswith("APPROVED") else "auto")
        trs.append(f"<tr><td>{html.escape(fmt_ts(r.get('ts')))}</td>"
                   f"<td><span class='pill {tier}'>{tier}</span></td>"
                   f"<td>{html.escape(str(r.get('tool','')))}</td>"
                   f"<td class='{dc}'>{html.escape(decision_mark(d))}</td>"
                   f"<td>{html.escape(str(r.get('outcome','-')))}</td>"
                   f"<td class='args'>{html.escape(json.dumps(r.get('args',{})))}</td></tr>")
    doc = (f"<!doctype html><meta charset=utf-8><title>qwen_harness audit</title><style>{css}</style>"
           f"<h1>qwen_harness — gateway audit</h1>"
           f"<p class=sub>Local security log · {len(rows)} tool calls · generated {fmt_ts(time.time())}</p>"
           f"<div class=cards>{cards}</div>"
           f"<div class=wrap><table><thead><tr><th>Time</th><th>Tier</th><th>Tool</th>"
           f"<th>Decision</th><th>Outcome</th><th>Args (redacted)</th></tr></thead>"
           f"<tbody>{''.join(trs)}</tbody></table></div>")
    with open(REPORT, "w") as f:
        f.write(doc)
    print(f"\nHTML report written: {REPORT}")

if __name__ == "__main__":
    rows = load()
    terminal(rows)
    if "--html" in sys.argv:
        to_html(rows)
