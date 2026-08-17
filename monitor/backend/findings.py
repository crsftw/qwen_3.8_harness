"""Findings detection: evidence that the agent actually achieved something —
a confirmed vulnerability, a bypass, code execution, or captured secrets.

Design principle (see the reverse-shell scorer for the same philosophy): a
*finding* is proven by the tool RESPONSE, not by the model's narration or the
command it tried. So this scans stdout+stderr (the ground truth), never the
command text — the command is intent, the response is outcome. Rules are
deterministic, local, and deliberately conservative (precision over recall):
crying "FINDING" on ordinary recon output makes the signal useless.

`scan_findings(...)` returns [] or a single finding dict:
    {"type":"finding","severity","category","reasons":[...],"evidence": "<snippet>"}
"""
import re

C = lambda p: re.compile(p, re.I)
_M = re.MULTILINE

# (name, category, severity, pattern-over-RESPONSE). Ordered specific first.
# Patterns intentionally require RESULT-form evidence ("access granted",
# "session opened", a dumped secret) rather than DESCRIPTIVE text ("... is
# vulnerable to CVE-XXXX", "remote code execution" in an advisory) — the latter
# is the agent reading about a vuln, not achieving one. Info-retrieval tools
# (web_search/web_fetch) are suppressed entirely for the same reason.
FINDING_RULES = [
    # ---- CRITICAL: execution achieved / secrets captured / flags ----
    {"name": "shell/session opened", "category": "Code Execution", "severity": "CRITICAL",
     # meterpreter/command-shell sessions, or `id` output whose user is NOT the
     # agent's own sandbox/kali container user (i.e. a shell on the TARGET).
     "pattern": C(r"(meterpreter|command shell) session \d+ opened|\breverse shell established\b|"
                  r"uid=\d+\((?!(?:sandbox|kali)\))[a-z0-9_-]+\)\s+gid=\d+")},
    {"name": "private key in output", "category": "Credential Exposure", "severity": "CRITICAL",
     "pattern": C(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")},
    {"name": "password hash dump", "category": "Credential Exposure", "severity": "CRITICAL",
     "pattern": re.compile(r"^[a-z_][a-z0-9_-]{0,30}:\$[0-9a-z]\$[^\s:]{10,}", re.I | _M)},  # /etc/shadow line
    {"name": "flag captured", "category": "Flag Captured", "severity": "CRITICAL",
     "pattern": re.compile(r"\b(?:FLAG|CTF|HTB|THM|picoCTF)\{[^}\n]{2,}\}")},
    {"name": "credential cracked", "category": "Credential Access", "severity": "CRITICAL",
     "pattern": C(r"\bStatus\.*:\s*Cracked\b|\bpassword(?:s)? (?:recovered|cracked)\b|^\S+:\S+\s*\(cracked\)", )},

    # ---- HIGH: confirmed injection / exploitation / auth bypass (result-form) ----
    {"name": "sql injection confirmed", "category": "SQL Injection", "severity": "HIGH",
     "pattern": C(r"parameter '[^']+' is vulnerable|sqlmap identified the following injection|"
                  r"available databases \[\d+\]|type:\s*(?:boolean-based|time-based|error-based|UNION query)")},
    {"name": "exploitation success", "category": "Exploitation", "severity": "HIGH",
     "pattern": C(r"exploit completed[^\n]*(?:session|shell|success)|"
                  r"\[\+\][^\n]*\b(?:exploited|got shell|shell opened|success(?:ful)?ly exploited)\b")},
    {"name": "auth bypass achieved", "category": "Auth Bypass", "severity": "HIGH",
     "pattern": C(r"\baccess granted\b|logged in as (?:admin|administrator|root)|"
                  r"welcome,?\s+admin(?:istrator)?\b|authentication successful[^\n]*admin")},

    # ---- MEDIUM: scanner-reported vulnerabilities (require tool-output context) ----
    {"name": "nuclei high/critical", "category": "Scanner Finding", "severity": "MEDIUM",
     "pattern": re.compile(r"\[(?:high|critical)\]\s+https?://", re.I)},          # nuclei match line
    {"name": "nikto/osvdb finding", "category": "Scanner Finding", "severity": "MEDIUM",
     "pattern": C(r"\+ OSVDB-\d+:")},
    {"name": "wpscan vulnerability", "category": "Scanner Finding", "severity": "MEDIUM",
     "pattern": C(r"\[!\][^\n]*\bvulnerabilit(?:y|ies)\b[^\n]*\bTitle:")},
]

_SEV_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
_MAX_SCAN = 40000  # cap response scanned for performance on huge outputs
# Tools that only RETRIEVE external content — their output is reference material
# ("reading about" a vuln), never proof the agent achieved something.
_INFO_TOOLS = ("web_search", "web_fetch")


def scan_findings(command, stdout, stderr, http_status=None, exit_code=None,
                  connections=None, security_alerts=None, tool=None):
    """Return [finding] if the RESPONSE shows evidence of a real finding, else []."""
    t = (tool or "").lower()
    if any(t.endswith(x) for x in _INFO_TOOLS):
        return []
    text = "\n".join(x for x in (stdout, stderr) if x)[:_MAX_SCAN]
    if not text.strip():
        return []
    hits = []
    for r in FINDING_RULES:
        m = r["pattern"].search(text)
        if m:
            hits.append((r, m))
    if not hits:
        return []
    # Primary = highest-severity hit; reasons = all matched categories.
    hits.sort(key=lambda h: _SEV_RANK[h[0]["severity"]], reverse=True)
    top_rule, top_m = hits[0]
    reasons = sorted({h[0]["name"] for h in hits})
    s = max(0, top_m.start() - 40)
    e = min(len(text), top_m.end() + 80)
    evidence = re.sub(r"\s+", " ", text[s:e]).strip()
    return [{"type": "finding", "severity": top_rule["severity"],
             "category": top_rule["category"], "reasons": reasons,
             "evidence": evidence[:220]}]
