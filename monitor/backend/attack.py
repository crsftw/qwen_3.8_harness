"""Deterministic, local MITRE ATT&CK classification for tool-call activity.

Maps a command / tool invocation to a single best-fit ATT&CK tactic + technique
(https://attack.mitre.org/). Rule-based and offline — no LLM, no network — in
the same spirit as detection.explain(). Rules are evaluated in order and the
first match wins; the list is ordered specific -> general so that, e.g., a
reverse shell is classified as Execution rather than as port scanning.

`classify()` returns {"tactic","technique","technique_id","label"} or None
(None = leave the column blank rather than force a noisy generic label).
"""
import json
import re

C = lambda p: re.compile(p, re.I | re.S)

# (compiled pattern, tactic, technique-to-display, technique_id)
ATTACK_RULES = [
    # --- Execution: an actual shell/interpreter spawned over the network (reverse/bind shell) ---
    (C(r">&\s*/dev/(tcp|udp)/|/dev/(tcp|udp)/\S+\s+\d*[<>]&\d|exec\s+\d*<>\s*/dev/(tcp|udp)/"
       r"|\bnc(at)?\b[^|;>&\n]*\s-(e|c)\b|socat[^\n]*(exec|system)|fsockopen[^\n]*(exec|system)"
       r"|new-object\s+system\.net\.sockets\.tcpclient"),
     "Execution", "Command and Scripting Interpreter: Unix Shell", "T1059.004"),

    # --- Resource Development: build/obtain offensive capability ---
    (C(r"\bmsfvenom\b|\bmsfconsole\b|\bpayload\s*="), "Resource Development", "Develop Capabilities: Malware", "T1587.001"),

    # --- Credential Access ---
    (C(r"\bhydra\b|\bmedusa\b|\bncrack\b|\bpatator\b|\bjohn\b|\bhashcat\b|\brockyou\b|--wordlist[^\n]*pass"),
     "Credential Access", "Brute Force", "T1110"),
    (C(r"/etc/shadow|/etc/passwd\b|/etc/sudoers|\.ssh/|\bid_rsa\b|\bmimikatz\b|\blsass\b|\bsecretsdump\b|hashdump"),
     "Credential Access", "Unsecured Credentials: Credentials In Files", "T1552.001"),

    # --- Initial Access / Execution: exploitation ---
    (C(r"\bsqlmap\b|union\s+select|information_schema|' or '1'='1"),
     "Initial Access", "Exploit Public-Facing Application", "T1190"),
    (C(r"\bsearchsploit\b|\bmetasploit\b|\bexploit/\b|cve-\d{4}-\d+|\bexploit-db\b"),
     "Execution", "Exploitation for Client Execution", "T1203"),

    # --- Privilege Escalation ---
    (C(r"\bbypassuac\b|\buac[-_ ]?bypass\b|\bfodhelper\b|\beventvwr\b"),
     "Privilege Escalation", "Bypass User Account Control", "T1548.002"),
    (C(r"\bsudo\b|\blinpeas\b|\bwinpeas\b|\bpspy\b|\bgtfobins\b|\bsetuid\b|\bpkexec\b|dirtypipe|dirtycow|\bgetsystem\b"),
     "Privilege Escalation", "Abuse Elevation Control Mechanism", "T1548"),

    # --- Reconnaissance: identity / breach lookups ---
    (C(r"haveibeenpwned|\bhibp\b|breachedaccount|/pwned"),
     "Reconnaissance", "Gather Victim Identity Information: Email Addresses", "T1589.002"),

    # --- Reconnaissance: active scanning (order: content brute -> vuln scan -> port scan) ---
    (C(r"\bgobuster\b|\bdirb\b|\bffuf\b|\bferoxbuster\b|\bdirbuster\b|\bwfuzz\b|\bwordlist\b"),
     "Reconnaissance", "Active Scanning: Wordlist Scanning", "T1595.003"),
    (C(r"\bnikto\b|\bwhatweb\b|\bwpscan\b|\bnuclei\b|\bwapiti\b|x-powered-by|wp-(content|login|admin)|<meta name=\"generator\""),
     "Reconnaissance", "Active Scanning: Vulnerability Scanning", "T1595.002"),
    (C(r"\bnmap\b|\bmasscan\b|\brustscan\b|\bunicornscan\b|--top-ports|\s-sV\b|\s-sT\b|\s-p-\b|/dev/(tcp|udp)/"
       r"|\bnc(at)?\b[^|;\n]*\b\d{1,5}\b"),
     "Reconnaissance", "Active Scanning", "T1595"),

    # --- Reconnaissance: passive/technical info gathering ---
    (C(r"\bdig\b|\bnslookup\b|\bwhois\b|\bdnsrecon\b|\bdnsenum\b|\bfierce\b|\bdnsx\b|reverseiplookup|hostsearch|\baxfr\b|\bnet dig\b|\bnet whois\b"),
     "Reconnaissance", "Gather Victim Network Information: DNS", "T1590.002"),
    (C(r"\bshodan\b|\bcensys\b|crt\.sh|securitytrails|virustotal"),
     "Reconnaissance", "Search Open Technical Databases", "T1596"),
    (C(r"\bweb search\b|\bsearx\b|site:|duckduckgo|/search\?q="),
     "Reconnaissance", "Search Open Websites/Domains", "T1593"),
    (C(r"s_client\s+-connect|openssl[^\n]*s_client|x509\s+-"),
     "Reconnaissance", "Gather Victim Host Information", "T1592"),

    # --- Command and Control: pulling tools/files in ---
    (C(r"\bwget\b|\bcurl\b[^\n]*\s-[oO]\b|\bscp\b|\btftp\b|certutil[^\n]*urlcache|invoke-webrequest"),
     "Command and Control", "Ingress Tool Transfer", "T1105"),

    # --- Reconnaissance: fetching a target page (fingerprint/probe) ---
    (C(r"\bweb fetch\b|\bcurl\b|\bhttpie\b|\bwget\b"),
     "Reconnaissance", "Gather Victim Host Information", "T1592"),

    # --- Discovery ---
    (C(r"\bping\b|\btraceroute\b|\btracepath\b|\bfping\b|arp-scan|\bnet tracepath\b|\bnet nc\b"),
     "Discovery", "Remote System Discovery", "T1018"),
    (C(r"\bwhoami\b|\bid\b\s|\buname\b|\bhostname\b|\bsysteminfo\b|/etc/os-release"),
     "Discovery", "System Information Discovery", "T1082"),
    (C(r"\bifconfig\b|\bip\s+a(ddr)?\b|\bnetstat\b|\bss\s+-|\broute\b|\barp\b\s"),
     "Discovery", "System Network Configuration Discovery", "T1016"),
    (C(r"\bps\s+-?[aefux]|\btasklist\b|/proc/\d+"),
     "Discovery", "Process Discovery", "T1057"),

    # --- Resource Development: reverse-engineering a target binary/firmware to find bugs ---
    (C(r"\bbinwalk\b|\bunsquashfs\b|\bobjdump\b|\breadelf\b|\bghidra\b|\bradare2?\b|\br2\b|\bgdb\b"
       r"|\bfirmware\b|\bsquashfs\b|\.trx\b|cfg_server|got\[|\bplt\b"),
     "Resource Development", "Develop Capabilities: Exploits", "T1587.004"),
]


def _match_text(tool, arguments, command, explained):
    # Underscores in tool names ("kali_nmap") break \b word matching, so split
    # them into words. Include the human explanation, which often names the verb.
    tool_words = (tool or "").replace("_", " ")
    args_text = ""
    if arguments and not command:
        try:
            args_text = json.dumps(arguments)
        except Exception:
            args_text = str(arguments)
    return " ".join(filter(None, [tool_words, command or "", explained or "", args_text]))


def classify(tool, arguments, command, explained=None):
    """Return {tactic, technique, technique_id, label} for the activity, or None."""
    text = _match_text(tool, arguments, command, explained)
    if not text.strip():
        return None
    for pattern, tactic, technique, tid in ATTACK_RULES:
        if pattern.search(text):
            return {"tactic": tactic, "technique": technique, "technique_id": tid,
                    "label": f"{tactic}: {technique}"}
    return None
