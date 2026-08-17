import re
C = re.compile

# Reverse-shell indicator rules (declarative). Each: name, weight, compiled
# `pattern`, and optional `standalone` (a single definitive mechanism that can
# reach HIGH on its own). Weak/corroborating indicators lack `standalone` and
# need >=2 rules + score>=4 to reach HIGH (see detection.scan_reverse_shell).
#
# Precision notes (tuned against real pentest recon, which heavily uses netcat
# as a probe client and bash /dev/tcp for port checks):
#  - "nc exec flag" restricts the -e/-c to netcat's OWN argument run: the span
#    stops at a pipe/redirect/semicolon, so `nc HOST PORT | head -c 300` (a
#    probe piped into `head -c`) does NOT match, while `nc -e /bin/sh HOST PORT`
#    does.
#  - A bare `/dev/tcp/` mention is NOT an indicator on its own: `echo >
#    /dev/tcp/host/port` and `cat < /dev/tcp/host/port` are standard port
#    checks. Only a shell fd-merge redirect into /dev/tcp (`>& /dev/tcp/...`,
#    `... 0>&1`, or `exec N<>/dev/tcp/...`) — the reverse-shell signature — fires.
REVERSE_SHELL_RULES = [
    {"name":"reverse shell /dev/tcp redirect", "weight":4, "standalone":True,
     "pattern":C(r"(?:>&\s*/dev/(?:tcp|udp)/)"
                 r"|(?:/dev/(?:tcp|udp)/\S+\s+\d*[<>]&\d)"
                 r"|(?:exec\s+\d*<>\s*/dev/(?:tcp|udp)/)")},
    {"name":"nc exec flag", "weight":3, "standalone":True,
     "pattern":C(r"\b(nc|ncat)\b[^|;>&\n]*\s-(e|c)\b")},
    {"name":"mkfifo+nc", "weight":3, "standalone":True,
     "pattern":C(r"mkfifo[^\n]*\n?[^\n]*\b(nc|ncat)\b")},
    {"name":"socat EXEC", "weight":3, "standalone":True,
     "pattern":C(r"socat[^\n]*(EXEC:|SYSTEM:)", re.I)},
    {"name":"python socket shell", "weight":3, "standalone":True,
     "pattern":C(r"socket[^\n]*(pty\.spawn|subprocess|os\.dup2)", re.S)},
    {"name":"php fsockopen exec", "weight":3, "standalone":True,
     "pattern":C(r"fsockopen[^\n]*(exec|system|shell_exec)", re.S|re.I)},
    {"name":"powershell tcpclient", "weight":3, "standalone":True,
     "pattern":C(r"New-Object\s+System\.Net\.Sockets\.TCPClient", re.I)},
    {"name":"perl socket exec", "weight":2, "standalone":True,
     "pattern":C(r"(IO::Socket|Socket)[^\n]*(exec|system)", re.S)},
    {"name":"ruby tcpsocket exec", "weight":2, "standalone":True,
     "pattern":C(r"TCPSocket[^\n]*(exec|system|/bin/sh)", re.S)},
    {"name":"interactive shell", "weight":2,
     "pattern":C(r"\b(bash|sh)\s+-i\b")},
    {"name":"base64 shell payload", "weight":2,
     "pattern":C(r"base64\s+-d[^\n]*\|\s*(bash|sh|python)")},
]
