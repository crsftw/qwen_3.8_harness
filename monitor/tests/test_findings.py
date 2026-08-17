from backend import findings as f

def _sev(out):
    r = f.scan_findings("", out, "")
    return r[0]["severity"] if r else None

def test_sql_injection_confirmed_is_high():
    assert _sev("Parameter 'id' is vulnerable\nsqlmap identified the following injection point(s):") == "HIGH"

def test_flag_captured_is_critical():
    assert _sev("nice: HTB{a_real_flag_1234}") == "CRITICAL"

def test_meterpreter_session_is_critical():
    assert _sev("[*] Meterpreter session 3 opened (a -> b)") == "CRITICAL"

def test_shadow_hash_is_critical():
    assert _sev("root:$6$saltsalt$averylonghashvalue000:19000:0:99999:7:::") == "CRITICAL"

def test_private_key_is_critical():
    assert _sev("-----BEGIN RSA PRIVATE KEY-----\nMIIE...") == "CRITICAL"

def test_nuclei_high_is_medium():
    # nuclei match-line format: [template] [protocol] [severity] URL
    assert _sev("[apache-detect] [http] [high] https://target/server-status") == "MEDIUM"

def test_reading_about_a_cve_is_not_a_finding():
    # advisory/reference text (the agent reading) must NOT be a finding
    assert f.scan_findings("web_search cve", "ASUS warns of critical remote authentication bypass on 7 routers; CVE-2024-3080 remote code execution", "", tool="web_search") == []
    assert f.scan_findings("curl blog", "This CVE describes an authentication bypass vulnerability enabling remote command execution", "", tool="web_fetch") == []

def test_auth_bypass_is_high():
    assert _sev("access granted\nWelcome, admin!") == "HIGH"

def test_findings_scan_the_response_not_the_command():
    # the same vulnerable-looking text in the COMMAND (intent) must NOT be a finding
    assert f.scan_findings("sqlmap -u http://x --flag 'is vulnerable'", "", "") == []

def test_benign_nmap_no_finding():
    assert f.scan_findings("", "22/tcp open ssh\n80/tcp open http\nNmap done", "") == []

def test_benign_403_no_finding():
    assert f.scan_findings("", "HTTP/1.1 403 Forbidden", "") == []

def test_benign_firmware_grep_no_finding():
    assert f.scan_findings("", "firmware version 3.0.0.6 found; cfg_server strings", "") == []

def test_empty_response_no_finding():
    assert f.scan_findings("nmap -sV x", "", "") == []
