from backend import detection

def test_nmap_structured():
    s = detection.explain("kali_nmap", {"target":"192.168.50.1","top_ports":100,"service_scan":True})
    assert "192.168.50.1" in s and "100" in s and "version" in s.lower()

def test_web_fetch():
    s = detection.explain("web_fetch", {"url":"https://example.com/a"})
    assert "example.com" in s

def test_shell_curl():
    s = detection.explain("sandbox_bash", {"command":"curl -s https://example.com -o /work/x"})
    assert "curl" in s.lower()

def test_shell_grep_not_firmware_falsepositive():
    # 'firmware' appears only inside the grep PATTERN; explanation must be about grep/curl, not "firmware analysis"
    cmd = "curl -s http://192.168.50.1/Main_Login.asp -o /work/login.html; grep -inE 'version|firmware|model' /work/login.html"
    s = detection.explain("sandbox_bash", {"command": cmd})
    assert "firmware analysis" not in s.lower()
    assert "curl" in s.lower() or "http" in s.lower()

def test_shell_python_heredoc():
    s = detection.explain("sandbox_bash", {"command":"cd /work && python3 - <<'EOF'\nprint(1)\nEOF"})
    assert "python" in s.lower()

def test_shell_quoted_separator_in_trivial():
    # A separator character inside a trivial command's quoted argument must not leak keywords
    # 'nmap' appears inside cd's quoted argument, not as a separate command
    cmd = "cd 'workdir; nmap fake' && ls"
    s = detection.explain("sandbox_bash", {"command": cmd})
    assert "scan" not in s.lower()  # nmap scan explanation must not appear
    assert "files" in s.lower()  # should describe ls/listing instead
