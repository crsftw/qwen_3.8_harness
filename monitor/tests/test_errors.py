from backend import detection as d

def test_nonzero_exit():
    assert d.classify_error(1, False, "AUTO", "", "boom", "sandbox_bash") == "exit code: 1"

def test_is_error_flag():
    assert d.classify_error(0, True, "AUTO", "", "", "web_fetch")

def test_denied_decision():
    assert "block" in d.classify_error(None, False, "DENIED:policy", "", "", "sandbox_bash").lower()

def test_http_4xx_in_output():
    assert "403" in d.classify_error(0, False, "AUTO", "HTTP/1.1 403 Forbidden", "", "sandbox_bash")

def test_stderr_with_zero_exit_is_not_error():
    assert d.classify_error(0, False, "AUTO", "ok", "warning: deprecated", "sandbox_bash") is None

def test_network_failure_token():
    assert d.classify_error(0, False, "AUTO", "", "Connection refused", "net_nc")
