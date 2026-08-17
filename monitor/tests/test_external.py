from backend import detection as d

def test_network_tool_internal():
    c = d.external_connections("kali_nmap", {"target":"192.168.50.1"}, None)
    assert c and c[0]["classification"] == "INTERNAL" and c[0]["source"] == "tool"

def test_network_tool_external():
    c = d.external_connections("net_dig", {"name":"example.com"}, None)
    assert c[0]["classification"] == "EXTERNAL" and c[0]["source"] == "tool"

def test_web_fetch_url_port():
    c = d.external_connections("web_fetch", {"url":"https://example.com/a"}, None)
    assert c[0]["host"] == "example.com" and c[0]["port"] == 443 and c[0]["proto"] == "https"

def test_shell_url_is_referenced_only():
    c = d.external_connections("sandbox_bash", {"command":"curl -s https://evil.example/x"}, "curl -s https://evil.example/x")
    assert c[0]["source"] == "referenced"

def test_no_host_no_connection():
    assert d.external_connections("sandbox_bash", {"command":"ls -la /work"}, "ls -la /work") == []

def test_web_fetch_out_of_range_port_degrades_to_none():
    # port 99999 is out of range; urlparse(...).port raises ValueError -- must
    # not crash, and must not silently guess the scheme's default port either.
    c = d.external_connections("web_fetch", {"url":"https://example.com:99999/x"}, None)
    assert c and c[0]["host"] == "example.com" and c[0]["port"] is None

def test_shell_malformed_port_does_not_raise():
    cmd = "curl http://host:notaport/x"
    c = d.external_connections("sandbox_bash", {"command":cmd}, cmd)
    assert c and c[0]["host"] == "host" and c[0]["port"] is None

def test_shell_malformed_ipv6_url_does_not_raise():
    # unclosed IPv6 bracket makes urlparse() ITSELF raise ValueError (not just
    # .port) -- must not crash; the bad URL just yields no connection for it.
    cmd = "curl http://[::1 -v"
    c = d.external_connections("sandbox_bash", {"command":cmd}, cmd)
    assert isinstance(c, list)

def test_web_fetch_malformed_ipv6_url_does_not_raise():
    c = d.external_connections("web_fetch", {"url":"http://[::1"}, None)
    assert isinstance(c, list)

def test_web_fetch_well_formed_url_still_works():
    # regression guard: the urlparse-crash fix must not affect normal URLs
    c = d.external_connections("web_fetch", {"url":"https://example.com"}, None)
    assert c and c[0]["host"] == "example.com" and c[0]["classification"] == "EXTERNAL"
