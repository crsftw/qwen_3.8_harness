from backend.wildcard import matches

def test_substring_default():
    assert matches("nmap", "run nmap -sV") is True
    assert matches("NMAP", "run nmap -sV") is True
    assert matches("xyz", "run nmap") is False

def test_glob_star():
    assert matches("*something*", "aaa something bbb") is True
    assert matches("nmap*", "nmap -sV") is True
    assert matches("nmap*", "run nmap") is False       # anchored start
    assert matches("*:443", "10.0.0.1:443") is True
    assert matches("*:443", "10.0.0.1:80") is False

def test_glob_question():
    assert matches("h?st", "host") is True
    assert matches("h?st", "haaast") is False

def test_empty_pattern_matches_all():
    assert matches("", "anything") is True
    assert matches(None, "anything") is True
