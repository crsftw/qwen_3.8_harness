import fnmatch

def matches(pattern, text):
    if not pattern:
        return True
    text = "" if text is None else str(text)
    if "*" in pattern or "?" in pattern:
        return fnmatch.fnmatch(text.lower(), pattern.lower())
    return pattern.lower() in text.lower()
