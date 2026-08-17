import json
from backend import normalizer as n

def _row(sid, mid, role, content, ts=1786950042641):
    return {"session_id":sid,"id":mid,"role":role,"created_timestamp":ts,
            "content_json":json.dumps(content)}

def test_thinking_dropped():
    items = n.iter_content(json.dumps([{"type":"thinking","text":"secret"},
                                       {"type":"text","text":"hi"}]))
    assert all(it["type"] != "thinking" for it in items)

def test_slug():
    assert n.slug("ASUS Router Pentest") == "asus_router_pentest"
    assert n.slug("", "hello world foo") == "hello_world_foo"

def test_tool_request_response_pairing():
    st = n.MessageState()
    req = [{"type":"toolRequest","id":"call_1",
            "toolCall":{"value":{"name":"sandbox_bash","arguments":{"command":"echo hi"}}},
            "_meta":{"goose_extension":"gateway"}}]
    resp = [{"type":"toolResponse","id":"call_1",
             "toolResult":{"value":{"structuredContent":{"stdout":"hi","stderr":"","exit_code":0},
                                    "isError":False,"content":[{"type":"text","text":"hi"}]}}}]
    ev = st.feed(_row("s1", 10, "assistant", req))
    assert ev == []                       # waits for response
    ev = st.feed(_row("s1", 11, "user", resp))
    assert len(ev) == 1
    e = ev[0]
    assert e["event_type"] == "tool_call" and e["tool"] == "sandbox_bash"
    assert e["command"] == "echo hi" and e["exit_code"] == 0
    assert e["command_explained"]
    assert e["event_id"] == "s1:10:call_1"

def test_text_messages_emit_events():
    st = n.MessageState()
    ev = st.feed(_row("s1", 1, "user", [{"type":"text","text":"pentest 192.168.50.1"}]))
    assert ev[0]["event_type"] == "user_message"
    ev = st.feed(_row("s1", 2, "assistant", [{"type":"text","text":"Starting scan"}]))
    assert ev[0]["event_type"] == "assistant_message"

def test_error_event_from_nonzero_exit():
    st = n.MessageState()
    st.feed(_row("s1", 3, "assistant",
        [{"type":"toolRequest","id":"c2","toolCall":{"value":{"name":"sandbox_bash","arguments":{"command":"false"}}}}]))
    ev = st.feed(_row("s1", 4, "user",
        [{"type":"toolResponse","id":"c2","toolResult":{"value":{"structuredContent":{"stdout":"","stderr":"","exit_code":1},"isError":False}}}]))
    assert ev[0]["error"] == "exit code: 1"
