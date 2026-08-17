import os
def test_build_app(tmp_path, monkeypatch):
    cfg = tmp_path/"c.yaml"
    cfg.write_text("basic_auth: {username: admin, password: x}\n"
                   "events_db: %s\n" % (tmp_path/'e.db'))
    monkeypatch.setenv("MONITOR_CONFIG", str(cfg))
    from backend import main
    app, config = main.build()
    assert app is not None and config.auth_password == "x"
