import asyncio
from backend import config as config_mod
from backend.store import Store
from backend.hub import Hub
from backend.collector import Collector
from backend.app import create_app

def build():
    cfg = config_mod.load()
    store = Store(cfg.events_db)
    hub = Hub()
    collector = Collector(cfg, store, hub)
    app = create_app(cfg, store, hub, collector=collector)
    return app, cfg

app = None
def get_app():
    global app
    if app is None:
        app, _ = build()
    return app
