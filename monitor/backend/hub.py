import asyncio, sys

class Hub:
    def __init__(self):
        self._subs = set()
        self._dropped = 0

    async def subscribe(self):
        q = asyncio.Queue(maxsize=1000); self._subs.add(q); return q
    def unsubscribe(self, q):
        self._subs.discard(q)
    async def publish(self, msg):
        for q in list(self._subs):
            try:
                q.put_nowait(msg)
            except asyncio.QueueFull:
                # non-blocking is intended -- don't slow down publish for one
                # slow subscriber, but make the silent loss diagnosable.
                self._dropped += 1
                print(f"[hub] dropped event for a slow subscriber (total dropped={self._dropped})", file=sys.stderr)
