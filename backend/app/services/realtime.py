"""WebSocket connection manager for real-time log / alert streaming."""
import asyncio
import logging
from typing import Any

from fastapi import WebSocket

logger = logging.getLogger("realtime")


class ConnectionManager:
    """Fan-out broadcaster for live security events."""

    def __init__(self):
        self.active: list[WebSocket] = []
        self.lock = asyncio.Lock()

    async def connect(self, ws: WebSocket):
        await ws.accept()
        async with self.lock:
            self.active.append(ws)

    def disconnect(self, ws: WebSocket):
        if ws in self.active:
            self.active.remove(ws)

    async def broadcast(self, event_type: str, payload: Any):
        message = {"type": event_type, "payload": payload}
        dead = []
        async with self.lock:
            for ws in list(self.active):
                try:
                    await ws.send_json(message)
                except Exception:
                    dead.append(ws)
            for ws in dead:
                self.disconnect(ws)

    @property
    def count(self) -> int:
        return len(self.active)


manager = ConnectionManager()
