"""WebSocket connection manager for real-time log / alert streaming."""
import asyncio
import logging
from typing import Any

from fastapi import WebSocket

logger = logging.getLogger("realtime")

_main_loop: asyncio.AbstractEventLoop | None = None


def set_main_loop(loop: asyncio.AbstractEventLoop) -> None:
    """Called at app startup so worker threads can schedule broadcasts."""
    global _main_loop
    _main_loop = loop


def broadcast_threadsafe(event_type: str, payload: Any) -> None:
    """Fan-out an event from any thread (sync endpoints, executor workers)."""
    if _main_loop is None or _main_loop.is_closed():
        return
    try:
        asyncio.run_coroutine_threadsafe(manager.broadcast(event_type, payload), _main_loop)
    except RuntimeError:  # loop shutting down
        pass


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
