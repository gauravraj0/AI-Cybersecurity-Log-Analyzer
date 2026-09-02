"""WebSocket endpoint for the real-time monitoring feed."""
import logging

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect
from jose import JWTError, jwt

from ..config import settings
from ..services.realtime import manager

logger = logging.getLogger("ws")
router = APIRouter(tags=["realtime"])


@router.websocket("/ws")
async def websocket_endpoint(ws: WebSocket, token: str = Query("")):
    """Authenticated live stream: logs | alerts | incidents events."""
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        if not payload.get("sub"):
            raise JWTError("no subject")
    except JWTError:
        await ws.close(code=4401)
        return

    await manager.connect(ws)
    try:
        await ws.send_json({"type": "hello", "payload": {"connections": manager.count}})
        while True:
            # client may send pings; we ignore content
            await ws.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(ws)
    except Exception:
        manager.disconnect(ws)
