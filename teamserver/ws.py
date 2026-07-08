"""
AURORA C2 - WebSocket router and broadcast helpers.
"""
from __future__ import annotations

import asyncio

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

import config
from crypto import verify_token

router = APIRouter()
_ws_clients: set[WebSocket] = set()


async def ws_broadcast(msg: dict):
    dead = set()
    for ws in _ws_clients:
        try:
            await ws.send_json(msg)
        except Exception:
            dead.add(ws)
    _ws_clients.difference_update(dead)


def ws_broadcast_sync(msg: dict):
    """Fire-and-forget broadcast from sync context."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.run_coroutine_threadsafe(ws_broadcast(msg), loop)
    except Exception:
        pass


@router.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    token = ws.query_params.get("token", "")
    user = verify_token(token, config.JWT_SECRET, config.JWT_ALGO)
    if not user:
        await ws.close(code=4001)
        return

    await ws.accept()
    _ws_clients.add(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        _ws_clients.discard(ws)
