"""
AURORA C2 - Shared application state.
"""
from __future__ import annotations

import sqlite3
from collections.abc import Awaitable, Callable

_db_conn: sqlite3.Connection | None = None
_listener_reload_callback: Callable[[], Awaitable[None]] | None = None


def set_conn(conn: sqlite3.Connection) -> None:
    global _db_conn
    _db_conn = conn


def get_conn() -> sqlite3.Connection:
    if _db_conn is None:
        raise RuntimeError("Database connection is not initialized")
    return _db_conn


def close_conn() -> None:
    global _db_conn
    if _db_conn is not None:
        _db_conn.close()
        _db_conn = None


def set_listener_reload_callback(callback: Callable[[], Awaitable[None]]) -> None:
    global _listener_reload_callback
    _listener_reload_callback = callback


async def reload_listener_sockets() -> None:
    if _listener_reload_callback is None:
        raise RuntimeError("Listener reload callback is not initialized")
    await _listener_reload_callback()
