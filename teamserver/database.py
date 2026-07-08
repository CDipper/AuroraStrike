"""
AURORA C2 - Database Layer (SQLite)
"""
from __future__ import annotations

import re
import sqlite3
import time
import uuid

from config import DATABASE, DEFAULT_OP_USER, DEFAULT_OP_PASS
from crypto import hash_password, verify_password

SCHEMA = """
CREATE TABLE IF NOT EXISTS operators (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at    REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         REAL NOT NULL,
    level      TEXT,
    message    TEXT,
    beacon_id  TEXT
);

CREATE TABLE IF NOT EXISTS listeners (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    bind_host   TEXT NOT NULL,
    bind_port   INTEGER NOT NULL,
    public_host TEXT NOT NULL,
    public_port INTEGER NOT NULL,
    protocol    TEXT NOT NULL DEFAULT 'http',
    created_at  REAL NOT NULL,
    updated_at  REAL NOT NULL
);
"""

_LISTENER_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
_LISTENER_COLUMNS = "id, name, bind_host, bind_port, public_host, public_port, protocol, created_at, updated_at"


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DATABASE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def _migrate_listeners_schema(conn: sqlite3.Connection) -> None:
    """Remove legacy listener enabled/active columns if present.

    SQLite's CREATE TABLE IF NOT EXISTS does not alter existing tables.
    Older databases may still have enabled/active columns, so rebuild
    the table once and keep only the current listener schema.
    """
    rows = conn.execute("PRAGMA table_info(listeners)").fetchall()
    columns = [r[1] for r in rows]
    if "enabled" not in columns and "active" not in columns:
        return

    now = time.time()
    conn.execute("ALTER TABLE listeners RENAME TO listeners_legacy")
    conn.execute(
        """
        CREATE TABLE listeners (
            id          TEXT PRIMARY KEY,
            name        TEXT NOT NULL,
            bind_host   TEXT NOT NULL,
            bind_port   INTEGER NOT NULL,
            public_host TEXT NOT NULL,
            public_port INTEGER NOT NULL,
            protocol    TEXT NOT NULL DEFAULT 'http',
            created_at  REAL NOT NULL,
            updated_at  REAL NOT NULL
        )
        """
    )
    conn.execute(
        """
        INSERT OR IGNORE INTO listeners
        (id, name, bind_host, bind_port, public_host, public_port, protocol, created_at, updated_at)
        SELECT id, name, bind_host, bind_port, public_host, public_port, protocol,
               COALESCE(created_at, ?), COALESCE(updated_at, ?)
        FROM listeners_legacy
        """,
        (now, now),
    )
    conn.execute("DROP TABLE listeners_legacy")


def init_db():
    conn = get_db()
    conn.executescript(SCHEMA)
    _migrate_listeners_schema(conn)

    row = conn.execute(
        "SELECT id, password_hash FROM operators WHERE username = ?", (DEFAULT_OP_USER,)
    ).fetchone()
    if not row:
        rows = conn.execute("SELECT id FROM operators ORDER BY id ASC").fetchall()
        if len(rows) == 1:
            conn.execute(
                "UPDATE operators SET username = ?, password_hash = ? WHERE id = ?",
                (DEFAULT_OP_USER, hash_password(DEFAULT_OP_PASS), rows[0]["id"]),
            )
        else:
            conn.execute(
                "INSERT INTO operators (username, password_hash, created_at) VALUES (?,?,?)",
                (DEFAULT_OP_USER, hash_password(DEFAULT_OP_PASS), time.time()),
            )
    elif not verify_password(DEFAULT_OP_PASS, row["password_hash"]):
        conn.execute(
            "UPDATE operators SET password_hash = ? WHERE username = ?",
            (hash_password(DEFAULT_OP_PASS), DEFAULT_OP_USER),
        )

    listener = conn.execute("SELECT id FROM listeners LIMIT 1").fetchone()
    if not listener:
        now = time.time()
        conn.execute(
            """
            INSERT OR IGNORE INTO listeners
            (id, name, bind_host, bind_port, public_host, public_port, protocol, created_at, updated_at)
            VALUES (?,?,?,?,?,?,?,?,?)
            """,
            ("default", "Default HTTP", "0.0.0.0", 8443, "127.0.0.1", 8443, "http", now, now),
        )
    conn.commit()
    conn.close()


# ── Operator ops ────────────────────────────────────────

def get_operator(conn, username: str) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT * FROM operators WHERE username = ?", (username,)
    ).fetchone()


# ── Listener ops ────────────────────────────────────────

def _listener_row(row: sqlite3.Row | None) -> dict | None:
    return dict(row) if row else None


def _normalize_listener_id(raw: str | None) -> str:
    value = (raw or "").strip()
    if not value:
        value = uuid.uuid4().hex[:8]
    if not _LISTENER_ID_RE.match(value):
        raise ValueError("Listener id must be 1-32 chars: letters, numbers, _ or -")
    return value


def _validate_listener(bind_host: str, bind_port: int, public_host: str, public_port: int, protocol: str) -> None:
    if not bind_host or len(bind_host) > 255:
        raise ValueError("Invalid bind host")
    if not public_host or len(public_host) > 255:
        raise ValueError("Invalid public host")
    if not (1 <= int(bind_port) <= 65535):
        raise ValueError("Invalid bind port")
    if not (1 <= int(public_port) <= 65535):
        raise ValueError("Invalid public port")
    if protocol not in ("http", "https"):
        raise ValueError("Invalid protocol")


def list_listeners(conn) -> list[dict]:
    rows = conn.execute(f"SELECT {_LISTENER_COLUMNS} FROM listeners ORDER BY created_at ASC").fetchall()
    return [_listener_row(r) for r in rows]


def get_listener(conn, listener_id: str) -> dict | None:
    return _listener_row(conn.execute(
        f"SELECT {_LISTENER_COLUMNS} FROM listeners WHERE id = ?", (listener_id,)
    ).fetchone())


def create_listener(conn, data: dict) -> dict:
    listener_id = _normalize_listener_id(None)  # always auto-generate
    name = (data.get("name") or listener_id).strip()[:100]
    bind_host = (data.get("bind_host") or "0.0.0.0").strip()
    bind_port = int(data.get("bind_port") or 8443)
    public_host = (data.get("public_host") or "127.0.0.1").strip()
    public_port = int(data.get("public_port") or bind_port)
    protocol = (data.get("protocol") or "http").strip().lower()
    _validate_listener(bind_host, bind_port, public_host, public_port, protocol)

    now = time.time()
    conn.execute(
        """
        INSERT INTO listeners
        (id, name, bind_host, bind_port, public_host, public_port, protocol, created_at, updated_at)
        VALUES (?,?,?,?,?,?,?,?,?)
        """,
        (listener_id, name, bind_host, bind_port, public_host, public_port, protocol, now, now),
    )
    conn.commit()
    return get_listener(conn, listener_id)


def update_listener(conn, listener_id: str, data: dict) -> dict:
    if not get_listener(conn, listener_id):
        raise KeyError("Listener not found")
    name = (data.get("name") or listener_id).strip()[:100]
    bind_host = (data.get("bind_host") or "0.0.0.0").strip()
    bind_port = int(data.get("bind_port") or 8443)
    public_host = (data.get("public_host") or "127.0.0.1").strip()
    public_port = int(data.get("public_port") or bind_port)
    protocol = (data.get("protocol") or "http").strip().lower()
    _validate_listener(bind_host, bind_port, public_host, public_port, protocol)

    conn.execute(
        """
        UPDATE listeners
        SET name=?, bind_host=?, bind_port=?, public_host=?, public_port=?, protocol=?, updated_at=?
        WHERE id=?
        """,
        (name, bind_host, bind_port, public_host, public_port, protocol, time.time(), listener_id),
    )
    conn.commit()
    return get_listener(conn, listener_id)


def delete_listener(conn, listener_id: str) -> None:
    conn.execute("DELETE FROM listeners WHERE id = ?", (listener_id,))
    conn.commit()


# ── Event log ───────────────────────────────────────────

def log_event(conn, level, message, beacon_id=None):
    conn.execute(
        "INSERT INTO events (ts, level, message, beacon_id) VALUES (?,?,?,?)",
        (time.time(), level, message, beacon_id),
    )
    conn.commit()


def list_events(conn, limit=100) -> list[dict]:
    rows = conn.execute(
        "SELECT * FROM events ORDER BY ts DESC LIMIT ?", (limit,)
    ).fetchall()
    return [dict(r) for r in rows]


def clear_events(conn) -> None:
    conn.execute("DELETE FROM events")
    conn.execute("DELETE FROM sqlite_sequence WHERE name = 'events'")
    conn.commit()
