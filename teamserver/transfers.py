# pyright: reportImplicitRelativeImport=false
"""
AURORA C2 - Chunked local file transfer helpers.

Upload local paths may be absolute or relative to the Teamserver current
working directory. Downloaded files are saved with random names under ./download.
File content is streamed in chunks, so no total file-size cap is applied.
"""
from __future__ import annotations

import base64
import secrets
from dataclasses import dataclass
from pathlib import Path

import config


class TransferError(ValueError):
    pass


@dataclass
class BrowserUpload:
    filename: str
    data: bytearray
    eof: bool


BROWSER_UPLOAD_PREFIX = "browser-upload://"
_browser_uploads: dict[str, BrowserUpload] = {}


def split_one_path(args: str, usage: str) -> str:
    parts = _split_args(args or "")
    if len(parts) != 1:
        raise TransferError(f"Usage: {usage}")
    return parts[0]


def split_two_paths(args: str, usage: str) -> tuple[str, str]:
    parts = _split_args(args or "")
    if len(parts) != 2:
        raise TransferError(f"Usage: {usage}")
    return parts[0], parts[1]


def prepare_upload_task(local_path: str, remote_path: str) -> tuple[str, str, dict[str, str]]:
    if _is_browser_upload_path(local_path):
        upload_id = _browser_upload_id(local_path)
        if upload_id not in _browser_uploads:
            raise TransferError("Browser upload buffer not found")
        display_args = f"{_browser_upload_display_name(local_path)} {remote_path}"
        meta = {"local_path": local_path, "remote_path": remote_path}
        return remote_path, display_args, meta

    src = _resolve_upload_path(local_path)
    if not src.is_file():
        raise TransferError(f"Local file not found: {local_path}")

    display_args = f"{local_path} {remote_path}"
    meta = {"local_path": local_path, "remote_path": remote_path}
    return remote_path, display_args, meta


def prepare_download_task(remote_path: str) -> tuple[str, str, dict[str, str]]:
    local_path = _random_download_path(remote_path)
    dst = _resolve_cwd_path(local_path)
    dst.parent.mkdir(parents=True, exist_ok=True)

    display_args = f"{remote_path} -> {local_path}"
    meta = {"local_path": local_path, "remote_path": remote_path}
    return remote_path, display_args, meta


def read_upload_chunk(local_path: str, offset: int) -> tuple[str, int]:
    if offset < 0:
        raise TransferError("Invalid upload offset")

    if _is_browser_upload_path(local_path):
        return _read_browser_upload_chunk(local_path, offset)

    src = _resolve_upload_path(local_path)
    if not src.is_file():
        raise TransferError(f"Local file not found: {local_path}")

    with src.open("rb") as f:
        _ = f.seek(offset)
        data = f.read(config.TRANSFER_CHUNK_SIZE)
        eof = 1 if len(data) < config.TRANSFER_CHUNK_SIZE else 0

    return base64.b64encode(data).decode(), eof


def write_download_chunk(local_path: str, offset: int, chunk_b64: str) -> int:
    if offset < 0:
        raise TransferError("Invalid download offset")

    dst = _resolve_cwd_path(local_path)
    dst.parent.mkdir(parents=True, exist_ok=True)

    try:
        data = base64.b64decode(chunk_b64, validate=True) if chunk_b64 else b""
    except Exception as exc:
        raise TransferError(f"Downloaded chunk decode failed: {exc}")

    mode = "r+b" if dst.exists() else "w+b"
    with dst.open(mode) as f:
        if offset == 0:
            _ = f.truncate(0)
        _ = f.seek(offset)
        _ = f.write(data)

    return len(data)


def resolve_local_display_path(local_path: str) -> str:
    return str(_resolve_cwd_path(local_path))


def stage_browser_upload_chunk(
    upload_id: str,
    filename: str,
    offset: int,
    chunk_b64: str,
    eof: bool,
) -> dict[str, str | bool | int]:
    if offset < 0:
        raise TransferError("Invalid local upload offset")
    if not upload_id or not all(ch.isalnum() or ch in "-_" for ch in upload_id):
        raise TransferError("Invalid local upload id")

    safe_name = _safe_filename(filename)
    try:
        data = base64.b64decode(chunk_b64, validate=True) if chunk_b64 else b""
    except Exception as exc:
        raise TransferError(f"Local upload chunk decode failed: {exc}")

    item = _browser_uploads.get(upload_id)
    if item is None or offset == 0:
        item = BrowserUpload(filename=safe_name, data=bytearray(), eof=False)
        _browser_uploads[upload_id] = item

    buf = item.data
    if offset > len(buf):
        raise TransferError("Non-contiguous browser upload chunk")
    if offset < len(buf):
        del buf[offset:]
    if len(buf) + len(data) > config.BROWSER_UPLOAD_MAX_BYTES:
        _ = _browser_uploads.pop(upload_id, None)
        raise TransferError("Browser upload exceeds max in-memory size")

    buf.extend(data)
    item.eof = eof

    local_path = f"{BROWSER_UPLOAD_PREFIX}{upload_id}/{safe_name}"
    return {"ok": True, "eof": eof, "local_path": local_path, "written": len(data)}


def cleanup_browser_upload(local_path: str) -> None:
    if _is_browser_upload_path(local_path):
        _ = _browser_uploads.pop(_browser_upload_id(local_path), None)


def _read_browser_upload_chunk(local_path: str, offset: int) -> tuple[str, int]:
    upload_id = _browser_upload_id(local_path)
    item = _browser_uploads.get(upload_id)
    if item is None:
        raise TransferError("Browser upload buffer not found")
    if item.eof is not True:
        raise TransferError("Browser upload is not complete yet")

    buf = item.data
    if offset > len(buf):
        raise TransferError("Invalid upload offset")

    data = bytes(buf[offset:offset + config.TRANSFER_CHUNK_SIZE])
    eof = 1 if offset + len(data) >= len(buf) else 0
    return base64.b64encode(data).decode(), eof


def _is_browser_upload_path(local_path: str) -> bool:
    return bool(local_path and local_path.startswith(BROWSER_UPLOAD_PREFIX))


def _browser_upload_id(local_path: str) -> str:
    rest = local_path[len(BROWSER_UPLOAD_PREFIX):]
    upload_id = rest.split("/", 1)[0]
    if not upload_id or not all(ch.isalnum() or ch in "-_" for ch in upload_id):
        raise TransferError("Invalid browser upload path")
    return upload_id


def _browser_upload_display_name(local_path: str) -> str:
    rest = local_path[len(BROWSER_UPLOAD_PREFIX):]
    parts = rest.split("/", 1)
    return parts[1] if len(parts) > 1 and parts[1] else "browser-upload"


def _safe_filename(filename: str) -> str:
    name = Path((filename or "upload.bin").replace("\\", "/")).name
    cleaned = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in name)
    return cleaned[:120] or "upload.bin"


def _resolve_upload_path(raw_path: str) -> Path:
    if not raw_path or "\x00" in raw_path:
        raise TransferError("Invalid local path")

    path = Path(raw_path).expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path

    return path.resolve()


def _random_download_path(remote_path: str) -> str:
    remote_name = remote_path.replace("\\", "/").rstrip("/").split("/")[-1]
    suffix = Path(remote_name).suffix
    if len(suffix) > 16 or not all(ch.isalnum() or ch in "._-" for ch in suffix):
        suffix = ""
    return f"download/{secrets.token_hex(8)}{suffix}"


def _resolve_cwd_path(raw_path: str) -> Path:
    if not raw_path or "\x00" in raw_path:
        raise TransferError("Invalid local path")
    if "\\" in raw_path or ":" in raw_path:
        raise TransferError("Local path must be relative to Teamserver current working directory")

    path = Path(raw_path)
    if path.is_absolute():
        raise TransferError("Local path must be relative to Teamserver current working directory")
    if any(part in ("", ".", "..") for part in path.parts):
        raise TransferError("Local path must not contain '.', '..' or empty segments")

    base = Path.cwd().resolve()
    target = (base / path).resolve()

    try:
        _ = target.relative_to(base)
    except ValueError as exc:
        raise TransferError("Local path escapes Teamserver current working directory") from exc

    return target


def _split_args(args: str) -> list[str]:
    tokens: list[str] = []
    buf: list[str] = []
    quote: str | None = None

    for ch in args.strip():
        if quote:
            if ch == quote:
                quote = None
            else:
                buf.append(ch)
            continue

        if ch in ('"', "'"):
            quote = ch
            continue

        if ch.isspace():
            if buf:
                tokens.append("".join(buf))
                buf = []
            continue

        buf.append(ch)

    if quote:
        raise TransferError("Unclosed quote in command arguments")
    if buf:
        tokens.append("".join(buf))

    return tokens
