# pyright: reportImplicitRelativeImport=false
"""
AURORA C2 - Profile loader.

Profiles use a small Cobalt-Strike-like text syntax and are the single source
of runtime configuration. Select a profile with: server.py --profile <name|path>.
"""
from __future__ import annotations

import shlex
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
DEFAULT_PROFILE = ROOT_DIR / "profiles" / "default.profile"


def resolve_profile_path() -> Path:
    raw = _profile_arg()
    if not raw:
        return DEFAULT_PROFILE

    path = Path(raw).expanduser()
    if path.is_absolute() or path.suffix:
        return path.resolve() if path.is_absolute() else (ROOT_DIR / path).resolve()

    return (ROOT_DIR / "profiles" / f"{raw}.profile").resolve()


def load_profile(path: Path | None = None) -> dict[str, str]:
    profile_path = path or resolve_profile_path()
    if not profile_path.exists():
        raise FileNotFoundError(f"Profile not found: {profile_path}")

    values: dict[str, str] = {}
    stack: list[str] = []

    for line_no, raw_line in enumerate(profile_path.read_text(encoding="utf-8").splitlines(), 1):
        line = _strip_comment(raw_line).strip()
        if not line:
            continue

        if line.endswith("{"):
            name = line[:-1].strip()
            if not name or any(ch.isspace() for ch in name):
                raise ValueError(f"Invalid profile block at {profile_path}:{line_no}")
            stack.append(name)
            continue

        if line == "}":
            if not stack:
                raise ValueError(f"Unmatched profile block close at {profile_path}:{line_no}")
            _ = stack.pop()
            continue

        if not line.startswith("set "):
            raise ValueError(f"Unsupported profile directive at {profile_path}:{line_no}: {line}")

        if line.endswith(";"):
            line = line[:-1].strip()

        try:
            tokens = shlex.split(line, comments=False, posix=True)
        except ValueError as exc:
            raise ValueError(f"Invalid profile syntax at {profile_path}:{line_no}: {exc}") from exc

        if len(tokens) != 3 or tokens[0] != "set":
            raise ValueError(f"Invalid set directive at {profile_path}:{line_no}: {line}")

        key = ".".join([*stack, tokens[1]]) if stack else tokens[1]
        values[key] = tokens[2]

    if stack:
        raise ValueError(f"Unclosed profile block in {profile_path}: {'.'.join(stack)}")

    return values


def profile_bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def _profile_arg() -> str:
    argv = sys.argv[1:]
    for i, arg in enumerate(argv):
        if arg in ("--profile", "-profile", "-p") and i + 1 < len(argv):
            return argv[i + 1].strip()
        if arg.startswith("--profile="):
            return arg.split("=", 1)[1].strip()
    return ""


def _strip_comment(line: str) -> str:
    quote: str | None = None
    i = 0
    while i < len(line):
        ch = line[i]
        if quote:
            if ch == quote:
                quote = None
            elif ch == "\\":
                i += 1
        else:
            if ch in ('"', "'"):
                quote = ch
            elif ch == "#":
                return line[:i]
            elif ch == "/" and i + 1 < len(line) and line[i + 1] == "/":
                return line[:i]
        i += 1
    return line
