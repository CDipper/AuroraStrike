# pyright: reportImplicitRelativeImport=false
"""
AURORA C2 - Team Server Configuration
"""
from pathlib import Path

from profile_loader import load_profile, profile_bool, resolve_profile_path

# ── Paths ───────────────────────────────────────────────
ROOT_DIR = Path(__file__).resolve().parent.parent
BASE_DIR = Path(__file__).resolve().parent
PROFILE_PATH = resolve_profile_path()
PROFILE = load_profile(PROFILE_PATH)


def _required(profile_key: str) -> str:
    value = PROFILE.get(profile_key)
    if value is None or value == "":
        raise RuntimeError(f"Missing required profile key: {profile_key}")
    return value


def _profile_path(profile_key: str) -> str:
    raw = Path(_required(profile_key)).expanduser()
    return str(raw.resolve() if raw.is_absolute() else (ROOT_DIR / raw).resolve())


# ── Server ───────────────────────────────────────────────
DATABASE = _profile_path("server.database")
WEBUI_DIR = _profile_path("server.webui_dir")
OPERATOR_PORT = int(_required("server.operator_port"))
TRANSFER_CHUNK_SIZE = int(_required("server.transfer_chunk_size"))
BROWSER_UPLOAD_MAX_BYTES = int(_required("server.browser_upload_max_bytes"))
CLEAR_EVENTS_ON_START = profile_bool(_required("server.clear_events_on_start"))
BEACON_TIMEOUT = int(_required("server.beacon_timeout"))

# ── Operator ────────────────────────────────────────────
DEFAULT_OP_USER = _required("operator.user")
DEFAULT_OP_PASS = _required("operator.password")

# ── JWT ─────────────────────────────────────────────────
JWT_SECRET = _required("jwt.secret")
JWT_ALGO = _required("jwt.algo")
JWT_EXP_HOURS = int(_required("jwt.exp_hours"))

# ── Encrypted resources ─────────────────────────────────
RESOURCES_KEY = _required("resources.key")
RSA_PRIVATE_KEY_RESOURCE = _required("resources.rsa_key_resource")

# ── Implant ─────────────────────────────────────────────
IMPLANT_SPAWN_PROCESS = _required("implant.spawn_process")
IMPLANT_USER_AGENT = _required("implant.user_agent")
DEFAULT_SLEEP = int(_required("implant.default_sleep"))
DEFAULT_JITTER = int(_required("implant.default_jitter"))
