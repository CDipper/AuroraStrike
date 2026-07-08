"""
AURORA C2 - Encrypted resource manager.

Resources (clr_loader.dll, beacon template, etc.) are stored encrypted
at rest in the resources/ directory. They are decrypted in memory only
when the teamserver needs them — plaintext is never written to disk.

Encrypted file format:
    [16-byte IV] [AES-256-CBC ciphertext]

The encryption key is derived from the profile key "resources.key" via
SHA-256.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

ROOT_DIR = Path(__file__).resolve().parent.parent
RESOURCES_DIR = ROOT_DIR / "resources"

_DEFAULT_KEY = "aurora_default_resource_key_change_me"

# In-memory cache: name → plaintext bytes
_cache: dict[str, bytes] = {}


def _get_key() -> bytes:
    """Derive a 32-byte AES key from the profile resource key."""
    try:
        import config
        raw = config.PROFILE.get("resources.key", _DEFAULT_KEY)
    except Exception:
        raw = _DEFAULT_KEY
    if not raw:
        raw = _DEFAULT_KEY
    return hashlib.sha256(raw.encode()).digest()


def _enc_path(name: str) -> Path:
    return RESOURCES_DIR / f"{name}.enc"


def encrypt_file(plaintext: bytes, name: str) -> Path:
    """Encrypt *plaintext* and write to resources/<name>.enc.

    Used by the resource packaging script. Returns the output path.
    """
    RESOURCES_DIR.mkdir(parents=True, exist_ok=True)
    key = _get_key()
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plaintext, AES.block_size))
    out = _enc_path(name)
    out.write_bytes(iv + ct)
    return out


def load_resource(name: str) -> bytes:
    """Load and decrypt a resource by name.

    Reads resources/<name>.enc, decrypts in memory, and caches the result.
    Raises FileNotFoundError if the encrypted file is missing.
    Raises ValueError if decryption fails (wrong key / corrupted).
    """
    if name in _cache:
        return _cache[name]

    path = _enc_path(name)
    if not path.is_file():
        raise FileNotFoundError(f"Encrypted resource not found: {path}")

    key = _get_key()
    raw = path.read_bytes()
    if len(raw) < 32 or (len(raw) - 16) % AES.block_size != 0:
        raise ValueError(f"Corrupted resource file: {name}")

    iv, ct = raw[:16], raw[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    try:
        pt = unpad(cipher.decrypt(ct), AES.block_size)
    except Exception as exc:
        raise ValueError(f"Resource decryption failed for '{name}': {exc}") from exc

    _cache[name] = pt
    return pt


def has_resource(name: str) -> bool:
    return _enc_path(name).is_file()


def list_resources() -> list[str]:
    if not RESOURCES_DIR.is_dir():
        return []
    return sorted(p.stem for p in RESOURCES_DIR.glob("*.enc"))


def clear_cache() -> None:
    """Clear the in-memory plaintext cache."""
    _cache.clear()


# ── RSA private key helper ───────────────────────────────
# The RSA private key is stored encrypted in resources/.
# The resource name is configurable via profile "resources.rsa_key_resource".
# It is decrypted in memory only when needed and cached as PEM bytes.

_DEFAULT_RSA_RESOURCE = "rsa_private_key"


def load_rsa_private_key_pem() -> bytes:
    """Load the RSA private key PEM bytes from encrypted resources.

    Cached after first load. Raises FileNotFoundError if missing.
    """
    try:
        import config
        name = config.RSA_PRIVATE_KEY_RESOURCE
    except Exception:
        name = _DEFAULT_RSA_RESOURCE
    return load_resource(name)
