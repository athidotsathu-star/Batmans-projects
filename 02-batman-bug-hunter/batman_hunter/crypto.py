"""Local authenticated encryption utilities for Batman Bug Hunter.

Format: BBH1.<base64(salt || nonce || AES-GCM ciphertext+tag)>
Passwords are never stored. Use a unique strong passphrase and keep it safe.
"""
from __future__ import annotations

import base64
import hashlib
import secrets
import string

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

_PREFIX = "BBH1."
_SALT_BYTES = 16
_NONCE_BYTES = 12
_KEY_BYTES = 32
_ITERATIONS = 600_000


class CryptoError(ValueError):
    """Invalid input or authentication failure."""


def _derive_key(password: str, salt: bytes) -> bytes:
    if not password or len(password) < 12:
        raise CryptoError("Use a passphrase of at least 12 characters.")
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=_KEY_BYTES,
                     salt=salt, iterations=_ITERATIONS)
    return kdf.derive(password.encode("utf-8"))


def encrypt_text(plaintext: str, password: str) -> str:
    if not plaintext:
        raise CryptoError("Enter text to encrypt.")
    salt = secrets.token_bytes(_SALT_BYTES)
    nonce = secrets.token_bytes(_NONCE_BYTES)
    key = _derive_key(password, salt)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), b"BatmanBugHunter:BBH1")
    payload = salt + nonce + ciphertext
    return _PREFIX + base64.urlsafe_b64encode(payload).decode("ascii")


def decrypt_text(token: str, password: str) -> str:
    if not token or not token.startswith(_PREFIX):
        raise CryptoError("This is not a supported BBH1 encrypted payload.")
    try:
        payload = base64.urlsafe_b64decode(token[len(_PREFIX):].encode("ascii"))
        if len(payload) < _SALT_BYTES + _NONCE_BYTES + 16:
            raise ValueError("short payload")
        salt = payload[:_SALT_BYTES]
        nonce = payload[_SALT_BYTES:_SALT_BYTES + _NONCE_BYTES]
        ciphertext = payload[_SALT_BYTES + _NONCE_BYTES:]
        key = _derive_key(password, salt)
        clear = AESGCM(key).decrypt(nonce, ciphertext, b"BatmanBugHunter:BBH1")
        return clear.decode("utf-8")
    except CryptoError:
        raise
    except Exception as exc:
        raise CryptoError("Decryption failed. Check the passphrase and encrypted text; data may be damaged.") from exc


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def generate_password(length: int = 20) -> str:
    length = max(16, min(int(length), 64))
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    while True:
        value = "".join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in value) and any(c.isupper() for c in value)
                and any(c.isdigit() for c in value) and any(c in "!@#$%^&*()-_=+" for c in value)):
            return value
