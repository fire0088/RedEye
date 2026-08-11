"""At-rest encryption for vault secrets.

Uses PBKDF2-HMAC-SHA256 to derive a Fernet key from a passphrase + per-database
salt. Encrypted values are stored with an ``enc:`` prefix so plaintext and
ciphertext can coexist (e.g. a DB created before encryption was enabled). If the
`cryptography` package is unavailable or no passphrase is supplied, callers fall
back to plaintext transparently.
"""
from __future__ import annotations

import base64
import os

try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    _HAVE_CRYPTO = True
except Exception:  # noqa: BLE001
    _HAVE_CRYPTO = False

PREFIX = "enc:"
_ITERATIONS = 200_000


def available() -> bool:
    return _HAVE_CRYPTO


def new_salt() -> bytes:
    return os.urandom(16)


class Cipher:
    """Wraps a Fernet keyed from (passphrase, salt)."""

    def __init__(self, passphrase: str, salt: bytes):
        if not _HAVE_CRYPTO:
            raise RuntimeError("cryptography not available")
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                         iterations=_ITERATIONS)
        key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))
        self._f = Fernet(key)

    def encrypt(self, plaintext: str) -> str:
        if plaintext is None:
            plaintext = ""
        token = self._f.encrypt(plaintext.encode("utf-8")).decode("ascii")
        return PREFIX + token

    def decrypt(self, value: str) -> str:
        if not value or not value.startswith(PREFIX):
            return value or ""          # legacy plaintext passthrough
        try:
            return self._f.decrypt(value[len(PREFIX):].encode("ascii")).decode("utf-8")
        except InvalidToken:
            return "<locked>"

    def verify(self, token: str) -> bool:
        """True if this cipher can decrypt a stored verifier token."""
        try:
            self._f.decrypt(token[len(PREFIX):].encode("ascii"))
            return True
        except Exception:  # noqa: BLE001
            return False


def is_encrypted(value: str) -> bool:
    return bool(value) and value.startswith(PREFIX)
