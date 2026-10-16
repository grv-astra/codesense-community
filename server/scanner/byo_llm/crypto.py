"""Encryption at rest for the user's LLM API key.

The key is derived per install from Django's SECRET_KEY (HKDF-SHA256 with a
fixed context string), the same pattern licenses.services.offline_license uses,
so no extra secret has to be provisioned. Rotating DJANGO_SECRET_KEY makes old
ciphertext undecryptable: ``decrypt_secret`` then returns None and callers treat
the key as "not set, please re-enter" -- it never raises and never crashes a scan.

Plaintext and ciphertext are never included in exception messages or logs.
"""
from __future__ import annotations

import base64

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

_INFO = b"codesense-byo-llm-key-v1"
_PREFIX = "v1:"      # ciphertext format version, so the scheme can change later


class SecretStorageError(RuntimeError):
    """The install has no usable SECRET_KEY to derive an encryption key from."""


def _fernet() -> Fernet:
    try:
        base = (getattr(settings, "SECRET_KEY", "") or "").encode("utf-8")
    except ImproperlyConfigured:     # Django raises this itself for an empty SECRET_KEY
        base = b""
    if not base:
        raise SecretStorageError("no SECRET_KEY available to encrypt the API key")
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=_INFO).derive(base)
    return Fernet(base64.urlsafe_b64encode(key))


def encrypt_secret(plaintext: str) -> str:
    """Encrypt ``plaintext`` for storage. Empty input returns "" (= no key)."""
    if not plaintext:
        return ""
    token = _fernet().encrypt(plaintext.encode("utf-8")).decode("ascii")
    return _PREFIX + token


def decrypt_secret(stored: str) -> str | None:
    """Decrypt a value from ``encrypt_secret``. Returns None when there is no
    key, the format is unknown, or it was encrypted under a different
    SECRET_KEY -- never raises."""
    if not stored or not stored.startswith(_PREFIX):
        return None
    try:
        return _fernet().decrypt(stored[len(_PREFIX):].encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError, SecretStorageError):
        return None
