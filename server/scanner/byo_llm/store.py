"""Persistence helpers for the singleton LLMConnection row.

The API key only ever crosses this boundary as plaintext on the way in
(``set_api_key``) and on the way to the provider adapter (``get_api_key``);
it is stored encrypted and is never serialised back out through the API.
"""
from __future__ import annotations

from local.api_app.models.orm import LLMConnection

from .crypto import decrypt_secret, encrypt_secret

SINGLETON_ID = "llmconnection"


def load() -> LLMConnection:
    """The install's one connection row, created (disabled, empty) on first use."""
    row, _ = LLMConnection.objects.get_or_create(pk=SINGLETON_ID)
    return row


def set_api_key(conn: LLMConnection, plaintext: str) -> None:
    """Encrypt and assign the key on ``conn`` (caller saves). "" clears it."""
    conn.api_key_enc = encrypt_secret(plaintext)


def get_api_key(conn: LLMConnection) -> str | None:
    """The decrypted key, or None if unset / undecryptable."""
    return decrypt_secret(conn.api_key_enc)


def key_is_set(conn: LLMConnection) -> bool:
    """True only if a key is stored AND can be decrypted right now."""
    return bool(get_api_key(conn))
