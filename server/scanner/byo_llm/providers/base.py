"""Provider interface + the error vocabulary the client's retry logic keys on.

Every message carried by these exceptions is already redacted (no API key, no
prompt text) and safe to log or show to the admin.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from ..config import ConnectionConfig


@dataclass(frozen=True)
class ProviderResult:
    text: str
    tokens_in: int | None = None
    tokens_out: int | None = None


class ProviderError(Exception):
    """Base class. ``fatal`` = retrying (or making further calls) cannot help."""
    fatal = False


class ProviderConfigError(ProviderError):
    """The connection itself is unusable (bad URL policy, missing key, unknown provider)."""
    fatal = True


class ProviderAuthError(ProviderError):
    """HTTP 401/403 -- wrong or missing API key."""
    fatal = True


class ProviderRateLimited(ProviderError):
    def __init__(self, message: str, retry_after: float | None = None):
        super().__init__(message)
        self.retry_after = retry_after


class ProviderUnavailable(ProviderError):
    """Network failure, timeout, TLS error or a 5xx -- worth retrying."""


class ProviderRequestError(ProviderError):
    """A 4xx the provider will not accept (not auth / rate limit). 404 is fatal
    (wrong URL or model name) so the client stops instead of failing every finding."""

    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.fatal = status == 404


class ProviderBadResponse(ProviderError):
    """HTTP 200 but the body was not usable (not JSON, no text, too large, a redirect)."""


class Provider(ABC):
    def __init__(self, cfg: ConnectionConfig):
        self.cfg = cfg

    @abstractmethod
    def complete_json(self, system: str, user: str, max_tokens: int = 512,
                      *, require_text: bool = True) -> ProviderResult:
        """One chat completion expected to contain a JSON object. Raises ProviderError."""

    def ping(self) -> ProviderResult:
        """Smallest call that proves URL + key + model work. An empty reply is fine
        (a reasoning model may spend a tiny budget on hidden tokens)."""
        return self.complete_json(
            'Reply with the JSON object {"ok": true}.', "ping", 64, require_text=False,
        )
