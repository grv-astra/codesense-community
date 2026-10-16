"""In-memory, immutable view of a connection, with the API key already decrypted."""
from __future__ import annotations

from dataclasses import dataclass, field

PROVIDER_OPENAI = "openai_compatible"
PROVIDER_AZURE = "azure_openai"
PROVIDER_ANTHROPIC = "anthropic"
PROVIDERS = (PROVIDER_OPENAI, PROVIDER_AZURE, PROVIDER_ANTHROPIC)

DEFAULT_AZURE_API_VERSION = "2024-10-21"

TIMEOUT_RANGE = (10, 300)
CONCURRENCY_RANGE = (1, 8)


@dataclass(frozen=True)
class ConnectionConfig:
    provider: str
    base_url: str
    model: str
    api_key: str = field(default="", repr=False)      # never shown in repr / logs
    timeout_s: int = 60
    api_version: str = ""

    @classmethod
    def from_connection(cls, conn) -> "ConnectionConfig":
        """Build from an LLMConnection row (decrypts the key; '' if unset/undecryptable)."""
        from .store import get_api_key
        return cls(
            provider=conn.provider,
            base_url=conn.base_url,
            model=conn.model,
            api_key=get_api_key(conn) or "",
            timeout_s=conn.timeout_s,
            api_version=conn.api_version,
        )
