"""Provider registry. Adding a provider = one adapter class + one entry here."""
from __future__ import annotations

from ..config import (
    PROVIDER_ANTHROPIC, PROVIDER_AZURE, PROVIDER_OPENAI, ConnectionConfig,
)
from .anthropic import AnthropicProvider
from .base import Provider, ProviderConfigError
from .openai_compat import AzureOpenAIProvider, OpenAICompatProvider

_REGISTRY = {
    PROVIDER_OPENAI: OpenAICompatProvider,
    PROVIDER_AZURE: AzureOpenAIProvider,
    PROVIDER_ANTHROPIC: AnthropicProvider,
}


def build_provider(cfg: ConnectionConfig) -> Provider:
    cls = _REGISTRY.get(cfg.provider)
    if cls is None:
        raise ProviderConfigError(f"Unknown LLM provider '{cfg.provider}'.")
    if not cfg.model:
        raise ProviderConfigError("A model name is required.")
    return cls(cfg)
