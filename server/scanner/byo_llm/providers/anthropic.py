"""Native Anthropic Messages API adapter."""
from __future__ import annotations

from . import _http
from .base import (
    Provider, ProviderBadResponse, ProviderConfigError, ProviderRequestError, ProviderResult,
)

ANTHROPIC_VERSION = "2023-06-01"
_MAX_ADAPTATIONS = 2


def _as_int(v) -> int | None:
    return v if isinstance(v, int) and not isinstance(v, bool) else None


class AnthropicProvider(Provider):
    def __init__(self, cfg):
        super().__init__(cfg)
        if not cfg.api_key:
            raise ProviderConfigError("Anthropic needs an API key.")
        if not cfg.model:
            raise ProviderConfigError("Anthropic needs a model name.")
        self._send_temperature = True

    @staticmethod
    def _url(base: str) -> str:
        return f"{base}/messages" if base.endswith("/v1") else f"{base}/v1/messages"

    def _headers(self) -> dict:
        return {
            "Content-Type": "application/json",
            "x-api-key": self.cfg.api_key,
            "anthropic-version": ANTHROPIC_VERSION,
        }

    def _body(self, system: str, user: str, max_tokens: int) -> dict:
        body = {
            "model": self.cfg.model,
            "max_tokens": max_tokens,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        }
        if self._send_temperature:
            body["temperature"] = 0
        return body

    def complete_json(self, system, user, max_tokens=512, *, require_text=True) -> ProviderResult:
        base = _http.checked_base(self.cfg.base_url)
        secrets = (self.cfg.api_key,)
        url = self._url(base.url)
        for _ in range(_MAX_ADAPTATIONS + 1):
            res = _http.post_json(url, self._headers(), self._body(system, user, max_tokens),
                                  self.cfg.timeout_s, secrets)
            if (res.status == 400 and self._send_temperature
                    and "temperature" in _http.error_message(res).lower()):
                self._send_temperature = False       # models that only take the default
                continue
            _http.raise_for_status(res, *secrets)
            return self._parse(res, require_text)
        raise ProviderRequestError(400, "The LLM rejected the request parameters.")

    @staticmethod
    def _parse(res, require_text: bool) -> ProviderResult:
        body = res.body
        if not isinstance(body, dict) or not isinstance(body.get("content"), list):
            raise ProviderBadResponse("The LLM reply had no content blocks.")
        text = "".join(
            b.get("text", "") for b in body["content"]
            if isinstance(b, dict) and b.get("type") == "text"
        )
        if require_text and not text.strip():
            raise ProviderBadResponse("The LLM returned an empty reply.")
        usage = body.get("usage") if isinstance(body.get("usage"), dict) else {}
        return ProviderResult(text, _as_int(usage.get("input_tokens")), _as_int(usage.get("output_tokens")))
