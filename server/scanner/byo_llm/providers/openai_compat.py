"""OpenAI-compatible chat-completions adapter (+ the Azure OpenAI variant).

Covers OpenAI, Azure OpenAI, Ollama, LM Studio, vLLM, LiteLLM, Gemini / Mistral /
Groq / DeepSeek via their OpenAI-compatible endpoints, and most gateways.

Providers disagree on small things, so the adapter starts with the common request
and, when the server answers HTTP 400 naming an unsupported parameter, adapts once
per quirk and retries: drops ``response_format``, switches ``max_tokens`` to
``max_completion_tokens`` (newer OpenAI models), drops ``temperature`` (models that
only accept the default). The learned settings are kept for the life of the instance.

An empty reply (a reasoning model that used its token budget thinking) is retried with a bigger
budget, and the budget that worked is remembered the same way.
"""
from __future__ import annotations

import threading
from urllib.parse import quote

from ..config import DEFAULT_AZURE_API_VERSION
from . import _http
from .base import (
    Provider, ProviderBadResponse, ProviderConfigError, ProviderEmptyReply, ProviderRequestError,
    ProviderResult,
)

_MAX_ADAPTATIONS = 3

# A reasoning model can spend the whole reply budget on hidden thinking and answer with nothing. On an
# empty reply the call is retried with a bigger budget (x4, then x8 of what the caller asked for, never
# above _MAX_REPLY_BUDGET), and the step that worked is kept for the rest of the instance's life, so the
# next findings do not each pay for a failed first attempt. The budget is only a ceiling: a model that
# answers briefly is not billed for it.
_BUDGET_STEPS = (1, 4, 8)
_MAX_REPLY_BUDGET = 4096
_EMPTY_REPLY_MESSAGE = (
    "The LLM returned an empty reply even with a larger token budget. This usually means a reasoning "
    "model that spends its tokens thinking; choose a model that answers directly."
)


def _as_int(v) -> int | None:
    return v if isinstance(v, int) and not isinstance(v, bool) else None


class OpenAICompatProvider(Provider):
    def __init__(self, cfg):
        super().__init__(cfg)
        self._json_mode = True
        self._token_param = "max_tokens"
        self._send_temperature = True
        self._budget_step = 0
        self._budget_lock = threading.Lock()

    # -- variant hooks (overridden by AzureOpenAIProvider) -----------------

    def _url(self, base: str) -> str:
        return f"{base}/chat/completions"

    def _headers(self) -> dict:
        h = {"Content-Type": "application/json"}
        if self.cfg.api_key:                       # local servers (Ollama...) need none
            h["Authorization"] = f"Bearer {self.cfg.api_key}"
        return h

    def _model_in_body(self) -> bool:
        return True

    # ---------------------------------------------------------------------

    def _body(self, system: str, user: str, max_tokens: int) -> dict:
        body = {
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            self._token_param: max_tokens,
        }
        if self._model_in_body():
            body["model"] = self.cfg.model
        if self._send_temperature:
            body["temperature"] = 0
        if self._json_mode:
            body["response_format"] = {"type": "json_object"}
        return body

    def _adapt(self, result) -> bool:
        """Adjust to a 400 that names an unsupported parameter. True = retry."""
        msg = _http.error_message(result).lower()
        if self._json_mode and ("response_format" in msg or "json_object" in msg or "json mode" in msg):
            self._json_mode = False
            return True
        if self._token_param == "max_tokens" and "max_completion_tokens" in msg:
            self._token_param = "max_completion_tokens"
            return True
        if self._send_temperature and "temperature" in msg:
            self._send_temperature = False
            return True
        return False

    def complete_json(self, system, user, max_tokens=512, *, require_text=True) -> ProviderResult:
        base = _http.checked_base(self.cfg.base_url)
        secrets = (self.cfg.api_key,)
        url = self._url(base.url)
        for _ in range(_MAX_ADAPTATIONS + len(_BUDGET_STEPS)):
            step = self._budget_step
            budget = max(max_tokens, min(max_tokens * _BUDGET_STEPS[step], _MAX_REPLY_BUDGET))
            res = _http.post_json(url, self._headers(), self._body(system, user, budget),
                                  self.cfg.timeout_s, secrets)
            if res.status == 400 and self._adapt(res):
                continue
            _http.raise_for_status(res, *secrets)
            try:
                return self._parse(res, require_text)
            except ProviderEmptyReply:
                if not self._escalate(step):
                    raise
        raise ProviderRequestError(400, "The LLM rejected the request parameters.")

    def _escalate(self, failed_step: int) -> bool:
        """Raise the budget step after an empty reply that was sent at ``failed_step``.

        The scanner's workers share one provider, so several can fail at the same step at once. Only the
        first of them raises the step; the others find it already raised and just retry at the current
        one. (Each of them raising it was how two workers jumped from x1 straight to x8 and a thinking
        model got a ceiling four times higher than it needed.) False = already at the top step.
        """
        with self._budget_lock:
            if self._budget_step > failed_step:
                return True
            if failed_step + 1 >= len(_BUDGET_STEPS):
                return False
            self._budget_step = failed_step + 1
            return True

    @staticmethod
    def _parse(res, require_text: bool) -> ProviderResult:
        body = res.body
        if not isinstance(body, dict):
            raise ProviderBadResponse("The LLM reply was not a JSON object.")
        try:
            message = body["choices"][0]["message"]
        except (KeyError, IndexError, TypeError):
            raise ProviderBadResponse("The LLM reply had no choices[0].message.") from None
        content = message.get("content") if isinstance(message, dict) else None
        if isinstance(content, list):           # some gateways return content parts
            content = "".join(
                p.get("text", "") for p in content if isinstance(p, dict) and p.get("type") in (None, "text")
            )
        text = content if isinstance(content, str) else ""
        if require_text and not text.strip():
            raise ProviderEmptyReply(_EMPTY_REPLY_MESSAGE)
        usage = body.get("usage") if isinstance(body.get("usage"), dict) else {}
        return ProviderResult(text, _as_int(usage.get("prompt_tokens")), _as_int(usage.get("completion_tokens")))


class AzureOpenAIProvider(OpenAICompatProvider):
    """Azure OpenAI: deployment name in the path, ``api-version`` query, ``api-key`` header."""

    def __init__(self, cfg):
        super().__init__(cfg)
        if not cfg.api_key:
            raise ProviderConfigError("Azure OpenAI needs an API key.")
        if not cfg.model:
            raise ProviderConfigError("Azure OpenAI needs the deployment name in the model field.")

    def _url(self, base: str) -> str:
        version = self.cfg.api_version or DEFAULT_AZURE_API_VERSION
        return (f"{base}/openai/deployments/{quote(self.cfg.model, safe='')}"
                f"/chat/completions?api-version={quote(version, safe='')}")

    def _headers(self) -> dict:
        return {"Content-Type": "application/json", "api-key": self.cfg.api_key}

    def _model_in_body(self) -> bool:
        return False
