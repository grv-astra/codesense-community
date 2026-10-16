"""Shared HTTP plumbing for provider adapters.

* the URL policy is enforced here, on every request;
* redirects are never followed (a 3xx is an error);
* the response body is read with a hard size cap;
* every error message is redacted before it leaves this module.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import requests

from ..redact import redact
from ..url_policy import UrlPolicyError, ValidatedUrl, validate_base_url
from .base import (
    ProviderAuthError, ProviderBadResponse, ProviderConfigError,
    ProviderRateLimited, ProviderRequestError, ProviderUnavailable,
)

CONNECT_TIMEOUT_S = 5
MAX_BODY_BYTES = 2 * 1024 * 1024


@dataclass
class HttpResult:
    status: int
    body: Any                 # parsed JSON (dict/list) or None
    headers: dict
    text: str                 # short, redacted snippet of the raw body for diagnostics


def checked_base(base_url: str) -> ValidatedUrl:
    try:
        return validate_base_url(base_url)
    except UrlPolicyError as exc:
        raise ProviderConfigError(str(exc)) from None


def post_json(url: str, headers: dict, payload: dict, timeout_s: int,
              secrets: tuple = ()) -> HttpResult:
    try:
        resp = requests.post(
            url, headers=headers, json=payload,
            timeout=(CONNECT_TIMEOUT_S, timeout_s),
            allow_redirects=False, stream=True,
        )
    except requests.exceptions.Timeout:
        raise ProviderUnavailable(f"The request timed out after {timeout_s}s.") from None
    except requests.exceptions.SSLError as exc:
        raise ProviderUnavailable(f"TLS error: {redact(exc, *secrets, limit=160)}") from None
    except requests.exceptions.ConnectionError:
        raise ProviderUnavailable("Could not connect to the LLM host.") from None
    except requests.exceptions.RequestException as exc:
        raise ProviderUnavailable(f"Request failed: {redact(exc, *secrets, limit=160)}") from None

    try:
        chunks, size = [], 0
        for chunk in resp.iter_content(65536):
            size += len(chunk)
            if size > MAX_BODY_BYTES:
                raise ProviderBadResponse("The LLM reply was too large.")
            chunks.append(chunk)
        raw = b"".join(chunks)
    except requests.exceptions.RequestException:
        raise ProviderUnavailable("The connection dropped while reading the reply.") from None
    finally:
        resp.close()

    text = raw.decode("utf-8", errors="replace")
    try:
        body = json.loads(text) if text.strip() else None
    except ValueError:
        body = None
    return HttpResult(resp.status_code, body, dict(resp.headers), redact(text, *secrets, limit=200))


def error_message(result: HttpResult, *secrets: str) -> str:
    """Best human-readable, redacted reason from a provider error body."""
    body = result.body
    msg = ""
    if isinstance(body, dict):
        err = body.get("error")
        if isinstance(err, dict):
            msg = err.get("message") or err.get("type") or ""
        elif isinstance(err, str):
            msg = err
        msg = msg or body.get("message") or ""
    return redact(msg or result.text, *secrets, limit=200)


def _retry_after(headers: dict) -> float | None:
    for k, v in headers.items():
        if k.lower() == "retry-after":
            try:
                return max(0.0, float(v))
            except (TypeError, ValueError):
                return None
    return None


def raise_for_status(result: HttpResult, *secrets: str) -> None:
    """Map a non-2xx result to the provider error vocabulary."""
    s = result.status
    if 200 <= s < 300:
        return
    if 300 <= s < 400:
        raise ProviderBadResponse("The LLM host answered with a redirect, which is not followed.")
    if s in (401, 403):
        raise ProviderAuthError(f"The LLM rejected the API key (HTTP {s}).")
    if s == 404:
        raise ProviderRequestError(
            404, "Not found (HTTP 404): check the base URL (it usually ends in /v1) and the model name.")
    if s == 429:
        raise ProviderRateLimited(
            "The LLM rate-limited the request (HTTP 429).", retry_after=_retry_after(result.headers))
    if s == 408 or s >= 500:
        raise ProviderUnavailable(f"The LLM server returned HTTP {s}.")
    raise ProviderRequestError(s, f"The LLM rejected the request (HTTP {s}): {error_message(result, *secrets)}")
