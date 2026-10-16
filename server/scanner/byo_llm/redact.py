"""Scrub secrets out of any text that may be logged or shown to a user.

Provider error bodies sometimes echo (part of) the API key, e.g. "Incorrect API
key provided: sk-abc***xyz". Every error string that leaves the BYO package goes
through ``redact`` first.
"""
from __future__ import annotations

import re

_PATTERNS = (
    re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{6,}"),
    re.compile(r"(?i)\b(x-api-key|api-key|apikey|api_key|authorization)\b(\s*[:=]\s*)\S+"),
    re.compile(r"\b(sk|rk|pk)-[A-Za-z0-9_\-*.]{6,}"),
)


def redact(text: object, *secrets: str | None, limit: int = 300) -> str:
    out = " ".join(str(text if text is not None else "").split())
    for secret in sorted((s for s in secrets if s and len(s) >= 4), key=len, reverse=True):
        out = out.replace(secret, "***")
    out = _PATTERNS[0].sub(lambda m: f"{m.group(1)} ***", out)
    out = _PATTERNS[1].sub(lambda m: f"{m.group(1)}{m.group(2)}***", out)
    out = _PATTERNS[2].sub("***", out)
    if len(out) > limit:
        out = out[: limit - 1] + "…"
    return out
