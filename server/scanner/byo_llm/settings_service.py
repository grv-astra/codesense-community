"""Business rules behind the AI-verification settings API.

Kept out of the views so the rules are unit-testable:

* the API key is write-only: nothing here ever returns it;
* consent is bound to the HOST it was given for -- change the host and consent (and
  ``enabled``) are cleared, and a saved key is dropped unless a new one is supplied,
  so data and credentials can never silently follow a URL edit;
* "Test connection" accepts unsaved draft values and only reuses the saved key when
  provider and host are unchanged, so a draft URL cannot harvest the stored key.
"""
from __future__ import annotations

import re
import time
from datetime import datetime, timezone

from .config import (
    CONCURRENCY_RANGE, DEFAULT_AZURE_API_VERSION, PROVIDER_ANTHROPIC, PROVIDER_AZURE, PROVIDER_OPENAI,
    PROVIDERS, TIMEOUT_RANGE, ConnectionConfig,
)
from .providers import build_provider
from .providers.base import ProviderError
from .redact import redact
from .store import get_api_key, key_is_set, set_api_key
from .url_policy import UrlPolicyError, consent_host_of, validate_base_url
from .reporter import MAX_NOTE_CHARS
from .verifier import FP_MIN_CONFIDENCE, MAX_EXCERPT_CHARS

TEST_TIMEOUT_CAP_S = 30
MAX_KEY_LEN = 512
_VERSION_RE = re.compile(r"^[A-Za-z0-9._\-]{0,32}$")
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")

REQUIRES_KEY = frozenset({PROVIDER_AZURE, PROVIDER_ANTHROPIC})

PROVIDER_INFO = [
    {"id": PROVIDER_OPENAI, "label": "OpenAI-compatible (OpenAI, Ollama, LM Studio, vLLM, LiteLLM, Gemini, Mistral, Groq...)",
     "needs_key": False, "needs_api_version": False},
    {"id": PROVIDER_AZURE, "label": "Azure OpenAI", "needs_key": True, "needs_api_version": True,
     "default_api_version": DEFAULT_AZURE_API_VERSION},
    {"id": PROVIDER_ANTHROPIC, "label": "Anthropic", "needs_key": True, "needs_api_version": False},
]


class SettingsError(ValueError):
    """A request the admin can fix. ``str(exc)`` is safe to show; ``field`` names the input."""

    def __init__(self, message: str, field: str | None = None):
        super().__init__(message)
        self.field = field


def disclosure() -> dict:
    """Exactly what leaves the machine -- shown in the consent dialog."""
    return {
        "sent": [
            "The type of weakness found (e.g. CWE-89) and the programming language",
            "The source-to-sink data-flow lines reported by the analyzer",
            f"A code excerpt around the flagged line (up to {MAX_EXCERPT_CHARS} characters)",
        ],
        # Only when "Also write mitigation advice" is on (a second call per finding):
        "sent_for_mitigation": [
            "The name of the analyzer rule that flagged the code",
            f"The analyzer's one-line message about the issue (up to {MAX_NOTE_CHARS} characters)",
            "The same data-flow lines and code excerpt, sent a second time to write the advice",
        ],
        "not_sent": [
            "File names and paths", "Repository, project or user names", "Any other file in the project",
        ],
        "key_note": "Your API key is stored encrypted on this machine and is sent only to this LLM host, "
                    "as its login.",
        "false_positive_min_confidence": FP_MIN_CONFIDENCE,
    }


def _iso(dt) -> str | None:
    return dt.isoformat() if dt else None


def consent_is_valid(conn) -> bool:
    host = consent_host_of(conn.base_url)
    return bool(conn.consent_at and host and conn.consent_host == host)


def serialize(conn) -> dict:
    """The connection as the UI sees it. Never includes the key."""
    return {
        "enabled": conn.enabled,
        "provider": conn.provider,
        "base_url": conn.base_url,
        "model": conn.model,
        "api_version": conn.api_version,
        "timeout_s": conn.timeout_s,
        "max_concurrency": conn.max_concurrency,
        "key_set": key_is_set(conn),
        "enrich_reports": conn.enrich_reports,
        "consent": {
            "given": consent_is_valid(conn),
            # consent covers the mitigation-writing data too (rule name + analyzer message)
            "reports": consent_is_valid(conn) and conn.consent_reports,
            "host": conn.consent_host,
            "at": _iso(conn.consent_at),
            "by": conn.consent_by,
        },
        "last_test": {"at": _iso(conn.last_test_at), "ok": conn.last_test_ok, "error": conn.last_test_error},
        "updated_at": _iso(conn.updated_at),
        "providers": PROVIDER_INFO,
        "limits": {"timeout_s": list(TIMEOUT_RANGE), "max_concurrency": list(CONCURRENCY_RANGE)},
        "disclosure": disclosure(),
    }


# -- validation helpers ---------------------------------------------------------

def _int_in(value, bounds, field: str) -> int:
    lo, hi = bounds
    if isinstance(value, bool):
        raise SettingsError(f"{field} must be a number between {lo} and {hi}.", field)
    try:
        n = int(value)
    except (TypeError, ValueError):
        raise SettingsError(f"{field} must be a number between {lo} and {hi}.", field) from None
    if not lo <= n <= hi:
        raise SettingsError(f"{field} must be between {lo} and {hi}.", field)
    return n


def _text(value, field: str, limit: int) -> str:
    if not isinstance(value, str):
        raise SettingsError(f"{field} must be text.", field)
    value = value.strip()
    if len(value) > limit or _CTRL_RE.search(value):
        raise SettingsError(f"{field} is invalid.", field)
    return value


def _checked_url(url, field: str = "base_url") -> str:
    try:
        return validate_base_url(url if isinstance(url, str) else "").url
    except UrlPolicyError as exc:
        raise SettingsError(str(exc), field) from None


def _checked_key(value) -> str:
    if not isinstance(value, str):
        raise SettingsError("api_key must be text.", "api_key")
    value = value.strip()
    if len(value) > MAX_KEY_LEN or re.search(r"[\s\x00-\x1f\x7f]", value):
        raise SettingsError("The API key contains invalid characters.", "api_key")
    return value


def _checked_provider(value) -> str:
    if value not in PROVIDERS:
        raise SettingsError("Choose a supported provider.", "provider")
    return value


def _checked_version(value) -> str:
    version = _text(value, "api_version", 32)
    if not _VERSION_RE.match(version):
        raise SettingsError("api_version is invalid.", "api_version")
    return version


# -- save -----------------------------------------------------------------------

def apply_update(conn, data, user_id: str) -> None:
    """Validate ``data`` against ``conn`` and save. Nothing is persisted on error."""
    if not isinstance(data, dict):
        raise SettingsError("Invalid request body.")

    old_host = consent_host_of(conn.base_url)

    if "provider" in data:
        conn.provider = _checked_provider(data["provider"])
    if "base_url" in data:
        conn.base_url = _checked_url(data["base_url"])
    if "model" in data:
        conn.model = _text(data["model"], "model", 200)
    if "api_version" in data:
        conn.api_version = _checked_version(data["api_version"])
    if "timeout_s" in data:
        conn.timeout_s = _int_in(data["timeout_s"], TIMEOUT_RANGE, "timeout_s")
    if "max_concurrency" in data:
        conn.max_concurrency = _int_in(data["max_concurrency"], CONCURRENCY_RANGE, "max_concurrency")

    if "enrich_reports" in data:
        if not isinstance(data["enrich_reports"], bool):
            raise SettingsError("enrich_reports must be true or false.", "enrich_reports")
        conn.enrich_reports = data["enrich_reports"]

    new_key = _checked_key(data["api_key"]) if data.get("api_key") not in (None, "") else ""
    if data.get("clear_api_key") is True:
        set_api_key(conn, "")
    if new_key:
        set_api_key(conn, new_key)

    new_host = consent_host_of(conn.base_url)
    if old_host and new_host != old_host:
        # The host changed: the stored key and any consent belonged to the old one.
        if not new_key:
            set_api_key(conn, "")
        conn.consent_at, conn.consent_by, conn.consent_host = None, "", ""
        conn.consent_reports = False
        conn.enabled = False

    if data.get("consent") is False:
        conn.consent_at, conn.consent_by, conn.consent_host = None, "", ""
        conn.consent_reports = False
        conn.enabled = False
    elif data.get("consent") is True:
        if not new_host:
            raise SettingsError("Enter the base URL before giving consent.", "base_url")
        conn.consent_at = datetime.now(timezone.utc)
        conn.consent_by = user_id or ""
        conn.consent_host = new_host
        # the consent dialog lists the mitigation data only while the switch is on
        conn.consent_reports = bool(conn.enrich_reports)

    if "enabled" in data:
        if not isinstance(data["enabled"], bool):
            raise SettingsError("enabled must be true or false.", "enabled")
        conn.enabled = data["enabled"]

    if conn.enabled:
        if not conn.base_url:
            raise SettingsError("Enter the base URL before enabling.", "base_url")
        _checked_url(conn.base_url)                      # re-run the policy (DNS may have changed)
        if not conn.model:
            raise SettingsError("Enter the model name before enabling.", "model")
        if conn.provider in REQUIRES_KEY and not key_is_set(conn):
            raise SettingsError("This provider needs an API key.", "api_key")
        if not consent_is_valid(conn):
            raise SettingsError(
                f"Confirm that code excerpts may be sent to {new_host or 'this host'} before enabling.",
                "consent")
        if conn.enrich_reports and not conn.consent_reports:
            raise SettingsError(
                f"Confirm that the rule name and analyzer message may also be sent to "
                f"{new_host or 'this host'} to write mitigation advice, or turn off "
                f"\"Also write mitigation advice\".", "consent")

    conn.updated_at = datetime.now(timezone.utc)
    conn.updated_by = user_id or ""
    conn.save()


# -- test connection ("Test connection" button) --------------------------------------------------------------

def check_connection(conn, data) -> dict:
    """Make one tiny, source-code-free call with the draft (or saved) settings."""
    data = data if isinstance(data, dict) else {}

    provider = _checked_provider(data.get("provider", conn.provider))
    base_url = _checked_url(data.get("base_url", conn.base_url))
    model = _text(data.get("model", conn.model), "model", 200)
    api_version = _checked_version(data.get("api_version", conn.api_version))
    timeout = min(_int_in(data.get("timeout_s", conn.timeout_s), TIMEOUT_RANGE, "timeout_s"), TEST_TIMEOUT_CAP_S)
    if not model:
        raise SettingsError("Enter the model name to test.", "model")

    supplied = data.get("api_key")
    if supplied not in (None, ""):
        key, saved_key_used = _checked_key(supplied), False
    elif provider == conn.provider and consent_host_of(base_url) == consent_host_of(conn.base_url):
        key, saved_key_used = get_api_key(conn) or "", True      # unchanged target: safe to reuse
    else:
        key, saved_key_used = "", False                          # changed target: never reuse
    if provider in REQUIRES_KEY and not key:
        raise SettingsError(
            "Enter the API key to test this connection." if not saved_key_used
            else "No API key is saved for this connection.", "api_key")

    cfg = ConnectionConfig(provider=provider, base_url=base_url, model=model, api_key=key,
                           timeout_s=timeout, api_version=api_version)
    started = time.monotonic()
    try:
        build_provider(cfg).ping()
        result = {"ok": True, "latency_ms": int((time.monotonic() - started) * 1000), "error": ""}
    except ProviderError as exc:
        result = {"ok": False, "latency_ms": int((time.monotonic() - started) * 1000),
                  "error": redact(exc, key)}

    same_as_saved = (saved_key_used and base_url == conn.base_url and provider == conn.provider
                     and model == conn.model and api_version == conn.api_version)
    if same_as_saved:
        conn.last_test_at = datetime.now(timezone.utc)
        conn.last_test_ok = result["ok"]
        conn.last_test_error = result["error"][:300]
        conn.save(update_fields=["last_test_at", "last_test_ok", "last_test_error"])
    return result


# -- status (dashboard light) -----------------------------------------------------

def status(conn, *, bundled_available: bool = False) -> dict:
    """State of the AI verification the next scan would use. No network call."""
    base = {"provider": "", "model": "", "host": "", "last_check_at": None, "error": ""}
    if conn is not None and conn.enabled:
        base.update(provider=conn.provider, model=conn.model, host=consent_host_of(conn.base_url),
                    last_check_at=_iso(conn.last_test_at), error=conn.last_test_error)
        if not consent_is_valid(conn):
            return {**base, "state": "needs_consent", "source": "byo"}
        if conn.last_test_ok is True:
            return {**base, "state": "connected", "source": "byo"}
        if conn.last_test_ok is False:
            return {**base, "state": "failing", "source": "byo"}
        return {**base, "state": "untested", "source": "byo"}
    if bundled_available:
        return {**base, "state": "bundled", "source": "bundled"}
    if conn is not None and (conn.base_url or conn.model):
        return {**base, "state": "disabled", "source": "none", "provider": conn.provider,
                "model": conn.model, "host": consent_host_of(conn.base_url)}
    return {**base, "state": "not_configured", "source": "none"}

