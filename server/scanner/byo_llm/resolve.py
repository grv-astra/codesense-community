"""Decide, at scan start, whether the user's own LLM can be used -- and wrap it.

``resolve_byo_backend()`` is read-only and never raises: any problem (no row, not
enabled, no consent, bad config, unreachable, no database in a unit test) returns
``(None, detail)`` and the scanner falls back to the bundled model (if the edition
has one) or to fail-open, exactly as before.
"""
from __future__ import annotations

import dataclasses
import logging
import threading
from datetime import datetime, timezone

from scanner.rag.lsast_types import DataflowContext, VerifierVerdict

from .client import ByoClient
from .config import CONCURRENCY_RANGE, TIMEOUT_RANGE, ConnectionConfig
from .providers import build_provider
from .providers.base import ProviderError
from .redact import redact
from .reporter import apply_report, generate_report
from .store import SINGLETON_ID
from .url_policy import consent_host_of
from .verifier import verify_finding

logger = logging.getLogger(__name__)

PREFLIGHT_TIMEOUT_S = 20


def _clamp(value, bounds) -> int:
    lo, hi = bounds
    try:
        return max(lo, min(hi, int(value)))
    except (TypeError, ValueError):
        return lo


class ByoBackend:
    """One scan's view of the user's LLM: a verify() function plus counters."""

    def __init__(self, client: ByoClient, cfg: ConnectionConfig, host: str,
                 enrich_reports: bool = False):
        self.client = client
        self.enrich_reports = enrich_reports     # write mitigation advice (needs its own consent)
        self.provider = cfg.provider
        self.model = cfg.model
        self.host = host
        self.detail = f"{cfg.provider} / {cfg.model} @ {host}"
        self._lock = threading.Lock()
        self._verified = 0
        self._unverified = 0
        self._reports_written = 0
        self._reports_skipped = 0

    def verify(self, *, cwe: str, language: str, dataflow: DataflowContext,
               code_excerpt: str) -> VerifierVerdict:
        verdict, verified = verify_finding(
            self.client, cwe=cwe, language=language, dataflow=dataflow, code_excerpt=code_excerpt)
        with self._lock:
            if verified:
                self._verified += 1
            else:
                self._unverified += 1
        return verdict

    def write_report(self, finding: dict, *, rule_name: str, cwe: str, language: str,
                     dataflow: DataflowContext, code_excerpt: str, detector_note: str = "") -> bool:
        """Have the user's LLM write the finding's mitigation advice and apply it.
        Fail-open: returns False (finding keeps its rule-derived text) on any problem."""
        if not self.enrich_reports:
            return False
        report = generate_report(
            self.client, rule_name=rule_name, cwe=cwe, language=language,
            dataflow=dataflow, code_excerpt=code_excerpt, detector_note=detector_note)
        applied = apply_report(finding, report)
        if applied:
            finding["report_source"] = "ai"
        with self._lock:
            if applied:
                self._reports_written += 1
            else:
                self._reports_skipped += 1
        return applied

    def finalize(self) -> None:
        """End-of-scan bookkeeping: if the breaker opened, the dashboard light goes red."""
        if self.client.tripped:
            _record_check(False, redact(self.client.trip_reason or "", limit=300))

    def metrics(self) -> dict:
        """What is stored on the scan record (no prompts, no key)."""
        with self._lock:
            verified, unverified = self._verified, self._unverified
            written, skipped = self._reports_written, self._reports_skipped
        return {
            "available": True,
            "backend": "byo",
            "provider": self.provider,
            "model": self.model,
            "host": self.host,
            "detail": self.detail,
            **self.client.stats.as_dict(),
            "verified": verified,
            "unverified": unverified,
            "enrich_reports": self.enrich_reports,
            "reports_written": written,
            "reports_skipped": skipped,
            "report_breaker_open": self.client.report_tripped,
            "breaker_open": self.client.tripped,
            "breaker_reason": self.client.trip_reason or "",
        }


def _record_check(ok: bool, error: str) -> None:
    from local.api_app.models.orm import LLMConnection
    try:
        LLMConnection.objects.filter(pk=SINGLETON_ID).update(
            last_test_at=datetime.now(timezone.utc), last_test_ok=ok, last_test_error=error[:300])
    except Exception:       # noqa: BLE001 -- bookkeeping must never affect a scan
        logger.debug("could not record LLM check result", exc_info=True)


def resolve_byo_backend() -> tuple[ByoBackend | None, str]:
    """(backend, detail). ``backend`` is None unless the connection is usable now;
    ``detail`` is "" when BYO is simply not set up, else the reason it is unusable."""
    try:
        from licenses.services import entitlements
        if not entitlements.get().feature("byo_llm"):
            return None, ""

        from local.api_app.models.orm import LLMConnection
        conn = LLMConnection.objects.filter(pk=SINGLETON_ID).first()
        if conn is None or not conn.enabled:
            return None, ""

        host = consent_host_of(conn.base_url)
        if not (conn.consent_at and host and conn.consent_host == host):
            return None, "Your LLM connection needs data-sharing consent in Settings."

        cfg = ConnectionConfig.from_connection(conn)
        try:
            build_provider(dataclasses.replace(
                cfg, timeout_s=min(cfg.timeout_s, PREFLIGHT_TIMEOUT_S))).ping()
        except ProviderError as exc:
            reason = redact(exc, cfg.api_key)
            _record_check(False, reason)
            return None, f"Your LLM connection is not working: {reason}"
        _record_check(True, "")

        cfg = dataclasses.replace(cfg, timeout_s=_clamp(cfg.timeout_s, TIMEOUT_RANGE))
        client = ByoClient(build_provider(cfg),
                           max_concurrency=_clamp(conn.max_concurrency, CONCURRENCY_RANGE))
        return ByoBackend(client, cfg, host,
                          enrich_reports=bool(conn.enrich_reports and conn.consent_reports)), ""
    except Exception as exc:    # noqa: BLE001 -- includes "no DB" in DB-less unit tests
        logger.debug("BYO LLM not available: %s", type(exc).__name__)
        return None, ""
