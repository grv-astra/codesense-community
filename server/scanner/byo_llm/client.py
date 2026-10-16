"""Resilient wrapper around a Provider, one instance per scan.

* bounded retries with exponential backoff + jitter for network errors, 5xx and 429
  (429 honours ``Retry-After``, capped);
* a semaphore caps simultaneous requests (the scanner runs findings in a thread pool);
* a circuit breaker stops calling a provider that is clearly broken: a fatal error
  (bad key, wrong URL/model) trips it at once, N consecutive failed calls trips it
  too. After that every call fails fast, so a dead LLM costs a scan seconds, not
  minutes -- the caller fail-opens every remaining finding;
* per-scan counters (calls, failures, retries, tokens) for the scan record.

Mitigation-writing calls (``purpose="report"``) are accounted for separately and have
their OWN small breaker: a struggling report call can never open the verification
breaker, so it cannot cost a scan any verification coverage. Only an open
verification breaker stops report calls too (the connection itself is dead then).

Nothing here logs prompts or replies.
"""
from __future__ import annotations

import logging
import random
import threading
import time
from dataclasses import dataclass, field

from .providers.base import (
    Provider, ProviderError, ProviderRateLimited, ProviderResult, ProviderUnavailable,
)
from .redact import redact

logger = logging.getLogger(__name__)


class ByoCallFailed(Exception):
    """A verification call did not produce a reply. Message is redacted and safe to log."""


class ByoUnavailable(ByoCallFailed):
    """The circuit breaker is open: no call was made."""


@dataclass
class CallStats:
    calls: int = 0          # logical verification calls (a call with retries counts once)
    failures: int = 0       # verification calls that ended without a reply
    retries: int = 0        # extra HTTP attempts (both purposes)
    tokens_in: int = 0      # both purposes
    tokens_out: int = 0
    report_calls: int = 0   # logical mitigation-writing calls
    report_failures: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False, compare=False)

    def as_dict(self) -> dict:
        with self._lock:
            return {
                "calls": self.calls, "failures": self.failures, "retries": self.retries,
                "tokens_in": self.tokens_in, "tokens_out": self.tokens_out,
                "report_calls": self.report_calls, "report_failures": self.report_failures,
            }


class ByoClient:
    def __init__(self, provider: Provider, *, max_concurrency: int = 2, max_attempts: int = 3,
                 breaker_threshold: int = 5, max_delay_s: float = 30.0,
                 sleep=time.sleep, jitter=random.random):
        self.provider = provider
        self.stats = CallStats()
        self._sem = threading.BoundedSemaphore(max(1, max_concurrency))
        self._max_attempts = max(1, max_attempts)
        self._breaker_threshold = max(1, breaker_threshold)
        self._max_delay_s = max_delay_s
        self._sleep = sleep
        self._jitter = jitter
        self._lock = threading.Lock()
        self._consecutive_failures = 0
        self._trip_reason: str | None = None
        self._report_consecutive_failures = 0
        self._report_trip_reason: str | None = None

    @property
    def tripped(self) -> bool:
        return self._trip_reason is not None

    @property
    def trip_reason(self) -> str | None:
        return self._trip_reason

    @property
    def report_tripped(self) -> bool:
        return self._report_trip_reason is not None

    def _delay(self, exc: ProviderError, attempt: int) -> float:
        if isinstance(exc, ProviderRateLimited) and exc.retry_after is not None:
            return min(exc.retry_after, self._max_delay_s)
        return min(2 ** (attempt - 1) + self._jitter() * 0.25, self._max_delay_s)

    def _record_failure(self, reason: str, *, trip: bool, report: bool = False) -> None:
        with self._lock:
            if report:
                # isolated: never touches the verification breaker or its counters
                self.stats.report_failures += 1
                self._report_consecutive_failures += 1
                if self._report_trip_reason is None and (
                        trip or self._report_consecutive_failures >= self._breaker_threshold):
                    self._report_trip_reason = reason
                    logger.warning("LLM report-writing stopped for this scan: %s", reason)
                return
            self.stats.failures += 1
            self._consecutive_failures += 1
            if self._trip_reason is None and (trip or self._consecutive_failures >= self._breaker_threshold):
                self._trip_reason = reason
                logger.warning("LLM circuit breaker open for this scan: %s", reason)

    def complete_json(self, system: str, user: str, max_tokens: int = 512,
                      *, purpose: str = "verify") -> ProviderResult:
        """One logical call. Raises ByoCallFailed (incl. ByoUnavailable); never anything else.
        ``purpose`` is "verify" (default) or "report" (mitigation writing, accounted apart)."""
        report = purpose == "report"
        with self._lock:
            if self._trip_reason is not None:
                raise ByoUnavailable(self._trip_reason)
            if report:
                if self._report_trip_reason is not None:
                    raise ByoUnavailable(self._report_trip_reason)
                self.stats.report_calls += 1
            else:
                self.stats.calls += 1

        for attempt in range(1, self._max_attempts + 1):
            try:
                with self._sem:
                    result = self.provider.complete_json(system, user, max_tokens)
            except ProviderError as exc:
                reason = redact(exc)
                retryable = isinstance(exc, (ProviderRateLimited, ProviderUnavailable))
                if retryable and attempt < self._max_attempts:
                    with self._lock:
                        self.stats.retries += 1
                        if self._trip_reason is not None:       # another thread gave up on it
                            if report:
                                self.stats.report_failures += 1
                            else:
                                self.stats.failures += 1
                            raise ByoUnavailable(self._trip_reason) from None
                    self._sleep(self._delay(exc, attempt))
                    continue
                self._record_failure(reason, trip=exc.fatal, report=report)
                raise ByoCallFailed(reason) from None
            except Exception as exc:                            # adapter bug: never escape
                reason = f"Unexpected error talking to the LLM ({type(exc).__name__})."
                self._record_failure(reason, trip=False, report=report)
                raise ByoCallFailed(reason) from None

            with self._lock:
                if report:
                    self._report_consecutive_failures = 0
                else:
                    self._consecutive_failures = 0
                self.stats.tokens_in += result.tokens_in or 0
                self.stats.tokens_out += result.tokens_out or 0
            return result

        raise AssertionError("unreachable")     # pragma: no cover
