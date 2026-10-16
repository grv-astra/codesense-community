"""ByoClient: retries, backoff, concurrency cap, circuit breaker, counters."""
import threading
import time

from django.test import SimpleTestCase

from scanner.byo_llm.client import ByoCallFailed, ByoClient, ByoUnavailable
from scanner.byo_llm.providers.base import (
    Provider, ProviderAuthError, ProviderBadResponse, ProviderRateLimited,
    ProviderRequestError, ProviderResult, ProviderUnavailable,
)


class ScriptedProvider(Provider):
    """Plays back a list of outcomes (exception instances raise, others are returned)."""

    def __init__(self, outcomes, delay=0.0):
        super().__init__(cfg=None)
        self.outcomes = list(outcomes)
        self.calls = 0
        self.delay = delay
        self._lock = threading.Lock()
        self.active = 0
        self.max_active = 0

    def complete_json(self, system, user, max_tokens=512, *, require_text=True):
        with self._lock:
            self.calls += 1
            self.active += 1
            self.max_active = max(self.max_active, self.active)
            outcome = self.outcomes.pop(0) if self.outcomes else ProviderResult("{}", 1, 1)
        try:
            if self.delay:
                time.sleep(self.delay)
            if isinstance(outcome, Exception):
                raise outcome
            return outcome
        finally:
            with self._lock:
                self.active -= 1


def ok(text="{}", i=10, o=5):
    return ProviderResult(text, i, o)


def make(outcomes, **kw):
    sleeps = []
    prov = ScriptedProvider(outcomes, delay=kw.pop("delay", 0.0))
    client = ByoClient(prov, sleep=sleeps.append, jitter=lambda: 0.0, **kw)
    return client, prov, sleeps


class RetryTests(SimpleTestCase):
    def test_success_counts_tokens(self):
        c, p, _ = make([ok(i=10, o=5), ok(i=3, o=2)])
        c.complete_json("s", "u")
        c.complete_json("s", "u")
        self.assertEqual(c.stats.as_dict(), {"calls": 2, "failures": 0, "retries": 0,
                                             "tokens_in": 13, "tokens_out": 7,
                                             "report_calls": 0, "report_failures": 0})

    def test_unavailable_is_retried_with_exponential_backoff(self):
        c, p, sleeps = make([ProviderUnavailable("down"), ProviderUnavailable("down"), ok()])
        c.complete_json("s", "u")
        self.assertEqual(p.calls, 3)
        self.assertEqual(sleeps, [1.0, 2.0])
        self.assertEqual(c.stats.retries, 2)
        self.assertEqual(c.stats.failures, 0)

    def test_gives_up_after_max_attempts(self):
        c, p, sleeps = make([ProviderUnavailable("down")] * 5)
        with self.assertRaises(ByoCallFailed) as ctx:
            c.complete_json("s", "u")
        self.assertNotIsInstance(ctx.exception, ByoUnavailable)
        self.assertEqual(p.calls, 3)
        self.assertEqual(c.stats.failures, 1)
        self.assertEqual(c.stats.calls, 1)

    def test_429_honours_retry_after_but_caps_it(self):
        c, p, sleeps = make([ProviderRateLimited("slow", retry_after=4),
                             ProviderRateLimited("slow", retry_after=999), ok()])
        c.complete_json("s", "u")
        self.assertEqual(sleeps, [4, 30.0])

    def test_429_without_retry_after_uses_backoff(self):
        c, p, sleeps = make([ProviderRateLimited("slow"), ok()])
        c.complete_json("s", "u")
        self.assertEqual(sleeps, [1.0])

    def test_bad_response_and_request_errors_are_not_retried(self):
        for exc in (ProviderBadResponse("garbage"), ProviderRequestError(422, "nope")):
            c, p, sleeps = make([exc, ok()])
            with self.assertRaises(ByoCallFailed):
                c.complete_json("s", "u")
            self.assertEqual(p.calls, 1)
            self.assertEqual(sleeps, [])

    def test_unexpected_exception_never_escapes(self):
        c, p, _ = make([RuntimeError("adapter bug with secret sk-abcdef123456")])
        with self.assertRaises(ByoCallFailed) as ctx:
            c.complete_json("s", "u")
        self.assertNotIn("sk-abcdef123456", str(ctx.exception))
        self.assertEqual(p.calls, 1)


class BreakerTests(SimpleTestCase):
    def test_auth_error_trips_immediately_and_later_calls_fail_fast(self):
        c, p, _ = make([ProviderAuthError("The LLM rejected the API key (HTTP 401).")])
        with self.assertRaises(ByoCallFailed):
            c.complete_json("s", "u")
        self.assertTrue(c.tripped)
        with self.assertRaises(ByoUnavailable) as ctx:
            c.complete_json("s", "u")
        self.assertIn("API key", str(ctx.exception))
        self.assertEqual(p.calls, 1)                     # second call never reached the provider

    def test_fatal_404_trips(self):
        c, p, _ = make([ProviderRequestError(404, "not found")])
        with self.assertRaises(ByoCallFailed):
            c.complete_json("s", "u")
        self.assertTrue(c.tripped)

    def test_consecutive_failures_trip_after_threshold(self):
        c, p, _ = make([ProviderBadResponse("garbage")] * 10, breaker_threshold=3)
        for _ in range(3):
            with self.assertRaises(ByoCallFailed):
                c.complete_json("s", "u")
        self.assertTrue(c.tripped)
        with self.assertRaises(ByoUnavailable):
            c.complete_json("s", "u")
        self.assertEqual(p.calls, 3)

    def test_a_success_resets_the_consecutive_count(self):
        c, p, _ = make([ProviderBadResponse("g"), ProviderBadResponse("g"), ok(),
                        ProviderBadResponse("g"), ProviderBadResponse("g"), ok()], breaker_threshold=3)
        for _ in range(6):
            try:
                c.complete_json("s", "u")
            except ByoCallFailed:
                pass
        self.assertFalse(c.tripped)

    def test_breaker_is_per_client_instance(self):
        a, _, _ = make([ProviderAuthError("bad key")])
        with self.assertRaises(ByoCallFailed):
            a.complete_json("s", "u")
        b, _, _ = make([ok()])
        b.complete_json("s", "u")                        # a fresh scan gets a fresh client
        self.assertFalse(b.tripped)


class ConcurrencyTests(SimpleTestCase):
    def test_semaphore_caps_parallel_requests(self):
        prov = ScriptedProvider([], delay=0.05)
        client = ByoClient(prov, max_concurrency=2, sleep=lambda s: None)
        threads = [threading.Thread(target=client.complete_json, args=("s", "u")) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(prov.calls, 8)
        self.assertLessEqual(prov.max_active, 2)
        self.assertEqual(client.stats.calls, 8)


class ReportIsolationTests(SimpleTestCase):
    """Mitigation-writing calls must never cost verification any coverage."""

    def report(self, c):
        return c.complete_json("s", "u", purpose="report")

    def test_report_calls_are_counted_apart_but_share_tokens(self):
        c, p, _ = make([ok(i=10, o=5), ok(i=20, o=8)])
        c.complete_json("s", "u")
        self.report(c)
        d = c.stats.as_dict()
        self.assertEqual((d["calls"], d["report_calls"], d["failures"], d["report_failures"]), (1, 1, 0, 0))
        self.assertEqual((d["tokens_in"], d["tokens_out"]), (30, 13))

    def test_report_failures_never_open_the_verification_breaker(self):
        c, p, _ = make([ProviderBadResponse("junk")] * 20, breaker_threshold=3)
        for _ in range(8):
            try:
                self.report(c)
            except ByoCallFailed:
                pass
        self.assertFalse(c.tripped)                       # verification is untouched
        p.outcomes = [ok()]
        c.complete_json("s", "u")                         # and still works
        self.assertEqual(c.stats.failures, 0)

    def test_report_breaker_stops_further_report_calls_only(self):
        c, p, _ = make([ProviderBadResponse("junk")] * 3 + [ok(), ok()], breaker_threshold=3)
        for _ in range(3):
            with self.assertRaises(ByoCallFailed):
                self.report(c)
        self.assertTrue(c.report_tripped)
        calls_before = p.calls
        with self.assertRaises(ByoUnavailable):
            self.report(c)
        self.assertEqual(p.calls, calls_before)           # no request was made
        c.complete_json("s", "u")                         # verification still runs
        self.assertEqual(p.calls, calls_before + 1)
        self.assertFalse(c.tripped)

    def test_a_fatal_report_error_only_stops_reports(self):
        c, p, _ = make([ProviderAuthError("bad key"), ok()])
        with self.assertRaises(ByoCallFailed):
            self.report(c)
        self.assertTrue(c.report_tripped)
        self.assertFalse(c.tripped)
        c.complete_json("s", "u")

    def test_verification_failures_do_not_count_toward_the_report_breaker(self):
        c, p, _ = make([ProviderBadResponse("junk")] * 2 + [ok()], breaker_threshold=3)
        for _ in range(2):
            with self.assertRaises(ByoCallFailed):
                c.complete_json("s", "u")
        self.report(c)
        self.assertFalse(c.report_tripped)

    def test_a_dead_connection_stops_report_calls_too(self):
        c, p, _ = make([ProviderAuthError("bad key")])
        with self.assertRaises(ByoCallFailed):
            c.complete_json("s", "u")
        with self.assertRaises(ByoUnavailable):
            self.report(c)
        self.assertEqual(p.calls, 1)

    def test_a_success_resets_the_report_failure_streak(self):
        c, p, _ = make([ProviderBadResponse("j"), ProviderBadResponse("j"), ok(),
                        ProviderBadResponse("j"), ProviderBadResponse("j"), ok()], breaker_threshold=3)
        for _ in range(6):
            try:
                self.report(c)
            except ByoCallFailed:
                pass
        self.assertFalse(c.report_tripped)

    def test_report_calls_retry_like_any_other(self):
        c, p, sleeps = make([ProviderUnavailable("down"), ok()])
        self.report(c)
        self.assertEqual(sleeps, [1.0])
        self.assertEqual(c.stats.retries, 1)
