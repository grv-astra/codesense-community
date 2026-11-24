"""FairSemaphore: arrival-order service, no barging, timeouts, and the ByoClient wiring."""
import threading
import time

from django.test import SimpleTestCase

from scanner.byo_llm.client import ByoClient
from scanner.byo_llm.fair_semaphore import FairSemaphore
from scanner.byo_llm.providers.base import Provider, ProviderResult


def wait_until(predicate, timeout=5.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return True
        time.sleep(0.005)
    return False


class FairSemaphoreTests(SimpleTestCase):
    def test_serves_waiters_in_arrival_order(self):
        sem = FairSemaphore(1)
        sem.acquire()
        order, threads = [], []

        def waiter(i):
            with sem:
                order.append(i)

        for i in range(6):
            t = threading.Thread(target=waiter, args=(i,))
            t.start()
            threads.append(t)
            self.assertTrue(wait_until(lambda n=i + 1: sem.waiting == n))   # waiter i is queued before i+1 starts
        sem.release()
        for t in threads:
            t.join(5)
        self.assertEqual(order, list(range(6)))

    def test_a_released_permit_cannot_be_taken_by_a_barging_caller(self):
        sem = FairSemaphore(1)
        sem.acquire()
        got, hold = threading.Event(), threading.Event()

        def waiter():
            with sem:
                got.set()
                hold.wait(5)

        t = threading.Thread(target=waiter)
        t.start()
        self.assertTrue(wait_until(lambda: sem.waiting == 1))
        sem.release()                                   # the permit goes to the waiter...
        self.assertFalse(sem.acquire(timeout=0.2))      # ...so releasing and re-acquiring at once must not win it back
        self.assertTrue(got.is_set())
        hold.set()
        t.join(5)

    def test_busy_workers_cannot_starve_a_waiter(self):
        sem = FairSemaphore(2)
        stop, got = threading.Event(), threading.Event()

        def hot():                                      # finish one item, start the next straight away
            while not stop.is_set():
                with sem:
                    time.sleep(0.002)

        hots = [threading.Thread(target=hot) for _ in range(2)]
        for h in hots:
            h.start()
        time.sleep(0.05)

        def late():
            with sem:
                got.set()

        t = threading.Thread(target=late)
        t.start()
        self.assertTrue(got.wait(2.0), "the waiting thread was starved by the busy ones")
        stop.set()
        for h in hots + [t]:
            h.join(5)

    def test_limits_simultaneous_holders(self):
        sem = FairSemaphore(2)
        lock, state = threading.Lock(), {"now": 0, "max": 0}

        def work():
            with sem:
                with lock:
                    state["now"] += 1
                    state["max"] = max(state["max"], state["now"])
                time.sleep(0.02)
                with lock:
                    state["now"] -= 1

        threads = [threading.Thread(target=work) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(5)
        self.assertEqual(state["max"], 2)

    def test_timed_out_waiter_leaves_the_queue_and_leaks_no_permit(self):
        sem = FairSemaphore(1)
        sem.acquire()
        self.assertFalse(sem.acquire(timeout=0.05))
        self.assertEqual(sem.waiting, 0)
        sem.release()
        self.assertTrue(sem.acquire(timeout=0.5))       # the permit was not lost to the timed-out waiter

    def test_release_beyond_the_initial_value_raises(self):
        sem = FairSemaphore(2)
        sem.acquire()
        sem.release()
        with self.assertRaises(ValueError):
            sem.release()

    def test_needs_a_positive_initial_value(self):
        with self.assertRaises(ValueError):
            FairSemaphore(0)


class _SlowProvider(Provider):
    def __init__(self):
        super().__init__(cfg=None)
        self.started = []
        self._lock = threading.Lock()
        self.gate = threading.Event()

    def complete_json(self, system, user, max_tokens=512, *, require_text=True):
        with self._lock:
            self.started.append(user)
        self.gate.wait(5)
        return ProviderResult("{}", 1, 1)


class ClientWiringTests(SimpleTestCase):
    def test_client_serves_concurrent_callers_in_arrival_order(self):
        prov = _SlowProvider()
        client = ByoClient(prov, max_concurrency=1, sleep=lambda s: None, jitter=lambda: 0.0)
        threads = []
        for i in range(5):
            t = threading.Thread(target=client.complete_json, args=("s", f"call-{i}"))
            t.start()
            threads.append(t)
            # call 0 is inside the provider; each later call must be queued on the client's limiter first
            if i:
                self.assertTrue(wait_until(lambda n=i: client._sem.waiting == n))
            else:
                self.assertTrue(wait_until(lambda: len(prov.started) == 1))
        prov.gate.set()
        for t in threads:
            t.join(5)
        self.assertEqual(prov.started, [f"call-{i}" for i in range(5)])
