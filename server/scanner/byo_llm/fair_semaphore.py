"""A first-come, first-served counting semaphore.

``threading.BoundedSemaphore`` lets a thread that has just released a permit take it again before a thread that
has waited longer wakes up. The scanner's workers do exactly that (finish a finding, start the next one at once), so
with more workers than permits the same few workers kept the permits while the others starved for as long as there
was work left. Their findings sat unfinished at the head of the in-order result stream, and the scan's progress
counter and findings list stopped moving.

Here a released permit is handed straight to the longest waiter, so callers are served in arrival order and nobody
can barge in. The cost is one lock and one small queue operation per call, which is nothing next to an HTTP request.
"""
from __future__ import annotations

import threading
from collections import deque


class FairSemaphore:
    def __init__(self, value: int = 1):
        if value < 1:
            raise ValueError("FairSemaphore needs an initial value of at least 1.")
        self._initial = value
        self._free = value
        self._waiters: deque[threading.Event] = deque()
        self._lock = threading.Lock()

    @property
    def waiting(self) -> int:
        with self._lock:
            return len(self._waiters)

    def acquire(self, timeout: float | None = None) -> bool:
        with self._lock:
            if self._free > 0 and not self._waiters:
                self._free -= 1
                return True
            ticket = threading.Event()
            self._waiters.append(ticket)
        if ticket.wait(timeout):
            return True
        with self._lock:
            if ticket.is_set():             # a permit was handed over just as the wait timed out: keep it
                return True
            self._waiters.remove(ticket)
            return False

    def release(self) -> None:
        with self._lock:
            if self._waiters:
                self._waiters.popleft().set()   # hand the permit over directly; the free count is unchanged
            elif self._free < self._initial:
                self._free += 1
            else:
                raise ValueError("FairSemaphore released too many times.")

    def __enter__(self) -> "FairSemaphore":
        self.acquire()
        return self

    def __exit__(self, *exc) -> None:
        self.release()
