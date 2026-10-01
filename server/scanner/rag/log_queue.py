"""Decouples all application logging from the underlying I/O.

Root cause of the multi-day scan-hang investigation (2026-08): a single thread
blocked writing a log record (console screen buffer full when the process is
attached to an interactive console -- confirmed via `scanner/rag/__init__.py`'s
``logging.basicConfig()`` defaulting to ``StreamHandler(sys.stderr)`` with no
explicit stream/filename) holds that handler's lock. Because every logger in
the app propagates up to root, EVERY thread that subsequently tries to log
anything -- waitress's request handling, the LSAST worker threads, the main
scan thread -- piles up behind that same lock. A live py-spy thread dump on a
stuck process confirmed this exactly: all 13 threads blocked in
``logging.Handler.handle()``/``acquire()``, one of them (the lock holder)
one frame deeper, inside ``emit()``, blocked on the actual stream write.

Fix: application threads never touch a real (I/O-bound) handler directly.
They only push onto an in-memory queue via ``QueueHandler``, which never
blocks. One dedicated background thread drains the queue and does the actual
writes -- so if a write ever hangs again, it stalls only that one thread, not
the rest of the process.
"""
from __future__ import annotations

import logging
import logging.handlers
import queue
import threading

_log_queue: "queue.Queue[logging.LogRecord]" = queue.Queue(-1)  # unbounded
_real_handlers: list[logging.Handler] = []
_lock = threading.Lock()
_started = False


def _drain_loop() -> None:
    while True:
        record = _log_queue.get()
        with _lock:
            handlers = list(_real_handlers)
        for handler in handlers:
            try:
                if record.levelno >= handler.level:
                    handler.handle(record)
            except Exception:
                # A handler write hanging is exactly the bug this module
                # exists to contain -- it must never propagate out and it
                # must never be allowed to crash the drain thread, since
                # that would silently stop ALL logging in the process.
                pass


def init_queued_logging() -> None:
    """Call once, as early as possible (right after whatever configures the
    root logger's handlers, e.g. ``logging.basicConfig()``). Moves the root
    logger's existing handlers behind the queue and makes the root logger's
    only direct handler a non-blocking ``QueueHandler`` -- every logger in
    the app propagates to root by default, so this covers all of them,
    including third-party loggers (waitress, django) that were never
    explicitly configured.
    """
    global _started
    if _started:
        return
    root = logging.getLogger()
    with _lock:
        _real_handlers.extend(root.handlers)
    root.handlers = []
    root.addHandler(logging.handlers.QueueHandler(_log_queue))
    threading.Thread(target=_drain_loop, name="log-drain", daemon=True).start()
    _started = True


def add_handler(handler: logging.Handler) -> None:
    """Register an additional handler with the drain thread (e.g. a per-scan
    FileHandler) -- its emit() now runs on the drain thread, never on the
    caller's thread."""
    with _lock:
        _real_handlers.append(handler)


def remove_handler(handler: logging.Handler) -> None:
    with _lock:
        if handler in _real_handlers:
            _real_handlers.remove(handler)
