"""Per-scan log file covering the semgrep + LLM verification stages.

Captures exactly the two stages that were silent in the shared app log while
debugging the client on-prem hang (2026-08-17): the semgrep subprocess call
and the per-finding LLM verify/enrich loop. Written to its own file per scan
so one file can be handed to a client for one incident, rather than grepping
the whole app log for a scan_id.

Implementation: register a filtered FileHandler with the process-wide
log-drain thread (see log_queue.py) for the duration of the scan, rather than
attaching it directly to the scoped loggers. Attaching directly would mean
its emit() (the actual disk write) runs synchronously on whichever
scan/request thread happens to be logging -- exactly the mechanism that
caused the multi-day hang this feature was built to diagnose. Going through
the queue means the write always happens on the dedicated drain thread, so
even a hung write can only ever stall itself.
"""
from __future__ import annotations

import logging
import os
from contextlib import contextmanager

from scanner.rag.log_queue import add_handler, remove_handler

_SCOPED_LOGGER_NAMES = (
    "scanner.rag.semgrep_detector",
    "scanner.rag.lsast_scanner",
    "scanner.rag.llm",
    "scanner.rag.llm_verifier",
    "scanner.rag.report_enricher",
    # The catch-all "Error during scan" + traceback -- the pipeline's outer
    # exception handler, which fires on anything NOT already logged by the
    # loggers above (e.g. an uncaught exception from the semgrep subprocess
    # call itself). Without this, a scan that dies via that path would be
    # missing from its own scan.log.
    "local.api_app.views.scan_views",
)

_FORMAT = "%(asctime)s - %(levelname)s - %(name)s - %(message)s"


def scan_log_path(scan_dir: str) -> str:
    return os.path.join(scan_dir, "scan.log")


class _ScopedLoggerFilter(logging.Filter):
    """Only pass records from this scan's own loggers (or their children)."""

    def __init__(self, names: tuple[str, ...]):
        super().__init__()
        self._names = names

    def filter(self, record: logging.LogRecord) -> bool:
        return any(record.name == n or record.name.startswith(n + ".") for n in self._names)


@contextmanager
def scan_log_context(scan_dir: str):
    """Register a per-scan FileHandler with the log-drain thread for the
    duration of the `with` block; always deregistered again in `finally`,
    even on an exception, so it never leaks onto a later scan's log lines.
    """
    os.makedirs(scan_dir, exist_ok=True)
    handler = logging.FileHandler(scan_log_path(scan_dir), encoding="utf-8")
    handler.setFormatter(logging.Formatter(_FORMAT))
    handler.setLevel(logging.INFO)
    handler.addFilter(_ScopedLoggerFilter(_SCOPED_LOGGER_NAMES))

    add_handler(handler)
    try:
        yield
    finally:
        remove_handler(handler)
        handler.close()
