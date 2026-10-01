"""Shared helpers for tests that straddle the llm_analysis edition boundary.

`scanner.rag.llm` / `scanner.rag.llm_verifier` / `scanner.rag.report_enricher`
are excluded from a generated Community export (docs/EDITIONS-REPO-SPLIT.md
§1a, §3) -- they genuinely don't exist there, not just "gated off". A test that
does `mock.patch("scanner.rag.llm.llm_health")` needs that module to exist just
to resolve the patch target, even in a test whose actual assertion never
depends on the module being present (e.g. proving Community's short-circuit
happens BEFORE any such import is attempted). Use these helpers instead of a
bare `mock.patch(...)` / `@mock.patch(...)` wherever a test's own logic doesn't
inherently require the llm subsystem to exist.

Tests that DO inherently require it (e.g. asserting a mocked verify() verdict
drives fusion output) should stay as plain `mock.patch(...)` and instead be
skipped outright on an edition without it, via `skip_unless_llm_present`.
"""
from __future__ import annotations

import importlib.util
import unittest
from contextlib import contextmanager
from unittest import mock

LLM_SUBSYSTEM_PRESENT = importlib.util.find_spec("scanner.rag.llm") is not None


def skip_unless_llm_present(reason: str = "tests the llm_analysis (Pro/Enterprise) code path; "
                                           "scanner.rag.llm et al. are absent from a Community export"):
    """Class or method decorator. Must be the OUTERMOST decorator on a method
    also wrapped in @mock.patch(...) -- mock.patch only resolves its target at
    call time, so skipping first means the (possibly-missing) module is never
    touched."""
    return unittest.skipUnless(LLM_SUBSYSTEM_PRESENT, reason)


class _NullSpy:
    """Stand-in for a mock.patch() handle when its target module doesn't exist
    in this edition. The module was never going to be imported either way, so
    "it was never called" is trivially, unconditionally true."""

    def assert_not_called(self):
        pass

    def __getattr__(self, name):
        raise AssertionError(
            f"_NullSpy.{name}(): scanner.rag.llm subsystem isn't present in this "
            "edition, so nothing was ever recorded to assert on beyond "
            "assert_not_called()."
        )


@contextmanager
def patch_if_present(target: str, **kwargs):
    """`mock.patch(target, **kwargs)` when the target's module exists, else a
    no-op yielding a `_NullSpy` -- for tests whose OWN code path never reaches
    the lazy import being stood in for (e.g. Community's llm_ok=False branch),
    so the test is meaningful and hermetic where the subsystem exists, and
    simply doesn't error where it doesn't."""
    module_path, _, _attr = target.rpartition(".")
    if importlib.util.find_spec(module_path) is None:
        yield _NullSpy()
        return
    with mock.patch(target, **kwargs) as m:
        yield m
