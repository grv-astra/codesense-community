"""Edition scale-limit accounting + predicates.

Scan-per-window counts come from the append-only ScanEvent table (never deleted),
so deleting Scan rows can't reset a quota. Project/seat counts are live COUNT(*)
over the respective tables. A limit of None (Enterprise) means unlimited -> the
predicate always returns True.

Predicates are advisory helpers for the view layer; callers 403/413 on a False.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from django.db import DatabaseError

from licenses.services import entitlements
from local.api_app.models.orm import Project, ScanEvent
from local.auth_app.models.orm import User

logger = logging.getLogger(__name__)

CODE = "code"
SBOM = "sbom"

_SCAN_TYPES = (CODE, SBOM)


def _check_type(scan_type: str) -> str:
    if scan_type not in _SCAN_TYPES:
        raise ValueError(f"unknown scan_type: {scan_type!r}")
    return scan_type


def _limit(name: str) -> int | None:
    return entitlements.get().limit(name)


def _window_start() -> datetime:
    days = _limit("window_days")
    if days is None:            # no catalog edition sets this None today; guard anyway
        days = 30
    return datetime.now(timezone.utc) - timedelta(days=days)


def scans_in_window(scan_type: str) -> int:
    _check_type(scan_type)
    return ScanEvent.objects.filter(
        scan_type=scan_type, completed_at__gte=_window_start()
    ).count()


def record_scan(scan_type: str) -> None:
    """Append one ScanEvent. Call right after trial.record_completion at each
    pipeline completion site. Best-effort: a DB error here must never sink the
    scan that triggered it, but it IS logged (a silent failure would under-count
    the quota permanently)."""
    _check_type(scan_type)
    try:
        ScanEvent.objects.create(
            scan_type=scan_type, completed_at=datetime.now(timezone.utc)
        )
    except DatabaseError:  # noqa: BLE001 — quota accounting must not sink a scan
        logger.exception("limits.record_scan(%s) failed to persist", scan_type)


def can_start_scan(scan_type: str) -> bool:
    _check_type(scan_type)
    key = "code_scans_per_window" if scan_type == CODE else "sbom_scans_per_window"
    lim = _limit(key)
    if lim is None:
        return True
    return scans_in_window(scan_type) < lim


def can_create_project() -> bool:
    lim = _limit("projects")
    if lim is None:
        return True
    return Project.objects.filter(deleted=False).count() < lim


def can_add_user() -> bool:
    lim = _limit("seats")
    if lim is None:
        return True
    return User.objects.filter(deleted=False).count() < lim


def codebase_size_ok(size_bytes: int) -> bool:
    lim_mb = _limit("max_codebase_mb")
    if lim_mb is None:
        return True
    return size_bytes <= lim_mb * 1024 * 1024


def usage_snapshot() -> dict:
    """For GET /api/edition/."""
    return {
        "projects": Project.objects.filter(deleted=False).count(),
        "code_scans_in_window": scans_in_window(CODE),
        "sbom_scans_in_window": scans_in_window(SBOM),
        "seats": User.objects.filter(deleted=False).count(),
    }
