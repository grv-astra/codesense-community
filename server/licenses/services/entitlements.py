"""Resolve the *running* edition, fully offline.

Order (fail-SAFE -- any error resolves DOWN to Community, never up):
  1. DATA_DIR/entitlements.json, if present:
       - unreadable / not JSON / no "payload"      -> community  (warn)
       - ENTITLEMENTS_PUBLIC_KEY set:
           valid Ed25519 signature over canonical payload -> use payload (source="signed")
           invalid / missing signature                    -> community (warn "signature")
       - ENTITLEMENTS_PUBLIC_KEY unset (dev build):
           accept payload unverified (source="unsigned-file", warn)
       - payload.edition not in EDITIONS            -> community  (warn)
       - expires_at in the past                     -> community  (warn "expired")
  2. else CODESENSE_EDITION env in {community,pro,enterprise} -> that (source="env")
  3. else                                                    -> community (source="default")

``overrides`` in the payload (limits / features / model_tier) are applied ONLY when
source == "signed".

Result is cached for the process, keyed by (path, file mtime). Call ``reload()`` after
swapping the file in place, or from tests.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from django.conf import settings

from licenses.editions import DEFAULT_EDITION, EDITIONS, edition_spec

_FILENAME = "entitlements.json"
_VALID = set(EDITIONS)

SOURCE_SIGNED = "signed"
SOURCE_UNSIGNED_FILE = "unsigned-file"
SOURCE_ENV = "env"
SOURCE_DEFAULT = "default"


@dataclass(frozen=True)
class Entitlements:
    edition: str
    source: str                       # "signed" | "unsigned-file" | "env" | "default"
    customer: str = ""
    issued_at: str = ""
    expires_at: str | None = None
    warnings: tuple[str, ...] = ()
    _overrides: dict = field(default_factory=dict, repr=False, compare=False)

    def feature(self, name: str) -> bool:
        spec = edition_spec(self.edition)["features"]
        if self.source == SOURCE_SIGNED:
            spec = {**spec, **self._overrides.get("features", {})}
        return bool(spec.get(name, False))

    def limit(self, name: str) -> int | None:
        spec = edition_spec(self.edition)["limits"]
        if name not in spec:
            return None
        if self.source == SOURCE_SIGNED and name in self._overrides.get("limits", {}):
            return self._overrides["limits"][name]
        return spec[name]

    @property
    def model_tier(self) -> str:
        base = edition_spec(self.edition)["model_tier"]
        if self.source == SOURCE_SIGNED:
            ov = self._overrides.get("model_tier")
            if ov in {"low", "mid", "high"}:
                return ov
        return base

    def to_public_dict(self) -> dict:
        spec = edition_spec(self.edition)
        return {
            "edition": self.edition,
            "label": spec["label"],
            "source": self.source,
            "customer": self.customer,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "features": {k: self.feature(k) for k in spec["features"]},
            "limits": {k: self.limit(k) for k in spec["limits"]},
            "model_tier": self.model_tier,
            "warnings": list(self.warnings),
        }


_cache: tuple[object, Entitlements] | None = None


def reload() -> None:
    global _cache
    _cache = None


def _file_path() -> Path:
    return Path(getattr(settings, "DATA_DIR")) / _FILENAME


def _public_key_pem() -> str:
    return (os.getenv("ENTITLEMENTS_PUBLIC_KEY")
            or getattr(settings, "ENTITLEMENTS_PUBLIC_KEY", None) or "").strip()


def _env_edition() -> str:
    return (os.getenv("CODESENSE_EDITION")
            or getattr(settings, "CODESENSE_EDITION", None) or "").strip().lower()


def _canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _default(*warnings: str) -> Entitlements:
    return Entitlements(edition=DEFAULT_EDITION, source=SOURCE_DEFAULT, warnings=tuple(warnings))


def _expired(expires_at) -> bool:
    if not expires_at:
        return False
    if not isinstance(expires_at, str):
        return True  # non-string expiry = unparsable = treat as expired (fail safe)
    try:
        dt = datetime.fromisoformat(expires_at)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt < datetime.now(timezone.utc)
    except (ValueError, TypeError):
        return True


def _verify(canonical: bytes, signature: str, pem: str) -> bool:
    if not signature:
        return False
    try:
        from licenses.services.crypto import load_public_key_from_pem, verify_signature
        return verify_signature(load_public_key_from_pem(pem), canonical, signature)
    except Exception:
        return False


def _resolve() -> Entitlements:
    path = _file_path()

    if path.exists():
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
            payload = doc["payload"]
            if not isinstance(payload, dict):
                raise TypeError("payload is not an object")
        except Exception:
            return _default(f"{_FILENAME} unreadable; defaulting to Community")

        signature = str(doc.get("signature", ""))
        pem = _public_key_pem()
        warnings: list[str] = []

        if pem:
            if not _verify(_canonical(payload), signature, pem):
                return _default("entitlements signature invalid; defaulting to Community")
            source = SOURCE_SIGNED
        else:
            source = SOURCE_UNSIGNED_FILE
            warnings.append("entitlements file not verified (no public key in this build)")

        edition = str(payload.get("edition", "")).lower()
        if edition not in _VALID:
            return _default(f"unknown edition {edition!r}; defaulting to Community")

        if _expired(payload.get("expires_at")):
            return _default(
                f"entitlements expired on {payload.get('expires_at')}; defaulting to Community"
            )

        return Entitlements(
            edition=edition,
            source=source,
            customer=str(payload.get("customer", "")),
            issued_at=str(payload.get("issued_at", "")),
            expires_at=payload.get("expires_at"),
            warnings=tuple(warnings),
            _overrides=payload.get("overrides", {}) or {},
        )

    env = _env_edition()
    if env in _VALID:
        return Entitlements(edition=env, source=SOURCE_ENV)

    return _default()


def get() -> Entitlements:
    """The resolved Entitlements for this process. Cheap: one os.stat unless the
    file changed since last call."""
    global _cache
    path = _file_path()
    try:
        mtime = path.stat().st_mtime_ns
    except OSError:
        mtime = None
    key = (mtime, _env_edition(), bool(_public_key_pem()))
    if _cache is not None and _cache[0] == key:
        return _cache[1]
    resolved = _resolve()
    _cache = (key, resolved)
    return resolved
