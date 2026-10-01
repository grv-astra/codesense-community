"""Static per-edition catalog: which features are on and what the scale limits
are for Community / Pro / Enterprise. Pure data + trivial accessors, NO I/O and
NO Django imports -- safe to import from anywhere (settings, management commands,
pipeline code). The *running* edition is resolved in
``licenses.services.entitlements``; this module only says what each edition means.

Tuning the product's default posture = editing the dict below. A signed
entitlements.json may additionally carry per-customer ``overrides`` (applied in
entitlements.py, signed source only).
"""
from __future__ import annotations

DEFAULT_EDITION = "community"

FEATURE_KEYS = (
    "llm_analysis",        # LLM verifier + report enrichment
    "sbom_signing",        # cosign SBOM signing + verification
    "license_compliance",  # grant license-policy findings
    "api_access",          # REST/CI-CD access via API keys
    "incremental_scan",    # changed-files-only re-scan
    "github_scan",         # clone + scan a GitHub repo
    "sso",                 # RESERVED (Enterprise) -- not yet enforced
    "audit_log",           # RESERVED (Enterprise) -- not yet enforced
)

LIMIT_KEYS = (
    "projects",
    "code_scans_per_window",
    "sbom_scans_per_window",
    "window_days",
    "max_codebase_mb",
    "seats",
)

_ALL_ON = {k: True for k in FEATURE_KEYS}
_UNLIMITED = {k: None for k in LIMIT_KEYS} | {"window_days": 30}

EDITIONS: dict[str, dict] = {
    "community": {
        "label": "Community",
        "model_tier": "low",
        "features": {
            **{k: False for k in FEATURE_KEYS},
            "github_scan": True,
        },
        "limits": {
            "projects": 1,
            "code_scans_per_window": 25,
            "sbom_scans_per_window": 25,
            "window_days": 30,
            "max_codebase_mb": 250,
            "seats": 3,
        },
    },
    "pro": {
        "label": "Pro",
        "model_tier": "mid",
        "features": {
            **_ALL_ON,
            "sso": False,
            "audit_log": False,
        },
        "limits": {
            "projects": 10,
            "code_scans_per_window": 500,
            "sbom_scans_per_window": 500,
            "window_days": 30,
            "max_codebase_mb": 2048,
            "seats": 25,
        },
    },
    "enterprise": {
        "label": "Enterprise",
        "model_tier": "high",
        "features": dict(_ALL_ON),
        "limits": dict(_UNLIMITED),
    },
}


def edition_spec(edition: str) -> dict:
    """The catalog entry for ``edition``, falling back to Community for anything
    unrecognized (callers that care about validity check membership first).

    The returned dict is the live catalog entry and must be treated as
    read-only: callers must not mutate it or its nested ``features``/``limits``.
    """
    return EDITIONS.get(edition, EDITIONS[DEFAULT_EDITION])


# Column order for the /plans comparison UI (cheapest -> richest).
CATALOG_ORDER = ("community", "pro", "enterprise")


def public_catalog() -> list[dict]:
    """Ordered [community, pro, enterprise] catalog entries for the UI /plans
    page. Returns fresh copies -- callers may keep or serialize these freely
    without touching the live ``EDITIONS`` dict."""
    return [
        {
            "edition": name,
            "label": EDITIONS[name]["label"],
            "model_tier": EDITIONS[name]["model_tier"],
            "features": dict(EDITIONS[name]["features"]),
            "limits": dict(EDITIONS[name]["limits"]),
        }
        for name in CATALOG_ORDER
    ]
