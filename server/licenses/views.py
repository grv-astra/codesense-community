import logging

from rest_framework.response import Response
from rest_framework.views import APIView

from licenses.services.offline_license import get_state
from licenses.services import activation, trial
from licenses.services import entitlements as _entitlements
from licenses.services import limits as _limits

logger = logging.getLogger(__name__)


class LicenseStatusView(APIView):
    """GET /api/license/ — current offline license state for the UI banner."""

    def get(self, request):
        return Response(get_state())


class TrialStatusView(APIView):
    """GET /api/trial/ — trial-mode scan usage for the UI (trial_mode/limit/used/remaining)."""

    def get(self, request):
        return Response(trial.status())


class ActivationView(APIView):
    """GET checks activation status; POST redeems the one-time password for
    this machine. See licenses.services.activation."""

    def get(self, request):
        return Response({
            "configured": activation.is_configured(),
            "activated": activation.is_activated(),
        })

    def post(self, request):
        password = request.data.get("password", "")
        if activation.activate(password):
            return Response({"activated": True})
        return Response(
            {"activated": False, "detail": "Incorrect activation password."},
            status=403,
        )


class EditionStatusView(APIView):
    """GET /api/edition/ — resolved edition, feature flags, limits, and live usage
    for the UI badge + quota display. Read-only; same open posture as
    LicenseStatusView."""

    def get(self, request):
        try:
            payload = _entitlements.get().to_public_dict()
        except Exception:
            logger.exception("entitlements.get() failed for /api/edition/")
            from licenses.editions import EDITIONS, DEFAULT_EDITION
            spec = EDITIONS[DEFAULT_EDITION]
            payload = {
                "edition": DEFAULT_EDITION, "label": spec["label"], "source": "error",
                "customer": "", "issued_at": "", "expires_at": None,
                "features": dict(spec["features"]), "limits": dict(spec["limits"]),
                "model_tier": spec["model_tier"],
                "warnings": ["edition resolution failed; showing Community"],
            }
        try:
            payload["usage"] = _limits.usage_snapshot()
        except Exception:
            logger.exception("usage_snapshot() failed for /api/edition/")
            payload["usage"] = {}
        return Response(payload)


class EditionsCatalogView(APIView):
    """GET /api/editions/ — the full Community/Pro/Enterprise catalog (feature
    flags + limits per edition) plus which one is active and its live usage, for
    the /plans comparison page. Read-only; same open posture as
    EditionStatusView (renders on a not-yet-activated / read-only install)."""

    def get(self, request):
        from licenses.editions import (
            DEFAULT_EDITION, FEATURE_KEYS, LIMIT_KEYS, public_catalog,
        )
        payload = {
            "feature_keys": list(FEATURE_KEYS),
            "limit_keys": list(LIMIT_KEYS),
            "editions": public_catalog(),
        }
        try:
            e = _entitlements.get()
            active = {
                "edition": e.edition, "source": e.source, "customer": e.customer,
                "expires_at": e.expires_at, "warnings": list(e.warnings),
            }
        except Exception:
            logger.exception("entitlements.get() failed for /api/editions/")
            active = {
                "edition": DEFAULT_EDITION, "source": "error", "customer": "",
                "expires_at": None,
                "warnings": ["edition resolution failed; showing Community"],
            }
        try:
            active["usage"] = _limits.usage_snapshot()
        except Exception:
            logger.exception("usage_snapshot() failed for /api/editions/")
            active["usage"] = {}
        payload["active"] = active
        return Response(payload)
