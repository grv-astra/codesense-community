"""AI-verification (bring-your-own LLM) settings API. Rules live in
scanner.byo_llm.settings_service; these views only do auth, edition gating and I/O.

Writes are admin-only and reachable only with a user JWT (never an API key).
Nothing here ever returns the API key.
"""
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from local.auth_app.permissions.decorators import require_permission, require_role
from scanner.byo_llm import settings_service as svc
from scanner.byo_llm import store


def _edition_gate():
    from licenses.services import entitlements
    if not entitlements.get().feature("byo_llm"):
        return Response({"error": "Connecting your own LLM is not available in this edition."},
                        status=status.HTTP_403_FORBIDDEN)
    return None


def _bad_request(exc: svc.SettingsError) -> Response:
    body = {"error": str(exc)}
    if exc.field:
        body["field"] = exc.field
    return Response(body, status=status.HTTP_400_BAD_REQUEST)


def _user_id(request) -> str:
    return request.user.get("id", "") if isinstance(request.user, dict) else ""


class LLMSettingsView(APIView):
    @require_role("admin")
    def get(self, request):
        return _edition_gate() or Response(svc.serialize(store.load()), status=status.HTTP_200_OK)

    @require_role("admin")
    def put(self, request):
        blocked = _edition_gate()
        if blocked:
            return blocked
        conn = store.load()
        try:
            svc.apply_update(conn, request.data, _user_id(request))
        except svc.SettingsError as exc:
            return _bad_request(exc)
        return Response(svc.serialize(conn), status=status.HTTP_200_OK)


class LLMTestView(APIView):
    @require_role("admin")
    def post(self, request):
        blocked = _edition_gate()
        if blocked:
            return blocked
        try:
            result = svc.check_connection(store.load(), request.data)
        except svc.SettingsError as exc:
            return _bad_request(exc)
        return Response(result, status=status.HTTP_200_OK)


class LLMStatusView(APIView):
    """Feeds the dashboard health light. Served from stored state; makes no LLM call."""

    @require_permission("view_scans")
    def get(self, request):
        from licenses.services import entitlements
        ent = entitlements.get()
        conn = store.load() if ent.feature("byo_llm") else None
        return Response(svc.status(conn, bundled_available=bool(ent.feature("llm_analysis"))),
                        status=status.HTTP_200_OK)
