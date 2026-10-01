import os
from unittest import mock

from django.test import TestCase, override_settings
from rest_framework.request import Request
from rest_framework.test import APIRequestFactory

from licenses.services import entitlements as ent
from local.api_app.models.apikey_model import ApiKeyModel
from local.auth_app.permissions.decorators import require_permission


class _DummyCreateScanView:
    @require_permission("create_scan")
    def post(self, request):
        return {"ok": True, "user": request.user}


class _DummyUpdateProjectView:
    @require_permission("update_project")
    def post(self, request):
        return {"ok": True}


def _request_with_auth(header_value):
    factory = APIRequestFactory()
    django_request = factory.post("/whatever/", data={}, format="json")
    request = Request(django_request)
    request.META["HTTP_AUTHORIZATION"] = header_value
    return request


# API-key auth requires the Pro/Enterprise "api_access" feature gate (editions F4);
# pin this class to Pro so these auth-behaviour tests run under an edition that
# permits API keys at all. Assertions are unchanged.
@override_settings(CODESENSE_EDITION="pro", ENTITLEMENTS_PUBLIC_KEY=None)
class RequirePermissionApiKeyTests(TestCase):
    def setUp(self):
        patcher = mock.patch.dict(os.environ, {}, clear=False)
        patcher.start()
        os.environ.pop("ENTITLEMENTS_PUBLIC_KEY", None)
        os.environ.pop("CODESENSE_EDITION", None)
        self.addCleanup(patcher.stop)
        ent.reload()
        self.addCleanup(ent.reload)

    def test_valid_api_key_grants_create_scan(self):
        _, plaintext = ApiKeyModel.create(project_id="proj1", name="ci", created_by="admin1")
        request = _request_with_auth(f"Bearer {plaintext}")
        response = _DummyCreateScanView().post(request)
        self.assertEqual(response["ok"], True)
        self.assertEqual(response["user"]["role"], "service")
        self.assertEqual(response["user"]["project_id"], "proj1")

    def test_revoked_api_key_rejected(self):
        row, plaintext = ApiKeyModel.create(project_id="proj1", name="ci", created_by="admin1")
        ApiKeyModel.revoke(row.id, "proj1")
        request = _request_with_auth(f"Bearer {plaintext}")
        response = _DummyCreateScanView().post(request)
        self.assertEqual(response.status_code, 401)

    def test_unknown_api_key_rejected(self):
        request = _request_with_auth("Bearer csk_totallyunknown")
        response = _DummyCreateScanView().post(request)
        self.assertEqual(response.status_code, 401)

    def test_api_key_cannot_access_non_create_scan_permission(self):
        _, plaintext = ApiKeyModel.create(project_id="proj1", name="ci", created_by="admin1")
        request = _request_with_auth(f"Bearer {plaintext}")
        response = _DummyUpdateProjectView().post(request)
        self.assertEqual(response.status_code, 403)
