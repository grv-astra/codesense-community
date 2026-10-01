import os
from unittest import mock

from django.test import SimpleTestCase, override_settings

from licenses.services import entitlements as ent
from local.auth_app.permissions import decorators


class ApiAccessEditionGateTests(SimpleTestCase):
    def setUp(self):
        patcher = mock.patch.dict(os.environ, {}, clear=False)
        patcher.start()
        os.environ.pop("ENTITLEMENTS_PUBLIC_KEY", None)
        os.environ.pop("CODESENSE_EDITION", None)
        self.addCleanup(patcher.stop)
        ent.reload()
        self.addCleanup(ent.reload)

    @override_settings(CODESENSE_EDITION="community", ENTITLEMENTS_PUBLIC_KEY=None)
    def test_api_key_request_rejected_in_community(self):
        @decorators.require_permission("create_scan")
        def view(self_, request):  # pragma: no cover - should not be reached
            return "OK"

        req = mock.Mock()
        req.headers = {"Authorization": "Bearer cs_live_somekey"}
        with mock.patch("local.auth_app.permissions.decorators.is_api_key",
                        return_value=True):
            resp = view(mock.Mock(), req)
        self.assertEqual(resp.status_code, 403)
        self.assertIn("Pro", str(resp.data))

    @override_settings(CODESENSE_EDITION="pro", ENTITLEMENTS_PUBLIC_KEY=None)
    def test_api_key_request_allowed_in_pro(self):
        @decorators.require_permission("create_scan")
        def view(self_, request):
            return "OK"

        req = mock.Mock()
        req.headers = {"Authorization": "Bearer cs_live_somekey"}
        with mock.patch("local.auth_app.permissions.decorators.is_api_key",
                        return_value=True), \
             mock.patch("local.auth_app.permissions.decorators.resolve_api_key",
                        return_value={"id": "apikey:1", "role": "service", "project_id": "p1"}):
            resp = view(mock.Mock(), req)
        self.assertEqual(resp, "OK")
