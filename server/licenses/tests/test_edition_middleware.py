import os
from unittest import mock

from django.test import SimpleTestCase, override_settings
from licenses.services import entitlements as ent


class EditionHeaderMiddlewareTests(SimpleTestCase):
    def setUp(self):
        # Edition resolution reads os.environ before Django settings, and a developer's
        # git-ignored server/.env (python-dotenv) may set CODESENSE_EDITION=pro. Isolate
        # the environment so these tests do not depend on the machine they run on.
        env = mock.patch.dict(os.environ)
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop("CODESENSE_EDITION", None)
        os.environ.pop("ENTITLEMENTS_PUBLIC_KEY", None)
        ent.reload()
        self.addCleanup(ent.reload)

    @override_settings(CODESENSE_EDITION="pro", ENTITLEMENTS_PUBLIC_KEY=None)
    def test_header_added_to_response(self):
        resp = self.client.get("/api/license/")
        self.assertEqual(resp.headers.get("X-CodeSense-Edition"), "pro")

    def test_middleware_never_breaks_the_response(self):
        with override_settings(DATA_DIR="/nonexistent/x", ENTITLEMENTS_PUBLIC_KEY=None,
                               CODESENSE_EDITION=None):
            resp = self.client.get("/api/license/")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.headers.get("X-CodeSense-Edition"), "community")
