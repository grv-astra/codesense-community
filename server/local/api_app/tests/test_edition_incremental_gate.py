import os
from unittest import mock

from django.test import SimpleTestCase, override_settings
from licenses.services import entitlements as ent
from local.api_app.views import scan_views


class IncrementalEditionGateTests(SimpleTestCase):
    def setUp(self):
        patcher = mock.patch.dict(os.environ, {}, clear=False)
        patcher.start()
        os.environ.pop("ENTITLEMENTS_PUBLIC_KEY", None)
        os.environ.pop("CODESENSE_EDITION", None)
        self.addCleanup(patcher.stop)
        ent.reload()
        self.addCleanup(ent.reload)

    @override_settings(CODESENSE_EDITION="community", ENTITLEMENTS_PUBLIC_KEY=None)
    def test_community_forces_full_scan(self):
        ent.reload()
        self.assertIsNone(scan_views._effective_project_id("real-project-id"))

    @override_settings(CODESENSE_EDITION="pro", ENTITLEMENTS_PUBLIC_KEY=None)
    def test_pro_keeps_project_id(self):
        ent.reload()
        self.assertEqual(scan_views._effective_project_id("real-project-id"),
                         "real-project-id")
