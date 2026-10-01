import os
from datetime import datetime, timezone
from unittest import mock

from django.test import TestCase, override_settings

from licenses.services import entitlements as ent
from local.api_app.models.orm import Project


@override_settings(CODESENSE_EDITION="community", ENTITLEMENTS_PUBLIC_KEY=None)
class EditionViewTests(TestCase):
    def setUp(self):
        patcher = mock.patch.dict(os.environ, {}, clear=False)
        patcher.start()
        os.environ.pop("CODESENSE_EDITION", None)
        os.environ.pop("ENTITLEMENTS_PUBLIC_KEY", None)
        self.addCleanup(patcher.stop)
        ent.reload()
        self.addCleanup(ent.reload)

    def test_shape(self):
        Project.objects.create(name="p", created_at=datetime.now(timezone.utc))
        r = self.client.get("/api/edition/")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(body["edition"], "community")
        self.assertEqual(body["label"], "Community")
        self.assertIn("features", body)
        self.assertIn("limits", body)
        self.assertEqual(body["usage"]["projects"], 1)
        self.assertFalse(body["features"]["llm_analysis"])
        self.assertEqual(body["model_tier"], "low")

    def test_endpoint_survives_entitlements_failure(self):
        from unittest import mock
        with mock.patch("licenses.views._entitlements.get", side_effect=RuntimeError("boom")):
            r = self.client.get("/api/edition/")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["edition"], "community")
        self.assertEqual(r.json()["source"], "error")
