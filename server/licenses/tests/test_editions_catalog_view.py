import os
from datetime import datetime, timezone
from unittest import mock

from django.test import TestCase, override_settings

from licenses.editions import FEATURE_KEYS, LIMIT_KEYS
from licenses.services import entitlements as ent
from local.api_app.models.orm import Project


@override_settings(CODESENSE_EDITION=None, ENTITLEMENTS_PUBLIC_KEY=None)
class EditionsCatalogViewTests(TestCase):
    def setUp(self):
        self._env = mock.patch.dict(os.environ, {}, clear=False)
        self._env.start()
        os.environ.pop("CODESENSE_EDITION", None)
        os.environ.pop("ENTITLEMENTS_PUBLIC_KEY", None)
        self.addCleanup(self._env.stop)
        ent.reload()
        self.addCleanup(ent.reload)

    def test_catalog_shape(self):
        r = self.client.get("/api/editions/")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(body["feature_keys"], list(FEATURE_KEYS))
        self.assertEqual(body["limit_keys"], list(LIMIT_KEYS))
        self.assertEqual([e["edition"] for e in body["editions"]],
                         ["community", "pro", "enterprise"])
        pro = next(e for e in body["editions"] if e["edition"] == "pro")
        self.assertTrue(pro["features"]["llm_analysis"])
        self.assertEqual(pro["limits"]["projects"], 10)
        ent_ent = next(e for e in body["editions"] if e["edition"] == "enterprise")
        self.assertIsNone(ent_ent["limits"]["projects"])

    def test_active_block_reports_running_edition_and_usage(self):
        Project.objects.create(name="p", created_at=datetime.now(timezone.utc))
        r = self.client.get("/api/editions/")
        active = r.json()["active"]
        self.assertEqual(active["edition"], "community")
        self.assertEqual(active["source"], "default")
        self.assertEqual(active["usage"]["projects"], 1)

    @override_settings(CODESENSE_EDITION="enterprise")
    def test_active_block_follows_env_override(self):
        ent.reload()
        r = self.client.get("/api/editions/")
        active = r.json()["active"]
        self.assertEqual(active["edition"], "enterprise")
        self.assertEqual(active["source"], "env")

    def test_endpoint_reachable_when_unactivated_and_survives_failure(self):
        # allow-listed past ActivationRequiredMiddleware, and defensive on error
        with mock.patch("licenses.views._entitlements.get",
                        side_effect=RuntimeError("boom")):
            r = self.client.get("/api/editions/")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["active"]["source"], "error")
        # the static catalog is still fully present
        self.assertEqual(len(r.json()["editions"]), 3)
