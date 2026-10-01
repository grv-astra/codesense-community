import json, tempfile
from datetime import datetime, timezone
from pathlib import Path
from django.test import TestCase, override_settings

from licenses.services import crypto
from licenses.services import entitlements as ent
from local.api_app.models.orm import Project


class EditionEndToEndTests(TestCase):
    def setUp(self):
        self._d = tempfile.TemporaryDirectory()
        self.data_dir = Path(self._d.name)
        self.addCleanup(self._d.cleanup)
        self.priv, self.pub = crypto.generate_keypair()
        self.pub_pem = self.pub.public_bytes(
            encoding=crypto.serialization.Encoding.PEM,
            format=crypto.serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        ent.reload(); self.addCleanup(ent.reload)
        # hermetic env guard
        import os
        from unittest import mock
        p = mock.patch.dict(os.environ, {}, clear=False)
        p.start()
        os.environ.pop("CODESENSE_EDITION", None)
        os.environ.pop("ENTITLEMENTS_PUBLIC_KEY", None)
        self.addCleanup(p.stop)

    def _install(self, edition, **payload_over):
        payload = {"edition": edition, "customer": "T",
                   "issued_at": datetime.now(timezone.utc).isoformat(),
                   "expires_at": None, **payload_over}
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        sig = crypto.sign_message(self.priv, canonical)
        (self.data_dir / "entitlements.json").write_text(
            json.dumps({"payload": payload, "signature": sig}))
        ent.reload()

    def test_community_default_then_upgrade_to_enterprise_in_place(self):
        with override_settings(DATA_DIR=self.data_dir, ENTITLEMENTS_PUBLIC_KEY=self.pub_pem,
                               CODESENSE_EDITION=None):
            r = self.client.get("/api/edition/")
            self.assertEqual(r.json()["edition"], "community")
            self.assertEqual(r.headers["X-CodeSense-Edition"], "community")

            Project.objects.create(name="p", created_at=datetime.now(timezone.utc))
            from licenses.services import limits
            self.assertFalse(limits.can_create_project())

            self._install("enterprise")
            r = self.client.get("/api/edition/")
            self.assertEqual(r.json()["edition"], "enterprise")
            self.assertTrue(limits.can_create_project())
            self.assertIsNone(r.json()["limits"]["projects"])

    def test_expired_file_beats_env_and_drops_to_community(self):
        import os
        past = "2020-01-01T00:00:00+00:00"
        with override_settings(DATA_DIR=self.data_dir, ENTITLEMENTS_PUBLIC_KEY=self.pub_pem):
            os.environ["CODESENSE_EDITION"] = "enterprise"   # would be honored ONLY if no file existed
            try:
                self._install("enterprise", expires_at=past)
                r = self.client.get("/api/edition/")
                self.assertEqual(r.json()["edition"], "community")
                self.assertTrue(any("expired" in w for w in r.json()["warnings"]))
            finally:
                os.environ.pop("CODESENSE_EDITION", None)
