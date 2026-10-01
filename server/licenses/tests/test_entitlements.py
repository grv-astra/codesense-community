import json
import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from django.test import SimpleTestCase, override_settings

from licenses.services import crypto
from licenses.services import entitlements as ent


def _canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


class EntitlementsResolutionTests(SimpleTestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.data_dir = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        self.priv, self.pub = crypto.generate_keypair()
        self.pub_pem = self.pub.public_bytes(
            encoding=crypto.serialization.Encoding.PEM,
            format=crypto.serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        patcher = mock.patch.dict(os.environ, {}, clear=False)
        patcher.start()
        os.environ.pop("ENTITLEMENTS_PUBLIC_KEY", None)
        os.environ.pop("CODESENSE_EDITION", None)
        self.addCleanup(patcher.stop)
        ent.reload()
        self.addCleanup(ent.reload)

    def _write_file(self, payload: dict, sign_with=None):
        sig = ""
        if sign_with is not None:
            sig = crypto.sign_message(sign_with, _canonical(payload))
        (self.data_dir / "entitlements.json").write_text(
            json.dumps({"payload": payload, "signature": sig}), encoding="utf-8"
        )

    def _payload(self, **over):
        base = {
            "edition": "pro",
            "customer": "Acme",
            "issued_at": "2026-09-04T00:00:00+00:00",
            "expires_at": None,
        }
        base.update(over)
        return base

    def test_no_file_no_env_defaults_to_community(self):
        with override_settings(DATA_DIR=self.data_dir, ENTITLEMENTS_PUBLIC_KEY=None,
                               CODESENSE_EDITION=None):
            e = ent.get()
        self.assertEqual((e.edition, e.source), ("community", "default"))

    def test_env_edition_used_when_no_file(self):
        with override_settings(DATA_DIR=self.data_dir, ENTITLEMENTS_PUBLIC_KEY=None,
                               CODESENSE_EDITION="enterprise"):
            e = ent.get()
        self.assertEqual((e.edition, e.source), ("enterprise", "env"))

    def test_signed_valid_file(self):
        self._write_file(self._payload(), sign_with=self.priv)
        with override_settings(DATA_DIR=self.data_dir,
                               ENTITLEMENTS_PUBLIC_KEY=self.pub_pem, CODESENSE_EDITION=None):
            e = ent.get()
        self.assertEqual((e.edition, e.source, e.customer), ("pro", "signed", "Acme"))

    def test_signed_but_bad_signature_falls_back_to_community(self):
        self._write_file(self._payload(), sign_with=self.priv)
        p = json.loads((self.data_dir / "entitlements.json").read_text())
        p["payload"]["edition"] = "enterprise"
        (self.data_dir / "entitlements.json").write_text(json.dumps(p), encoding="utf-8")
        with override_settings(DATA_DIR=self.data_dir,
                               ENTITLEMENTS_PUBLIC_KEY=self.pub_pem, CODESENSE_EDITION=None):
            e = ent.get()
        self.assertEqual(e.edition, "community")
        self.assertTrue(any("signature" in w for w in e.warnings))

    def test_unsigned_file_without_pubkey_is_accepted_with_warning(self):
        self._write_file(self._payload(), sign_with=None)
        with override_settings(DATA_DIR=self.data_dir, ENTITLEMENTS_PUBLIC_KEY=None,
                               CODESENSE_EDITION=None):
            e = ent.get()
        self.assertEqual((e.edition, e.source), ("pro", "unsigned-file"))
        self.assertTrue(e.warnings)

    def test_expired_file_falls_back_to_community(self):
        past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        self._write_file(self._payload(expires_at=past), sign_with=self.priv)
        with override_settings(DATA_DIR=self.data_dir,
                               ENTITLEMENTS_PUBLIC_KEY=self.pub_pem, CODESENSE_EDITION=None):
            e = ent.get()
        self.assertEqual(e.edition, "community")
        self.assertTrue(any("expired" in w for w in e.warnings))

    def test_unknown_edition_falls_back(self):
        self._write_file(self._payload(edition="ultra"), sign_with=self.priv)
        with override_settings(DATA_DIR=self.data_dir,
                               ENTITLEMENTS_PUBLIC_KEY=self.pub_pem, CODESENSE_EDITION=None):
            e = ent.get()
        self.assertEqual(e.edition, "community")

    def test_overrides_apply_for_signed_only(self):
        self._write_file(self._payload(overrides={"limits": {"projects": 99}}),
                         sign_with=self.priv)
        with override_settings(DATA_DIR=self.data_dir,
                               ENTITLEMENTS_PUBLIC_KEY=self.pub_pem, CODESENSE_EDITION=None):
            e = ent.get()
        self.assertEqual(e.limit("projects"), 99)

    def test_overrides_ignored_for_env_source(self):
        with override_settings(DATA_DIR=self.data_dir, ENTITLEMENTS_PUBLIC_KEY=None,
                               CODESENSE_EDITION="pro"):
            e = ent.get()
        self.assertEqual(e.limit("projects"), 10)

    def test_feature_and_limit_and_model_tier(self):
        with override_settings(DATA_DIR=self.data_dir, ENTITLEMENTS_PUBLIC_KEY=None,
                               CODESENSE_EDITION="community"):
            e = ent.get()
        self.assertFalse(e.feature("llm_analysis"))
        self.assertEqual(e.limit("projects"), 1)
        self.assertIsNone(e.limit("does_not_exist"))
        self.assertEqual(e.model_tier, "low")

    def test_corrupt_file_falls_back_to_community(self):
        (self.data_dir / "entitlements.json").write_text("{ not json", encoding="utf-8")
        with override_settings(DATA_DIR=self.data_dir, ENTITLEMENTS_PUBLIC_KEY=None,
                               CODESENSE_EDITION=None):
            e = ent.get()
        self.assertEqual(e.edition, "community")
        self.assertTrue(any("unreadable" in w for w in e.warnings))

    def test_non_string_expires_at_falls_back_to_community(self):
        self._write_file(self._payload(expires_at=1798761600), sign_with=self.priv)
        with override_settings(DATA_DIR=self.data_dir,
                               ENTITLEMENTS_PUBLIC_KEY=self.pub_pem, CODESENSE_EDITION=None):
            e = ent.get()
        self.assertEqual(e.edition, "community")

    def test_payload_not_an_object_falls_back_to_community(self):
        (self.data_dir / "entitlements.json").write_text(
            json.dumps({"payload": "pro", "signature": ""}), encoding="utf-8")
        with override_settings(DATA_DIR=self.data_dir, ENTITLEMENTS_PUBLIC_KEY=None,
                               CODESENSE_EDITION=None):
            e = ent.get()
        self.assertEqual(e.edition, "community")

    def test_signed_feature_and_model_tier_overrides_apply(self):
        self._write_file(
            self._payload(overrides={"features": {"sso": True}, "model_tier": "high"}),
            sign_with=self.priv)
        with override_settings(DATA_DIR=self.data_dir,
                               ENTITLEMENTS_PUBLIC_KEY=self.pub_pem, CODESENSE_EDITION=None):
            e = ent.get()
        self.assertTrue(e.feature("sso"))
        self.assertEqual(e.model_tier, "high")

    def test_reload_picks_up_in_place_file_change(self):
        self._write_file(self._payload(edition="pro"), sign_with=self.priv)
        with override_settings(DATA_DIR=self.data_dir,
                               ENTITLEMENTS_PUBLIC_KEY=self.pub_pem, CODESENSE_EDITION=None):
            self.assertEqual(ent.get().edition, "pro")
            import time as _t; _t.sleep(0.01)
            self._write_file(self._payload(edition="enterprise"), sign_with=self.priv)
            self.assertEqual(ent.get().edition, "enterprise")
