import json
import os
import tempfile
from pathlib import Path
from unittest import mock

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import SimpleTestCase, override_settings

from licenses.services import crypto
from licenses.services import entitlements as ent


def _canonical_bytes(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


class VendorCommandsTests(SimpleTestCase):
    # ------------------------------------------------------------------ helpers
    def _tmpdir(self) -> Path:
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        return Path(td.name)

    def _keypair(self, password=None):
        """Generate a fresh vendor keypair in its own temp dir; return (priv, pub) paths."""
        d = self._tmpdir()
        args = ["gen_entitlements_keypair", "--outdir", str(d)]
        if password is not None:
            args += ["--password", password]
        call_command(*args)
        return (d / "vendor_entitlements_private.pem",
                d / "vendor_entitlements_public.pem")

    def _mint(self, priv, out, *extra, key_password=None):
        args = [
            "mint_entitlements",
            "--edition", "pro", "--customer", "Acme Corp",
            "--private-key", str(priv),
            "--out", str(out),
            *extra,
        ]
        if key_password is not None:
            args += ["--key-password", key_password]
        call_command(*args)

    def _assert_verifies(self, out, pub):
        doc = json.loads(Path(out).read_text())
        canonical = _canonical_bytes(doc["payload"])
        pubkey = crypto.load_public_key(str(pub))
        self.assertTrue(crypto.verify_signature(pubkey, canonical, doc["signature"]))
        return doc

    # ----------------------------------------------------- existing 3 (de-leaked)
    def test_keypair_then_mint_then_verify(self):
        priv, pub = self._keypair()
        out = self._tmpdir() / "entitlements.json"
        self._mint(priv, out, "--expires", "2099-01-01",
                   "--override-limit", "projects=20")
        doc = self._assert_verifies(out, pub)
        self.assertEqual(doc["payload"]["edition"], "pro")
        self.assertEqual(doc["payload"]["overrides"]["limits"]["projects"], 20)

    def test_mint_rejects_unknown_edition(self):
        with self.assertRaises(CommandError):
            call_command("mint_entitlements", "--edition", "ultra",
                         "--private-key", "x.pem", "--out", "y.json")

    def test_minted_file_resolves_through_real_resolver(self):
        priv, pub = self._keypair()
        pub_pem = Path(pub).read_text()

        data_dir = self._tmpdir()
        self._mint(priv, data_dir / "entitlements.json",
                   "--expires", "2099-01-01", "--override-limit", "projects=20")

        patcher = mock.patch.dict(os.environ, {}, clear=False)
        patcher.start()
        os.environ.pop("ENTITLEMENTS_PUBLIC_KEY", None)
        os.environ.pop("CODESENSE_EDITION", None)
        self.addCleanup(patcher.stop)
        ent.reload()
        self.addCleanup(ent.reload)

        with override_settings(DATA_DIR=data_dir, ENTITLEMENTS_PUBLIC_KEY=pub_pem,
                               CODESENSE_EDITION=None):
            e = ent.get()
        self.assertEqual(e.edition, "pro")
        self.assertEqual(e.source, "signed")
        self.assertEqual(e.limit("projects"), 20)

    # ------------------------------------------------------------- expiry rules
    def test_perpetual_when_no_expires(self):
        priv, _ = self._keypair()
        out = self._tmpdir() / "entitlements.json"
        self._mint(priv, out)
        doc = json.loads(out.read_text())
        self.assertIsNone(doc["payload"]["expires_at"])

    def test_expires_is_end_of_day_inclusive(self):
        priv, _ = self._keypair()
        out = self._tmpdir() / "entitlements.json"
        self._mint(priv, out, "--expires", "2099-01-01")
        doc = json.loads(out.read_text())
        self.assertEqual(doc["payload"]["expires_at"], "2099-01-01T23:59:59+00:00")

    def test_bad_expires_date_is_command_error(self):
        priv, _ = self._keypair()
        out = self._tmpdir() / "entitlements.json"
        with self.assertRaises(CommandError):
            self._mint(priv, out, "--expires", "2099-13-99")

    # -------------------------------------------------------- override-limit rules
    def test_bad_override_limit_value_is_command_error(self):
        priv, _ = self._keypair()
        out = self._tmpdir() / "entitlements.json"
        with self.assertRaises(CommandError):
            self._mint(priv, out, "--override-limit", "projects=abc")
        with self.assertRaises(CommandError):
            self._mint(priv, out, "--override-limit", "projects")

    def test_unknown_override_limit_key_is_command_error(self):
        priv, _ = self._keypair()
        out = self._tmpdir() / "entitlements.json"
        with self.assertRaises(CommandError):
            self._mint(priv, out, "--override-limit", "bogus=5")

    # ------------------------------------------------------------------ overrides
    def test_override_model_tier_lands_in_payload(self):
        priv, pub = self._keypair()
        out = self._tmpdir() / "entitlements.json"
        self._mint(priv, out, "--override-model-tier", "mid")
        doc = self._assert_verifies(out, pub)
        self.assertEqual(doc["payload"]["overrides"]["model_tier"], "mid")

    # ---------------------------------------------------- encrypted private key
    def test_password_encrypted_private_key_round_trips(self):
        priv, pub = self._keypair(password="s3cret")
        out = self._tmpdir() / "entitlements.json"
        self._mint(priv, out, key_password="s3cret")
        self._assert_verifies(out, pub)

        # Minting against the encrypted key WITHOUT the password must fail.
        out2 = self._tmpdir() / "entitlements.json"
        with self.assertRaises(Exception):
            self._mint(priv, out2)

    # -------------------------------------------- canonicalisation parity check
    def test_canonical_matches_resolver(self):
        from licenses.services import entitlements as ent_mod
        from licenses.management.commands.mint_entitlements import (
            _canonical as mint_canonical,
        )
        payload = {
            "edition": "pro",
            "customer": "Ácmé BräND 株式会社 — ĝ",
            "issued_at": "2026-01-01T00:00:00+00:00",
            "expires_at": None,
            "overrides": {"limits": {"projects": 7}, "model_tier": "mid"},
        }
        self.assertEqual(mint_canonical(payload), ent_mod._canonical(payload))
