"""API-key encryption + the singleton row."""
import pathlib

from django.test import SimpleTestCase, TestCase, override_settings

from scanner.byo_llm import crypto, store

FAKE_KEY = "sk-test-FAKE-0000000000000000"


@override_settings(SECRET_KEY="unit-test-secret-one")
class CryptoTests(SimpleTestCase):
    def test_round_trip(self):
        stored = crypto.encrypt_secret(FAKE_KEY)
        self.assertEqual(crypto.decrypt_secret(stored), FAKE_KEY)

    def test_ciphertext_does_not_contain_plaintext(self):
        stored = crypto.encrypt_secret(FAKE_KEY)
        self.assertNotIn(FAKE_KEY, stored)
        self.assertTrue(stored.startswith("v1:"))

    def test_each_encryption_is_distinct(self):
        self.assertNotEqual(crypto.encrypt_secret(FAKE_KEY), crypto.encrypt_secret(FAKE_KEY))

    def test_empty_means_no_key(self):
        self.assertEqual(crypto.encrypt_secret(""), "")
        self.assertIsNone(crypto.decrypt_secret(""))

    def test_rotated_secret_key_returns_none_not_raises(self):
        stored = crypto.encrypt_secret(FAKE_KEY)
        with override_settings(SECRET_KEY="a-different-secret"):
            self.assertIsNone(crypto.decrypt_secret(stored))

    def test_garbage_and_unknown_version_return_none(self):
        self.assertIsNone(crypto.decrypt_secret("not-a-token"))
        self.assertIsNone(crypto.decrypt_secret("v1:not-base64-fernet"))
        self.assertIsNone(crypto.decrypt_secret("v9:" + crypto.encrypt_secret(FAKE_KEY)[3:]))

    def test_missing_secret_key_cannot_encrypt_and_never_leaks_plaintext(self):
        with override_settings(SECRET_KEY=""):
            with self.assertRaises(crypto.SecretStorageError) as ctx:
                crypto.encrypt_secret(FAKE_KEY)
            self.assertNotIn(FAKE_KEY, str(ctx.exception))
            self.assertIsNone(crypto.decrypt_secret("v1:anything"))


@override_settings(SECRET_KEY="unit-test-secret-one")
class StoreTests(TestCase):
    def test_load_creates_one_disabled_empty_row(self):
        conn = store.load()
        self.assertFalse(conn.enabled)
        self.assertEqual(conn.provider, "openai_compatible")
        self.assertFalse(store.key_is_set(conn))
        self.assertEqual(type(conn).objects.count(), 1)

    def test_load_is_a_singleton(self):
        a = store.load()
        b = store.load()
        self.assertEqual(a.pk, b.pk)
        self.assertEqual(type(a).objects.count(), 1)

    def test_key_is_stored_encrypted_and_survives_reload(self):
        conn = store.load()
        store.set_api_key(conn, FAKE_KEY)
        conn.save()
        reloaded = store.load()
        self.assertNotIn(FAKE_KEY, reloaded.api_key_enc)
        self.assertEqual(store.get_api_key(reloaded), FAKE_KEY)
        self.assertTrue(store.key_is_set(reloaded))

    def test_clearing_the_key(self):
        conn = store.load()
        store.set_api_key(conn, FAKE_KEY)
        store.set_api_key(conn, "")
        self.assertEqual(conn.api_key_enc, "")
        self.assertFalse(store.key_is_set(conn))

    def test_undecryptable_key_reads_as_not_set(self):
        conn = store.load()
        store.set_api_key(conn, FAKE_KEY)
        conn.save()
        with override_settings(SECRET_KEY="rotated"):
            self.assertFalse(store.key_is_set(store.load()))

    def test_key_not_in_model_repr_or_str(self):
        conn = store.load()
        store.set_api_key(conn, FAKE_KEY)
        self.assertNotIn(FAKE_KEY, repr(conn))
        self.assertNotIn(FAKE_KEY, str(conn))


class ExportBoundaryTests(SimpleTestCase):
    """scanner/byo_llm ships in the Community export, where these four modules
    do not exist -- so it must never import them (docs/EDITIONS-REPO-SPLIT.md)."""

    EXCLUDED = ("scanner.rag.llm", "llm_verifier", "report_enricher", "model_tiers")

    def test_package_imports_no_excluded_module(self):
        import re
        pkg = pathlib.Path(__file__).resolve().parents[1] / "byo_llm"
        pattern = re.compile(
            r"^\s*(?:from|import)\s+[\w.]*?(" + "|".join(re.escape(m) for m in self.EXCLUDED) + r")\b",
            re.MULTILINE,
        )
        offenders = [
            f"{p.name}: {m.group(0).strip()}"
            for p in pkg.rglob("*.py")
            for m in pattern.finditer(p.read_text(encoding="utf-8"))
        ]
        self.assertEqual(offenders, [])
