import json
import os
import tempfile

from django.test import TestCase, override_settings

from local.auth_app.models.orm import User
from local.auth_app.models.user_model import UserModel
from local.auth_app.utils import account_integrity
from local.auth_app.utils.password import hash_password, verify_password
from local.auth_app.utils.password_reset import ResetError, reset_password

OLD = "Old!Passw0rd1"
NEW = "New!Passw0rd2"


class ResetPasswordTests(TestCase):
    def setUp(self):
        # The integrity registry is a shared file on disk; keep every test off the real one.
        self.keys_dir = tempfile.mkdtemp()
        ov = override_settings(LOCAL_KEYS_DIR=self.keys_dir)
        ov.enable()
        self.addCleanup(ov.disable)
        created = UserModel.create_user(
            email="admin@x.com", hashed_password=hash_password(OLD),
            name="Admin", company="Acme", role="admin",
        )
        self.user_id = created["id"]

    def _stored(self):
        return User.objects.get(id=self.user_id).password

    def _registry(self):
        path = account_integrity.registry_path()
        if not os.path.exists(path):
            return {}
        with open(path, encoding="utf-8") as f:
            return json.load(f)

    def test_new_password_replaces_old_one(self):
        result = reset_password("admin@x.com", NEW)
        self.assertEqual(result["email"], "admin@x.com")
        self.assertTrue(verify_password(NEW, self._stored()))
        self.assertFalse(verify_password(OLD, self._stored()))
        self.assertNotEqual(self._stored(), NEW)  # hashed, never stored in clear

    def test_email_match_ignores_case_and_surrounding_space(self):
        reset_password("  Admin@X.com ", NEW)
        self.assertTrue(verify_password(NEW, self._stored()))

    def test_weak_password_is_refused_and_nothing_changes(self):
        for weak, reason in (("abc", "at least 8"), ("alllowercase1!", "uppercase"),
                             ("NoDigitsHere!", "digit"), ("NoSpecial123", "special")):
            with self.assertRaises(ResetError) as ctx:
                reset_password("admin@x.com", weak)
            self.assertIn(reason, str(ctx.exception), weak)
        self.assertTrue(verify_password(OLD, self._stored()))

    def test_unknown_account_is_refused(self):
        with self.assertRaises(ResetError):
            reset_password("nobody@x.com", NEW)
        with self.assertRaises(ResetError):
            reset_password("", NEW)
        self.assertTrue(verify_password(OLD, self._stored()))

    def test_deleted_account_is_not_reset(self):
        UserModel.update_user(self.user_id, {"deleted": True})
        with self.assertRaises(ResetError):
            reset_password("admin@x.com", NEW)
        self.assertTrue(verify_password(OLD, self._stored()))

    def test_ambiguous_email_is_refused(self):
        UserModel.create_user(email="ADMIN@x.com", hashed_password=hash_password(OLD),
                              name="Twin", company="Acme", role="user")
        with self.assertRaises(ResetError) as ctx:
            reset_password("admin@x.com", NEW)
        self.assertIn("More than one", str(ctx.exception))
        self.assertTrue(verify_password(OLD, self._stored()))

    def test_tracked_account_still_passes_the_integrity_check(self):
        account_integrity.register_user(UserModel.find_raw_by_id(self.user_id), created_by="setup")
        result = reset_password("admin@x.com", NEW)
        self.assertTrue(result["registry_updated"])
        self.assertIsNone(account_integrity.verify_user(UserModel.find_raw_by_id(self.user_id)))
        self.assertEqual(self._registry()["admin@x.com"]["created_by"], "setup")

    def test_without_the_refresh_a_tracked_account_would_be_flagged(self):
        # Documents WHY the registry is touched: a plain hash change trips the integrity check.
        account_integrity.register_user(UserModel.find_raw_by_id(self.user_id))
        UserModel.update_user(self.user_id, {"password": hash_password(NEW)})
        flagged = account_integrity.verify_user(UserModel.find_raw_by_id(self.user_id))
        self.assertIn("password_fingerprint", flagged["changed_fields"])

    def test_untracked_account_is_not_added_to_the_registry(self):
        result = reset_password("admin@x.com", NEW)
        self.assertFalse(result["registry_updated"])
        self.assertEqual(self._registry(), {})
        self.assertFalse(os.path.exists(account_integrity.registry_path()))

    def test_unreadable_registry_reports_that_the_password_was_changed(self):
        path = account_integrity.registry_path()
        with open(path, "w", encoding="utf-8") as f:
            f.write("{not json")
        with self.assertRaises(ResetError) as ctx:
            reset_password("admin@x.com", NEW)
        self.assertIn("WAS changed", str(ctx.exception))
        self.assertTrue(verify_password(NEW, self._stored()))
