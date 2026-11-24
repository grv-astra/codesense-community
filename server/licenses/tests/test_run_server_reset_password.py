"""Covers the `codesense-server reset-password` CLI subcommand in run_server.py -- the only
way back in for a locked-out account on the frozen desktop backend (no manage.py there)."""
import os
import tempfile
from pathlib import Path
from unittest import mock

import bcrypt
from django.test import TestCase, override_settings

import run_server
from local.auth_app.models.orm import User
from local.auth_app.models.user_model import UserModel
from local.auth_app.utils import account_integrity
from local.auth_app.utils.password import hash_password, verify_password

OLD = "Old!Passw0rd1"
NEW = "New!Passw0rd2"
_GATE_PASSWORD = "correct-horse-battery-staple"
_GATE_HASH = bcrypt.hashpw(_GATE_PASSWORD.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


class ResetPasswordCliTests(TestCase):
    def setUp(self):
        keys_dir = tempfile.mkdtemp()
        ov = override_settings(LOCAL_KEYS_DIR=keys_dir, ACTIVATION_PASSWORD_HASH="")
        ov.enable()
        self.addCleanup(ov.disable)

        self.db = Path(tempfile.mkdtemp()) / "app.sqlite3"
        self.db.write_bytes(b"")  # the CLI only checks that the file exists
        for p in (
            mock.patch.dict(os.environ, {"CODESENSE_DATA_DIR": str(self.db.parent)}),
            mock.patch.object(run_server, "_django_setup"),
            mock.patch.object(run_server, "_db_path", side_effect=lambda: self.db),
        ):
            p.start()
            self.addCleanup(p.stop)

        created = UserModel.create_user(
            email="admin@x.com", hashed_password=hash_password(OLD),
            name="Admin", company="Acme", role="admin",
        )
        self.user_id = created["id"]

    def _stored(self):
        return User.objects.get(id=self.user_id).password

    def _run(self, args, **kw):
        with mock.patch("builtins.print") as p:
            rc = run_server._cli_reset_password(args)
        printed = "\n".join(str(c.args[0]) for c in p.call_args_list)
        return rc, printed

    def test_password_flag_resets_and_never_echoes_the_password(self):
        rc, printed = self._run(["--email", "admin@x.com", "--password", NEW])
        self.assertEqual(rc, 0)
        self.assertTrue(verify_password(NEW, self._stored()))
        self.assertIn("Password updated for admin@x.com", printed)
        self.assertNotIn(NEW, printed)

    def test_prompts_twice_when_no_password_flag(self):
        with mock.patch("run_server.getpass.getpass", side_effect=[NEW, NEW]) as gp:
            rc, _ = self._run(["--email", "admin@x.com"])
        self.assertEqual(gp.call_count, 2)
        self.assertEqual(rc, 0)
        self.assertTrue(verify_password(NEW, self._stored()))

    def test_mismatched_confirmation_changes_nothing(self):
        with mock.patch("run_server.getpass.getpass", side_effect=[NEW, "Other!Passw0rd3"]):
            rc, printed = self._run(["--email", "admin@x.com"])
        self.assertEqual(rc, 1)
        self.assertIn("do not match", printed)
        self.assertTrue(verify_password(OLD, self._stored()))

    def test_weak_password_is_refused(self):
        rc, printed = self._run(["--email", "admin@x.com", "--password", "weak"])
        self.assertEqual(rc, 1)
        self.assertIn("Reset failed", printed)
        self.assertTrue(verify_password(OLD, self._stored()))

    def test_unknown_email_is_refused(self):
        rc, printed = self._run(["--email", "nobody@x.com", "--password", NEW])
        self.assertEqual(rc, 1)
        self.assertIn("No active account", printed)

    def test_refuses_without_data_dir_env(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("CODESENSE_DATA_DIR", None)
            with mock.patch.object(run_server, "_django_setup") as setup:
                rc, printed = self._run(["--email", "admin@x.com", "--password", NEW])
        self.assertEqual(rc, 2)
        self.assertIn("CODESENSE_DATA_DIR is not set", printed)
        setup.assert_not_called()  # settings must not even load: that would create a data folder
        self.assertTrue(verify_password(OLD, self._stored()))

    def test_refuses_when_there_is_no_database_file(self):
        self.db.unlink()
        rc, printed = self._run(["--email", "admin@x.com", "--password", NEW])
        self.assertEqual(rc, 2)
        self.assertIn("No database at", printed)
        self.assertTrue(verify_password(OLD, self._stored()))

    def test_tracked_account_keeps_working_and_registry_is_reported(self):
        account_integrity.register_user(UserModel.find_raw_by_id(self.user_id))
        rc, printed = self._run(["--email", "admin@x.com", "--password", NEW])
        self.assertEqual(rc, 0)
        self.assertIn("registry updated", printed)
        self.assertIsNone(account_integrity.verify_user(UserModel.find_raw_by_id(self.user_id)))

    def test_untracked_account_prints_the_hint(self):
        rc, printed = self._run(["--email", "admin@x.com", "--password", NEW])
        self.assertEqual(rc, 0)
        self.assertIn("not tracked in the integrity registry", printed)

    def test_activation_gate_wrong_password_refuses(self):
        with override_settings(ACTIVATION_PASSWORD_HASH=_GATE_HASH):
            rc, printed = self._run(["--email", "admin@x.com", "--password", NEW,
                                     "--activation-password", "wrong"])
        self.assertEqual(rc, 1)
        self.assertIn("incorrect activation password", printed)
        self.assertTrue(verify_password(OLD, self._stored()))

    def test_activation_gate_correct_password_allows(self):
        with override_settings(ACTIVATION_PASSWORD_HASH=_GATE_HASH):
            rc, _ = self._run(["--email", "admin@x.com", "--password", NEW,
                               "--activation-password", _GATE_PASSWORD])
        self.assertEqual(rc, 0)
        self.assertTrue(verify_password(NEW, self._stored()))

    def test_activation_gate_prompts_when_not_given(self):
        with override_settings(ACTIVATION_PASSWORD_HASH=_GATE_HASH), \
                mock.patch("run_server.getpass.getpass", return_value=_GATE_PASSWORD) as gp:
            rc, _ = self._run(["--email", "admin@x.com", "--password", NEW])
        gp.assert_called_once()
        self.assertEqual(rc, 0)

    def test_email_is_required(self):
        with self.assertRaises(SystemExit) as ctx:
            with mock.patch("sys.stderr"):
                run_server._cli_reset_password(["--password", NEW])
        self.assertEqual(ctx.exception.code, 2)
