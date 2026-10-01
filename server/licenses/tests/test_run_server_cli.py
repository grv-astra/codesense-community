"""Covers the `codesense-server activate` / `activation-status` CLI subcommands
added to run_server.py -- the only entry point that ships in the frozen native
web deploy (no manage.py, no frontend UI for the activation password there)."""
import tempfile
from unittest import mock

import bcrypt
from django.test import SimpleTestCase, override_settings

import run_server
from licenses.services import activation as act

_PASSWORD = "correct-horse-battery-staple"
_HASH = bcrypt.hashpw(_PASSWORD.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


class RunServerActivationCliTests(SimpleTestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self._ov = override_settings(DATA_DIR=self.dir, ACTIVATION_PASSWORD_HASH=_HASH)
        self._ov.enable()
        self._reg = {}
        self._reg_read = mock.patch.object(
            act, "_registry_read", side_effect=lambda: self._reg.get("rec"))
        self._reg_write = mock.patch.object(
            act, "_registry_write", side_effect=lambda rec: self._reg.__setitem__("rec", rec))
        self._reg_read.start()
        self._reg_write.start()
        self._fp_patch = mock.patch.object(act, "machine_fingerprint", side_effect=lambda: "machine-a")
        self._fp_patch.start()
        # _django_setup() re-runs django.setup() every call; harmless but
        # avoid the real cost/side effects across many small tests.
        self._setup_patch = mock.patch.object(run_server, "_django_setup")
        self._setup_patch.start()

    def tearDown(self):
        self._setup_patch.stop()
        self._reg_read.stop()
        self._reg_write.stop()
        self._fp_patch.stop()
        self._ov.disable()

    def test_activate_with_correct_password_flag_succeeds(self):
        rc = run_server._cli_activate(["--password", _PASSWORD])
        self.assertEqual(rc, 0)
        self.assertTrue(act.is_activated())

    def test_activate_with_wrong_password_flag_fails(self):
        rc = run_server._cli_activate(["--password", "wrong"])
        self.assertEqual(rc, 1)
        self.assertFalse(act.is_activated())

    def test_activate_prompts_hidden_when_no_password_flag_given(self):
        with mock.patch("run_server.getpass.getpass", return_value=_PASSWORD) as gp:
            rc = run_server._cli_activate([])
        gp.assert_called_once()
        self.assertEqual(rc, 0)
        self.assertTrue(act.is_activated())

    def test_activate_short_circuits_when_already_activated(self):
        self.assertTrue(act.activate(_PASSWORD))
        with mock.patch("run_server.getpass.getpass") as gp:
            rc = run_server._cli_activate([])
        gp.assert_not_called()
        self.assertEqual(rc, 0)

    def test_activate_noop_when_gate_not_configured(self):
        ov2 = override_settings(ACTIVATION_PASSWORD_HASH="")
        ov2.enable()
        self.addCleanup(ov2.disable)
        with mock.patch("run_server.getpass.getpass") as gp:
            rc = run_server._cli_activate([])
        gp.assert_not_called()
        self.assertEqual(rc, 0)

    def test_status_reports_configured_and_activated(self):
        act.activate(_PASSWORD)
        with mock.patch("builtins.print") as p:
            rc = run_server._cli_activation_status()
        self.assertEqual(rc, 0)
        printed = "\n".join(str(c.args[0]) for c in p.call_args_list)
        self.assertIn("configured: true", printed)
        self.assertIn("activated: True", printed)

    def test_status_reports_not_configured(self):
        ov2 = override_settings(ACTIVATION_PASSWORD_HASH="")
        ov2.enable()
        self.addCleanup(ov2.disable)
        with mock.patch("builtins.print") as p:
            rc = run_server._cli_activation_status()
        self.assertEqual(rc, 0)
        printed = "\n".join(str(c.args[0]) for c in p.call_args_list)
        self.assertIn("configured: false", printed)
