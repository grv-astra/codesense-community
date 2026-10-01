import os
from unittest import mock

from django.test import SimpleTestCase, override_settings

from licenses.services import entitlements as ent
from scanner.rag import lsast_scanner
from scanner.tests.edition_test_support import patch_if_present, skip_unless_llm_present
from scanner.tests.test_lsast_scanner import _sqli_finding


class LlmEditionGateTests(SimpleTestCase):
    def setUp(self):
        # Hermetic: a stray CODESENSE_EDITION / ENTITLEMENTS_PUBLIC_KEY on the
        # runner would defeat override_settings (entitlements reads os.environ
        # first). Same guard as licenses/tests/test_entitlements.py.
        patcher = mock.patch.dict(os.environ, {}, clear=False)
        patcher.start()
        os.environ.pop("ENTITLEMENTS_PUBLIC_KEY", None)
        os.environ.pop("CODESENSE_EDITION", None)
        self.addCleanup(patcher.stop)
        ent.reload()
        self.addCleanup(ent.reload)

    @override_settings(CODESENSE_EDITION="community", ENTITLEMENTS_PUBLIC_KEY=None)
    def test_community_reports_llm_unavailable_without_calling_llm_health(self):
        # Community's short-circuit in _edition_aware_llm_health() returns
        # BEFORE the `from scanner.rag.llm import llm_health` line ever runs,
        # so this doesn't need scanner.rag.llm to exist at all -- meaningful
        # and portable whether or not this edition has that module
        # (docs/EDITIONS-REPO-SPLIT.md §3).
        ok, detail = lsast_scanner._edition_aware_llm_health()
        self.assertFalse(ok)
        self.assertIn("Pro", detail)

    @skip_unless_llm_present()
    @override_settings(CODESENSE_EDITION="pro", ENTITLEMENTS_PUBLIC_KEY=None)
    def test_pro_delegates_to_llm_health(self):
        with mock.patch("scanner.rag.llm.llm_health",
                        return_value=(True, "ok")) as health:
            ok, detail = lsast_scanner._edition_aware_llm_health()
        health.assert_called_once()
        self.assertTrue(ok)

    @override_settings(CODESENSE_EDITION="community", ENTITLEMENTS_PUBLIC_KEY=None)
    def test_community_scan_keeps_findings_and_never_calls_llm(self):
        # End-to-end proof that the edition gate short-circuits at the REAL call
        # site: lsast_scan_folder() under Community must keep every deterministic
        # finding while never touching llm_health / verify / generate_report.
        # Persistence + progress are mocked (same targets as
        # LsastScanFolderTests) so no DB is needed and SimpleTestCase still fits.
        # patch_if_present keeps the "never called" assertions where the llm
        # subsystem IS present (codesense) without erroring where it isn't (a
        # generated Community export -- docs/EDITIONS-REPO-SPLIT.md §3): under
        # Community, lsast_scan_folder() never reaches those lazy imports at
        # all, so there's nothing to spy on either way.
        with mock.patch("scanner.rag.lsast_scanner.run_semgrep",
                        return_value=[_sqli_finding()]), \
             mock.patch("scanner.rag.lsast_scanner.save_findings_to_db"), \
             mock.patch("scanner.rag.lsast_scanner.update_progress"), \
             patch_if_present("scanner.rag.llm.llm_health") as health, \
             patch_if_present("scanner.rag.llm_verifier.verify") as verify_, \
             patch_if_present("scanner.rag.report_enricher.generate_report") as report_:
            visible, _filtered = lsast_scanner.lsast_scan_folder(
                folder_path="/tmp/code", scan_id="s1", triggered_by="user-1")
        health.assert_not_called()
        verify_.assert_not_called()
        report_.assert_not_called()
        self.assertEqual(len(visible), 1)
