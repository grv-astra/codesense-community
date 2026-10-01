import os
from unittest import mock

from django.test import SimpleTestCase, override_settings

from licenses.services import entitlements as ent
from scanner.services import sbom_pipeline


class SbomEditionGateTests(SimpleTestCase):
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
    def test_community_disables_signing_and_grant(self):
        self.assertFalse(sbom_pipeline._signing_enabled())
        self.assertFalse(sbom_pipeline._license_compliance_enabled())

    @override_settings(CODESENSE_EDITION="pro", ENTITLEMENTS_PUBLIC_KEY=None)
    def test_pro_enables_both(self):
        self.assertTrue(sbom_pipeline._signing_enabled())
        self.assertTrue(sbom_pipeline._license_compliance_enabled())

    @override_settings(CODESENSE_EDITION="community", ENTITLEMENTS_PUBLIC_KEY=None)
    def test_community_pipeline_skips_signing_and_grant_calls(self):
        import scanner.services.sbom_pipeline as sp

        with mock.patch.object(sp, "_sign_sbom") as sign, \
             mock.patch.object(sp, "_run_grant") as grant, \
             mock.patch.object(sp, "_run_grype", return_value={}), \
             mock.patch.object(sp, "_parse_grype_results", return_value=([], {})), \
             mock.patch.object(sp, "_detect_sbom_format", return_value="cyclonedx-json"), \
             mock.patch.object(sp.Path, "mkdir"), \
             mock.patch("scanner.services.sbom_pipeline.shutil.copy2"), \
             mock.patch("builtins.open", mock.mock_open(read_data="{}")), \
             mock.patch("scanner.services.sbom_pipeline.SbomModel") as SbomModel:
            try:
                sp.run_sbom_pipeline(sbom_path="/tmp/x.json", scan_id="sc1", triggered_by="u1")
            except Exception:
                pass  # we only care that signing/grant were gated before any failure

        sign.assert_not_called()
        grant.assert_not_called()

        # the skipped signing_status shape (skipped_reason == "edition") was persisted
        calls = [c.args[1] for c in SbomModel.update_scan_fields.call_args_list if len(c.args) > 1] \
            + [c.kwargs for c in SbomModel.update_scan_fields.call_args_list]
        self.assertTrue(
            any(
                isinstance(d, dict)
                and d.get("sbom_signing", {}).get("skipped_reason") == "edition"
                for d in calls
            )
        )
