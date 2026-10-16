"""Settings API rules for "Also write mitigation advice" (step 7).

The rule: an ENABLED connection must have consent that covers everything it sends. The
mitigation call sends more (rule name + analyzer message), so consent given before the
switch existed -- or while it was off -- does not cover it until the admin confirms again.
"""
from local.api_app.tests.test_llm_settings_api import KEY, SETTINGS, ApiBase
from scanner.byo_llm import store


class ReportSettingsTests(ApiBase):
    def legacy_state(self):
        """An admin who enabled verification before the mitigation switch existed."""
        self.enabled()
        conn = store.load()
        conn.consent_reports = False
        conn.enrich_reports = True
        conn.save()

    def test_defaults_and_disclosure(self):
        body = self.get(SETTINGS).json()
        self.assertTrue(body["enrich_reports"])
        self.assertFalse(body["consent"]["reports"])
        extra = body["disclosure"]["sent_for_mitigation"]
        self.assertTrue(any("rule" in s.lower() for s in extra))
        self.assertTrue(any("message" in s.lower() for s in extra))
        self.assertFalse(any("path" in s.lower() for s in extra))

    def test_enabling_with_the_switch_on_records_consent_for_the_extra_data(self):
        body = self.enabled()
        self.assertTrue(body["enrich_reports"])
        self.assertTrue(body["consent"]["given"])
        self.assertTrue(body["consent"]["reports"])

    def test_enabling_with_the_switch_off_does_not_cover_the_extra_data(self):
        body = self.enabled(enrich_reports=False)
        self.assertTrue(body["consent"]["given"])
        self.assertFalse(body["consent"]["reports"])

    def test_turning_the_switch_on_later_needs_a_fresh_confirmation(self):
        self.enabled(enrich_reports=False)
        resp = self.put({"enrich_reports": True})
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.json()["field"], "consent")
        self.assertIn("mitigation", resp.json()["error"])
        self.assertIn("127.0.0.1", resp.json()["error"])
        self.assertFalse(store.load().enrich_reports)          # nothing was saved

        ok = self.put({"enrich_reports": True, "consent": True})
        self.assertEqual(ok.status_code, 200)
        self.assertTrue(ok.json()["consent"]["reports"])

    def test_consent_given_before_the_switch_existed_blocks_edits_until_confirmed(self):
        self.legacy_state()
        for change in ({"model": "m-2"}, {"timeout_s": 30}):
            resp = self.put(change)
            self.assertEqual(resp.status_code, 400, change)
            self.assertEqual(resp.json()["field"], "consent")
        self.assertEqual(store.load().model, "m-1")

    def test_a_legacy_connection_can_still_be_turned_off_or_downgraded_without_consent(self):
        self.legacy_state()
        self.assertEqual(self.put({"enrich_reports": False}).status_code, 200)
        self.legacy_state()
        self.assertEqual(self.put({"enabled": False}).status_code, 200)

    def test_confirming_fixes_a_legacy_connection(self):
        self.legacy_state()
        body = self.put({"consent": True}).json()
        self.assertTrue(body["enabled"] and body["consent"]["reports"])

    def test_switching_off_keeps_the_existing_coverage(self):
        self.enabled()
        self.assertTrue(self.put({"enrich_reports": False}).json()["consent"]["reports"])
        self.assertEqual(self.put({"enrich_reports": True}).status_code, 200)   # still covered

    def test_a_host_change_clears_the_extra_consent(self):
        self.enabled()
        body = self.put({"base_url": "http://127.0.0.2:9999/v1"}).json()
        self.assertFalse(body["consent"]["reports"])
        self.assertFalse(store.load().consent_reports)

    def test_withdrawing_consent_clears_the_extra_consent(self):
        self.enabled()
        body = self.put({"consent": False}).json()
        self.assertFalse(body["consent"]["reports"])
        self.assertFalse(body["enabled"])

    def test_not_a_boolean_is_rejected(self):
        for bad in ("yes", 1, None, "true"):
            resp = self.put({"enrich_reports": bad})
            self.assertEqual(resp.status_code, 400, bad)
            self.assertEqual(resp.json()["field"], "enrich_reports")

    def test_a_disabled_connection_needs_no_consent_to_change_the_switch(self):
        self.put(self.base_payload())
        self.assertEqual(self.put({"enrich_reports": False}).status_code, 200)
        self.assertEqual(self.put({"enrich_reports": True}).status_code, 200)

    def test_the_key_is_still_never_returned(self):
        self.enabled()
        self.assertNotIn(KEY, self.get(SETTINGS).content.decode())
