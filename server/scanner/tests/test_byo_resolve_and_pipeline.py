"""Backend selection + the real scan loop with the user's own LLM (fake server).

Runs under Community edition on purpose: BYO verification must work there.
"""
import os
from datetime import datetime, timezone
from unittest import mock

from django.test import TestCase, override_settings

from licenses.services import entitlements as ent
from scanner.byo_llm import store
from scanner.byo_llm.resolve import resolve_byo_backend
from scanner.rag.lsast_scanner import lsast_scan_folder
from scanner.tests.byo_fake_server import FakeLLMServer
from scanner.tests.edition_test_support import patch_if_present
from scanner.tests.test_lsast_scanner import _safe_orm_finding, _sqli_finding

KEY = "sk-test-FAKE-0000000000000000"


def tp(conf=0.9):
    return '{"verdict":"TP","reason":"reaches the sink","confidence":%s}' % conf


def fp(conf=0.95):
    return '{"verdict":"FP","reason":"parameterised","confidence":%s}' % conf


class ByoTestBase(TestCase):
    EDITION = "community"

    def setUp(self):
        env = mock.patch.dict(os.environ, {
            "NO_PROXY": "127.0.0.1,localhost", "no_proxy": "127.0.0.1,localhost",
            "LSAST_MAX_WORKERS": "1",             # deterministic reply order
        })
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop("ENTITLEMENTS_PUBLIC_KEY", None)
        os.environ.pop("CODESENSE_EDITION", None)
        ov = override_settings(CODESENSE_EDITION=self.EDITION, ENTITLEMENTS_PUBLIC_KEY=None,
                               SECRET_KEY="byo-test-secret")
        ov.enable()
        self.addCleanup(ov.disable)
        ent.reload()
        self.addCleanup(ent.reload)
        self.server = FakeLLMServer().start()
        self.addCleanup(self.server.stop)

    def configure(self, *, enabled=True, consent=True, provider="openai_compatible", key=KEY,
                  base_path="/v1", consent_host=None, reports=False):
        conn = store.load()
        conn.enabled = enabled
        conn.provider = provider
        conn.base_url = self.server.url + base_path
        conn.model = "test-model"
        conn.timeout_s = 10
        store.set_api_key(conn, key)
        if consent:
            conn.consent_at = datetime.now(timezone.utc)
            conn.consent_host = consent_host if consent_host is not None else f"127.0.0.1:{self.server.port}"
            conn.consent_by = "admin"
        # mitigation advice: switched on AND consented. reports=False = verification only.
        conn.enrich_reports = reports
        conn.consent_reports = bool(reports and consent)
        conn.save()
        return conn


class ResolveTests(ByoTestBase):
    def test_not_configured(self):
        self.assertEqual(resolve_byo_backend(), (None, ""))
        self.assertEqual(self.server.requests, [])

    def test_disabled_makes_no_call(self):
        self.configure(enabled=False)
        self.assertEqual(resolve_byo_backend(), (None, ""))
        self.assertEqual(self.server.requests, [])

    def test_enabled_without_consent_makes_no_call(self):
        self.configure(consent=False)
        backend, detail = resolve_byo_backend()
        self.assertIsNone(backend)
        self.assertIn("consent", detail)
        self.assertEqual(self.server.requests, [])

    def test_consent_for_another_host_is_not_valid(self):
        self.configure(consent_host="api.somewhere-else.com")
        backend, detail = resolve_byo_backend()
        self.assertIsNone(backend)
        self.assertIn("consent", detail)
        self.assertEqual(self.server.requests, [])

    def test_edition_without_the_feature_never_calls(self):
        self.configure()
        with mock.patch("licenses.services.entitlements.get") as get:
            get.return_value.feature.return_value = False
            self.assertEqual(resolve_byo_backend(), (None, ""))
        self.assertEqual(self.server.requests, [])

    def test_working_connection_yields_a_backend_and_records_the_check(self):
        self.configure()
        self.server.reply_openai("")                       # preflight ping
        backend, detail = resolve_byo_backend()
        self.assertIsNotNone(backend)
        self.assertEqual(detail, "")
        self.assertIn("test-model", backend.detail)
        self.assertEqual(len(self.server.requests), 1)
        conn = store.load()
        self.assertTrue(conn.last_test_ok)
        self.assertEqual(conn.last_test_error, "")

    def test_bad_key_is_reported_without_leaking_it(self):
        self.configure()
        self.server.reply(401, {"error": {"message": f"Incorrect API key provided: {KEY}"}})
        backend, detail = resolve_byo_backend()
        self.assertIsNone(backend)
        self.assertIn("not working", detail)
        self.assertNotIn(KEY, detail)
        conn = store.load()
        self.assertFalse(conn.last_test_ok)
        self.assertNotIn(KEY, conn.last_test_error)

    def test_unreachable_host(self):
        self.configure()
        self.server.stop()
        backend, detail = resolve_byo_backend()
        self.assertIsNone(backend)
        self.assertIn("not working", detail)

    def test_forbidden_url_never_leaves_the_machine(self):
        conn = self.configure()
        conn.base_url = "http://169.254.169.254/v1"
        conn.consent_host = "169.254.169.254"
        conn.save()
        backend, detail = resolve_byo_backend()
        self.assertIsNone(backend)
        self.assertIn("not allowed", detail)

    def test_rotated_secret_key_means_missing_key_not_a_crash(self):
        self.configure(provider="anthropic", base_path="")
        with override_settings(SECRET_KEY="rotated"):
            backend, detail = resolve_byo_backend()
        self.assertIsNone(backend)
        self.assertIn("API key", detail)


class PipelineTests(ByoTestBase):
    def run_scan(self, findings):
        saved, progress = [], []
        with mock.patch("scanner.rag.lsast_scanner.run_semgrep", return_value=findings), \
             mock.patch("scanner.rag.lsast_scanner.save_findings_to_db", side_effect=saved.append), \
             mock.patch("scanner.rag.lsast_scanner.update_progress",
                        side_effect=lambda *a, **k: progress.append(k)):
            visible, filtered = lsast_scan_folder(folder_path="/tmp/code", scan_id="s1", triggered_by="u1")
        llm_metrics = [p["extra_metrics"]["llm"] for p in progress
                       if p.get("extra_metrics") and "llm" in p["extra_metrics"]]
        return visible, filtered, llm_metrics

    def test_community_verifies_with_the_users_llm(self):
        self.configure()
        self.server.reply_openai("")                         # preflight
        self.server.reply_openai(tp(0.9))                    # sqli (high)
        self.server.reply_openai(fp(0.95))                   # orm (medium) -> filtered
        visible, filtered, metrics = self.run_scan([_sqli_finding(), _safe_orm_finding()])
        self.assertEqual([f["severity"] for f in visible], ["high"])
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0]["status"], "filtered")
        self.assertEqual(visible[0]["confidence"], 0.9)
        self.assertEqual(len(self.server.requests), 3)
        final = metrics[-1]
        self.assertEqual((final["backend"], final["calls"], final["verified"], final["unverified"]),
                         ("byo", 2, 2, 0))
        self.assertEqual(final["tokens_in"], 22)
        self.assertNotIn("api_key", repr(final).lower())
        self.assertNotIn(KEY, repr(final))

    def test_prompts_sent_have_no_file_paths_and_use_a_json_request(self):
        self.configure()
        self.server.reply_openai("")
        self.server.reply_openai(tp())
        self.run_scan([_sqli_finding()])
        sent = self.server.requests[1]["json"]
        text = " ".join(m["content"] for m in sent["messages"])
        self.assertNotIn("app/views.py", text)
        self.assertIn("cursor.execute(query)", text)
        self.assertEqual(sent["response_format"], {"type": "json_object"})

    def test_unsure_false_positive_stays_visible_and_is_counted_unverified(self):
        self.configure()
        self.server.reply_openai("")
        self.server.reply_openai(fp(0.5))
        visible, filtered, metrics = self.run_scan([_safe_orm_finding()])
        self.assertEqual((len(visible), len(filtered)), (1, 0))
        self.assertEqual(visible[0]["confidence"], 0.3)
        self.assertIn("unverified", visible[0]["verifier_reason"])
        self.assertEqual(metrics[-1]["unverified"], 1)

    def test_garbage_reply_keeps_the_finding(self):
        self.configure()
        self.server.reply_openai("")
        self.server.reply_openai("sorry, I cannot help with that")
        visible, _f, metrics = self.run_scan([_sqli_finding()])
        self.assertEqual(len(visible), 1)
        self.assertEqual(visible[0]["confidence"], 0.3)

    def test_llm_dies_mid_scan_findings_kept_and_breaker_stops_calls(self):
        self.configure()
        self.server.reply_openai("")                         # preflight ok
        self.server.reply(401, {"error": "bad key"})         # first finding: key revoked
        visible, filtered, metrics = self.run_scan([_sqli_finding(), _safe_orm_finding()])
        self.assertEqual(len(visible), 2)                    # nothing lost
        self.assertEqual(filtered, [])
        self.assertEqual(len(self.server.requests), 2)       # no calls after the breaker opened
        final = metrics[-1]
        self.assertTrue(final["breaker_open"])
        self.assertEqual(final["unverified"], 2)
        conn = store.load()                                  # the dashboard light turns red
        self.assertFalse(conn.last_test_ok)
        self.assertNotIn(KEY, conn.last_test_error)
        self.assertNotIn(KEY, repr(final))

    def test_configured_but_broken_connection_keeps_findings_and_says_why(self):
        self.configure()
        self.server.reply(401, {"error": "bad key"})         # preflight fails
        visible, _f, metrics = self.run_scan([_sqli_finding()])
        self.assertEqual(len(visible), 1)
        self.assertFalse(metrics[-1]["available"])
        self.assertIn("not working", metrics[-1]["detail"])
        self.assertEqual(len(self.server.requests), 1)

    def test_unconfigured_community_makes_zero_calls(self):
        visible, _f, metrics = self.run_scan([_sqli_finding(), _safe_orm_finding()])
        self.assertEqual(len(visible), 2)
        self.assertEqual(self.server.requests, [])
        self.assertFalse(metrics[-1]["available"])
        self.assertIn("Settings", metrics[-1]["detail"])

    def test_disabled_connection_makes_zero_calls(self):
        self.configure(enabled=False)
        self.run_scan([_sqli_finding()])
        self.assertEqual(self.server.requests, [])

    def test_anthropic_end_to_end(self):
        self.configure(provider="anthropic", base_path="")
        self.server.reply_anthropic("")
        self.server.reply_anthropic(fp(0.9))
        visible, filtered, _m = self.run_scan([_safe_orm_finding()])
        self.assertEqual((len(visible), len(filtered)), (0, 1))
        self.assertEqual(self.server.requests[1]["path"], "/v1/messages")

    def test_bundled_enrichment_is_not_run_for_byo(self):
        self.configure()
        self.server.reply_openai("")
        self.server.reply_openai(tp())
        with patch_if_present("scanner.rag.report_enricher.generate_report") as report_:
            self.run_scan([_sqli_finding()])
        report_.assert_not_called()


class ProWithByoTests(ByoTestBase):
    EDITION = "pro"

    def test_users_llm_takes_precedence_over_the_bundled_model(self):
        self.configure()
        self.server.reply_openai("")
        self.server.reply_openai(tp())
        with patch_if_present("scanner.rag.llm.llm_health", return_value=(True, "ok")) as health, \
             patch_if_present("scanner.rag.llm_verifier.verify") as bundled_verify, \
             patch_if_present("scanner.rag.report_enricher.generate_report") as report_, \
             mock.patch("scanner.rag.lsast_scanner.run_semgrep", return_value=[_sqli_finding()]), \
             mock.patch("scanner.rag.lsast_scanner.save_findings_to_db"), \
             mock.patch("scanner.rag.lsast_scanner.update_progress"):
            visible, _f = lsast_scan_folder(folder_path="/tmp/code", scan_id="s1", triggered_by="u1")
        health.assert_not_called()
        bundled_verify.assert_not_called()
        report_.assert_not_called()
        self.assertEqual(len(visible), 1)
        self.assertEqual(len(self.server.requests), 2)
