"""AI-verification settings API: auth, key handling, consent, test-connection, status."""
import json
import os
from unittest import mock

from django.test import TestCase, override_settings

from licenses.services import entitlements as ent
from local.auth_app.models.permission_model import PermissionModel
from local.auth_app.utils.jwt import generate_token
from scanner.byo_llm import store
from scanner.tests.byo_fake_server import FakeLLMServer
from scanner.tests.edition_test_support import skip_unless_llm_present

KEY = "sk-test-FAKE-0000000000000000"
NEW_KEY = "sk-test-FAKE-NEWNEWNEWNEW1111"
SETTINGS = "/api/settings/llm/"
TEST = "/api/settings/llm/test/"
STATUS = "/api/llm/status/"


def public_resolver(host, port, type=0):
    return [(2, 1, 6, "", ("93.184.216.34", port))]


@override_settings(SECRET_KEY="api-test-secret")
class ApiBase(TestCase):
    EDITION = "community"

    def setUp(self):
        env = mock.patch.dict(os.environ, {"NO_PROXY": "127.0.0.1,localhost", "no_proxy": "127.0.0.1,localhost"})
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop("ENTITLEMENTS_PUBLIC_KEY", None)
        os.environ.pop("CODESENSE_EDITION", None)
        ov = override_settings(CODESENSE_EDITION=self.EDITION, ENTITLEMENTS_PUBLIC_KEY=None)
        ov.enable()
        self.addCleanup(ov.disable)
        ent.reload()
        self.addCleanup(ent.reload)
        # account-integrity needs a protected-accounts registry; role checks are what we test here
        integ = mock.patch("local.auth_app.permissions.decorators.verify_payload_user", return_value=None)
        integ.start()
        self.addCleanup(integ.stop)
        self.server = FakeLLMServer().start()
        self.addCleanup(self.server.stop)
        self.url = self.server.url + "/v1"

    # -- helpers ---------------------------------------------------------
    def auth(self, role="admin", uid="admin1"):
        return {"HTTP_AUTHORIZATION": f"Bearer {generate_token({'id': uid, 'role': role})}"}

    def get(self, path, role="admin"):
        return self.client.get(path, **self.auth(role))

    def put(self, data, role="admin", path=SETTINGS):
        return self.client.put(path, data=json.dumps(data), content_type="application/json", **self.auth(role))

    def post(self, data, path=TEST, role="admin"):
        return self.client.post(path, data=json.dumps(data), content_type="application/json", **self.auth(role))

    def base_payload(self, **over):
        p = {"provider": "openai_compatible", "base_url": self.url, "model": "m-1", "api_key": KEY}
        p.update(over)
        return p

    def enabled(self, **over):
        resp = self.put(self.base_payload(enabled=True, consent=True, **over))
        self.assertEqual(resp.status_code, 200, resp.content)
        return resp.json()


class AuthTests(ApiBase):
    def test_unauthenticated_is_401(self):
        for call in (lambda: self.client.get(SETTINGS), lambda: self.client.put(SETTINGS, {}),
                     lambda: self.client.post(TEST, {}), lambda: self.client.get(STATUS)):
            self.assertEqual(call().status_code, 401)

    def test_non_admin_cannot_read_or_change_settings(self):
        for role in ("user", "manager"):
            self.assertEqual(self.get(SETTINGS, role).status_code, 403, role)
            self.assertEqual(self.put({"model": "x"}, role).status_code, 403, role)
            self.assertEqual(self.post({}, role=role).status_code, 403, role)
        self.assertIsNone(store.load().last_test_at)

    def test_api_key_credentials_cannot_reach_settings(self):
        resp = self.client.get(SETTINGS, HTTP_AUTHORIZATION="Bearer csk_not_a_jwt_just_an_api_key")
        self.assertEqual(resp.status_code, 401)

    def test_status_needs_view_scans(self):
        self.assertEqual(self.get(STATUS, "user").status_code, 403)
        PermissionModel.set_permissions_for_role("analyst", {"view_scans": True})
        self.assertEqual(self.get(STATUS, "analyst").status_code, 200)
        self.assertEqual(self.get(STATUS, "admin").status_code, 200)

    def test_edition_without_the_feature_is_refused(self):
        with mock.patch("licenses.services.entitlements.get") as get:
            get.return_value.feature.return_value = False
            self.assertEqual(self.get(SETTINGS).status_code, 403)
            self.assertEqual(self.put({"model": "x"}).status_code, 403)
            self.assertEqual(self.post({}).status_code, 403)


class SettingsTests(ApiBase):
    def test_initial_state_has_no_key_and_describes_the_disclosure(self):
        body = self.get(SETTINGS).json()
        self.assertFalse(body["enabled"])
        self.assertFalse(body["key_set"])
        self.assertNotIn("api_key", body)
        self.assertNotIn("api_key_enc", body)
        self.assertTrue(body["disclosure"]["sent"])
        self.assertTrue(any("path" in s.lower() for s in body["disclosure"]["not_sent"]))
        self.assertFalse(any("api key" in s.lower() for s in body["disclosure"]["not_sent"]))
        self.assertIn("API key", body["disclosure"]["key_note"])
        self.assertEqual({p["id"] for p in body["providers"]},
                         {"openai_compatible", "azure_openai", "anthropic"})

    def test_the_key_is_never_returned_and_is_stored_encrypted(self):
        resp = self.put(self.base_payload())
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.json()["key_set"])
        self.assertNotIn(KEY, resp.content.decode())
        self.assertNotIn(KEY, self.get(SETTINGS).content.decode())
        conn = store.load()
        self.assertNotIn(KEY, conn.api_key_enc)
        self.assertEqual(store.get_api_key(conn), KEY)

    def test_empty_key_field_keeps_the_saved_key_and_clear_removes_it(self):
        self.put(self.base_payload())
        self.assertTrue(self.put({"model": "m-2", "api_key": ""}).json()["key_set"])
        self.assertEqual(store.load().model, "m-2")
        self.assertFalse(self.put({"clear_api_key": True}).json()["key_set"])

    def test_enabling_requires_consent_for_this_host(self):
        self.put(self.base_payload())
        resp = self.put({"enabled": True})
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.json()["field"], "consent")
        self.assertIn("127.0.0.1", resp.json()["error"])
        self.assertFalse(store.load().enabled)

    def test_enable_with_consent_records_who_when_and_which_host(self):
        body = self.enabled()
        self.assertTrue(body["enabled"])
        self.assertTrue(body["consent"]["given"])
        self.assertEqual(body["consent"]["host"], f"127.0.0.1:{self.server.port}")
        self.assertEqual(body["consent"]["by"], "admin1")
        self.assertIsNotNone(body["consent"]["at"])

    def test_changing_the_host_clears_consent_enabled_and_the_saved_key(self):
        self.enabled()
        resp = self.put({"base_url": "http://127.0.0.2:9999/v1"})
        body = resp.json()
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(body["enabled"])
        self.assertFalse(body["consent"]["given"])
        self.assertFalse(body["key_set"])              # the old host's key does not follow the URL
        self.assertEqual(store.load().consent_host, "")

    def test_changing_the_host_with_a_new_key_keeps_only_the_new_key(self):
        self.enabled()
        body = self.put({"base_url": "http://127.0.0.2:9999/v1", "api_key": NEW_KEY}).json()
        self.assertTrue(body["key_set"])
        self.assertEqual(store.get_api_key(store.load()), NEW_KEY)
        self.assertFalse(body["enabled"])

    def test_changing_only_the_model_keeps_everything(self):
        self.enabled()
        body = self.put({"model": "m-2"}).json()
        self.assertTrue(body["enabled"] and body["consent"]["given"] and body["key_set"])

    def test_revoking_consent_disables(self):
        self.enabled()
        body = self.put({"consent": False}).json()
        self.assertFalse(body["enabled"])
        self.assertFalse(body["consent"]["given"])

    def test_disable_keeps_the_configuration(self):
        self.enabled()
        body = self.put({"enabled": False}).json()
        self.assertFalse(body["enabled"])
        self.assertTrue(body["key_set"])
        self.assertEqual(body["model"], "m-1")

    def test_hosted_providers_need_a_key_to_enable(self):
        resp = self.put({"provider": "anthropic", "base_url": self.server.url, "model": "claude-x",
                         "enabled": True, "consent": True})
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.json()["field"], "api_key")

    def test_local_openai_compatible_server_works_without_a_key(self):
        resp = self.put({"provider": "openai_compatible", "base_url": self.url, "model": "llama3",
                         "enabled": True, "consent": True})
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(resp.json()["key_set"])

    def test_forbidden_and_malformed_urls_are_rejected_and_nothing_is_saved(self):
        for bad in ("http://169.254.169.254/v1", "ftp://x.example.com", "https://user:pw@x.example.com/v1",
                    "https://x.example.com/v1?key=1", ""):
            resp = self.put(self.base_payload(base_url=bad))
            self.assertEqual(resp.status_code, 400, bad)
            self.assertEqual(resp.json()["field"], "base_url", bad)
            self.assertNotIn("pw@", resp.content.decode())
        self.assertEqual(store.load().base_url, "")

    def test_plain_http_to_a_public_host_is_rejected(self):
        with mock.patch("scanner.byo_llm.url_policy.socket.getaddrinfo", side_effect=public_resolver):
            resp = self.put(self.base_payload(base_url="http://llm.example.com/v1"))
            self.assertEqual(resp.status_code, 400)
            self.assertIn("https", resp.json()["error"])
            self.assertEqual(
                self.put(self.base_payload(base_url="https://llm.example.com/v1")).status_code, 200)

    def test_field_validation(self):
        for bad in ({"provider": "skynet"}, {"timeout_s": 1}, {"timeout_s": "abc"}, {"timeout_s": True},
                    {"max_concurrency": 99}, {"model": "x" * 300}, {"model": "bad\nmodel"},
                    {"api_version": "../../etc"}, {"api_key": "has space"}, {"api_key": "x" * 600},
                    {"enabled": "yes"}):
            self.assertEqual(self.put(bad).status_code, 400, bad)

    def test_non_object_body_is_400(self):
        resp = self.client.put(SETTINGS, data=json.dumps(["x"]), content_type="application/json",
                               **self.auth())
        self.assertEqual(resp.status_code, 400)

    def test_error_messages_never_contain_the_key(self):
        resp = self.put(self.base_payload(base_url="ftp://x", api_key=KEY))
        self.assertNotIn(KEY, resp.content.decode())

    def test_azure_api_version_is_stored(self):
        body = self.put({"provider": "azure_openai", "base_url": self.server.url, "model": "dep",
                         "api_version": "2024-10-21", "api_key": KEY}).json()
        self.assertEqual(body["api_version"], "2024-10-21")


class TestConnectionTests(ApiBase):
    def test_success_against_the_saved_config_records_the_result(self):
        self.put(self.base_payload())
        self.server.reply_openai("")
        body = self.post({}).json()
        self.assertTrue(body["ok"])
        self.assertGreaterEqual(body["latency_ms"], 0)
        self.assertEqual(self.server.requests[0]["headers"]["authorization"], f"Bearer {KEY}")
        self.assertTrue(store.load().last_test_ok)

    def test_a_failing_provider_returns_ok_false_with_a_redacted_reason(self):
        self.put(self.base_payload())
        self.server.reply(401, {"error": {"message": f"Incorrect API key provided: {KEY}"}})
        resp = self.post({})
        body = resp.json()
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(body["ok"])
        self.assertNotIn(KEY, resp.content.decode())
        self.assertFalse(store.load().last_test_ok)
        self.assertNotIn(KEY, store.load().last_test_error)

    def test_draft_values_can_be_tested_before_saving_and_are_not_saved(self):
        self.server.reply_openai("")
        body = self.post(self.base_payload(api_key=NEW_KEY)).json()
        self.assertTrue(body["ok"])
        self.assertEqual(self.server.requests[0]["headers"]["authorization"], f"Bearer {NEW_KEY}")
        self.assertEqual(store.load().base_url, "")
        self.assertIsNone(store.load().last_test_ok)         # a draft never touches the saved status

    def test_saved_key_is_never_sent_to_a_different_host(self):
        self.put(self.base_payload())
        other = FakeLLMServer().start()
        self.addCleanup(other.stop)
        other.reply_openai("")
        body = self.post({"base_url": other.url + "/v1"}).json()      # no key supplied
        self.assertTrue(body["ok"])
        self.assertNotIn("authorization", other.requests[0]["headers"])
        self.assertEqual(self.server.requests, [])

    def test_saved_key_is_never_sent_when_the_provider_changes(self):
        self.put(self.base_payload())
        resp = self.post({"provider": "anthropic", "base_url": self.server.url, "model": "claude-x"})
        self.assertEqual(resp.status_code, 400)               # key required, saved one not borrowed
        self.assertEqual(resp.json()["field"], "api_key")
        self.assertEqual(self.server.requests, [])

    def test_invalid_input_is_400_and_makes_no_request(self):
        for bad in ({"base_url": "http://169.254.169.254/"}, {"provider": "nope"}, {"model": ""},
                    {"timeout_s": 0}):
            self.put(self.base_payload())
            resp = self.post(bad)
            self.assertEqual(resp.status_code, 400, bad)
        self.assertEqual(self.server.requests, [])

    def test_test_does_not_require_consent_and_sends_no_source_code(self):
        self.server.reply_openai("")
        self.post(self.base_payload())
        sent = json.dumps(self.server.requests[0]["json"])
        self.assertIn("ping", sent)
        self.assertNotIn("cursor.execute", sent)


class StatusTests(ApiBase):
    def status(self):
        resp = self.get(STATUS)
        self.assertEqual(resp.status_code, 200)
        self.assertNotIn(KEY, resp.content.decode())
        return resp.json()

    def test_not_configured(self):
        s = self.status()
        self.assertEqual((s["state"], s["source"]), ("not_configured", "none"))

    def test_configured_but_disabled(self):
        self.put(self.base_payload())
        self.assertEqual(self.status()["state"], "disabled")

    def test_untested_connected_and_failing(self):
        self.enabled()
        self.assertEqual(self.status()["state"], "untested")
        conn = store.load()
        conn.last_test_ok, conn.last_test_error = True, ""
        conn.save()
        s = self.status()
        self.assertEqual((s["state"], s["source"], s["model"]), ("connected", "byo", "m-1"))
        self.assertEqual(s["host"], f"127.0.0.1:{self.server.port}")
        conn.last_test_ok, conn.last_test_error = False, "The LLM rejected the API key (HTTP 401)."
        conn.save()
        s = self.status()
        self.assertEqual(s["state"], "failing")
        self.assertIn("rejected", s["error"])

    def test_enabled_without_valid_consent_needs_consent(self):
        self.enabled()
        conn = store.load()
        conn.consent_at = None
        conn.save()
        self.assertEqual(self.status()["state"], "needs_consent")

    @override_settings(CODESENSE_EDITION="pro")
    def test_pro_without_byo_reports_the_bundled_model(self):
        ent.reload()
        s = self.status()
        self.assertEqual((s["state"], s["source"]), ("bundled", "bundled"))

    @override_settings(CODESENSE_EDITION="pro")
    def test_pro_with_byo_enabled_reports_byo(self):
        ent.reload()
        self.enabled()
        self.assertEqual(self.status()["source"], "byo")


class ModelHealthGateTests(TestCase):
    def setUp(self):
        for var in ("ENTITLEMENTS_PUBLIC_KEY", "CODESENSE_EDITION"):
            p = mock.patch.dict(os.environ, {}, clear=False)
            p.start()
            self.addCleanup(p.stop)
            os.environ.pop(var, None)
        ent.reload()
        self.addCleanup(ent.reload)

    @override_settings(CODESENSE_EDITION="community", ENTITLEMENTS_PUBLIC_KEY=None)
    def test_community_gets_a_clean_403_not_a_500(self):
        from local.api_app.views.scan_views import ModelHealthView
        ent.reload()
        resp = ModelHealthView.get.__wrapped__(ModelHealthView(), object())
        self.assertEqual(resp.status_code, 403)
        self.assertIn("Pro", resp.data["error"])
        self.assertIn("/api/llm/status/", resp.data["error"])

    @skip_unless_llm_present()
    @override_settings(CODESENSE_EDITION="pro", ENTITLEMENTS_PUBLIC_KEY=None)
    def test_pro_error_text_is_redacted(self):
        from local.api_app.views.scan_views import ModelHealthView
        ent.reload()
        client = mock.Mock(model="m", base_url="http://127.0.0.1:8001/v1", api_key=KEY)
        client.healthcheck.side_effect = RuntimeError(f"401 for key {KEY}")
        with mock.patch("scanner.rag.llm.get_llm", return_value=client):
            resp = ModelHealthView.get.__wrapped__(ModelHealthView(), object())
        self.assertEqual(resp.status_code, 503)
        self.assertNotIn(KEY, json.dumps(resp.data))
