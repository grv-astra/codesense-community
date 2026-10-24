"""Provider adapters against a local fake LLM server (no real provider calls)."""
import os
from unittest import mock

from django.test import SimpleTestCase

from scanner.byo_llm.config import (
    PROVIDER_ANTHROPIC, PROVIDER_AZURE, PROVIDER_OPENAI, ConnectionConfig,
)
from scanner.byo_llm.providers import build_provider
from scanner.byo_llm.providers.base import (
    ProviderAuthError, ProviderBadResponse, ProviderConfigError, ProviderRateLimited,
    ProviderRequestError, ProviderUnavailable,
)
from scanner.tests.byo_fake_server import FakeLLMServer

KEY = "sk-test-FAKE-0000000000000000"


class ProviderTestBase(SimpleTestCase):
    def setUp(self):
        # a machine-wide proxy must not intercept our loopback fake server
        patcher = mock.patch.dict(os.environ, {"NO_PROXY": "127.0.0.1,localhost", "no_proxy": "127.0.0.1,localhost"})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.server = FakeLLMServer().start()
        self.addCleanup(self.server.stop)

    def cfg(self, provider=PROVIDER_OPENAI, path="/v1", **kw):
        base = dict(provider=provider, base_url=self.server.url + path, model="m-1",
                    api_key=KEY, timeout_s=5, api_version="")
        base.update(kw)
        return ConnectionConfig(**base)

    def provider(self, **kw):
        return build_provider(self.cfg(**kw))


class OpenAICompatTests(ProviderTestBase):
    def test_success_request_shape_and_usage(self):
        self.server.reply_openai('{"verdict":"FP"}', 21, 9)
        res = self.provider().complete_json("SYS", "USER", 300)
        self.assertEqual(res.text, '{"verdict":"FP"}')
        self.assertEqual((res.tokens_in, res.tokens_out), (21, 9))
        req = self.server.requests[0]
        self.assertEqual(req["path"], "/v1/chat/completions")
        self.assertEqual(req["headers"]["authorization"], f"Bearer {KEY}")
        body = req["json"]
        self.assertEqual(body["model"], "m-1")
        self.assertEqual(body["messages"], [{"role": "system", "content": "SYS"},
                                            {"role": "user", "content": "USER"}])
        self.assertEqual(body["max_tokens"], 300)
        self.assertEqual(body["temperature"], 0)
        self.assertEqual(body["response_format"], {"type": "json_object"})

    def test_no_key_sends_no_authorization_header(self):
        self.server.reply_openai()
        self.provider(api_key="").complete_json("s", "u")
        self.assertNotIn("authorization", self.server.requests[0]["headers"])

    def test_content_parts_are_joined(self):
        self.server.reply(200, {"choices": [{"message": {"content": [
            {"type": "text", "text": '{"a":'}, {"type": "text", "text": '1}'}]}}]})
        self.assertEqual(self.provider().complete_json("s", "u").text, '{"a":1}')

    def test_401_and_403_are_fatal_auth_errors_without_the_key(self):
        for status in (401, 403):
            self.server.reply(status, {"error": {"message": f"Incorrect API key provided: {KEY}"}})
            with self.assertRaises(ProviderAuthError) as ctx:
                self.provider().complete_json("s", "u")
            self.assertTrue(ctx.exception.fatal)
            self.assertNotIn(KEY, str(ctx.exception))

    def test_404_is_fatal_with_a_hint(self):
        self.server.reply(404, {"error": "nope"})
        with self.assertRaises(ProviderRequestError) as ctx:
            self.provider().complete_json("s", "u")
        self.assertTrue(ctx.exception.fatal)
        self.assertIn("base URL", str(ctx.exception))

    def test_429_carries_retry_after(self):
        self.server.reply(429, {"error": "slow down"}, headers={"Retry-After": "7"})
        with self.assertRaises(ProviderRateLimited) as ctx:
            self.provider().complete_json("s", "u")
        self.assertEqual(ctx.exception.retry_after, 7.0)

    def test_429_without_header(self):
        self.server.reply(429, {})
        with self.assertRaises(ProviderRateLimited) as ctx:
            self.provider().complete_json("s", "u")
        self.assertIsNone(ctx.exception.retry_after)

    def test_5xx_is_unavailable_and_not_fatal(self):
        self.server.reply(503, {})
        with self.assertRaises(ProviderUnavailable) as ctx:
            self.provider().complete_json("s", "u")
        self.assertFalse(ctx.exception.fatal)

    def test_other_4xx_is_a_request_error_with_redacted_reason(self):
        self.server.reply(422, {"error": {"message": f"bad thing with {KEY} in it"}})
        with self.assertRaises(ProviderRequestError) as ctx:
            self.provider().complete_json("s", "u")
        self.assertFalse(ctx.exception.fatal)
        self.assertNotIn(KEY, str(ctx.exception))

    def test_malformed_and_empty_replies(self):
        self.server.reply(200, raw=b"<html>not json</html>")
        with self.assertRaises(ProviderBadResponse):
            self.provider().complete_json("s", "u")
        self.server.reply(200, {"choices": []})
        with self.assertRaises(ProviderBadResponse):
            self.provider().complete_json("s", "u")
        # A blank reply is retried with a bigger budget (see test_byo_empty_reply), so it takes one
        # blank answer per budget step before the call gives up.
        for _ in range(3):
            self.server.reply_openai("   ")
        with self.assertRaises(ProviderBadResponse):
            self.provider().complete_json("s", "u")

    def test_ping_accepts_an_empty_reply(self):
        self.server.reply_openai("")
        self.provider().ping()                      # must not raise

    def test_redirect_is_not_followed(self):
        self.server.reply(302, {}, headers={"Location": "http://169.254.169.254/"})
        with self.assertRaises(ProviderBadResponse):
            self.provider().complete_json("s", "u")
        self.assertEqual(len(self.server.requests), 1)

    def test_oversized_reply_is_rejected(self):
        with mock.patch("scanner.byo_llm.providers._http.MAX_BODY_BYTES", 1000):
            self.server.reply(200, raw=b"x" * 5000)
            with self.assertRaises(ProviderBadResponse):
                self.provider().complete_json("s", "u")

    def test_timeout_is_unavailable(self):
        self.server.reply_openai()
        self.server._replies[0] = (*self.server._replies[0][:3], 2)      # delay 2s
        with self.assertRaises(ProviderUnavailable) as ctx:
            self.provider(timeout_s=1).complete_json("s", "u")
        self.assertIn("timed out", str(ctx.exception))

    def test_connection_refused_is_unavailable(self):
        port = self.server.port
        self.server.stop()
        with self.assertRaises(ProviderUnavailable):
            build_provider(ConnectionConfig(PROVIDER_OPENAI, f"http://127.0.0.1:{port}/v1", "m", KEY, 5)
                           ).complete_json("s", "u")

    # -- tolerance of provider differences --------------------------------

    def test_drops_response_format_when_rejected_and_remembers(self):
        self.server.reply(400, {"error": {"message": "response_format is not supported by this model"}})
        self.server.reply_openai()
        self.server.reply_openai()
        p = self.provider()
        p.complete_json("s", "u")
        self.assertIn("response_format", self.server.requests[0]["json"])
        self.assertNotIn("response_format", self.server.requests[1]["json"])
        p.complete_json("s", "u")                   # learned: not sent again
        self.assertNotIn("response_format", self.server.requests[2]["json"])

    def test_switches_to_max_completion_tokens(self):
        self.server.reply(400, {"error": {"message": "Unsupported parameter: 'max_tokens'. "
                                                     "Use 'max_completion_tokens' instead."}})
        self.server.reply_openai()
        self.provider().complete_json("s", "u", 123)
        retry = self.server.requests[1]["json"]
        self.assertNotIn("max_tokens", retry)
        self.assertEqual(retry["max_completion_tokens"], 123)

    def test_drops_temperature_when_rejected(self):
        self.server.reply(400, {"error": {"message": "Unsupported value: 'temperature' does not support 0"}})
        self.server.reply_openai()
        self.provider().complete_json("s", "u")
        self.assertNotIn("temperature", self.server.requests[1]["json"])

    def test_unrelated_400_is_not_retried_forever(self):
        self.server.reply(400, {"error": {"message": "context length exceeded"}})
        with self.assertRaises(ProviderRequestError):
            self.provider().complete_json("s", "u")
        self.assertEqual(len(self.server.requests), 1)

    def test_adaptation_loop_is_bounded(self):
        for _ in range(6):
            self.server.reply(400, {"error": {"message": "response_format temperature max_completion_tokens"}})
        with self.assertRaises(ProviderRequestError):
            self.provider().complete_json("s", "u")
        self.assertLessEqual(len(self.server.requests), 4)


class AzureTests(ProviderTestBase):
    def test_url_header_and_body(self):
        self.server.reply_openai()
        p = self.provider(provider=PROVIDER_AZURE, path="", model="my-gpt4o", api_version="2024-10-21")
        p.complete_json("s", "u")
        req = self.server.requests[0]
        self.assertEqual(req["path"], "/openai/deployments/my-gpt4o/chat/completions?api-version=2024-10-21")
        self.assertEqual(req["headers"]["api-key"], KEY)
        self.assertNotIn("authorization", req["headers"])
        self.assertNotIn("model", req["json"])

    def test_default_api_version(self):
        self.server.reply_openai()
        self.provider(provider=PROVIDER_AZURE, path="").complete_json("s", "u")
        self.assertIn("api-version=2024-10-21", self.server.requests[0]["path"])

    def test_needs_key_and_deployment(self):
        with self.assertRaises(ProviderConfigError):
            self.provider(provider=PROVIDER_AZURE, api_key="")
        with self.assertRaises(ProviderConfigError):
            build_provider(self.cfg(provider=PROVIDER_AZURE, model=""))


class AnthropicTests(ProviderTestBase):
    def test_request_shape_and_parse(self):
        self.server.reply_anthropic('{"verdict":"TP"}', 30, 12)
        res = self.provider(provider=PROVIDER_ANTHROPIC, path="").complete_json("SYS", "USER", 256)
        self.assertEqual(res.text, '{"verdict":"TP"}')
        self.assertEqual((res.tokens_in, res.tokens_out), (30, 12))
        req = self.server.requests[0]
        self.assertEqual(req["path"], "/v1/messages")
        self.assertEqual(req["headers"]["x-api-key"], KEY)
        self.assertEqual(req["headers"]["anthropic-version"], "2023-06-01")
        self.assertNotIn("authorization", req["headers"])
        self.assertEqual(req["json"]["system"], "SYS")
        self.assertEqual(req["json"]["messages"], [{"role": "user", "content": "USER"}])
        self.assertEqual(req["json"]["max_tokens"], 256)

    def test_base_url_with_v1_is_not_doubled(self):
        self.server.reply_anthropic()
        self.provider(provider=PROVIDER_ANTHROPIC, path="/v1").complete_json("s", "u")
        self.assertEqual(self.server.requests[0]["path"], "/v1/messages")

    def test_only_text_blocks_are_used(self):
        self.server.reply(200, {"content": [{"type": "thinking", "thinking": "hmm"},
                                            {"type": "text", "text": "{}"}]})
        self.assertEqual(self.provider(provider=PROVIDER_ANTHROPIC, path="").complete_json("s", "u").text, "{}")

    def test_errors_map_like_openai(self):
        p = self.provider(provider=PROVIDER_ANTHROPIC, path="")
        self.server.reply(401, {"error": {"type": "authentication_error"}})
        with self.assertRaises(ProviderAuthError):
            p.complete_json("s", "u")
        self.server.reply(529, {})
        with self.assertRaises(ProviderUnavailable):
            p.complete_json("s", "u")
        self.server.reply(429, {}, headers={"retry-after": "3"})
        with self.assertRaises(ProviderRateLimited) as ctx:
            p.complete_json("s", "u")
        self.assertEqual(ctx.exception.retry_after, 3.0)
        self.server.reply(200, {"content": "nope"})
        with self.assertRaises(ProviderBadResponse):
            p.complete_json("s", "u")

    def test_drops_temperature_when_rejected(self):
        self.server.reply(400, {"error": {"message": "temperature is deprecated for this model"}})
        self.server.reply_anthropic()
        self.provider(provider=PROVIDER_ANTHROPIC, path="").complete_json("s", "u")
        self.assertNotIn("temperature", self.server.requests[1]["json"])

    def test_needs_key_and_model(self):
        with self.assertRaises(ProviderConfigError):
            self.provider(provider=PROVIDER_ANTHROPIC, api_key="")


class PolicyEnforcementTests(SimpleTestCase):
    """The URL policy is applied by the provider itself, on every call."""

    def test_metadata_url_is_refused_before_any_request(self):
        p = build_provider(ConnectionConfig(PROVIDER_OPENAI, "http://169.254.169.254/v1", "m", KEY, 5))
        with mock.patch("scanner.byo_llm.providers._http.requests.post") as post:
            with self.assertRaises(ProviderConfigError) as ctx:
                p.complete_json("s", "u")
            post.assert_not_called()
        self.assertTrue(ctx.exception.fatal)

    def test_plain_http_to_remote_is_refused(self):
        p = build_provider(ConnectionConfig(PROVIDER_OPENAI, "http://example.com/v1", "m", KEY, 5))
        with mock.patch("scanner.byo_llm.url_policy.socket.getaddrinfo",
                        return_value=[(2, 1, 6, "", ("93.184.216.34", 80))]):
            with self.assertRaises(ProviderConfigError) as ctx:
                p.complete_json("s", "u")
        self.assertIn("https", str(ctx.exception))      # proves the patched (public) address was judged

    def test_unknown_provider_and_missing_model(self):
        with self.assertRaises(ProviderConfigError):
            build_provider(ConnectionConfig("skynet", "https://x", "m", KEY))
        with self.assertRaises(ProviderConfigError):
            build_provider(ConnectionConfig(PROVIDER_OPENAI, "https://x", "", KEY))

    def test_config_repr_hides_the_key(self):
        self.assertNotIn(KEY, repr(ConnectionConfig(PROVIDER_OPENAI, "https://x", "m", KEY)))
