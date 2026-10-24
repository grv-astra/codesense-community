"""SSRF policy for the user-supplied LLM base URL."""
import socket

from django.test import SimpleTestCase

from scanner.byo_llm.redact import redact
from scanner.byo_llm.url_policy import UrlPolicyError, consent_host_of, validate_base_url


def resolver_to(*addrs):
    """A fake getaddrinfo that always answers with ``addrs``."""
    def fake(host, port, type=0):
        out = []
        for a in addrs:
            fam = socket.AF_INET6 if ":" in a else socket.AF_INET
            out.append((fam, socket.SOCK_STREAM, 6, "", (a, port)))
        return out
    return fake


def unresolvable(host, port, type=0):
    raise socket.gaierror("no such host")


class AllowedTests(SimpleTestCase):
    def ok(self, url, *addrs):
        return validate_base_url(url, resolver=resolver_to(*addrs))

    def test_remote_https(self):
        v = self.ok("https://api.openai.com/v1", "104.18.7.192")
        self.assertEqual(v.url, "https://api.openai.com/v1")
        self.assertEqual(v.consent_host, "api.openai.com")

    def test_loopback_http_is_allowed(self):
        self.assertEqual(self.ok("http://localhost:11434/v1", "127.0.0.1").consent_host, "localhost:11434")
        self.ok("http://[::1]:1234/v1", "::1")

    def test_private_lan_http_is_allowed(self):
        for ip in ("10.1.2.3", "172.16.5.5", "192.168.0.20", "fd12:3456::1"):
            self.ok("http://gpu-box:8000/v1", ip)

    def test_tailscale_cgnat_http_is_allowed(self):
        self.ok("http://100.101.102.103:8000/v1", "100.101.102.103")

    def test_private_over_https_allowed(self):
        self.ok("https://llm.corp.internal/v1", "10.0.0.5")

    def test_trailing_slash_and_case_normalised(self):
        v = self.ok("HTTPS://Api.Example.com/v1/", "93.184.216.34")
        self.assertEqual(v.url, "https://api.example.com/v1")


class BlockedTests(SimpleTestCase):
    def blocked(self, url, *addrs, contains=None):
        with self.assertRaises(UrlPolicyError) as ctx:
            validate_base_url(url, resolver=resolver_to(*addrs))
        if contains:
            self.assertIn(contains, str(ctx.exception))

    def test_cloud_metadata_ipv4(self):
        self.blocked("http://169.254.169.254/latest", "169.254.169.254")
        self.blocked("https://169.254.169.254", "169.254.169.254")

    def test_other_link_local(self):
        self.blocked("http://169.254.1.1", "169.254.1.1", contains="link-local")
        self.blocked("http://[fe80::1]", "fe80::1", contains="link-local")

    def test_aws_ipv6_and_alibaba_metadata(self):
        self.blocked("http://[fd00:ec2::254]/", "fd00:ec2::254", contains="metadata")
        self.blocked("http://100.100.100.200", "100.100.100.200", contains="metadata")

    def test_dns_name_pointing_at_metadata_is_blocked(self):
        self.blocked("https://metadata.google.internal", "169.254.169.254")

    def test_ipv4_hidden_in_ipv6_is_unwrapped(self):
        self.blocked("http://[::ffff:169.254.169.254]", "::ffff:169.254.169.254")
        self.blocked("http://x", "64:ff9b::a9fe:a9fe")           # NAT64 of 169.254.169.254

    def test_any_blocked_address_among_several_blocks(self):
        self.blocked("https://rebind.example.com", "93.184.216.34", "169.254.169.254")

    def test_unspecified_and_multicast(self):
        self.blocked("http://0.0.0.0:8000", "0.0.0.0", contains="unspecified")
        self.blocked("http://x", "224.0.0.1", contains="multicast")

    def test_plain_http_to_a_remote_host(self):
        self.blocked("http://api.example.com/v1", "93.184.216.34", contains="https")

    def test_plain_http_blocked_if_any_address_is_public(self):
        self.blocked("http://mixed.example.com", "10.0.0.1", "93.184.216.34", contains="https")

    def test_bad_schemes(self):
        for url in ("ftp://example.com", "file:///etc/passwd", "gopher://x", "javascript:alert(1)", "//example.com"):
            with self.assertRaises(UrlPolicyError):
                validate_base_url(url, resolver=resolver_to("93.184.216.34"))

    def test_credentials_query_fragment_rejected(self):
        for url in ("https://user:pw@example.com", "https://user@example.com",
                    "https://example.com/v1?key=abc", "https://example.com/v1#frag"):
            with self.assertRaises(UrlPolicyError):
                validate_base_url(url, resolver=resolver_to("93.184.216.34"))

    def test_empty_whitespace_control_chars_and_length(self):
        for url in ("", "   ", "https://exa mple.com", "https://exam\nple.com/v1", "https://" + "a" * 600 + ".com"):
            with self.assertRaises(UrlPolicyError):
                validate_base_url(url, resolver=resolver_to("93.184.216.34"))

    def test_bad_port(self):
        with self.assertRaises(UrlPolicyError):
            validate_base_url("https://example.com:99999", resolver=resolver_to("93.184.216.34"))

    def test_unresolvable_host(self):
        with self.assertRaises(UrlPolicyError) as ctx:
            validate_base_url("https://nope.invalid", resolver=unresolvable)
        self.assertIn("could not be resolved", str(ctx.exception))

    def test_odd_ip_spellings_are_judged_by_what_they_resolve_to(self):
        # decimal / hex / octal forms of 169.254.169.254 as a real resolver returns them
        for spelling in ("http://2852039166", "http://0xa9fea9fe", "http://0251.0376.0251.0376"):
            self.blocked(spelling, "169.254.169.254")

    def test_error_messages_do_not_echo_credentials(self):
        with self.assertRaises(UrlPolicyError) as ctx:
            validate_base_url("https://user:SECRETPW@example.com", resolver=resolver_to("93.184.216.34"))
        self.assertNotIn("SECRETPW", str(ctx.exception))


class ConsentHostTests(SimpleTestCase):
    def test_consent_host_without_dns(self):
        self.assertEqual(consent_host_of("https://API.OpenAI.com/v1"), "api.openai.com")
        self.assertEqual(consent_host_of("http://localhost:11434/v1"), "localhost:11434")
        self.assertEqual(consent_host_of("http://[::1]:1234/v1"), "[::1]:1234")
        self.assertEqual(consent_host_of("not a url"), "")
        self.assertEqual(consent_host_of(""), "")


class RedactTests(SimpleTestCase):
    def test_explicit_secret_removed(self):
        self.assertNotIn("abcd1234secret", redact("bad key abcd1234secret supplied", "abcd1234secret"))

    def test_bearer_and_header_forms(self):
        self.assertNotIn("tok_12345678", redact("Authorization: Bearer tok_12345678"))
        self.assertNotIn("zzzz9999", redact("x-api-key: zzzz9999 invalid"))

    def test_openai_style_key_echo(self):
        out = redact("Incorrect API key provided: sk-proj-abc123XYZ789")
        self.assertNotIn("abc123XYZ789", out)

    def test_whitespace_collapsed_and_truncated(self):
        out = redact("a\n\n  b" + "x" * 500, limit=50)
        self.assertLessEqual(len(out), 50)
        self.assertNotIn("\n", out)

    def test_short_secret_is_not_over_redacted(self):
        self.assertEqual(redact("ok to go", "ok"), "ok to go")
