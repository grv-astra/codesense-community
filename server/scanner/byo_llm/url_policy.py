"""SSRF policy for the user-supplied LLM base URL.

Loopback and private ranges are LEGITIMATE (Ollama, LM Studio, vLLM on the LAN or
a tailnet), so they are allowed. What is blocked is what a base URL should never
reach: link-local (incl. the cloud metadata endpoints), unspecified and multicast
addresses. Plain http is only allowed when every resolved address is local/private
(a remote host must use https). Credentials, query strings and fragments in the URL
are rejected.

The check is done on the RESOLVED addresses, not the URL string, so decimal / hex /
octal IP spellings, IPv4-mapped IPv6 and DNS names that point at metadata IPs are
all caught. It must be re-run before every request (DNS can change); a residual
resolve-then-connect race remains and is accepted.
"""
from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit

MAX_URL_LEN = 500

_METADATA = frozenset(ipaddress.ip_address(a) for a in (
    "169.254.169.254",      # AWS / Azure / GCP / most clouds
    "fd00:ec2::254",        # AWS IPv6 metadata
    "100.100.100.200",      # Alibaba Cloud metadata
))
_CGNAT = ipaddress.ip_network("100.64.0.0/10")      # Tailscale and carrier-grade NAT
_NAT64 = ipaddress.ip_network("64:ff9b::/96")


class UrlPolicyError(ValueError):
    """The base URL is not acceptable. The message is safe to show to the user."""


@dataclass(frozen=True)
class ValidatedUrl:
    url: str            # normalised: scheme://host[:port]/path, no trailing slash
    scheme: str
    host: str           # lower-case hostname (no port)
    port: int | None    # explicit port or None
    consent_host: str   # host[:port] -- what the user consents to send data to


def _unwrap(ip):
    """Reveal an IPv4 address hidden inside an IPv6 one (mapped / NAT64 / 6to4)."""
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return ip.ipv4_mapped
        if ip in _NAT64:
            return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
        if ip.sixtofour is not None:
            return ip.sixtofour
    return ip


def _block_reason(ip) -> str | None:
    if ip in _METADATA:
        return "cloud metadata address"
    if ip.is_link_local:
        return "link-local address"
    if ip.is_unspecified:
        return "unspecified address"
    if ip.is_multicast:
        return "multicast address"
    return None


def _is_local(ip) -> bool:
    return ip.is_loopback or ip.is_private or (ip.version == 4 and ip in _CGNAT)


def _resolve(host: str, port: int, resolver) -> list:
    try:
        infos = resolver(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError, OSError):
        raise UrlPolicyError(f"Host '{host}' could not be resolved.") from None
    ips = []
    for info in infos:
        addr = str(info[4][0]).split("%", 1)[0]          # drop IPv6 scope id
        try:
            ips.append(ipaddress.ip_address(addr))
        except ValueError:
            continue
    if not ips:
        raise UrlPolicyError(f"Host '{host}' could not be resolved.")
    return ips


def validate_base_url(url: str, resolver=None) -> ValidatedUrl:
    resolver = resolver or socket.getaddrinfo        # looked up per call so tests can patch it
    raw = (url or "").strip()
    if not raw:
        raise UrlPolicyError("Base URL is required.")
    if len(raw) > MAX_URL_LEN:
        raise UrlPolicyError("Base URL is too long.")
    if any(c.isspace() or ord(c) < 32 for c in raw):
        raise UrlPolicyError("Base URL must not contain spaces or control characters.")

    try:
        parts = urlsplit(raw)
        host = parts.hostname
        port = parts.port
    except ValueError:
        raise UrlPolicyError("Base URL is not a valid URL.") from None

    scheme = (parts.scheme or "").lower()
    if scheme not in ("http", "https"):
        raise UrlPolicyError("Base URL must start with http:// or https://.")
    if not host:
        raise UrlPolicyError("Base URL has no host.")
    if parts.username is not None or parts.password is not None:
        raise UrlPolicyError("Base URL must not contain credentials; use the API key field.")
    if parts.query or parts.fragment:
        raise UrlPolicyError("Base URL must not contain a query string or fragment.")

    host = host.lower()
    effective_port = port or (443 if scheme == "https" else 80)
    ips = [_unwrap(ip) for ip in _resolve(host, effective_port, resolver)]
    for ip in ips:
        reason = _block_reason(ip)
        if reason:
            raise UrlPolicyError(f"Host '{host}' resolves to a {reason} ({ip}), which is not allowed.")
    if scheme == "http" and not all(_is_local(ip) for ip in ips):
        raise UrlPolicyError(
            "Plain http is only allowed for local or private hosts; use https for a remote host."
        )

    shown_host = f"[{host}]" if ":" in host else host
    netloc = f"{shown_host}:{port}" if port else shown_host
    path = parts.path.rstrip("/")
    return ValidatedUrl(
        url=f"{scheme}://{netloc}{path}",
        scheme=scheme,
        host=host,
        port=port,
        consent_host=netloc,
    )


def consent_host_of(url: str) -> str:
    """The host[:port] a consent is bound to, without resolving DNS. '' if unparseable."""
    try:
        parts = urlsplit((url or "").strip())
        host = (parts.hostname or "").lower()
        port = parts.port
    except ValueError:
        return ""
    if not host:
        return ""
    shown = f"[{host}]" if ":" in host else host
    return f"{shown}:{port}" if port else shown
