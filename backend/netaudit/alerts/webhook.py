"""The one and only outbound network path this whole backend exposes to
user configuration (per docs/API_CONTRACT_V3.md's top-of-file rule 2: "No
outbound network requests except those the user explicitly triggers.").

Every send goes through `send_webhook()`, which re-validates and
re-resolves the URL on *every call* -- never caches a validated IP across
calls -- specifically so a DNS answer that pointed at a public address when
the URL was saved can't be swapped out for a private one later (DNS
rebinding) and still get connected to. `validate_and_resolve()` is the
single choke point enforcing: https-only, and none of the resolved
addresses may be private/loopback/link-local/reserved/multicast/
unspecified.

`RealTransport.send()` is the *only* function in this package (and,
per `tests/alerts/test_no_stray_network_calls.py`, in this whole file) that
opens a real socket. Everything else takes a `Transport` (a tiny Protocol)
so tests can inject a fake and make zero real network calls.
"""
from __future__ import annotations

import http.client
import ipaddress
import json
import socket
import ssl
from dataclasses import dataclass
from typing import Optional, Protocol, runtime_checkable
from urllib.parse import urlsplit

DEFAULT_TIMEOUT_SECONDS = 5.0
_MAX_RESPONSE_BYTES = 4096  # bounded read -- never buffer an arbitrarily large webhook response


class WebhookRejected(Exception):
    """Raised by `validate_and_resolve()` for anything that must never be
    connected to: wrong scheme, unresolvable host, or a resolved address
    that isn't public. `code` is a short machine-readable reason the
    router maps to a 400 body."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(message)


@dataclass(frozen=True)
class WebhookResult:
    ok: bool
    status_code: Optional[int]
    detail: str


@runtime_checkable
class Transport(Protocol):
    def send(self, *, ip: str, port: int, host: str, path: str, body: bytes, headers: dict, timeout: float) -> WebhookResult: ...


def _is_public_ip(ip_str: str) -> bool:
    """True only for a genuinely public, routable unicast address. Every
    one of these properties has to be checked explicitly -- `is_global`
    alone (on some Python versions) doesn't reliably exclude every
    RFC1918/loopback/link-local/reserved case across both IPv4 and IPv6,
    so this enumerates the rejection reasons instead of trusting one
    catch-all flag."""
    addr = ipaddress.ip_address(ip_str)
    site_local = getattr(addr, "is_site_local", False)  # legacy IPv6 site-local (fec0::/10); IPv4 has no such attribute
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
        or site_local
    )


def validate_and_resolve(url: str) -> tuple[str, str, int, str]:
    """Returns `(host, ip, port, path)` for a URL that has passed every
    check. Raises `WebhookRejected` otherwise. Called both when a webhook
    URL is saved (`PUT /api/alerts/config`) and again, fresh, every time a
    webhook is actually sent -- defense in depth against DNS rebinding
    between those two moments.
    """
    parsed = urlsplit(url)
    if parsed.scheme != "https":
        raise WebhookRejected("invalid_scheme", f"webhook URL must use https, got {parsed.scheme or '(none)'!r}")
    host = parsed.hostname
    if not host:
        raise WebhookRejected("invalid_url", "webhook URL has no host")

    try:
        port = parsed.port or 443
    except ValueError as exc:
        raise WebhookRejected("invalid_url", f"invalid port: {exc}") from exc

    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise WebhookRejected("resolve_failed", f"could not resolve host {host!r}: {exc}") from exc

    ips = sorted({info[4][0] for info in infos})
    if not ips:
        raise WebhookRejected("resolve_failed", f"host {host!r} resolved to no addresses")

    for ip_str in ips:
        ip_clean = ip_str.split("%")[0]  # strip an IPv6 zone id (fe80::1%eth0) before parsing
        if not _is_public_ip(ip_clean):
            raise WebhookRejected(
                "ssrf_blocked",
                f"webhook host {host!r} resolves to {ip_clean}, which is a private/loopback/link-local/"
                "reserved address -- refusing to send (this would let a webhook probe the local network)",
            )

    return host, ips[0], port, path


class RealTransport:
    """The only code in this package that touches a real socket. Connects
    directly to the pre-validated, pre-resolved IP address (not back
    through DNS a second time) while still sending the original hostname
    for TLS SNI and certificate validation. No redirects are ever followed
    -- a 3xx response is simply reported as a non-2xx result, never
    re-requested."""

    def send(self, *, ip: str, port: int, host: str, path: str, body: bytes, headers: dict, timeout: float) -> WebhookResult:
        try:
            raw_sock = socket.create_connection((ip, port), timeout=timeout)
        except OSError as exc:
            return WebhookResult(ok=False, status_code=None, detail=f"connection failed: {exc}")

        context = ssl.create_default_context()
        try:
            tls_sock = context.wrap_socket(raw_sock, server_hostname=host)
        except (OSError, ssl.SSLError) as exc:
            raw_sock.close()
            return WebhookResult(ok=False, status_code=None, detail=f"TLS handshake failed: {exc}")

        conn = http.client.HTTPSConnection(host, timeout=timeout)
        conn.sock = tls_sock
        try:
            conn.request("POST", path, body=body, headers=headers)
            resp = conn.getresponse()
            status = resp.status
            resp.read(_MAX_RESPONSE_BYTES)
            return WebhookResult(ok=200 <= status < 300, status_code=status, detail=f"HTTP {status}")
        except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
            return WebhookResult(ok=False, status_code=None, detail=f"request failed: {exc}")
        finally:
            conn.close()


_REAL_TRANSPORT = RealTransport()


def send_webhook(url: str, payload: dict, timeout: float = DEFAULT_TIMEOUT_SECONDS, transport: Optional[Transport] = None) -> WebhookResult:
    """Validates+resolves fresh, then does exactly one POST attempt via
    `transport` (defaults to the real one). Never retries -- a caller that
    wants "never retried in a tight loop" gets that for free because this
    function makes exactly one attempt and returns."""
    transport = transport or _REAL_TRANSPORT
    host, ip, port, path = validate_and_resolve(url)
    body = json.dumps(payload).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Content-Length": str(len(body)),
        "User-Agent": "NetAudit-Alerts/1.0",
    }
    return transport.send(ip=ip, port=port, host=host, path=path, body=body, headers=headers, timeout=timeout)
