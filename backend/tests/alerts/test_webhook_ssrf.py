"""Every rule from Part F3 of docs/API_CONTRACT_V3.md, each with a test
that fails if the protection is removed. No real DNS lookup and no real
socket -- `socket.getaddrinfo` is monkeypatched per-test and every send
goes through `FakeTransport`.
"""
from __future__ import annotations

import pytest

from netaudit.alerts import webhook
from netaudit.alerts.webhook import WebhookRejected, WebhookResult, send_webhook, validate_and_resolve

from .conftest import fake_getaddrinfo


def test_http_scheme_rejected(monkeypatch):
    with pytest.raises(WebhookRejected) as exc:
        validate_and_resolve("http://example.com/hook")
    assert exc.value.code == "invalid_scheme"


def test_file_scheme_rejected():
    with pytest.raises(WebhookRejected) as exc:
        validate_and_resolve("file:///etc/passwd")
    assert exc.value.code == "invalid_scheme"


def test_ftp_scheme_rejected():
    with pytest.raises(WebhookRejected) as exc:
        validate_and_resolve("ftp://example.com/hook")
    assert exc.value.code == "invalid_scheme"


def test_no_scheme_rejected():
    with pytest.raises(WebhookRejected) as exc:
        validate_and_resolve("example.com/hook")
    assert exc.value.code == "invalid_scheme"


@pytest.mark.parametrize(
    "host,ip",
    [
        ("loopback.example", "127.0.0.1"),
        ("localhost", "127.0.0.1"),
        ("private10.example", "10.1.2.3"),
        ("private172.example", "172.16.5.5"),
        ("private192.example", "192.168.1.50"),
        ("linklocal.example", "169.254.1.1"),
        ("reserved.example", "240.0.0.1"),
        ("unspecified.example", "0.0.0.0"),
        ("multicast.example", "224.0.0.1"),
    ],
)
def test_ssrf_blocked_for_non_public_addresses(monkeypatch, host, ip):
    monkeypatch.setattr(webhook.socket, "getaddrinfo", fake_getaddrinfo({host: [ip]}))
    with pytest.raises(WebhookRejected) as exc:
        validate_and_resolve(f"https://{host}/hook")
    assert exc.value.code == "ssrf_blocked"


def test_ssrf_blocked_ipv6_loopback(monkeypatch):
    monkeypatch.setattr(webhook.socket, "getaddrinfo", fake_getaddrinfo({"v6loop.example": ["::1"]}))
    with pytest.raises(WebhookRejected) as exc:
        validate_and_resolve("https://v6loop.example/hook")
    assert exc.value.code == "ssrf_blocked"


def test_ssrf_blocked_when_any_resolved_address_is_private(monkeypatch):
    # Public and private both present -- reject the whole thing.
    monkeypatch.setattr(webhook.socket, "getaddrinfo", fake_getaddrinfo({"mixed.example": ["8.8.8.8", "10.0.0.1"]}))
    with pytest.raises(WebhookRejected) as exc:
        validate_and_resolve("https://mixed.example/hook")
    assert exc.value.code == "ssrf_blocked"


def test_genuinely_public_address_is_accepted(monkeypatch):
    monkeypatch.setattr(webhook.socket, "getaddrinfo", fake_getaddrinfo({"hooks.example.com": ["8.8.8.8"]}))
    host, ip, port, path = validate_and_resolve("https://hooks.example.com/x/y?z=1")
    assert host == "hooks.example.com"
    assert ip == "8.8.8.8"
    assert port == 443
    assert path == "/x/y?z=1"


def test_unresolvable_host_rejected(monkeypatch):
    monkeypatch.setattr(webhook.socket, "getaddrinfo", fake_getaddrinfo({}))
    with pytest.raises(WebhookRejected) as exc:
        validate_and_resolve("https://does-not-resolve.example/hook")
    assert exc.value.code == "resolve_failed"


def test_send_webhook_uses_validated_ip_not_a_second_dns_lookup(monkeypatch, fake_transport):
    monkeypatch.setattr(webhook.socket, "getaddrinfo", fake_getaddrinfo({"hooks.example.com": ["8.8.8.8"]}))
    result = send_webhook("https://hooks.example.com/hook", {"a": 1}, transport=fake_transport)
    assert result.ok is True
    assert fake_transport.calls[0]["ip"] == "8.8.8.8"
    assert fake_transport.calls[0]["host"] == "hooks.example.com"  # SNI/Host still uses the real hostname


def test_send_webhook_never_persists_across_calls_rechecks_every_time(monkeypatch, fake_transport):
    # First call: public. Second call: same host now resolves privately
    # (simulated DNS rebinding). Must be rejected on the second call even
    # though the first call succeeded -- proves there's no cached "this
    # host is fine" state.
    monkeypatch.setattr(webhook.socket, "getaddrinfo", fake_getaddrinfo({"rebind.example": ["8.8.8.8"]}))
    result1 = send_webhook("https://rebind.example/hook", {}, transport=fake_transport)
    assert result1.ok is True

    monkeypatch.setattr(webhook.socket, "getaddrinfo", fake_getaddrinfo({"rebind.example": ["10.0.0.5"]}))
    with pytest.raises(WebhookRejected):
        send_webhook("https://rebind.example/hook", {}, transport=fake_transport)


def test_no_redirect_is_followed(monkeypatch, fake_transport):
    monkeypatch.setattr(webhook.socket, "getaddrinfo", fake_getaddrinfo({"hooks.example.com": ["8.8.8.8"]}))
    fake_transport._responses = [WebhookResult(ok=False, status_code=302, detail="HTTP 302")]
    result = send_webhook("https://hooks.example.com/hook", {}, transport=fake_transport)
    assert result.ok is False
    assert result.status_code == 302
    # exactly one attempt -- nothing re-requested the Location header
    assert len(fake_transport.calls) == 1


def test_five_second_timeout_is_passed_through(monkeypatch, fake_transport):
    monkeypatch.setattr(webhook.socket, "getaddrinfo", fake_getaddrinfo({"hooks.example.com": ["8.8.8.8"]}))
    send_webhook("https://hooks.example.com/hook", {}, transport=fake_transport)
    assert fake_transport.calls[0]["timeout"] == webhook.DEFAULT_TIMEOUT_SECONDS == 5.0


def test_failure_is_a_single_attempt_never_a_retry_loop(monkeypatch, fake_transport):
    monkeypatch.setattr(webhook.socket, "getaddrinfo", fake_getaddrinfo({"hooks.example.com": ["8.8.8.8"]}))
    fake_transport._responses = [WebhookResult(ok=False, status_code=500, detail="HTTP 500")]
    send_webhook("https://hooks.example.com/hook", {}, transport=fake_transport)
    assert len(fake_transport.calls) == 1
