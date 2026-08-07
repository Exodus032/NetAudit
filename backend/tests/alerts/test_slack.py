from __future__ import annotations

import json

import pytest

from netaudit.alerts.models import AlertChannel, AlertsConfigUpdate
from netaudit.alerts.service import AlertConfigError, AlertService
from netaudit.alerts.slack import SEVERITY_COLORS, build_slack_payload

from .conftest import FakeTransport, fake_getaddrinfo


def _slack_channel(enabled=True, url="https://hooks.example.com/slack-hook"):
    return AlertChannel(id="slack-1", kind="slack", enabled=enabled, url=url, template="json")


def test_payload_uses_severity_color(db_path):
    payload = build_slack_payload(title="beaconing to 1.2.3.4", severity="high", source="threat", source_id="t1", ts="2026-08-07T10:00:00.000Z")
    assert payload["text"] == "*[high] threat* - beaconing to 1.2.3.4"
    attachment = payload["attachments"][0]
    assert attachment["color"] == SEVERITY_COLORS["high"]
    fields = {f["title"]: f["value"] for f in attachment["fields"]}
    assert fields == {"Severity": "high", "Source": "threat", "Source ID": "t1", "Time": "2026-08-07T10:00:00.000Z"}
    assert attachment["footer"] == "NetAudit"


def test_payload_unknown_severity_falls_back_to_info_color():
    payload = build_slack_payload(title="x", severity="wibble", source="s", source_id="i", ts="t")
    assert payload["attachments"][0]["color"] == SEVERITY_COLORS["info"]


def test_enabled_slack_channel_without_url_rejected(db_path):
    svc = AlertService(db_path=db_path)
    update = AlertsConfigUpdate(enabled=True, min_severity="high", channels=[_slack_channel(enabled=True, url="")], rate_limit_per_hour=20)
    with pytest.raises(AlertConfigError) as exc:
        svc.update_config(update)
    assert exc.value.code == "missing_url"


def test_enabled_slack_channel_with_ssrf_url_rejected(db_path, monkeypatch):
    from netaudit.alerts import webhook

    monkeypatch.setattr(webhook.socket, "getaddrinfo", fake_getaddrinfo({"hooks.example.com": ["127.0.0.1"]}))
    svc = AlertService(db_path=db_path)
    update = AlertsConfigUpdate(enabled=True, min_severity="high", channels=[_slack_channel(enabled=True, url="https://hooks.example.com/slack-hook")], rate_limit_per_hour=20)
    with pytest.raises(AlertConfigError) as exc:
        svc.update_config(update)
    assert exc.value.code == "ssrf_blocked"


def test_disabled_slack_channel_url_is_never_validated(db_path):
    # Mirrors the webhook rule: an inert channel can carry a bad URL.
    svc = AlertService(db_path=db_path)
    update = AlertsConfigUpdate(enabled=False, min_severity="high", channels=[_slack_channel(enabled=False, url="http://not-even-https")], rate_limit_per_hour=20)
    result = svc.update_config(update)
    assert result.channels[0].url == "http://not-even-https"


def test_slack_dispatch_sends_formatted_payload_via_fake_transport(db_path, monkeypatch):
    from netaudit.alerts import webhook

    monkeypatch.setattr(webhook.socket, "getaddrinfo", fake_getaddrinfo({"hooks.example.com": ["8.8.8.8"]}))

    svc = AlertService(db_path=db_path)
    svc.update_config(
        AlertsConfigUpdate(enabled=True, min_severity="low", channels=[_slack_channel(url="https://hooks.example.com/slack-hook")], rate_limit_per_hour=20)
    )
    transport = FakeTransport()
    result = svc.dispatch("critical", "threat", "t1", "beaconing detected", transport=transport)

    assert result is not None
    assert result.channels[0].status == "delivered"
    assert len(transport.calls) == 1
    call = transport.calls[0]
    assert call["host"] == "hooks.example.com"
    body = json.loads(call["body"])
    assert body["text"] == "*[critical] threat* - beaconing detected"
    assert body["attachments"][0]["color"] == SEVERITY_COLORS["critical"]
    assert body["attachments"][0]["title"] == "beaconing detected"


def test_slack_dispatch_failure_recorded_as_failed(db_path, monkeypatch):
    from netaudit.alerts import webhook

    from .conftest import WebhookResult

    monkeypatch.setattr(webhook.socket, "getaddrinfo", fake_getaddrinfo({"hooks.example.com": ["8.8.8.8"]}))

    svc = AlertService(db_path=db_path)
    svc.update_config(
        AlertsConfigUpdate(enabled=True, min_severity="low", channels=[_slack_channel(url="https://hooks.example.com/slack-hook")], rate_limit_per_hour=20)
    )
    transport = FakeTransport(responses=[WebhookResult(ok=False, status_code=400, detail="HTTP 400")])
    result = svc.dispatch("high", "threat", "t1", "something", transport=transport)
    assert result.channels[0].status == "failed"
    assert svc.history().alerts[0].channels[0].status == "failed"


def test_slack_test_channel_bypasses_filters(db_path, monkeypatch):
    from netaudit.alerts import webhook

    monkeypatch.setattr(webhook.socket, "getaddrinfo", fake_getaddrinfo({"hooks.example.com": ["8.8.8.8"]}))

    svc = AlertService(db_path=db_path)
    # Alerting is disabled and the channel is disabled -- the explicit test
    # send must still go out.
    svc.update_config(AlertsConfigUpdate(enabled=False, min_severity="high", channels=[_slack_channel(enabled=False, url="https://hooks.example.com/slack-hook")], rate_limit_per_hour=20))
    transport = FakeTransport()
    result = svc.test_channel("slack-1", transport=transport)
    assert result.status == "delivered"
    assert len(transport.calls) == 1
    body = json.loads(transport.calls[0]["body"])
    assert "test alert" in body["text"].lower()


def test_slack_dispatch_without_url_is_skipped_silently(db_path, monkeypatch):
    from netaudit.alerts import webhook

    monkeypatch.setattr(webhook.socket, "getaddrinfo", fake_getaddrinfo({"hooks.example.com": ["8.8.8.8"]}))

    svc = AlertService(db_path=db_path)
    # A channel can lose its URL via a raw store write (the UI always sends
    # one, but the store doesn't enforce it); dispatch must skip it without
    # raising or attempting a send, exactly like the generic webhook kind.
    from netaudit.alerts import store as alerts_store

    svc.update_config(AlertsConfigUpdate(enabled=True, min_severity="low", channels=[_slack_channel()], rate_limit_per_hour=20))
    alerts_store.replace_channels([{**c, "url": None} for c in alerts_store.list_channels(svc._db_path)], svc._db_path)
    transport = FakeTransport()
    result = svc.dispatch("high", "threat", "t1", "x", transport=transport)
    assert result is not None
    assert result.channels == []
    assert transport.calls == []
