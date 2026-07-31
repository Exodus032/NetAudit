from __future__ import annotations

import pytest

from netaudit.alerts.desktop import DesktopResult
from netaudit.alerts.models import AlertChannel, AlertsConfigUpdate, QuietHours
from netaudit.alerts.service import AlertConfigError, AlertService

from .conftest import FakeTransport


class FakeDesktopSender:
    def __init__(self, status="delivered"):
        self.calls = []
        self._status = status

    def send(self, title, message, timeout=5.0):
        self.calls.append((title, message))
        return DesktopResult(status=self._status)


def _desktop_channel(enabled=True):
    return AlertChannel(id="desktop", kind="desktop", enabled=enabled)


def _webhook_channel(enabled=True, url="https://hooks.example.com/x"):
    return AlertChannel(id="webhook-1", kind="webhook", enabled=enabled, url=url, template="json")


def test_disabled_by_default(db_path):
    # brand-new config (no PUT yet) -- default must be disabled
    svc = AlertService(db_path=db_path)
    config = svc.get_config()
    assert config.enabled is False
    assert any(c.id == "desktop" and c.kind == "desktop" for c in config.channels)


def test_enabled_webhook_without_url_rejected(db_path):
    svc = AlertService(db_path=db_path)
    update = AlertsConfigUpdate(enabled=True, min_severity="high", channels=[_webhook_channel(enabled=True, url="")], rate_limit_per_hour=20)
    with pytest.raises(AlertConfigError) as exc:
        svc.update_config(update)
    assert exc.value.code == "missing_url"


def test_enabled_webhook_with_ssrf_url_rejected(db_path, monkeypatch):
    from netaudit.alerts import webhook

    from .conftest import fake_getaddrinfo

    monkeypatch.setattr(webhook.socket, "getaddrinfo", fake_getaddrinfo({"internal.example": ["10.0.0.5"]}))
    svc = AlertService(db_path=db_path)
    update = AlertsConfigUpdate(enabled=True, min_severity="high", channels=[_webhook_channel(enabled=True, url="https://internal.example/hook")], rate_limit_per_hour=20)
    with pytest.raises(AlertConfigError) as exc:
        svc.update_config(update)
    assert exc.value.code == "ssrf_blocked"


def test_disabled_webhook_url_is_never_validated(db_path):
    # A disabled webhook channel can carry an obviously-bad URL without
    # rejecting the whole config save -- it's inert until enabled.
    svc = AlertService(db_path=db_path)
    update = AlertsConfigUpdate(enabled=False, min_severity="high", channels=[_webhook_channel(enabled=False, url="http://not-even-https")], rate_limit_per_hour=20)
    result = svc.update_config(update)
    assert result.channels[0].url == "http://not-even-https"


def test_min_severity_filters_low_severity_alerts(db_path):
    svc = AlertService(db_path=db_path)
    svc.update_config(AlertsConfigUpdate(enabled=True, min_severity="high", channels=[_desktop_channel()], rate_limit_per_hour=20))
    desktop = FakeDesktopSender()
    result = svc.dispatch("low", "threat", "t1", "low severity thing", desktop_sender=desktop)
    assert result is None
    assert desktop.calls == []  # never even attempted
    assert svc.history().alerts == []


def test_min_severity_allows_at_or_above_threshold(db_path):
    svc = AlertService(db_path=db_path)
    svc.update_config(AlertsConfigUpdate(enabled=True, min_severity="high", channels=[_desktop_channel()], rate_limit_per_hour=20))
    desktop = FakeDesktopSender()
    result = svc.dispatch("critical", "threat", "t1", "critical thing", desktop_sender=desktop)
    assert result is not None
    assert len(desktop.calls) == 1
    assert result.channels[0].status == "delivered"


def test_disabled_config_dispatch_is_a_full_no_op(db_path):
    svc = AlertService(db_path=db_path)
    svc.update_config(AlertsConfigUpdate(enabled=False, min_severity="low", channels=[_desktop_channel()], rate_limit_per_hour=20))
    desktop = FakeDesktopSender()
    result = svc.dispatch("critical", "threat", "t1", "x", desktop_sender=desktop)
    assert result is None
    assert desktop.calls == []


def test_rate_limit_suppresses_after_threshold(db_path):
    svc = AlertService(db_path=db_path)
    svc.update_config(AlertsConfigUpdate(enabled=True, min_severity="low", channels=[_desktop_channel()], rate_limit_per_hour=2))
    desktop = FakeDesktopSender()
    r1 = svc.dispatch("high", "threat", "a", "one", desktop_sender=desktop)
    r2 = svc.dispatch("high", "threat", "b", "two", desktop_sender=desktop)
    r3 = svc.dispatch("high", "threat", "c", "three", desktop_sender=desktop)
    assert r1.channels[0].status == "delivered"
    assert r2.channels[0].status == "delivered"
    # third one within the same hour, over the cap of 2 -- rate limited, not delivered
    assert r3.channels[0].status == "rate_limited"
    assert len(desktop.calls) == 2  # the third never actually reached the sender


def test_quiet_hours_suppresses_delivery_but_still_records_history(db_path):
    from datetime import datetime, timedelta

    svc = AlertService(db_path=db_path)
    now = datetime.now()
    start = (now - timedelta(minutes=1)).strftime("%H:%M")
    end = (now + timedelta(hours=1)).strftime("%H:%M")
    svc.update_config(
        AlertsConfigUpdate(
            enabled=True, min_severity="low", channels=[_desktop_channel()], rate_limit_per_hour=20,
            quiet_hours=QuietHours(start=start, end=end),
        )
    )
    desktop = FakeDesktopSender()
    result = svc.dispatch("critical", "threat", "t1", "urgent", desktop_sender=desktop)
    assert result is not None
    assert result.channels[0].status == "suppressed"
    assert desktop.calls == []  # quiet hours means it never actually reaches the sender
    assert len(svc.history().alerts) == 1


def test_quiet_hours_window_wrapping_midnight(db_path):
    # 23:00-07:00 quiet window, "now" forced to be inside it via a wide
    # window that always contains "now" regardless of test run time --
    # exercise the wraparound branch directly.
    from netaudit.alerts.service import _is_quiet_now
    from netaudit.alerts.models import QuietHours

    assert _is_quiet_now(QuietHours(start="23:00", end="07:00")) in (True, False)  # doesn't crash
    # Deterministic check of the wraparound logic itself:
    from datetime import datetime
    import netaudit.alerts.service as service_mod

    class _FrozenDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime(2026, 1, 1, 23, 30)

    original = service_mod.datetime
    service_mod.datetime = _FrozenDatetime
    try:
        assert _is_quiet_now(QuietHours(start="23:00", end="07:00")) is True
        assert _is_quiet_now(QuietHours(start="09:00", end="17:00")) is False
    finally:
        service_mod.datetime = original


def test_webhook_dispatch_uses_fake_transport_no_real_network(db_path, monkeypatch):
    from netaudit.alerts import webhook

    from .conftest import fake_getaddrinfo

    monkeypatch.setattr(webhook.socket, "getaddrinfo", fake_getaddrinfo({"hooks.example.com": ["8.8.8.8"]}))

    svc = AlertService(db_path=db_path)
    svc.update_config(
        AlertsConfigUpdate(enabled=True, min_severity="low", channels=[_webhook_channel(url="https://hooks.example.com/x")], rate_limit_per_hour=20)
    )
    transport = FakeTransport()
    result = svc.dispatch("high", "threat", "t1", "something", transport=transport)
    assert result.channels[0].status == "delivered"
    assert len(transport.calls) == 1
