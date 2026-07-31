from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from netaudit.alerts.desktop import DesktopResult
from netaudit.alerts.providers import get_desktop_sender, get_webhook_transport
from netaudit.alerts.router import router
from netaudit.alerts.service import AlertService, get_alert_service

from .conftest import FakeTransport
from .test_config_rules import FakeDesktopSender


def make_client(db_path, desktop_status="delivered"):
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_alert_service] = lambda: AlertService(db_path=db_path)
    app.dependency_overrides[get_webhook_transport] = lambda: FakeTransport()
    app.dependency_overrides[get_desktop_sender] = lambda: FakeDesktopSender(status=desktop_status)
    return TestClient(app)


def test_get_config_default(tmp_path):
    client = make_client(tmp_path / "t.db")
    resp = client.get("/api/alerts/config")
    assert resp.status_code == 200
    body = resp.json()
    assert body["enabled"] is False
    assert body["channels"][0]["id"] == "desktop"


def test_put_config_rejects_bad_webhook_url(tmp_path):
    client = make_client(tmp_path / "t.db")
    payload = {
        "enabled": True,
        "min_severity": "high",
        "channels": [{"id": "webhook-1", "kind": "webhook", "enabled": True, "url": "http://not-https.example"}],
        "rate_limit_per_hour": 20,
        "quiet_hours": None,
    }
    resp = client.put("/api/alerts/config", json=payload)
    assert resp.status_code == 400


def test_put_config_accepts_valid_config(tmp_path):
    client = make_client(tmp_path / "t.db")
    payload = {
        "enabled": True,
        "min_severity": "medium",
        "channels": [{"id": "desktop", "kind": "desktop", "enabled": True}],
        "rate_limit_per_hour": 10,
        "quiet_hours": {"start": "23:00", "end": "07:00"},
    }
    resp = client.put("/api/alerts/config", json=payload)
    assert resp.status_code == 200
    body = resp.json()
    assert body["enabled"] is True
    assert body["quiet_hours"] == {"start": "23:00", "end": "07:00"}


def test_alerts_test_endpoint_desktop(tmp_path):
    client = make_client(tmp_path / "t.db", desktop_status="delivered")
    resp = client.post("/api/alerts/test", json={"channel_id": "desktop"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["channel_id"] == "desktop"
    assert body["status"] == "delivered"


def test_alerts_test_endpoint_unknown_channel(tmp_path):
    client = make_client(tmp_path / "t.db")
    resp = client.post("/api/alerts/test", json={"channel_id": "does-not-exist"})
    assert resp.status_code == 200  # a real result, not an HTTP error -- "unknown channel" is itself the result
    assert resp.json()["status"] == "failed"


def test_alerts_history_empty_initially(tmp_path):
    client = make_client(tmp_path / "t.db")
    resp = client.get("/api/alerts/history")
    assert resp.status_code == 200
    assert resp.json() == {"alerts": []}


def test_alerts_history_reflects_dispatched_alerts(tmp_path):
    db_path = tmp_path / "t.db"
    client = make_client(db_path)
    client.put(
        "/api/alerts/config",
        json={"enabled": True, "min_severity": "low", "channels": [{"id": "desktop", "kind": "desktop", "enabled": True}], "rate_limit_per_hour": 20, "quiet_hours": None},
    )
    svc = AlertService(db_path=db_path)
    svc.dispatch("high", "threat", "t1", "Something happened", desktop_sender=FakeDesktopSender())
    resp = client.get("/api/alerts/history")
    body = resp.json()
    assert len(body["alerts"]) == 1
    assert body["alerts"][0]["title"] == "Something happened"
    assert body["alerts"][0]["channels"][0]["status"] == "delivered"
