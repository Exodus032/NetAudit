from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from netaudit.baselines.providers import (
    StaticPostureProvider,
    StaticScoreProvider,
    StaticTrafficProvider,
    get_posture_provider,
    get_score_provider,
    get_traffic_provider,
)
from netaudit.baselines.router import get_baseline_monitor, get_baseline_service, router
from netaudit.baselines.service import BaselineService


class RecordingMonitor:
    def __init__(self) -> None:
        self.wake_count = 0

    def wake(self) -> None:
        self.wake_count += 1


def make_client(db_path, checks=None, peers=None, listeners=None, posture=50, threats=None, overall=None, monitor=None):
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_posture_provider] = lambda: StaticPostureProvider(checks or [])
    app.dependency_overrides[get_traffic_provider] = lambda: StaticTrafficProvider(peers or [], listeners or [])
    app.dependency_overrides[get_score_provider] = lambda: StaticScoreProvider(posture, threats, overall)
    app.dependency_overrides[get_baseline_service] = lambda: BaselineService(db_path=db_path)
    app.dependency_overrides[get_baseline_monitor] = lambda: monitor or RecordingMonitor()
    return TestClient(app)


def test_get_schedule_returns_default_schedule_at_static_path(tmp_path):
    client = make_client(tmp_path / "t.db")

    response = client.get("/api/baselines/schedule")

    assert response.status_code == 200
    assert response.json() == {
        "enabled": False,
        "interval_hours": 24,
        "last_succeeded_at": None,
        "last_error": None,
        "next_due_at": None,
    }


def test_put_schedule_persists_enabled_48_hour_schedule_and_wakes_monitor(tmp_path):
    monitor = RecordingMonitor()
    client = make_client(tmp_path / "t.db", monitor=monitor)

    response = client.put("/api/baselines/schedule", json={"enabled": True, "interval_hours": 48})

    assert response.status_code == 200
    assert response.json()["enabled"] is True
    assert response.json()["interval_hours"] == 48
    assert monitor.wake_count == 1
    assert client.get("/api/baselines/schedule").json()["interval_hours"] == 48


def test_put_schedule_rejects_nonpreset_interval(tmp_path):
    client = make_client(tmp_path / "t.db")

    response = client.put("/api/baselines/schedule", json={"enabled": True, "interval_hours": 36})

    assert response.status_code == 422


def test_create_and_list(tmp_path):
    db_path = tmp_path / "t.db"
    client = make_client(db_path, checks=[{"id": "a", "status": "pass"}], peers=["10.0.0.5"])
    resp = client.post("/api/baselines", json={"label": "Before hardening"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["label"] == "Before hardening"
    assert body["checks_count"] == 1
    assert body["peers_count"] == 1

    resp2 = client.get("/api/baselines")
    assert resp2.status_code == 200
    assert len(resp2.json()["baselines"]) == 1


def test_create_empty_label_400(tmp_path):
    db_path = tmp_path / "t.db"
    client = make_client(db_path)
    resp = client.post("/api/baselines", json={"label": "   "})
    assert resp.status_code == 400


def test_diff_shape_and_disclaimer_free_fields(tmp_path):
    db_path = tmp_path / "t.db"
    client = make_client(db_path, checks=[{"id": "smb_signing_required", "status": "fail"}])
    r1 = client.post("/api/baselines", json={"label": "Before"})
    b1 = r1.json()["id"]

    client2 = make_client(db_path, checks=[{"id": "smb_signing_required", "status": "pass"}])
    r2 = client2.post("/api/baselines", json={"label": "After"})
    b2 = r2.json()["id"]

    resp = client.get(f"/api/baselines/{b1}/diff/{b2}")
    assert resp.status_code == 200
    body = resp.json()
    assert set(body.keys()) == {"from", "to", "score_delta", "checks", "new_peers", "new_listeners", "removed_listeners"}
    assert body["checks"]["fixed"] == [{"id": "smb_signing_required", "from": "fail", "to": "pass"}]


def test_diff_unknown_id_404(tmp_path):
    db_path = tmp_path / "t.db"
    client = make_client(db_path)
    r1 = client.post("/api/baselines", json={"label": "Before"})
    b1 = r1.json()["id"]
    resp = client.get(f"/api/baselines/{b1}/diff/does_not_exist")
    assert resp.status_code == 404
