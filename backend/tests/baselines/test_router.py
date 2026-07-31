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
from netaudit.baselines.router import get_baseline_service, router
from netaudit.baselines.service import BaselineService


def make_client(db_path, checks=None, peers=None, listeners=None, posture=50, threats=None, overall=None):
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_posture_provider] = lambda: StaticPostureProvider(checks or [])
    app.dependency_overrides[get_traffic_provider] = lambda: StaticTrafficProvider(peers or [], listeners or [])
    app.dependency_overrides[get_score_provider] = lambda: StaticScoreProvider(posture, threats, overall)
    app.dependency_overrides[get_baseline_service] = lambda: BaselineService(db_path=db_path)
    return TestClient(app)


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
