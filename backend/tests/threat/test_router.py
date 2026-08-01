"""Router: TestClient over the real `router` with a fully isolated test
`ThreatEngine` (its own temp SQLite store, its own tiny test detector) swapped
in via `app.dependency_overrides` -- pagination, filters, include_acknowledged,
PATCH tunable range validation returning 400 with the standard error body,
and timeline zero-fill/contiguity.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from starlette.exceptions import HTTPException as StarletteHTTPException

from netaudit.threat.detectors.base import Detector, Finding
from netaudit.threat.engine import ThreatEngine
from netaudit.threat.models import Evidence, MitreRef, TunableSpec
from netaudit.threat.router import get_threat_engine, router
from netaudit.threat.source import ListTrafficSource
from netaudit.threat.store import ThreatStore

NOW = datetime(2026, 7, 31, 14, 0, 0, tzinfo=timezone.utc)


def _make_app() -> FastAPI:
    """Bare app + our router, plus the same standard-error-body unwrapping
    the real server (server.py, outside this package) applies: our router
    raises HTTPException(detail={"error": {...}}) and relies on that outer
    handler to surface `detail` at the top level of the response body."""
    app = FastAPI()
    app.include_router(router)

    @app.exception_handler(StarletteHTTPException)
    async def _unwrap(request: Request, exc: StarletteHTTPException):
        detail = exc.detail
        if isinstance(detail, dict) and "error" in detail:
            return JSONResponse(status_code=exc.status_code, content=detail)
        return JSONResponse(status_code=exc.status_code, content={"error": {"code": "error", "message": str(detail)}})

    return app


class _SeedDetector(Detector):
    id = "test_seed"
    label = "Test seed detector"
    category = "anomaly"
    description = "test detector"
    default_severity = "medium"
    mitre = [MitreRef(tactic="TA0011", tactic_name="Command and Control")]
    tunables = [
        TunableSpec(key="threshold", value=10, type="int", min=1, max=100, description="test tunable"),
    ]

    def __init__(self):
        self.keys_to_fire: list[tuple[str, str, str]] = []  # (key, severity, category override unused)

    def run(self, source, since, until, tunables):
        return [
            Finding(
                key=key, title=f"Finding for {key}", severity=severity, confidence=0.6,
                summary="summary", detail="detail", observed_at=until,
                evidence=[Evidence(label="k", value=key)],
            )
            for key, severity, _ in self.keys_to_fire
        ]


@pytest.fixture
def client(db_path):
    store = ThreatStore(db_path)
    detector = _SeedDetector()
    engine = ThreatEngine(ListTrafficSource(), store, detectors=[detector])

    app = _make_app()
    app.dependency_overrides[get_threat_engine] = lambda: engine
    test_client = TestClient(app)
    test_client.detector = detector
    test_client.engine = engine
    return test_client


def _seed(client, entries, now=NOW):
    client.detector.keys_to_fire = entries
    client.engine.run_once(now=now)
    client.detector.keys_to_fire = []


def test_list_threats_pagination(client):
    _seed(client, [(f"peer-{i}", "medium", "") for i in range(5)])

    resp = client.get("/api/threats", params={"limit": 2, "offset": 0})
    body = resp.json()
    assert resp.status_code == 200
    assert body["total"] == 5
    assert body["limit"] == 2
    assert len(body["threats"]) == 2

    resp2 = client.get("/api/threats", params={"limit": 2, "offset": 4})
    assert len(resp2.json()["threats"]) == 1


def test_list_threats_limit_is_capped_at_1000(client):
    resp = client.get("/api/threats", params={"limit": 5000})
    assert resp.json()["limit"] == 1000


def test_list_threats_filters_by_severity(client):
    _seed(client, [("a", "high", ""), ("b", "low", "")])

    resp = client.get("/api/threats", params={"severity": "high"})
    body = resp.json()
    assert body["total"] == 1
    assert body["threats"][0]["severity"] == "high"


def test_list_threats_excludes_acknowledged_by_default(client):
    _seed(client, [("a", "medium", "")])
    threat_id = client.get("/api/threats").json()["threats"][0]["id"]
    client.post(f"/api/threats/{threat_id}/acknowledge", json={"note": "seen it"})

    resp = client.get("/api/threats")
    assert resp.json()["total"] == 0

    resp_incl = client.get("/api/threats", params={"include_acknowledged": True})
    assert resp_incl.json()["total"] == 1
    assert resp_incl.json()["threats"][0]["status"] == "acknowledged"


def test_get_single_threat_404(client):
    resp = client.get("/api/threats/does-not-exist")
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "not_found"


def test_acknowledge_and_unacknowledge_roundtrip(client):
    _seed(client, [("a", "medium", "")])
    threat_id = client.get("/api/threats").json()["threats"][0]["id"]

    ack = client.post(f"/api/threats/{threat_id}/acknowledge", json={"note": "known telemetry agent"})
    assert ack.status_code == 200
    assert ack.json() == {"id": threat_id, "status": "acknowledged", "note": "known telemetry agent"}

    unack = client.post(f"/api/threats/{threat_id}/unacknowledge", json={})
    assert unack.json()["status"] == "active"


def test_timeline_is_contiguous_and_zero_filled(client):
    resp = client.get("/api/threats/timeline", params={"window": "6h", "bucket": 3600})
    body = resp.json()
    assert resp.status_code == 200
    assert body["bucket_seconds"] == 3600
    assert len(body["points"]) == 6
    for point in body["points"]:
        assert set(point.keys()) == {"t", "critical", "high", "medium", "low", "info"}
        assert point["critical"] == 0 and point["high"] == 0

    # Contiguity: each bucket's timestamp is exactly bucket_seconds after the previous one.
    timestamps = [datetime.fromisoformat(p["t"].replace("Z", "+00:00")) for p in body["points"]]
    for a, b in zip(timestamps, timestamps[1:]):
        assert (b - a).total_seconds() == 3600


def test_list_threats_bad_since_is_400(client):
    resp = client.get("/api/threats", params={"since": "not-a-timestamp"})
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "bad_request"


def test_list_threats_bad_until_is_400(client):
    resp = client.get("/api/threats", params={"until": "2026-13-99T99:99:99Z"})
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "bad_request"


@pytest.mark.parametrize("window", ["nan", "inf", "nanh", "-5m", "bogus"])
def test_timeline_non_finite_or_bogus_window_is_400(client, window):
    resp = client.get("/api/threats/timeline", params={"window": window})
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "bad_request"


def test_list_detectors_includes_test_detector(client):
    resp = client.get("/api/threats/detectors")
    ids = [d["id"] for d in resp.json()["detectors"]]
    assert "test_seed" in ids


def test_patch_detector_enabled(client):
    resp = client.patch("/api/threats/detectors/test_seed", json={"enabled": False})
    assert resp.status_code == 200
    assert resp.json()["enabled"] is False


def test_patch_detector_tunable_out_of_range_returns_400_standard_body(client):
    resp = client.patch("/api/threats/detectors/test_seed", json={"tunables": {"threshold": 999}})
    assert resp.status_code == 400
    body = resp.json()
    assert "error" in body
    assert "code" in body["error"] and "message" in body["error"]


def test_patch_detector_unknown_tunable_returns_400(client):
    resp = client.patch("/api/threats/detectors/test_seed", json={"tunables": {"not_a_real_key": 1}})
    assert resp.status_code == 400


def test_patch_detector_unknown_id_returns_404(client):
    resp = client.patch("/api/threats/detectors/does_not_exist", json={"enabled": False})
    assert resp.status_code == 404


def test_patch_detector_valid_tunable_applies(client):
    resp = client.patch("/api/threats/detectors/test_seed", json={"tunables": {"threshold": 50}})
    assert resp.status_code == 200
    tunables = {t["key"]: t["value"] for t in resp.json()["tunables"]}
    assert tunables["threshold"] == 50


def test_intel_lookup_private_ip_is_clean():
    client = TestClient(_make_app())

    resp = client.get("/api/intel/lookup", params={"value": "192.168.1.1", "type": "ip"})
    body = resp.json()
    assert resp.status_code == 200
    assert body["classification"]["is_private"] is True
    assert body["reputation"] == "clean"


def test_intel_lookup_bad_type_returns_400():
    client = TestClient(_make_app())

    resp = client.get("/api/intel/lookup", params={"value": "x", "type": "not-a-type"})
    assert resp.status_code == 400
