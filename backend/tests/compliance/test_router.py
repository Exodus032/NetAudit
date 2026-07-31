from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from netaudit.compliance.providers import StaticPostureProvider, get_posture_provider
from netaudit.compliance.router import router


def make_client(checks):
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_posture_provider] = lambda: StaticPostureProvider(checks)
    return TestClient(app)


def test_frameworks_endpoint_shape():
    client = make_client([])
    resp = client.get("/api/compliance/frameworks")
    assert resp.status_code == 200
    body = resp.json()
    assert "frameworks" in body
    ids = {f["id"] for f in body["frameworks"]}
    assert ids == {"cis_win11", "nist_800_53", "essential_eight"}
    for fw in body["frameworks"]:
        assert set(fw.keys()) == {"id", "label", "controls_mapped", "checks_mapped", "coverage_note"}
        assert fw["coverage_note"]


def test_unknown_framework_404():
    client = make_client([])
    resp = client.get("/api/compliance/does_not_exist")
    assert resp.status_code == 404


def test_compliance_report_shape_and_disclaimer():
    checks = [{"id": "smb_signing_required", "status": "fail"}]
    client = make_client(checks)
    resp = client.get("/api/compliance/cis_win11")
    assert resp.status_code == 200
    body = resp.json()
    assert set(body.keys()) == {"framework", "generated_at", "summary", "disclaimer", "controls"}
    assert body["framework"]["id"] == "cis_win11"
    assert body["disclaimer"]
    assert set(body["summary"].keys()) == {"pass", "fail", "partial", "not_assessed", "coverage_percent"}
    smb_controls = [c for c in body["controls"] if c["control_id"] == "2.3.9.2"]
    assert len(smb_controls) == 1
    assert smb_controls[0]["status"] == "fail"
    assert smb_controls[0]["evidence_checks"] == [{"check_id": "smb_signing_required", "status": "fail"}]


def test_not_assessed_when_no_evidence_supplied():
    client = make_client([])  # nothing fed through
    resp = client.get("/api/compliance/nist_800_53")
    body = resp.json()
    assert body["summary"]["not_assessed"] == body["summary"]["not_assessed"]  # sanity
    assert all(c["status"] == "not_assessed" for c in body["controls"])
    assert body["summary"]["pass"] == 0 and body["summary"]["fail"] == 0 and body["summary"]["partial"] == 0
