"""Router tests: mount only `posture.router`, override `get_posture_service`
with a fake, and assert response shapes match API_CONTRACT_V2_SECURITY.md
Part A field-for-field -- no real scanning happens anywhere in this file.
"""
from __future__ import annotations

from typing import Optional

from fastapi import FastAPI
from fastapi.testclient import TestClient

from netaudit.posture.base import utc_now_iso
from netaudit.posture.models import (
    CategoryScore,
    Counts,
    EvidenceItem,
    PostureCheck,
    PostureReport,
    Remediation,
    RemediationCommand,
    ScoreComponent,
    ScoreHistoryPoint,
    SecurityScoreResponse,
    TopWin,
)
from netaudit.posture.router import router
from netaudit.posture.service import get_posture_service


def _sample_check(check_id: str = "smb_signing_required", status: str = "fail") -> PostureCheck:
    return PostureCheck(
        id=check_id,
        category="smb",
        title="SMB signing is not required",
        status=status,
        severity="high",
        score_weight=8,
        observed="RequireSecuritySignature = False on the SMB client and server",
        expected="RequireSecuritySignature = True",
        why_it_matters="Without required signing, an attacker on the same network can relay or tamper with SMB sessions.",
        evidence=[EvidenceItem(label="Client", value="RequireSecuritySignature: False")],
        remediation=Remediation(
            summary="Require SMB signing on both the client and the server.",
            commands=[RemediationCommand(shell="powershell", command="Set-SmbClientConfiguration -RequireSecuritySignature $true -Force", requires_admin=True, reversible=True, risk_note="May reduce throughput slightly.")],
            docs_url="https://learn.microsoft.com/windows-server/storage/file-server/smb-signing",
        ),
        references=["CIS Microsoft Windows 11 v3.0.0 2.3.9.2"],
        checked_at=utc_now_iso(),
        duration_ms=34,
    )


def _sample_report() -> PostureReport:
    check = _sample_check()
    return PostureReport(
        generated_at=utc_now_iso(),
        scan_duration_ms=2140,
        score=68,
        grade="C",
        counts=Counts(**{"pass": 21, "warn": 6, "fail": 3, "error": 1, "skipped": 2}),
        categories=[CategoryScore(id="smb", label="SMB", score=55, checks=[check.id])],
        checks=[check],
    )


class _FakeService:
    """Duck-typed stand-in for `PostureService` -- only the methods the
    router actually calls."""

    def __init__(self):
        self.report = _sample_report()
        self.rescan_calls: list[Optional[list[str]]] = []

    def get_report(self, category=None, include_pass=True):
        checks = self.report.checks
        if category:
            checks = [c for c in checks if c.category == category]
        if not include_pass:
            checks = [c for c in checks if c.status != "pass"]
        return self.report.model_copy(update={"checks": checks})

    def get_check(self, check_id: str):
        for c in self.report.checks:
            if c.id == check_id:
                return c
        return None

    def rescan(self, categories=None):
        self.rescan_calls.append(categories)
        return self.report

    def get_security_score(self):
        return SecurityScoreResponse(
            generated_at=utc_now_iso(),
            overall=64,
            grade="C",
            components=[
                ScoreComponent(id="posture", label="Host configuration", score=68, weight=0.4, grade="C"),
                ScoreComponent(id="threats", label="Active threats", score=55, weight=0.35, grade="D"),
                ScoreComponent(id="hygiene", label="Traffic hygiene", score=74, weight=0.25, grade="B"),
            ],
            history=[ScoreHistoryPoint(t=utc_now_iso(), overall=61)],
            top_wins=[TopWin(id="smb_signing_required", kind="posture", title="Require SMB signing", score_gain=8, effort="low")],
        )


def _make_client(fake_service: _FakeService) -> TestClient:
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_posture_service] = lambda: fake_service

    # The router raises HTTPException with an already-`{"error": {...}}`
    # shaped detail (see router.py's 404), matching the v1 error-envelope
    # convention shared across the whole API. Bare FastAPI wraps any
    # exception detail under a top-level "detail" key by default, so the
    # orchestrator's real app (netaudit/server.py) registers this exact
    # passthrough handler once for the whole app; we register the same
    # minimal handler here since this test intentionally mounts only this
    # package's router, not the orchestrator's app.
    from fastapi.responses import JSONResponse
    from starlette.exceptions import HTTPException as StarletteHTTPException

    @app.exception_handler(StarletteHTTPException)
    async def _http_exception_handler(request, exc: StarletteHTTPException):
        detail = exc.detail
        if isinstance(detail, dict) and "error" in detail:
            body = detail
        else:
            body = {"error": {"code": "error", "message": str(detail)}}
        return JSONResponse(status_code=exc.status_code, content=body)

    return TestClient(app)


def test_get_posture_matches_part_a_shape():
    client = _make_client(_FakeService())
    resp = client.get("/api/posture")
    assert resp.status_code == 200
    body = resp.json()
    assert set(body.keys()) == {"generated_at", "scan_duration_ms", "score", "grade", "counts", "categories", "checks"}
    assert set(body["counts"].keys()) == {"pass", "warn", "fail", "error", "skipped"}
    assert body["score"] == 68
    assert body["grade"] == "C"
    check = body["checks"][0]
    assert set(check.keys()) == {
        "id", "category", "title", "status", "severity", "score_weight", "observed", "expected",
        "why_it_matters", "evidence", "remediation", "references", "checked_at", "duration_ms",
    }
    assert check["status"] in {"pass", "warn", "fail", "error", "skipped"}
    assert check["checked_at"].endswith("Z")


def test_get_posture_category_filter():
    client = _make_client(_FakeService())
    resp = client.get("/api/posture", params={"category": "smb"})
    assert resp.status_code == 200
    body = resp.json()
    assert all(c["category"] == "smb" for c in body["checks"])


def test_get_posture_include_pass_false():
    fake = _FakeService()
    fake.report = fake.report.model_copy(update={"checks": [_sample_check("a", "pass"), _sample_check("b", "fail")]})
    client = _make_client(fake)
    resp = client.get("/api/posture", params={"include_pass": "false"})
    body = resp.json()
    assert [c["id"] for c in body["checks"]] == ["b"]


def test_get_posture_check_by_id_found():
    client = _make_client(_FakeService())
    resp = client.get("/api/posture/checks/smb_signing_required")
    assert resp.status_code == 200
    body = resp.json()
    assert body["id"] == "smb_signing_required"


def test_get_posture_check_by_id_not_found_returns_error_envelope():
    client = _make_client(_FakeService())
    resp = client.get("/api/posture/checks/does_not_exist")
    assert resp.status_code == 404
    body = resp.json()
    assert "error" in body
    assert set(body["error"].keys()) == {"code", "message"}


def test_post_rescan_without_body_scans_everything():
    fake = _FakeService()
    client = _make_client(fake)
    resp = client.post("/api/posture/rescan")
    assert resp.status_code == 200
    assert fake.rescan_calls == [None]
    body = resp.json()
    assert body["score"] == 68


def test_post_rescan_with_categories_body():
    fake = _FakeService()
    client = _make_client(fake)
    resp = client.post("/api/posture/rescan", json={"categories": ["firewall", "smb"]})
    assert resp.status_code == 200
    assert fake.rescan_calls == [["firewall", "smb"]]


def test_get_security_score_matches_part_a_shape():
    client = _make_client(_FakeService())
    resp = client.get("/api/security/score")
    assert resp.status_code == 200
    body = resp.json()
    assert set(body.keys()) == {"generated_at", "overall", "grade", "components", "history", "top_wins"}
    assert {c["id"] for c in body["components"]} == {"posture", "threats", "hygiene"}
    component = body["components"][0]
    assert set(component.keys()) == {"id", "label", "score", "weight", "grade"}
    assert body["history"][0]["t"].endswith("Z")
    win = body["top_wins"][0]
    assert set(win.keys()) == {"id", "kind", "title", "score_gain", "effort"}
    assert win["kind"] in {"posture", "threat", "recommendation"}
    assert win["effort"] in {"low", "medium", "high"}
