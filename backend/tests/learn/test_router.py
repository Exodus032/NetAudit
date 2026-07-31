"""Router: TestClient over the real `router`, asserting the Part D shapes
field-for-field against docs/API_CONTRACT_V3.md, 404s on unknown ids, 400
on an unknown explain kind, and D6 wired through
`app.dependency_overrides[get_findings_provider]` with a faked provider --
mirroring the pattern threat/router's own test suite uses.
"""
from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from starlette.exceptions import HTTPException as StarletteHTTPException

from netaudit.learn.router import get_findings_provider, router
from netaudit.learn.service import StaticFindingsProvider


def _make_app(provider=None) -> FastAPI:
    app = FastAPI()
    app.include_router(router)

    @app.exception_handler(StarletteHTTPException)
    async def _unwrap(request: Request, exc: StarletteHTTPException):
        detail = exc.detail
        if isinstance(detail, dict) and "error" in detail:
            return JSONResponse(status_code=exc.status_code, content=detail)
        return JSONResponse(status_code=exc.status_code, content={"error": {"code": "error", "message": str(detail)}})

    if provider is not None:
        app.dependency_overrides[get_findings_provider] = lambda: provider
    return app


# ---------------------------------------------------------------------
# D1/D2 -- glossary
# ---------------------------------------------------------------------

def test_glossary_list_shape():
    client = TestClient(_make_app())
    resp = client.get("/api/glossary")
    assert resp.status_code == 200
    body = resp.json()
    assert "terms" in body
    assert len(body["terms"]) >= 47
    arp = next(t for t in body["terms"] if t["id"] == "arp")
    for field in ("id", "term", "short", "detail", "why_it_matters", "see_also", "category", "difficulty"):
        assert field in arp


def test_glossary_single_term():
    client = TestClient(_make_app())
    resp = client.get("/api/glossary/arp")
    assert resp.status_code == 200
    assert resp.json()["term"] == "ARP"


def test_glossary_single_term_404():
    client = TestClient(_make_app())
    resp = client.get("/api/glossary/not_a_real_term")
    assert resp.status_code == 404
    body = resp.json()
    assert body["error"]["code"] == "not_found"


# ---------------------------------------------------------------------
# D3 -- explain
# ---------------------------------------------------------------------

def test_explain_detector_shape():
    client = TestClient(_make_app())
    resp = client.get("/api/explain/detector/c2_beaconing")
    assert resp.status_code == 200
    body = resp.json()
    assert body["kind"] == "detector"
    assert body["id"] == "c2_beaconing"
    for field in ("title", "plain", "how_it_decides", "what_would_make_it_wrong", "glossary_terms"):
        assert field in body
    assert body["worked_example"]["scenario"]
    assert len(body["worked_example"]["walkthrough"]) >= 2


def test_explain_check_shape():
    client = TestClient(_make_app())
    resp = client.get("/api/explain/check/smb_signing_required")
    assert resp.status_code == 200
    body = resp.json()
    assert body["kind"] == "check"
    assert body["id"] == "smb_signing_required"


def test_explain_metric_shape():
    client = TestClient(_make_app())
    resp = client.get("/api/explain/metric/coefficient_of_variation")
    assert resp.status_code == 200
    body = resp.json()
    assert body["kind"] == "metric"


def test_explain_unknown_id_404():
    client = TestClient(_make_app())
    resp = client.get("/api/explain/detector/not_a_real_detector")
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "not_found"


def test_explain_unknown_kind_400():
    client = TestClient(_make_app())
    resp = client.get("/api/explain/spaceship/whatever")
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "bad_request"


# ---------------------------------------------------------------------
# D4 -- tour
# ---------------------------------------------------------------------

def test_tour_shape():
    client = TestClient(_make_app())
    resp = client.get("/api/tour")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["steps"]) >= 12
    step = body["steps"][0]
    for field in ("id", "order", "view", "target", "title", "body", "glossary_terms", "action_hint"):
        assert field in step


# ---------------------------------------------------------------------
# D5 -- lessons
# ---------------------------------------------------------------------

def test_lessons_list_shape():
    client = TestClient(_make_app())
    resp = client.get("/api/lessons")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["lessons"]) >= 6
    lesson = body["lessons"][0]
    for field in ("id", "title", "summary", "difficulty", "estimated_minutes", "prerequisites", "objectives", "steps", "uses_live_data"):
        assert field in lesson


def test_lessons_single():
    client = TestClient(_make_app())
    list_resp = client.get("/api/lessons")
    first_id = list_resp.json()["lessons"][0]["id"]
    resp = client.get(f"/api/lessons/{first_id}")
    assert resp.status_code == 200
    assert resp.json()["id"] == first_id


def test_lessons_single_404():
    client = TestClient(_make_app())
    resp = client.get("/api/lessons/not_a_real_lesson")
    assert resp.status_code == 404


# ---------------------------------------------------------------------
# D6 -- findings/prioritised, with a faked FindingsProvider
# ---------------------------------------------------------------------

def test_findings_prioritised_shape_and_ranking():
    provider = StaticFindingsProvider(
        posture=[
            {"id": "smb_signing_required", "title": "Require SMB signing", "severity": "high",
             "status": "fail", "effort": "low", "one_line_fix": "Run one PowerShell command as administrator."},
            {"id": "wpad_disabled", "title": "Disable WPAD", "severity": "medium",
             "status": "fail", "effort": "low", "one_line_fix": "Run netsh winhttp reset proxy."},
        ],
        recommendations=[
            {"id": "plaintext_http", "title": "Unencrypted HTTP", "severity": "medium",
             "confidence": 0.9, "effort": "low", "one_line_fix": "Enable HTTPS-only mode."},
        ],
        threats=[],
    )
    client = TestClient(_make_app(provider))
    resp = client.get("/api/findings/prioritised")
    assert resp.status_code == 200
    body = resp.json()
    assert "generated_at" in body
    assert len(body["items"]) == 3
    top = body["items"][0]
    for field in ("id", "source", "title", "severity", "impact_score", "effort", "priority_rank", "why_first", "one_line_fix", "deep_link"):
        assert field in top
    assert top["id"] == "posture:smb_signing_required"
    assert top["priority_rank"] == 1
    assert body["items"][0]["priority_rank"] < body["items"][1]["priority_rank"] < body["items"][2]["priority_rank"]


def test_findings_prioritised_defaults_to_empty_without_override():
    client = TestClient(_make_app())  # no override -> default empty StaticFindingsProvider
    resp = client.get("/api/findings/prioritised")
    assert resp.status_code == 200
    assert resp.json()["items"] == []
