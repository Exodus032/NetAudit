"""Part D endpoints, bare `APIRouter` with no prefix -- paths are written
out in full (`/api/glossary`, ...) exactly as `docs/API_CONTRACT_V3.md`
Part D specifies, matching the convention already used by the v1/v2/v3
routers this package must not import from.

`get_findings_provider` resolves D6's live data the same way
`threat/router.py` resolves its engine: from `request.app.state`, with
`app.dependency_overrides[get_findings_provider] = lambda: real_provider`
as the override path a test (or the orchestrator) uses instead. Unlike the
threat engine, a missing provider is not a 500 here -- an install with
nothing wired up yet just has no findings to prioritise, which is a valid
(if boring) answer, not an error.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from .models import ExplainKind
from .service import FindingsProvider, LearnService, StaticFindingsProvider

router = APIRouter()

_VALID_EXPLAIN_KINDS = set(ExplainKind.__args__)  # type: ignore[attr-defined]


def get_findings_provider(request: Request) -> FindingsProvider:
    provider = getattr(request.app.state, "learn_findings_provider", None)
    if provider is None:
        return StaticFindingsProvider()
    return provider


def _service_for(provider: FindingsProvider) -> LearnService:
    return LearnService(findings_provider=provider)


def _error(status_code: int, code: str, message: str) -> HTTPException:
    return HTTPException(status_code=status_code, detail={"error": {"code": code, "message": message}})


@router.get("/api/glossary")
def list_glossary():
    service = LearnService()
    return {"terms": [t.model_dump(exclude_none=True) for t in service.list_glossary()]}


@router.get("/api/glossary/{term_id}")
def get_glossary_term(term_id: str):
    service = LearnService()
    term = service.get_glossary_term(term_id)
    if term is None:
        raise _error(404, "not_found", f"No glossary term '{term_id}'")
    return term.model_dump(exclude_none=True)


@router.get("/api/explain/{kind}/{item_id}")
def explain(kind: str, item_id: str):
    if kind not in _VALID_EXPLAIN_KINDS:
        raise _error(400, "bad_request", f"Unsupported explain kind '{kind}'; must be one of {sorted(_VALID_EXPLAIN_KINDS)}")
    service = LearnService()
    explanation = service.get_explanation(kind, item_id)
    if explanation is None:
        raise _error(404, "not_found", f"No {kind} explanation for '{item_id}'")
    return explanation.model_dump(exclude_none=True)


@router.get("/api/tour")
def get_tour():
    service = LearnService()
    return {"steps": [s.model_dump(exclude_none=True) for s in service.get_tour()]}


@router.get("/api/lessons")
def list_lessons():
    service = LearnService()
    return {"lessons": [l.model_dump(exclude_none=True) for l in service.list_lessons()]}


@router.get("/api/lessons/{lesson_id}")
def get_lesson(lesson_id: str):
    service = LearnService()
    lesson = service.get_lesson(lesson_id)
    if lesson is None:
        raise _error(404, "not_found", f"No lesson '{lesson_id}'")
    return lesson.model_dump(exclude_none=True)


@router.get("/api/findings/prioritised")
def findings_prioritised(provider: FindingsProvider = Depends(get_findings_provider)):
    service = _service_for(provider)
    return service.prioritised_findings()
