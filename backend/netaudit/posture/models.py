"""Pydantic response models for the host security posture package.

These match Part A of docs/API_CONTRACT_V2_SECURITY.md field-for-field.
`__init__.py` re-exports `PostureReport`, `PostureCheck`, `CheckStatus`, and
`Remediation` as the package's public model surface.
"""
from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

# ---------------------------------------------------------------------------
# Shared vocab
# ---------------------------------------------------------------------------

CheckStatus = Literal["pass", "warn", "fail", "error", "skipped"]
Severity = Literal["critical", "high", "medium", "low", "info"]
Grade = Literal["A", "B", "C", "D", "F"]


def _model() -> ConfigDict:
    return ConfigDict(populate_by_name=True)


class EvidenceItem(BaseModel):
    model_config = _model()
    label: str
    value: str


class RemediationCommand(BaseModel):
    model_config = _model()
    shell: str
    command: str
    requires_admin: bool
    reversible: bool
    risk_note: Optional[str] = None


class Remediation(BaseModel):
    model_config = _model()
    summary: str
    commands: list[RemediationCommand] = Field(default_factory=list)
    docs_url: Optional[str] = None


class PostureCheck(BaseModel):
    """One element of `GET /api/posture`'s `checks` array, and the full body
    of `GET /api/posture/checks/{id}`."""

    model_config = _model()
    id: str
    category: str
    title: str
    status: CheckStatus
    severity: Severity
    score_weight: int
    observed: str
    expected: str
    why_it_matters: str
    evidence: list[EvidenceItem] = Field(default_factory=list)
    remediation: Remediation
    references: list[str] = Field(default_factory=list)
    checked_at: str
    duration_ms: int


class CategoryScore(BaseModel):
    model_config = _model()
    id: str
    label: str
    score: int
    checks: list[str] = Field(default_factory=list)


class Counts(BaseModel):
    """`pass` is a Python keyword, so the field is declared as `pass_` with
    an alias of `pass` -- construct/serialize with `by_alias=True` or via
    `model_dump(by_alias=True)` to get the contract's exact key names."""

    model_config = _model()
    pass_: int = Field(alias="pass")
    warn: int
    fail: int
    error: int
    skipped: int


class PostureReport(BaseModel):
    """Body of `GET /api/posture` and `POST /api/posture/rescan`."""

    model_config = _model()
    generated_at: str
    scan_duration_ms: int
    score: int
    grade: Grade
    counts: Counts
    categories: list[CategoryScore] = Field(default_factory=list)
    checks: list[PostureCheck] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# /api/security/score
# ---------------------------------------------------------------------------


class ScoreComponent(BaseModel):
    model_config = _model()
    id: str
    label: str
    score: int
    weight: float
    grade: Grade


class ScoreHistoryPoint(BaseModel):
    model_config = _model()
    t: str
    overall: int


class TopWin(BaseModel):
    model_config = _model()
    id: str
    kind: Literal["posture", "threat", "recommendation"]
    title: str
    score_gain: int
    effort: Literal["low", "medium", "high"]


class SecurityScoreResponse(BaseModel):
    model_config = _model()
    generated_at: str
    overall: int
    grade: Grade
    components: list[ScoreComponent] = Field(default_factory=list)
    history: list[ScoreHistoryPoint] = Field(default_factory=list)
    top_wins: list[TopWin] = Field(default_factory=list)


class ErrorBody(BaseModel):
    model_config = _model()
    code: str
    message: str


class ErrorResponse(BaseModel):
    model_config = _model()
    error: ErrorBody
