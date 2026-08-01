"""Pydantic response models for Part E8 of docs/API_CONTRACT_V3.md
(baseline snapshots and diff)."""
from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


def _model() -> ConfigDict:
    return ConfigDict(populate_by_name=True)


class BaselineCreateRequest(BaseModel):
    model_config = _model()
    label: str


class BaselineRef(BaseModel):
    """`{"id", "label", "captured_at"}` -- used both as the `from`/`to`
    refs in a diff and as one row of `GET /api/baselines`."""

    model_config = _model()
    id: str
    label: str
    captured_at: str

class BaselineListItem(BaselineRef):
    model_config = _model()
    origin: Literal["manual", "scheduled"] = "manual"
    checks_count: int
    peers_count: int
    listeners_count: int
    posture_score: int
    threats_score: Optional[int] = None
    overall_score: int


class BaselinesResponse(BaseModel):
    model_config = _model()
    baselines: list[BaselineListItem] = Field(default_factory=list)



class BaselineScheduleUpdateRequest(BaseModel):
    model_config = _model()
    enabled: bool
    interval_hours: Literal[6, 12, 24, 48, 168]


class BaselineScheduleResponse(BaseModel):
    model_config = _model()
    enabled: bool
    interval_hours: Literal[6, 12, 24, 48, 168]
    last_success_at: Optional[str] = None
    last_error: Optional[str] = None
    next_due_at: Optional[str] = None

class ScoreDelta(BaseModel):
    model_config = _model()
    posture: int
    threats: int
    overall: int


class CheckTransition(BaseModel):
    model_config = _model()
    id: str
    from_: str = Field(alias="from")
    to: str


class CheckPresence(BaseModel):
    """Additive (not in the frozen contract shape): a check that exists in
    only one of the two snapshots. Kept separate from `fixed`/`regressed`
    so a check that didn't exist in the older snapshot is never counted as
    a regression, and a check removed since is never counted as a fix."""

    model_config = _model()
    id: str
    status: str


class ChecksDiff(BaseModel):
    model_config = _model()
    fixed: list[CheckTransition] = Field(default_factory=list)
    regressed: list[CheckTransition] = Field(default_factory=list)
    unchanged_count: int
    added: list[CheckPresence] = Field(default_factory=list)
    removed: list[CheckPresence] = Field(default_factory=list)
    inconclusive: list[CheckTransition] = Field(default_factory=list)


class ListenerRef(BaseModel):
    model_config = _model()
    port: int
    process: str


class BaselineDiff(BaseModel):
    """Body of `GET /api/baselines/{a}/diff/{b}`."""

    model_config = _model()
    from_: BaselineRef = Field(alias="from")
    to: BaselineRef
    score_delta: ScoreDelta
    checks: ChecksDiff
    new_peers: list[str] = Field(default_factory=list)
    new_listeners: list[ListenerRef] = Field(default_factory=list)
    removed_listeners: list[ListenerRef] = Field(default_factory=list)


class ErrorBody(BaseModel):
    model_config = _model()
    code: str
    message: str


class ErrorResponse(BaseModel):
    model_config = _model()
    error: ErrorBody
