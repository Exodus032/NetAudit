"""Part D response shapes, field-for-field against
`docs/API_CONTRACT_V3.md` Part D. Pure data -- no behavior, no imports from
`netaudit.threat`, `netaudit.posture` or `netaudit.rules` (see package
`__init__.py` for why: those packages are owned and actively changed by
other agents, and this router must not break if their internals move).
"""
from __future__ import annotations

from typing import Literal, Optional, Union

from pydantic import BaseModel, Field

Severity = Literal["critical", "high", "medium", "low", "info"]

GlossaryCategory = Literal["protocol", "security", "networking", "tool"]
Difficulty = Literal["beginner", "intermediate", "advanced"]
ExplainKind = Literal["detector", "rule", "check", "metric", "field"]
LessonCheckKind = Literal["view_visited", "filter_applied", "element_clicked", "manual"]
ViewId = Literal["overview", "traffic-log", "connections", "recommendations", "posture", "threats"]
FindingSource = Literal["posture", "recommendation", "threat"]
Effort = Literal["low", "medium", "high"]


class GlossaryTerm(BaseModel):
    id: str
    term: str
    expansion: Optional[str] = None
    short: str
    detail: str
    why_it_matters: str
    see_also: list[str] = Field(default_factory=list)
    category: GlossaryCategory
    difficulty: Difficulty


class GlossaryResponse(BaseModel):
    terms: list[GlossaryTerm]


class WorkedExample(BaseModel):
    scenario: str
    walkthrough: list[str]


class Explanation(BaseModel):
    kind: ExplainKind
    id: str
    title: str
    plain: str
    how_it_decides: str
    what_would_make_it_wrong: str
    worked_example: Optional[WorkedExample] = None
    glossary_terms: list[str] = Field(default_factory=list)
    learn_more: Optional[str] = None


class TourStep(BaseModel):
    id: str
    order: int
    view: ViewId
    target: str
    title: str
    body: str
    glossary_terms: list[str] = Field(default_factory=list)
    action_hint: Optional[str] = None


class TourResponse(BaseModel):
    steps: list[TourStep]


class LessonCheck(BaseModel):
    kind: LessonCheckKind
    value: str


class LessonStep(BaseModel):
    order: int
    instruction: str
    explanation: str
    check: LessonCheck
    glossary_terms: list[str] = Field(default_factory=list)


class Lesson(BaseModel):
    id: str
    title: str
    summary: str
    difficulty: Difficulty
    estimated_minutes: int
    prerequisites: list[str] = Field(default_factory=list)
    objectives: list[str]
    steps: list[LessonStep]
    uses_live_data: bool


class LessonsResponse(BaseModel):
    lessons: list[Lesson]


class DeepLink(BaseModel):
    view: str
    id: str


class PrioritisedFinding(BaseModel):
    id: str
    source: FindingSource
    title: str
    # Optional and additive. Posture check titles state the desired end
    # state ("SMB signing is required"), which reads correctly beside a
    # pass/fail badge but backwards in a list where every entry is by
    # definition a failure. This carries what is actually true instead.
    # Absent when the source has nothing more specific to say.
    observed: Optional[str] = None
    severity: Severity
    impact_score: int
    effort: Effort
    priority_rank: int
    why_first: str
    one_line_fix: str
    deep_link: DeepLink


class PrioritisedFindingsResponse(BaseModel):
    generated_at: str
    items: list[PrioritisedFinding]


class ErrorBody(BaseModel):
    code: str
    message: str


class ErrorResponse(BaseModel):
    error: ErrorBody
