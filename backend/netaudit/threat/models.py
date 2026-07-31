"""Part B response shapes, field-for-field against API_CONTRACT_V2_SECURITY.md.

Pydantic models so FastAPI/the router can serialize them directly and so
`PATCH /api/threats/detectors/{id}` gets real type/range validation for
free. These are pure data shapes -- no behavior, no imports from the rest
of netaudit.
"""
from __future__ import annotations

from typing import Literal, Optional, Union

from pydantic import BaseModel, Field

Severity = Literal["critical", "high", "medium", "low", "info"]

ThreatCategory = Literal[
    "command_and_control",
    "exfiltration",
    "reconnaissance",
    "lateral_movement",
    "credential_exposure",
    "dns_abuse",
    "spoofing",
    "malicious_peer",
    "policy_violation",
    "anomaly",
]

ThreatStatus = Literal["active", "resolved", "acknowledged"]

IndicatorType = Literal["ip", "domain", "url", "port", "process", "mac", "ja3", "hash"]

TunableType = Literal["int", "float", "bool", "str"]


class MitreRef(BaseModel):
    tactic: str
    tactic_name: str
    # Genuinely ambiguous detectors (see mitre.py) ship tactic-only rather
    # than inventing a technique id -- both fields are optional for that
    # reason, not because they're unimportant.
    technique: Optional[str] = None
    technique_name: Optional[str] = None


class Evidence(BaseModel):
    label: str
    value: str


class Indicator(BaseModel):
    type: IndicatorType
    value: str
    context: Optional[str] = None


class Action(BaseModel):
    label: str
    kind: Literal["command", "manual", "link"] = "command"
    shell: Optional[str] = None
    command: Optional[str] = None
    requires_admin: bool = False
    reversible: Optional[bool] = None
    risk_note: Optional[str] = None
    detail: Optional[str] = None
    url: Optional[str] = None


class Threat(BaseModel):
    id: str
    detector_id: str
    title: str
    severity: Severity
    confidence: float
    category: ThreatCategory
    status: ThreatStatus
    mitre: list[MitreRef] = Field(default_factory=list)
    summary: str
    detail: str
    evidence: list[Evidence] = Field(default_factory=list)
    indicators: list[Indicator] = Field(default_factory=list)
    metrics: dict[str, Union[int, float, str, bool, None]] = Field(default_factory=dict)
    first_seen: str
    last_seen: str
    occurrences: int
    related_connection_ids: list[str] = Field(default_factory=list)
    related_log_ids: list[int] = Field(default_factory=list)
    false_positive_notes: str = ""
    recommended_actions: list[Action] = Field(default_factory=list)
    # Not in the wire contract's example but harmless additive fields used
    # by the ack endpoints; acknowledge_note is only ever non-null once a
    # user has acknowledged the threat.
    acknowledged_note: Optional[str] = None


class TunableSpec(BaseModel):
    key: str
    value: Union[int, float, bool, str]
    type: TunableType
    min: Optional[float] = None
    max: Optional[float] = None
    description: str


class DetectorMitreRef(BaseModel):
    tactic: str
    technique: Optional[str] = None


class Detector(BaseModel):
    id: str
    label: str
    category: ThreatCategory
    description: str
    enabled: bool
    default_severity: Severity
    mitre: list[DetectorMitreRef] = Field(default_factory=list)
    tunables: list[TunableSpec] = Field(default_factory=list)
    fired_count: int = 0
    last_fired: Optional[str] = None


class ErrorBody(BaseModel):
    code: str
    message: str


class ErrorResponse(BaseModel):
    error: ErrorBody
