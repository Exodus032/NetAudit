"""Rule ABC. A Rule inspects a RuleContext snapshot of recent data and
yields RuleFinding instances -- the engine (rules/engine.py) takes care of
turning those into stable, deduped, persisted Recommendation rows."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Iterable


@dataclass
class RuleFinding:
    key: str  # stable per-subject key, e.g. remote addr or pid -- engine hashes this into the id
    title: str
    severity: str  # critical|high|medium|low|info
    confidence: float
    category: str  # encryption|exposure|suspicious_peer|configuration|volume|discovery|hygiene
    summary: str
    detail: str
    evidence: list[dict] = field(default_factory=list)  # [{label, value}]
    actions: list[dict] = field(default_factory=list)
    related_connection_ids: list[str] = field(default_factory=list)


@dataclass
class RuleContext:
    """Snapshot of recent data a rule can inspect. Built once per engine
    tick and shared across all rules for that tick."""
    now: float
    window_seconds: float
    flows: list  # sqlite3.Row from flows table
    packets: list  # sqlite3.Row from packets table, within window_seconds
    devices: list  # sqlite3.Row from devices table
    capture_mode: str
    elevated: bool


class Rule(ABC):
    rule_id: str = "base"

    @abstractmethod
    def evaluate(self, ctx: RuleContext) -> Iterable[RuleFinding]:
        ...
