"""Detector ABC + the `Finding` a detector emits.

A `Finding` is a detector's raw output for one tick: everything needed to
build a `Threat` except the identity/lifecycle bookkeeping (stable id,
status, first_seen/last_seen, occurrences) that `engine.py` owns across
ticks. `key` is the one field that matters for that bookkeeping: it must be
stable for "the same underlying subject" (e.g. the same peer IP, the same
scanning host) across runs so the engine can recognize a re-fire as the
same threat rather than minting a new one every tick.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from ..models import Action, Evidence, Indicator, MitreRef, Severity, ThreatCategory, TunableSpec
from ..source import TrafficSource


@dataclass
class Finding:
    key: str  # stable subject identity, e.g. "93.184.216.34" or "svchost.exe|93.184.216.34"
    title: str
    severity: Severity
    confidence: float
    summary: str
    detail: str
    observed_at: datetime  # timestamp of the evidence that triggered this finding
    evidence: list[Evidence] = field(default_factory=list)
    indicators: list[Indicator] = field(default_factory=list)
    metrics: dict = field(default_factory=dict)
    related_connection_ids: list[str] = field(default_factory=list)
    related_log_ids: list[int] = field(default_factory=list)
    false_positive_notes: str = ""
    recommended_actions: list[Action] = field(default_factory=list)
    occurrence_count: int = 1  # how many raw events this single finding already summarizes


class Detector(ABC):
    """Subclasses set the class attributes below and implement `run`.

    `run` must be a pure function of `(source, since, until, tunables)` --
    no hidden state, no wall-clock reads other than `since`/`until` -- so
    detectors run deterministically over stored data and are unit-testable
    without mocking time.
    """

    id: str
    label: str
    category: ThreatCategory
    description: str
    default_severity: Severity
    mitre: list[MitreRef]
    tunables: list[TunableSpec]
    # How long a threat this detector raised keeps its status once the
    # detector stops re-firing for it before the engine marks it resolved.
    cooldown_seconds: float = 1800.0

    def default_tunable_values(self) -> dict:
        return {t.key: t.value for t in self.tunables}

    @abstractmethod
    def run(
        self,
        source: TrafficSource,
        since: datetime,
        until: datetime,
        tunables: dict,
    ) -> list[Finding]:
        ...
