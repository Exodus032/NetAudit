"""Lookup, search and prioritisation over the validated content in
`content.py`, plus the `FindingsProvider` Protocol that decouples D6 from
the real posture/threat/recommendation packages.

No import from `netaudit.threat`, `netaudit.posture` or `netaudit.rules`
anywhere in this module -- the real `FindingsProvider` implementation is
supplied by the orchestrator at wire-up time (see `router.py`'s
`get_findings_provider` dependency), not built here.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional, Protocol

from . import content
from .models import Explanation, GlossaryTerm, Lesson, TourStep
from .prioritise import rank


class FindingsProvider(Protocol):
    """Supplies the live data D6 ranks. Each method returns a list of plain
    dicts (not pydantic models -- this package must not need to know the
    real `PostureCheck`/`RuleFinding`/`Threat` shapes to stay decoupled).

    Expected dict shape, all three methods:
        id: str -- unprefixed id (e.g. "smb_signing_required")
        title: str
        severity: "critical"|"high"|"medium"|"low"|"info"
        one_line_fix: str (optional but strongly expected)
        observed: str (optional) -- what is actually true right now.
            Strongly expected from `posture_checks()`, whose titles state
            the desired end state and so read backwards on their own in a
            list where every entry is by definition a failure.

    `posture_checks()` additionally expects:
        status: "fail"|"warn"  (only failing/warning checks should be
            included at all -- a `pass`/`error`/`skipped` check is not a
            finding; filtering that is this provider's job, not
            `prioritise.rank`'s)
        effort: "low"|"medium"|"high" (optional, defaults to "medium")

    `recommendations()`/`threats()` additionally expect:
        confidence: float 0-1 (optional, defaults to 1.0)
        effort: "low"|"medium"|"high" (optional, defaults to "medium")
    """

    def posture_checks(self) -> list[dict]: ...

    def recommendations(self) -> list[dict]: ...

    def threats(self) -> list[dict]: ...


class StaticFindingsProvider:
    """Fixed in-memory `FindingsProvider` for tests and local development.
    Takes exactly the lists it's given -- no filtering, no defaults beyond
    what `prioritise.rank` itself applies."""

    def __init__(
        self,
        posture: Optional[list[dict]] = None,
        recommendations: Optional[list[dict]] = None,
        threats: Optional[list[dict]] = None,
    ) -> None:
        self._posture = posture or []
        self._recommendations = recommendations or []
        self._threats = threats or []

    def posture_checks(self) -> list[dict]:
        return list(self._posture)

    def recommendations(self) -> list[dict]:
        return list(self._recommendations)

    def threats(self) -> list[dict]:
        return list(self._threats)


def _iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{datetime.now(timezone.utc).microsecond // 1000:03d}Z"


class LearnService:
    """Read-only service over the validated learn content plus D6
    prioritisation. Holds no mutable state of its own beyond the injected
    `FindingsProvider` -- content is loaded once at import time in
    `content.py`."""

    def __init__(self, findings_provider: Optional[FindingsProvider] = None) -> None:
        self._findings_provider = findings_provider or StaticFindingsProvider()

    # -- glossary ----------------------------------------------------
    def list_glossary(self) -> list[GlossaryTerm]:
        return sorted(content.GLOSSARY.values(), key=lambda t: t.id)

    def get_glossary_term(self, term_id: str) -> Optional[GlossaryTerm]:
        return content.GLOSSARY.get(term_id)

    # -- explanations --------------------------------------------------
    def get_explanation(self, kind: str, item_id: str) -> Optional[Explanation]:
        return content.EXPLANATIONS.get((kind, item_id))

    # -- tour ------------------------------------------------------------
    def get_tour(self) -> list[TourStep]:
        return list(content.TOUR)

    # -- lessons -----------------------------------------------------
    def list_lessons(self) -> list[Lesson]:
        return sorted(content.LESSONS.values(), key=lambda l: l.id)

    def get_lesson(self, lesson_id: str) -> Optional[Lesson]:
        return content.LESSONS.get(lesson_id)

    # -- D6 prioritisation --------------------------------------------
    def prioritised_findings(self) -> dict:
        items: list[dict] = []

        for check in self._findings_provider.posture_checks():
            status = check.get("status")
            if status not in ("fail", "warn"):
                continue
            items.append({**check, "source": "posture"})

        for rec in self._findings_provider.recommendations():
            items.append({**rec, "source": "recommendation"})

        for threat in self._findings_provider.threats():
            items.append({**threat, "source": "threat"})

        ranked = rank(items)
        return {"generated_at": _iso_now(), "items": ranked}
