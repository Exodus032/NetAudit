"""NetAudit learning mode -- Part D of `docs/API_CONTRACT_V3.md` (FROZEN).

Glossary, plain-language explanations of every detector/rule/check/metric,
a guided tour, structured lessons, and the D6 prioritised-findings
endpoint. All content lives as data (`learn/data/*.json`), loaded and
validated at import by `content.py`.

Deliberately does not import from `netaudit.threat`, `netaudit.posture` or
`netaudit.rules` anywhere in this package's production code -- those
packages are owned and actively changed elsewhere, and this router must
keep working even if their internals move. Where live data is genuinely
needed (D6), it's resolved through the `FindingsProvider` Protocol in
`service.py` and the `get_findings_provider` FastAPI dependency in
`router.py`, which the orchestrator overrides with the real
posture/threat/recommendation wiring.
"""
from __future__ import annotations

from .models import Explanation, GlossaryTerm, Lesson, PrioritisedFinding, TourStep
from .router import router
from .service import LearnService

__all__ = [
    "router",
    "LearnService",
    "GlossaryTerm",
    "Explanation",
    "TourStep",
    "Lesson",
    "PrioritisedFinding",
]
