"""The score formula and grade bands from API_CONTRACT_V2_SECURITY.md Part A.

Formula (verbatim from the spec):
    score = 100 * (sum(score_weight for pass) + 0.5 * sum(score_weight for warn))
                 / sum(score_weight for pass|warn|fail)
`error` and `skipped` checks are excluded from both sides. Round to nearest int.

Grade bands are not specified numerically in the contract -- only one worked
example is given (`score: 68` -> `grade: "C"`). The bands below are chosen so
that example holds, and are otherwise a standard-shaped A/B/C/D/F curve:

    A: score >= 90
    B: 80 <= score < 90
    C: 65 <= score < 80
    D: 50 <= score < 65
    F: score < 50

If product wants different cut points later, this is the only place to change.
"""
from __future__ import annotations

from typing import Iterable, Protocol

GRADE_BANDS: tuple[tuple[int, str], ...] = (
    (90, "A"),
    (80, "B"),
    (65, "C"),
    (50, "D"),
    (0, "F"),
)


class _WeightedStatus(Protocol):
    status: str
    score_weight: int


def compute_score(checks: Iterable[_WeightedStatus]) -> int:
    """0-100. Checks with status `error` or `skipped` are excluded from the
    denominator entirely. If nothing scorable remains (e.g. every check
    errored), returns 0 rather than dividing by zero -- no verifiable data
    means no assurance can be claimed, so we don't default to a passing or
    neutral score."""
    scorable = [c for c in checks if c.status in ("pass", "warn", "fail")]
    denominator = sum(c.score_weight for c in scorable)
    if denominator <= 0:
        return 0
    numerator = sum(c.score_weight for c in scorable if c.status == "pass") + 0.5 * sum(
        c.score_weight for c in scorable if c.status == "warn"
    )
    return round(100 * numerator / denominator)


def grade_for_score(score: int) -> str:
    for threshold, grade in GRADE_BANDS:
        if score >= threshold:
            return grade
    return "F"  # unreachable given the 0 floor in GRADE_BANDS, kept for safety
