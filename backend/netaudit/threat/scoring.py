"""The `threats` component score (0-100) for `/api/security/score`
(API_CONTRACT_V2_SECURITY.md A5), exposed as a `ScoreContributor`-shaped
object: `{id, label, score, grade}`. The orchestrator (owner of
`api/security_score.py` or wherever A5 gets assembled) combines this with
the `posture` and `hygiene` components at its own weights -- this module
only ever computes the `threats` slice.

Scoring model: start at 100 and subtract a per-severity penalty for every
threat that is still `active` (an `acknowledged` threat counts at a
quarter weight -- the user has seen it and made a call, so it should stop
dominating the score, but shouldn't vanish entirely since the underlying
condition is still true). `resolved` threats don't count at all.
"""
from __future__ import annotations

from typing import Optional

SEVERITY_PENALTY = {"critical": 25, "high": 12, "medium": 5, "low": 2, "info": 0}
ACKNOWLEDGED_WEIGHT = 0.25


def grade_for_score(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def compute_threats_score(threats: list[dict]) -> dict:
    """`threats` is a list of threat dicts as returned by
    `ThreatEngine.list_threats` (must include `severity` and `status`)."""
    penalty = 0.0
    for t in threats:
        status = t.get("status")
        if status == "resolved":
            continue
        weight = ACKNOWLEDGED_WEIGHT if status == "acknowledged" else 1.0
        penalty += SEVERITY_PENALTY.get(t.get("severity"), 0) * weight

    score = max(0, min(100, round(100 - penalty)))
    return {
        "id": "threats",
        "label": "Active threats",
        "score": score,
        "grade": grade_for_score(score),
    }
