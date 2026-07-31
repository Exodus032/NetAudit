"""scoring.py: the `threats` component score for /api/security/score."""
from __future__ import annotations

from netaudit.threat.scoring import compute_threats_score, grade_for_score


def test_no_threats_is_perfect_score():
    result = compute_threats_score([])
    assert result == {"id": "threats", "label": "Active threats", "score": 100, "grade": "A"}


def test_active_critical_threat_penalizes_heavily():
    result = compute_threats_score([{"severity": "critical", "status": "active"}])
    assert result["score"] == 75
    assert result["grade"] == "C"


def test_resolved_threats_do_not_count():
    result = compute_threats_score([{"severity": "critical", "status": "resolved"}])
    assert result["score"] == 100


def test_acknowledged_threats_count_at_reduced_weight():
    active = compute_threats_score([{"severity": "high", "status": "active"}])
    acked = compute_threats_score([{"severity": "high", "status": "acknowledged"}])
    assert acked["score"] > active["score"]


def test_score_never_goes_below_zero():
    threats = [{"severity": "critical", "status": "active"} for _ in range(10)]
    result = compute_threats_score(threats)
    assert result["score"] == 0
    assert result["grade"] == "F"


def test_grade_boundaries():
    assert grade_for_score(95) == "A"
    assert grade_for_score(90) == "A"
    assert grade_for_score(89) == "B"
    assert grade_for_score(80) == "B"
    assert grade_for_score(79) == "C"
    assert grade_for_score(70) == "C"
    assert grade_for_score(69) == "D"
    assert grade_for_score(60) == "D"
    assert grade_for_score(59) == "F"
