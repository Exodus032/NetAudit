"""The score formula and grade bands, against hand-computed expected values."""
from __future__ import annotations

from dataclasses import dataclass

import pytest

from netaudit.posture.scoring import GRADE_BANDS, compute_score, grade_for_score


@dataclass
class _Fake:
    status: str
    score_weight: int


def test_all_pass_scores_100():
    checks = [_Fake("pass", 10), _Fake("pass", 5)]
    assert compute_score(checks) == 100


def test_all_fail_scores_0():
    checks = [_Fake("fail", 10), _Fake("fail", 5)]
    assert compute_score(checks) == 0


def test_hand_computed_mixed():
    # denominator = 8+8+5 = 21; numerator = 8 (pass) + 0.5*8 (warn) = 12
    # score = 100 * 12/21 = 57.14... -> round to 57
    checks = [_Fake("pass", 8), _Fake("warn", 8), _Fake("fail", 5)]
    assert compute_score(checks) == 57


def test_exact_contract_example():
    # From API_CONTRACT_V2_SECURITY.md's own worked example: score 68 -> grade C.
    # Construct a check set whose formula lands on exactly 68.
    # denominator = 100; numerator = 68 -> 68 pass-weight, 0 warn, 32 fail-weight.
    checks = [_Fake("pass", 68), _Fake("fail", 32)]
    score = compute_score(checks)
    assert score == 68
    assert grade_for_score(score) == "C"


def test_error_and_skipped_excluded_from_denominator():
    checks = [_Fake("pass", 10), _Fake("error", 1000), _Fake("skipped", 1000)]
    # error/skipped must not affect the score at all
    assert compute_score(checks) == 100


def test_all_error_does_not_divide_by_zero():
    checks = [_Fake("error", 10), _Fake("error", 5), _Fake("skipped", 3)]
    assert compute_score(checks) == 0


def test_empty_check_list_does_not_divide_by_zero():
    assert compute_score([]) == 0


def test_warn_counts_half():
    # denominator = 10 (single warn check); numerator = 0.5*10 = 5 -> score 50
    checks = [_Fake("warn", 10)]
    assert compute_score(checks) == 50


@pytest.mark.parametrize(
    "score,expected_grade",
    [
        (100, "A"), (90, "A"),
        (89, "B"), (80, "B"),
        (79, "C"), (68, "C"), (65, "C"),
        (64, "D"), (50, "D"),
        (49, "F"), (0, "F"),
    ],
)
def test_grade_bands(score, expected_grade):
    assert grade_for_score(score) == expected_grade


def test_grade_bands_are_contiguous_and_cover_0_to_100():
    thresholds = sorted((t for t, _ in GRADE_BANDS))
    assert thresholds[0] == 0
    # every integer 0-100 must resolve to exactly one grade with no gaps
    for score in range(0, 101):
        grade = grade_for_score(score)
        assert grade in {"A", "B", "C", "D", "F"}
