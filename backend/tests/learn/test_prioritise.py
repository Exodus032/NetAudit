"""D6 prioritisation: hand-computed impact_score values against the exact
formula in prioritise.py (SEVERITY_BASE * multiplier + EFFORT_BONUS +
ATTACK_PATH_BONUS, clamped 0-100), table-driven ranking with deterministic
tie-breaks, plus empty and all-clear inputs.
"""
from __future__ import annotations

from netaudit.learn.prioritise import ATTACK_PATH_BONUS, EFFORT_BONUS, SEVERITY_BASE, impact_score, rank


# ---------------------------------------------------------------------
# impact_score: one hand-computed value at a time
# ---------------------------------------------------------------------

def test_smb_signing_required_scores_87():
    # posture, severity high (base 72), status fail (x1.0), effort low
    # (+10), and it carries the +5 attack-path bonus (unauthenticated
    # SMB relay/tamper needs no credentials).
    item = {"id": "smb_signing_required", "source": "posture", "severity": "high",
            "status": "fail", "effort": "low"}
    assert SEVERITY_BASE["high"] == 72
    assert EFFORT_BONUS["low"] == 10
    assert ATTACK_PATH_BONUS["smb_signing_required"] == 5
    assert impact_score(item) == 87


def test_firewall_inbound_default_block_scores_82_no_bonus():
    # Same severity/status/effort as smb_signing_required, but not in
    # ATTACK_PATH_BONUS (a default-deny gap is defense-in-depth, not
    # itself a named credential-free attack path) -- 72 + 10 + 0 = 82.
    item = {"id": "firewall_inbound_default_block", "source": "posture", "severity": "high",
            "status": "fail", "effort": "low"}
    assert impact_score(item) == 82


def test_warn_status_applies_06_multiplier():
    # llmnr_disabled: high (72) * warn (0.6) = round(43.2) = 43, + low
    # effort (+10) + its +5 bonus = 58.
    item = {"id": "llmnr_disabled", "source": "posture", "severity": "high",
            "status": "warn", "effort": "low"}
    assert impact_score(item) == 58


def test_recommendation_uses_confidence_as_multiplier():
    # plaintext_http: medium (50) * confidence 0.9 = round(45) = 45,
    # + low effort (+10), no bonus = 55.
    item = {"id": "plaintext_http", "source": "recommendation", "severity": "medium",
            "confidence": 0.9, "effort": "low"}
    assert impact_score(item) == 55


def test_listening_exposed_recommendation():
    # high (72) * confidence 0.85 = round(61.2) = 61, + medium effort
    # (+0) + its +4 bonus = 65.
    item = {"id": "listening_exposed", "source": "recommendation", "severity": "high",
            "confidence": 0.85, "effort": "medium"}
    assert impact_score(item) == 65


def test_missing_confidence_defaults_to_full_weight():
    item = {"id": "unlisted_threat", "source": "threat", "severity": "critical", "effort": "medium"}
    assert impact_score(item) == SEVERITY_BASE["critical"]  # 92 + 0 + 0


def test_high_effort_reduces_score():
    item = {"id": "unlisted_check", "source": "posture", "severity": "high", "status": "fail", "effort": "high"}
    assert impact_score(item) == 72 - 10  # 62


def test_missing_effort_defaults_to_medium_zero_bonus():
    item = {"id": "unlisted_check2", "source": "posture", "severity": "medium", "status": "fail"}
    assert impact_score(item) == 50  # EFFORT_BONUS["medium"] == 0


def test_score_is_clamped_to_zero_not_negative():
    # info (10) * warn (0.6) = round(6) = 6, - high effort (10) = -4 -> clamp to 0.
    item = {"id": "unlisted_info", "source": "posture", "severity": "info", "status": "warn", "effort": "high"}
    assert impact_score(item) == 0


def test_score_is_clamped_to_100_not_above():
    item = {"id": "smb1_disabled", "source": "posture", "severity": "critical", "status": "fail", "effort": "low"}
    # 92 + 10 + 6 (smb1_disabled bonus) = 108 -> clamped to 100.
    assert impact_score(item) == 100


# ---------------------------------------------------------------------
# rank(): the required scenario from the task, end to end
# ---------------------------------------------------------------------

REQUIRED_SCENARIO = [
    {"id": "smb_signing_required", "source": "posture", "title": "Require SMB signing",
     "severity": "high", "status": "fail", "effort": "low", "one_line_fix": "Run one PowerShell command as administrator."},
    {"id": "firewall_inbound_default_block", "source": "posture", "title": "Set default inbound action to Block",
     "severity": "high", "status": "fail", "effort": "low", "one_line_fix": "Run one PowerShell command as administrator."},
    {"id": "wpad_disabled", "source": "posture", "title": "Disable WPAD proxy auto-detection",
     "severity": "medium", "status": "fail", "effort": "low", "one_line_fix": "Run 'netsh winhttp reset proxy' as administrator."},
    {"id": "llmnr_disabled", "source": "posture", "title": "Disable LLMNR",
     "severity": "high", "status": "warn", "effort": "low", "one_line_fix": "Set EnableMulticast to 0 via policy."},
    {"id": "listening_exposed", "source": "recommendation", "title": "SMB listening on all interfaces",
     "severity": "high", "confidence": 0.85, "effort": "medium", "one_line_fix": "Restrict the port to your LAN subnet via firewall rule."},
    {"id": "plaintext_http", "source": "recommendation", "title": "Unencrypted HTTP traffic observed",
     "severity": "medium", "confidence": 0.9, "effort": "low", "one_line_fix": "Enable HTTPS-only mode in your browser."},
]


def test_required_scenario_scores():
    scores = {item["id"]: impact_score(item) for item in REQUIRED_SCENARIO}
    assert scores == {
        "smb_signing_required": 87,
        "firewall_inbound_default_block": 82,
        "listening_exposed": 65,
        "wpad_disabled": 63,
        "llmnr_disabled": 58,
        "plaintext_http": 55,
    }


def test_required_scenario_ranking_order():
    ranked = rank(REQUIRED_SCENARIO)
    assert [r["id"].split(":", 1)[1] for r in ranked] == [
        "smb_signing_required",
        "firewall_inbound_default_block",
        "listening_exposed",
        "wpad_disabled",
        "llmnr_disabled",
        "plaintext_http",
    ]
    assert [r["priority_rank"] for r in ranked] == [1, 2, 3, 4, 5, 6]
    assert ranked[0]["impact_score"] == 87
    assert ranked[0]["source"] == "posture"
    assert ranked[0]["deep_link"] == {"view": "posture", "id": "smb_signing_required"}


def test_why_first_references_real_reasons_not_just_severity():
    ranked = rank(REQUIRED_SCENARIO)
    top = ranked[0]
    assert "high severity" in top["why_first"].lower()
    assert "attack path" in top["why_first"].lower()
    # A warn-status item should say so, distinguishing it from a hard fail.
    llmnr = next(r for r in ranked if r["id"] == "posture:llmnr_disabled")
    assert "warning" in llmnr["why_first"].lower() or "warn" in llmnr["why_first"].lower()


# ---------------------------------------------------------------------
# Ties, empty input, all-clear input
# ---------------------------------------------------------------------

def test_ties_broken_by_id_ascending_when_everything_else_equal():
    items = [
        {"id": "zzz_check", "source": "posture", "title": "Z", "severity": "high", "status": "fail", "effort": "medium"},
        {"id": "aaa_check", "source": "posture", "title": "A", "severity": "high", "status": "fail", "effort": "medium"},
    ]
    ranked = rank(items)
    assert [r["id"] for r in ranked] == ["posture:aaa_check", "posture:zzz_check"]
    assert ranked[0]["impact_score"] == ranked[1]["impact_score"]


def test_ties_broken_by_source_priority_before_id():
    # Same score, same severity: threat outranks posture outranks recommendation.
    items = [
        {"id": "m", "source": "recommendation", "title": "R", "severity": "high", "confidence": 1.0, "effort": "medium"},
        {"id": "m", "source": "posture", "title": "P", "severity": "high", "status": "fail", "effort": "medium"},
        {"id": "m", "source": "threat", "title": "T", "severity": "high", "confidence": 1.0, "effort": "medium"},
    ]
    ranked = rank(items)
    assert [r["source"] for r in ranked] == ["threat", "posture", "recommendation"]


def test_rank_is_deterministic_regardless_of_input_order():
    forward = rank(REQUIRED_SCENARIO)
    backward = rank(list(reversed(REQUIRED_SCENARIO)))
    assert [r["id"] for r in forward] == [r["id"] for r in backward]


def test_empty_input_returns_empty_list():
    assert rank([]) == []


def test_all_clear_input_has_no_findings_to_rank():
    # An "all clear" run has nothing fail/warn -- the caller (LearnService)
    # is responsible for filtering pass/error/skipped statuses out before
    # calling rank(); rank() itself just has nothing to do with an empty list.
    assert rank([]) == []


def test_single_item_gets_rank_one():
    ranked = rank([{"id": "solo", "source": "threat", "title": "Solo", "severity": "low", "confidence": 1.0, "effort": "medium"}])
    assert len(ranked) == 1
    assert ranked[0]["priority_rank"] == 1


def test_one_line_fix_falls_back_when_absent():
    ranked = rank([{"id": "no_fix_text", "source": "posture", "title": "X", "severity": "low", "status": "warn"}])
    assert ranked[0]["one_line_fix"]
