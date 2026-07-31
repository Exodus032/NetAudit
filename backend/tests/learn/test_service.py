"""LearnService: lookup methods over the validated content, and D6
end-to-end through StaticFindingsProvider -- including the "all clear"
case, where the service (not prioritise.rank itself) is responsible for
filtering out pass/error/skipped posture checks before ranking.
"""
from __future__ import annotations

from netaudit.learn import content
from netaudit.learn.service import LearnService, StaticFindingsProvider


def test_list_glossary_sorted_by_id():
    service = LearnService()
    terms = service.list_glossary()
    ids = [t.id for t in terms]
    assert ids == sorted(ids)
    assert len(terms) == len(content.GLOSSARY)


def test_get_glossary_term_hit_and_miss():
    service = LearnService()
    assert service.get_glossary_term("arp") is not None
    assert service.get_glossary_term("not_a_real_term") is None


def test_get_explanation_hit_and_miss():
    service = LearnService()
    assert service.get_explanation("detector", "c2_beaconing") is not None
    assert service.get_explanation("detector", "does_not_exist") is None
    assert service.get_explanation("check", "c2_beaconing") is None  # wrong kind


def test_get_tour_returns_all_steps():
    service = LearnService()
    assert len(service.get_tour()) == len(content.TOUR)


def test_list_and_get_lessons():
    service = LearnService()
    lessons = service.list_lessons()
    assert len(lessons) == len(content.LESSONS)
    one = service.get_lesson(lessons[0].id)
    assert one is not None
    assert service.get_lesson("not_a_real_lesson") is None


def test_default_findings_provider_is_empty():
    service = LearnService()
    result = service.prioritised_findings()
    assert result["items"] == []
    assert "generated_at" in result


def test_all_clear_input_produces_no_items():
    provider = StaticFindingsProvider(
        posture=[
            {"id": "smb1_disabled", "title": "SMBv1 disabled", "severity": "critical", "status": "pass"},
            {"id": "uac_enabled", "title": "UAC enabled", "severity": "critical", "status": "error"},
            {"id": "ipv6_state", "title": "IPv6 state", "severity": "low", "status": "skipped"},
        ],
        recommendations=[],
        threats=[],
    )
    service = LearnService(findings_provider=provider)
    result = service.prioritised_findings()
    assert result["items"] == []


def test_only_fail_and_warn_posture_checks_become_findings():
    provider = StaticFindingsProvider(
        posture=[
            {"id": "a", "title": "A", "severity": "high", "status": "fail", "effort": "low"},
            {"id": "b", "title": "B", "severity": "high", "status": "pass"},
            {"id": "c", "title": "C", "severity": "medium", "status": "warn", "effort": "medium"},
        ],
    )
    service = LearnService(findings_provider=provider)
    result = service.prioritised_findings()
    ids = {item["id"] for item in result["items"]}
    assert ids == {"posture:a", "posture:c"}


def test_recommendations_and_threats_pass_through_unfiltered():
    provider = StaticFindingsProvider(
        recommendations=[{"id": "plaintext_http", "title": "Plaintext HTTP", "severity": "medium", "confidence": 0.9, "effort": "low"}],
        threats=[{"id": "port_scan_inbound", "title": "Inbound port scan", "severity": "high", "confidence": 0.7, "effort": "medium"}],
    )
    service = LearnService(findings_provider=provider)
    result = service.prioritised_findings()
    ids = {item["id"] for item in result["items"]}
    assert ids == {"recommendation:plaintext_http", "threat:port_scan_inbound"}


def test_generated_at_is_iso8601_with_z_suffix():
    service = LearnService()
    result = service.prioritised_findings()
    assert result["generated_at"].endswith("Z")
    assert "T" in result["generated_at"]
