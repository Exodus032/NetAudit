"""content.py's own validation logic, exercised against deliberately broken
fixture data (not the real shipped data files, which the other test_data_*
modules already cover) -- placeholder text, dangling references, and
prerequisite cycles should all raise ContentError, not silently pass.
"""
from __future__ import annotations

import json

import pytest

from netaudit.learn import content

VALID_TERM = {
    "id": "arp", "term": "ARP", "expansion": "Address Resolution Protocol",
    "short": "short", "detail": "detail", "why_it_matters": "why",
    "see_also": [], "category": "protocol", "difficulty": "beginner",
}


def _write(tmp_path, name, data):
    with open(tmp_path / name, "w", encoding="utf-8") as f:
        json.dump(data, f)


def test_glossary_rejects_placeholder_text(tmp_path, monkeypatch):
    monkeypatch.setattr(content, "DATA_DIR", tmp_path)
    term = {**VALID_TERM, "detail": "TODO: write this"}
    required = {rid: {**VALID_TERM, "id": rid, "term": rid} for rid in content.REQUIRED_GLOSSARY_IDS}
    required["arp"] = term
    _write(tmp_path, "glossary.json", {"terms": list(required.values())})
    with pytest.raises(content.ContentError, match="placeholder"):
        content.load_glossary()


def test_glossary_rejects_dangling_see_also(tmp_path, monkeypatch):
    monkeypatch.setattr(content, "DATA_DIR", tmp_path)
    required = {rid: {**VALID_TERM, "id": rid, "term": rid} for rid in content.REQUIRED_GLOSSARY_IDS}
    required["arp"] = {**VALID_TERM, "see_also": ["does_not_exist"]}
    _write(tmp_path, "glossary.json", {"terms": list(required.values())})
    with pytest.raises(content.ContentError, match="dangling see_also"):
        content.load_glossary()


def test_glossary_rejects_missing_required_id(tmp_path, monkeypatch):
    monkeypatch.setattr(content, "DATA_DIR", tmp_path)
    _write(tmp_path, "glossary.json", {"terms": [VALID_TERM]})
    with pytest.raises(content.ContentError, match="missing required"):
        content.load_glossary()


def test_glossary_rejects_duplicate_id(tmp_path, monkeypatch):
    monkeypatch.setattr(content, "DATA_DIR", tmp_path)
    required = {rid: {**VALID_TERM, "id": rid, "term": rid} for rid in content.REQUIRED_GLOSSARY_IDS}
    _write(tmp_path, "glossary.json", {"terms": list(required.values()) + [VALID_TERM]})
    with pytest.raises(content.ContentError, match="duplicate"):
        content.load_glossary()


def test_missing_file_raises_content_error(tmp_path, monkeypatch):
    monkeypatch.setattr(content, "DATA_DIR", tmp_path)
    with pytest.raises(content.ContentError, match="missing"):
        content.load_glossary()


def test_malformed_json_raises_content_error(tmp_path, monkeypatch):
    monkeypatch.setattr(content, "DATA_DIR", tmp_path)
    (tmp_path / "glossary.json").write_text("{not valid json", encoding="utf-8")
    with pytest.raises(content.ContentError, match="not valid JSON"):
        content.load_glossary()


def _valid_glossary_dict():
    return {rid: {**VALID_TERM, "id": rid, "term": rid} for rid in content.REQUIRED_GLOSSARY_IDS}


def test_lessons_reject_prerequisite_cycle(tmp_path, monkeypatch):
    monkeypatch.setattr(content, "DATA_DIR", tmp_path)
    _write(tmp_path, "glossary.json", {"terms": list(_valid_glossary_dict().values())})
    lesson_a = {
        "id": "a", "title": "A", "summary": "s", "difficulty": "beginner", "estimated_minutes": 1,
        "prerequisites": ["b"], "objectives": ["o"],
        "steps": [{"order": 1, "instruction": "i", "explanation": "e",
                    "check": {"kind": "manual", "value": "v"}, "glossary_terms": []}],
        "uses_live_data": False,
    }
    lesson_b = {**lesson_a, "id": "b", "prerequisites": ["a"]}
    extra = [{**lesson_a, "id": f"filler{i}", "prerequisites": []} for i in range(4)]
    _write(tmp_path, "lessons.json", {"lessons": [lesson_a, lesson_b] + extra})
    with pytest.raises(content.ContentError, match="cycle"):
        content.load_lessons()


def test_lessons_reject_dangling_prerequisite(tmp_path, monkeypatch):
    monkeypatch.setattr(content, "DATA_DIR", tmp_path)
    _write(tmp_path, "glossary.json", {"terms": list(_valid_glossary_dict().values())})
    lesson_a = {
        "id": "a", "title": "A", "summary": "s", "difficulty": "beginner", "estimated_minutes": 1,
        "prerequisites": ["does_not_exist"], "objectives": ["o"],
        "steps": [{"order": 1, "instruction": "i", "explanation": "e",
                    "check": {"kind": "manual", "value": "v"}, "glossary_terms": []}],
        "uses_live_data": False,
    }
    extra = [{**lesson_a, "id": f"filler{i}", "prerequisites": []} for i in range(5)]
    _write(tmp_path, "lessons.json", {"lessons": [lesson_a] + extra})
    with pytest.raises(content.ContentError, match="dangling prerequisite"):
        content.load_lessons()


def test_tour_rejects_fewer_than_twelve_steps(tmp_path, monkeypatch):
    monkeypatch.setattr(content, "DATA_DIR", tmp_path)
    _write(tmp_path, "glossary.json", {"terms": list(_valid_glossary_dict().values())})
    steps = [
        {"id": f"s{i}", "order": i, "view": "overview", "target": "[data-tour='x']",
         "title": "t", "body": "b", "glossary_terms": [], "action_hint": None}
        for i in range(1, 4)
    ]
    _write(tmp_path, "tour.json", {"steps": steps})
    with pytest.raises(content.ContentError, match="at least 12"):
        content.load_tour()
