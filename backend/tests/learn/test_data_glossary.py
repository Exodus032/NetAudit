"""glossary.json: loads, validates against GlossaryTerm, covers every
required D1 id, has no placeholder text, and every see_also points at a
real term."""
from __future__ import annotations

from netaudit.learn import content
from netaudit.learn.models import GlossaryTerm


def test_glossary_loads_and_validates():
    assert len(content.GLOSSARY) >= 47
    for term in content.GLOSSARY.values():
        assert isinstance(term, GlossaryTerm)


def test_glossary_covers_every_required_id():
    missing = [t for t in content.REQUIRED_GLOSSARY_IDS if t not in content.GLOSSARY]
    assert not missing, f"glossary is missing required terms: {missing}"


def test_glossary_required_ids_are_exactly_48():
    # The literal list in API_CONTRACT_V3.md D1 -- a change here should be
    # a deliberate, visible diff, not a silent drift.
    assert len(content.REQUIRED_GLOSSARY_IDS) == 48


def test_every_see_also_points_at_a_real_term():
    for term in content.GLOSSARY.values():
        for ref in term.see_also:
            assert ref in content.GLOSSARY, f"{term.id} see_also references missing term {ref!r}"


def test_no_term_references_itself():
    for term in content.GLOSSARY.values():
        assert term.id not in term.see_also, f"{term.id} references itself in see_also"


def test_no_placeholder_or_empty_text():
    banned = ("TODO", "TBD", "FIXME", "lorem ipsum")
    for term in content.GLOSSARY.values():
        for field in (term.term, term.short, term.detail, term.why_it_matters):
            assert field and field.strip(), f"{term.id} has an empty field"
            for marker in banned:
                assert marker.lower() not in field.lower(), f"{term.id} contains placeholder text {marker!r}"


def test_categories_and_difficulties_are_valid():
    valid_categories = {"protocol", "security", "networking", "tool"}
    valid_difficulties = {"beginner", "intermediate", "advanced"}
    for term in content.GLOSSARY.values():
        assert term.category in valid_categories
        assert term.difficulty in valid_difficulties


def test_ids_are_unique_and_match_dict_keys():
    for key, term in content.GLOSSARY.items():
        assert key == term.id
