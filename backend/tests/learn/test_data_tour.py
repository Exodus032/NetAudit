"""tour.json: loads, validates against TourStep, at least 12 steps, covers
all six views, non-empty target selectors, ordered, glossary refs resolve."""
from __future__ import annotations

from netaudit.learn import content
from netaudit.learn.models import TourStep

REQUIRED_VIEWS = {"overview", "traffic-log", "connections", "recommendations", "posture", "threats"}


def test_tour_loads_and_validates():
    assert len(content.TOUR) >= 12
    for step in content.TOUR:
        assert isinstance(step, TourStep)


def test_tour_covers_every_view():
    views = {s.view for s in content.TOUR}
    missing = REQUIRED_VIEWS - views
    assert not missing, f"tour does not cover views: {missing}"


def test_every_target_selector_is_non_empty():
    for step in content.TOUR:
        assert step.target.strip()


def test_step_ids_are_unique():
    ids = [s.id for s in content.TOUR]
    assert len(ids) == len(set(ids))


def test_orders_are_sequential_when_sorted():
    orders = sorted(s.order for s in content.TOUR)
    assert orders == list(range(1, len(content.TOUR) + 1))


def test_glossary_terms_resolve():
    for step in content.TOUR:
        for term in step.glossary_terms:
            assert term in content.GLOSSARY, f"tour step {step.id} references missing glossary term {term!r}"


def test_action_hint_is_null_or_short_instruction():
    for step in content.TOUR:
        if step.action_hint is not None:
            assert step.action_hint.strip()
            assert len(step.action_hint) < 100
