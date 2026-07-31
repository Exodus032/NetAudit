"""lessons.json: loads, validates against Lesson, at least 6 lessons
spanning beginner->advanced, prerequisites resolve and contain no cycle,
step checks are well-formed, glossary refs resolve."""
from __future__ import annotations

from netaudit.learn import content
from netaudit.learn.models import Lesson


def test_lessons_load_and_validate():
    assert len(content.LESSONS) >= 6
    for lesson in content.LESSONS.values():
        assert isinstance(lesson, Lesson)


def test_spans_beginner_to_advanced():
    difficulties = {l.difficulty for l in content.LESSONS.values()}
    assert "beginner" in difficulties
    assert "advanced" in difficulties


def test_every_prerequisite_resolves():
    for lesson in content.LESSONS.values():
        for prereq in lesson.prerequisites:
            assert prereq in content.LESSONS, f"{lesson.id} has dangling prerequisite {prereq!r}"


def test_no_prerequisite_cycle():
    # content.py's import-time load already raises on a cycle; this test
    # re-derives it independently over the already-loaded data as a second,
    # more direct check the graph really is acyclic.
    WHITE, GRAY, BLACK = 0, 1, 2
    color = {lid: WHITE for lid in content.LESSONS}

    def visit(lid, path):
        color[lid] = GRAY
        for prereq in content.LESSONS[lid].prerequisites:
            assert color[prereq] != GRAY, f"cycle: {' -> '.join(path + [prereq])}"
            if color[prereq] == WHITE:
                visit(prereq, path + [prereq])
        color[lid] = BLACK

    for lid in content.LESSONS:
        if color[lid] == WHITE:
            visit(lid, [lid])


def test_no_lesson_is_its_own_prerequisite():
    for lesson in content.LESSONS.values():
        assert lesson.id not in lesson.prerequisites


def test_steps_are_ordered_from_one():
    for lesson in content.LESSONS.values():
        orders = [s.order for s in lesson.steps]
        assert orders == list(range(1, len(orders) + 1)), f"{lesson.id} steps aren't sequential from 1"


def test_step_check_kind_is_valid():
    valid = {"view_visited", "filter_applied", "element_clicked", "manual"}
    for lesson in content.LESSONS.values():
        for step in lesson.steps:
            assert step.check.kind in valid
            assert step.check.value.strip()


def test_glossary_terms_resolve():
    for lesson in content.LESSONS.values():
        for step in lesson.steps:
            for term in step.glossary_terms:
                assert term in content.GLOSSARY, f"{lesson.id} step {step.order} references missing glossary term {term!r}"


def test_every_lesson_has_at_least_one_objective_and_step():
    for lesson in content.LESSONS.values():
        assert len(lesson.objectives) >= 1
        assert len(lesson.steps) >= 1
