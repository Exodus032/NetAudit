"""Loads and validates the four content files under `learn/data/` at import
time. If a data file is malformed, references a term that doesn't exist, or
contains obvious placeholder text, importing this module raises -- the
content is the product here, so a broken content file should fail loudly
and immediately, not serve garbage to a student.

Deliberately does not import anything from `netaudit.threat`, `.posture` or
`.rules` -- see package `__init__.py`. Coverage against the *real* detector/
rule/check registries is a test-time concern with a guarded import
(`backend/tests/learn/test_coverage.py`), not a production import-time one.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from pydantic import ValidationError

from .models import Explanation, GlossaryTerm, Lesson, TourStep

DATA_DIR = Path(__file__).parent / "data"

_PLACEHOLDER_MARKERS = ("TODO", "TBD", "FIXME", "lorem ipsum", "lorem")

REQUIRED_GLOSSARY_IDS: list[str] = [
    "ip_address", "mac_address", "port", "tcp", "udp", "icmp", "dns", "dhcp",
    "arp", "gateway", "subnet", "nat", "packet", "flow", "bandwidth",
    "latency", "tls", "https", "certificate", "encryption", "plaintext",
    "vpn", "proxy", "tor", "firewall", "port_scan", "beaconing", "c2",
    "exfiltration", "lateral_movement", "arp_spoofing", "mitm",
    "dns_tunneling", "dga", "smb", "rdp", "llmnr", "netbios", "wpad",
    "promiscuous_mode", "pcap", "bpf", "mitre_attack", "false_positive",
    "baseline", "loopback", "broadcast", "multicast",
]

REQUIRED_VIEWS: set[str] = {
    "overview", "traffic-log", "connections", "recommendations", "posture", "threats",
}


class ContentError(ValueError):
    """Raised when a data file fails to load or validate. Deliberately a
    plain ValueError subclass -- this is a startup-time configuration
    error, not something any caller should try to catch and route around."""


def _read_json(name: str) -> object:
    path = DATA_DIR / name
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError as exc:
        raise ContentError(f"learn content file missing: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ContentError(f"learn content file {path} is not valid JSON: {exc}") from exc


def _check_no_placeholder(value: str, where: str) -> None:
    if value is None or not str(value).strip():
        raise ContentError(f"{where}: empty text is not allowed")
    lowered = str(value).lower()
    for marker in _PLACEHOLDER_MARKERS:
        if marker.lower() in lowered:
            raise ContentError(f"{where}: contains placeholder text ({marker!r})")


def _scan_strings(obj: object, where: str) -> None:
    """Recursively walk a loaded JSON structure and reject placeholder text
    or empty strings anywhere in it -- run once per top-level item so the
    error message can point at which item is broken."""
    if isinstance(obj, str):
        _check_no_placeholder(obj, where)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            _scan_strings(v, f"{where}[{i}]")
    elif isinstance(obj, dict):
        for k, v in obj.items():
            _scan_strings(v, f"{where}.{k}")


def load_glossary() -> dict[str, GlossaryTerm]:
    raw = _read_json("glossary.json")
    if not isinstance(raw, dict) or "terms" not in raw:
        raise ContentError("glossary.json must be an object with a 'terms' array")
    terms: dict[str, GlossaryTerm] = {}
    for i, entry in enumerate(raw["terms"]):
        try:
            term = GlossaryTerm.model_validate(entry)
        except ValidationError as exc:
            raise ContentError(f"glossary.json terms[{i}] failed validation: {exc}") from exc
        if term.id in terms:
            raise ContentError(f"glossary.json has a duplicate term id: {term.id!r}")
        _scan_strings(entry, f"glossary.json terms[{i}] ({term.id})")
        terms[term.id] = term

    missing = [t for t in REQUIRED_GLOSSARY_IDS if t not in terms]
    if missing:
        raise ContentError(f"glossary.json is missing required term(s): {missing}")

    for term in terms.values():
        for ref in term.see_also:
            if ref not in terms:
                raise ContentError(f"glossary term {term.id!r} has a dangling see_also reference: {ref!r}")
    return terms


def load_explanations() -> dict[tuple[str, str], Explanation]:
    raw = _read_json("explanations.json")
    if not isinstance(raw, dict) or "explanations" not in raw:
        raise ContentError("explanations.json must be an object with an 'explanations' array")
    glossary = load_glossary()
    out: dict[tuple[str, str], Explanation] = {}
    for i, entry in enumerate(raw["explanations"]):
        try:
            exp = Explanation.model_validate(entry)
        except ValidationError as exc:
            raise ContentError(f"explanations.json[{i}] failed validation: {exc}") from exc
        key = (exp.kind, exp.id)
        if key in out:
            raise ContentError(f"explanations.json has a duplicate (kind, id): {key!r}")
        _scan_strings(entry, f"explanations.json[{i}] ({exp.kind}/{exp.id})")
        for term in exp.glossary_terms:
            if term not in glossary:
                raise ContentError(f"explanation {exp.kind}/{exp.id} references unknown glossary term {term!r}")
        out[key] = exp
    return out


def load_tour() -> list[TourStep]:
    raw = _read_json("tour.json")
    if not isinstance(raw, dict) or "steps" not in raw:
        raise ContentError("tour.json must be an object with a 'steps' array")
    glossary = load_glossary()
    steps: list[TourStep] = []
    seen_ids: set[str] = set()
    seen_views: set[str] = set()
    for i, entry in enumerate(raw["steps"]):
        try:
            step = TourStep.model_validate(entry)
        except ValidationError as exc:
            raise ContentError(f"tour.json steps[{i}] failed validation: {exc}") from exc
        if step.id in seen_ids:
            raise ContentError(f"tour.json has a duplicate step id: {step.id!r}")
        seen_ids.add(step.id)
        seen_views.add(step.view)
        if not step.target.strip():
            raise ContentError(f"tour.json step {step.id!r} has an empty target selector")
        _scan_strings(entry, f"tour.json steps[{i}] ({step.id})")
        for term in step.glossary_terms:
            if term not in glossary:
                raise ContentError(f"tour step {step.id!r} references unknown glossary term {term!r}")
        steps.append(step)
    if len(steps) < 12:
        raise ContentError(f"tour.json must have at least 12 steps, has {len(steps)}")
    missing_views = REQUIRED_VIEWS - seen_views
    if missing_views:
        raise ContentError(f"tour.json does not cover every view: missing {sorted(missing_views)}")
    steps.sort(key=lambda s: s.order)
    return steps


def _lesson_prereq_cycle(lessons: dict[str, Lesson]) -> Optional[list[str]]:
    """DFS cycle detection over the prerequisites graph. Returns the cycle
    (list of lesson ids) if one exists, else None."""
    WHITE, GRAY, BLACK = 0, 1, 2
    color = {lid: WHITE for lid in lessons}
    path: list[str] = []

    def visit(lid: str) -> Optional[list[str]]:
        color[lid] = GRAY
        path.append(lid)
        for prereq in lessons[lid].prerequisites:
            if color.get(prereq) == GRAY:
                cycle_start = path.index(prereq)
                return path[cycle_start:] + [prereq]
            if color.get(prereq) == WHITE:
                result = visit(prereq)
                if result:
                    return result
        path.pop()
        color[lid] = BLACK
        return None

    for lid in lessons:
        if color[lid] == WHITE:
            result = visit(lid)
            if result:
                return result
    return None


def load_lessons() -> dict[str, Lesson]:
    raw = _read_json("lessons.json")
    if not isinstance(raw, dict) or "lessons" not in raw:
        raise ContentError("lessons.json must be an object with a 'lessons' array")
    glossary = load_glossary()
    lessons: dict[str, Lesson] = {}
    for i, entry in enumerate(raw["lessons"]):
        try:
            lesson = Lesson.model_validate(entry)
        except ValidationError as exc:
            raise ContentError(f"lessons.json[{i}] failed validation: {exc}") from exc
        if lesson.id in lessons:
            raise ContentError(f"lessons.json has a duplicate lesson id: {lesson.id!r}")
        _scan_strings(entry, f"lessons.json[{i}] ({lesson.id})")
        for step in lesson.steps:
            for term in step.glossary_terms:
                if term not in glossary:
                    raise ContentError(f"lesson {lesson.id!r} step {step.order} references unknown glossary term {term!r}")
        lessons[lesson.id] = lesson

    if len(lessons) < 6:
        raise ContentError(f"lessons.json must have at least 6 lessons, has {len(lessons)}")

    for lesson in lessons.values():
        for prereq in lesson.prerequisites:
            if prereq not in lessons:
                raise ContentError(f"lesson {lesson.id!r} has a dangling prerequisite: {prereq!r}")

    cycle = _lesson_prereq_cycle(lessons)
    if cycle:
        raise ContentError(f"lessons.json prerequisites contain a cycle: {' -> '.join(cycle)}")

    return lessons


# Loaded and validated once, at import time, so a broken content file fails
# the moment this package is imported rather than on the first request.
GLOSSARY: dict[str, GlossaryTerm] = load_glossary()
EXPLANATIONS: dict[tuple[str, str], Explanation] = load_explanations()
TOUR: list[TourStep] = load_tour()
LESSONS: dict[str, Lesson] = load_lessons()
