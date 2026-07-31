"""Loads and structurally validates the framework data files under
`compliance/data/*.json`. Pure JSON-shape validation only -- this module
never imports `netaudit.posture` (or anything else outside this package),
so it can't verify that a `check_id` is a *real* posture check id. That
cross-check lives in `tests/compliance/test_data_validation.py`, which does
a guarded, test-only import of `netaudit.posture` and skips if unavailable.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Optional

DATA_DIR = Path(__file__).resolve().parent / "data"

FRAMEWORK_IDS = ("cis_win11", "nist_800_53", "essential_eight")


class FrameworkDataError(ValueError):
    """A data file is structurally invalid. Raised at load time, never
    silently swallowed -- a broken data file should fail loudly in tests,
    not produce a quietly-wrong compliance report."""


@dataclass(frozen=True)
class ControlDef:
    control_id: str
    title: str
    check_ids: tuple[str, ...]


@dataclass(frozen=True)
class FrameworkDef:
    id: str
    label: str
    coverage_note: str
    controls: tuple[ControlDef, ...]

    @property
    def all_check_ids(self) -> set[str]:
        return {cid for c in self.controls for cid in c.check_ids}

    @property
    def controls_mapped(self) -> int:
        """Controls that actually carry at least one check_id -- an entry
        with an empty check_ids list (Essential Eight's unassessable
        strategies) is real and shown in the report, but it isn't "mapped"
        in the sense this count is meant to convey."""
        return sum(1 for c in self.controls if c.check_ids)

    @property
    def checks_mapped(self) -> int:
        return len(self.all_check_ids)


def _validate_raw(raw: dict, path: Path) -> None:
    for key in ("id", "label", "coverage_note", "controls"):
        if key not in raw:
            raise FrameworkDataError(f"{path}: missing required key {key!r}")
    if not isinstance(raw["coverage_note"], str) or not raw["coverage_note"].strip():
        raise FrameworkDataError(f"{path}: coverage_note must be a non-empty string")
    if not isinstance(raw["controls"], list) or not raw["controls"]:
        raise FrameworkDataError(f"{path}: controls must be a non-empty list")

    seen_ids: set[str] = set()
    for i, entry in enumerate(raw["controls"]):
        for key in ("control_id", "title", "check_ids"):
            if key not in entry:
                raise FrameworkDataError(f"{path}: controls[{i}] missing required key {key!r}")
        cid = entry["control_id"]
        if not isinstance(cid, str) or not cid.strip():
            raise FrameworkDataError(f"{path}: controls[{i}].control_id must be a non-empty string")
        if cid in seen_ids:
            raise FrameworkDataError(f"{path}: duplicate control_id {cid!r}")
        seen_ids.add(cid)
        if not isinstance(entry["title"], str) or not entry["title"].strip():
            raise FrameworkDataError(f"{path}: controls[{i}].title must be a non-empty string")
        check_ids = entry["check_ids"]
        if not isinstance(check_ids, list) or not all(isinstance(c, str) and c.strip() for c in check_ids):
            raise FrameworkDataError(f"{path}: controls[{i}].check_ids must be a list of non-empty strings")
        if len(set(check_ids)) != len(check_ids):
            raise FrameworkDataError(f"{path}: controls[{i}].check_ids has a duplicate")


def _parse(raw: dict) -> FrameworkDef:
    controls = tuple(
        ControlDef(control_id=c["control_id"], title=c["title"], check_ids=tuple(c["check_ids"]))
        for c in raw["controls"]
    )
    return FrameworkDef(id=raw["id"], label=raw["label"], coverage_note=raw["coverage_note"], controls=controls)


def load_framework(framework_id: str, data_dir: Optional[Path] = None) -> Optional[FrameworkDef]:
    """Returns None if `framework_id` isn't one of the three known
    frameworks (the router turns that into a 404), rather than raising --
    a malformed *existing* file is a bug (FrameworkDataError), an unknown id
    is a normal client error."""
    if framework_id not in FRAMEWORK_IDS:
        return None
    directory = data_dir or DATA_DIR
    path = directory / f"{framework_id}.json"
    if not path.exists():
        raise FrameworkDataError(f"missing data file: {path}")
    raw = json.loads(path.read_text(encoding="utf-8"))
    _validate_raw(raw, path)
    if raw["id"] != framework_id:
        raise FrameworkDataError(f"{path}: id field {raw['id']!r} does not match filename {framework_id!r}")
    return _parse(raw)


@lru_cache(maxsize=None)
def _load_all_cached(data_dir_str: str) -> tuple[FrameworkDef, ...]:
    directory = Path(data_dir_str)
    return tuple(load_framework(fid, directory) for fid in FRAMEWORK_IDS)  # type: ignore[misc]


def load_all_frameworks(data_dir: Optional[Path] = None) -> list[FrameworkDef]:
    directory = data_dir or DATA_DIR
    return list(_load_all_cached(str(directory)))
