from __future__ import annotations

from datetime import datetime, timezone

import pytest

from netaudit.threat.store import ThreatStore
from netaudit.threat.store import reset_for_tests as _reset_store_for_tests


@pytest.fixture
def db_path(tmp_path):
    path = tmp_path / "threat-test.db"
    yield path
    _reset_store_for_tests(path)


@pytest.fixture
def store(db_path):
    return ThreatStore(db_path)


@pytest.fixture
def now():
    return datetime(2026, 7, 31, 14, 0, 0, tzinfo=timezone.utc)
