from __future__ import annotations

import pytest

from netaudit.store import db as dbmod


@pytest.fixture
def db_path(tmp_path):
    path = tmp_path / "test.db"
    yield path
    dbmod.reset_for_tests(path)
