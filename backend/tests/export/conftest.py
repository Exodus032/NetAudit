from __future__ import annotations

import importlib

import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from starlette.exceptions import HTTPException as StarletteHTTPException

from netaudit import config
from netaudit.export import reports_store
from netaudit.export.provider import StaticReportDataProvider, get_report_provider
from netaudit.store import db as dbmod

# See tests/pcap/conftest.py for why importlib.import_module is required
# here instead of `from netaudit.export import router as x` -- the package
# __init__.py's `from .router import router` shadows the submodule name.
export_router_module = importlib.import_module("netaudit.export.router")


@pytest.fixture
def isolated_env(tmp_path, monkeypatch):
    live_db = tmp_path / "live.db"
    reports_dir = tmp_path / "reports"
    dbmod.get_conn(live_db)
    monkeypatch.setattr(config, "DB_PATH", live_db)
    monkeypatch.setattr(reports_store, "DEFAULT_REPORTS_DIR", reports_dir)
    yield {"live_db": live_db, "reports_dir": reports_dir}
    dbmod.reset_for_tests(live_db)


@pytest.fixture
def app(isolated_env):
    app = FastAPI()
    app.include_router(export_router_module.router)

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException):
        detail = exc.detail
        if isinstance(detail, dict) and "error" in detail:
            body = detail
        else:
            body = {"error": {"code": "error", "message": str(detail)}}
        return JSONResponse(status_code=exc.status_code, content=body)

    return app


@pytest.fixture
def client(app):
    return TestClient(app)


@pytest.fixture
def override_provider(app):
    """Call with a StaticReportDataProvider (or any ReportDataProvider) to
    override the router's dependency for one test."""
    def _set(provider):
        app.dependency_overrides[get_report_provider] = lambda: provider
        return provider
    yield _set
    app.dependency_overrides.pop(get_report_provider, None)
