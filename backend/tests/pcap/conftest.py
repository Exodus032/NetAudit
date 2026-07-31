from __future__ import annotations

import importlib

import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from starlette.exceptions import HTTPException as StarletteHTTPException

from netaudit import config
from netaudit.pcap import session_store
from netaudit.store import db as dbmod

# NOTE: `netaudit/pcap/__init__.py` does `from .router import router`,
# which binds the *attribute* `netaudit.pcap.router` to the APIRouter
# instance -- shadowing the submodule of the same name (`import
# netaudit.pcap.router as x` still resolves through that same shadowed
# attribute, per the language's "roughly `x = netaudit.pcap.router`"
# semantics for `import a.b as x`). `importlib.import_module` is the one
# form that looks the module up in `sys.modules` directly, bypassing the
# shadowed attribute, so `pcap_router_module._filter_state` below reaches
# the real module.
pcap_router_module = importlib.import_module("netaudit.pcap.router")


@pytest.fixture
def isolated_dbs(tmp_path, monkeypatch):
    live_db = tmp_path / "live.db"
    sessions_db = tmp_path / "sessions.db"
    dbmod.get_conn(live_db)
    monkeypatch.setattr(config, "DB_PATH", live_db)
    monkeypatch.setattr(session_store, "DEFAULT_DB_PATH", sessions_db)
    yield {"live_db": live_db, "sessions_db": sessions_db}
    dbmod.reset_for_tests(live_db)
    session_store.reset_for_tests(sessions_db)


@pytest.fixture(autouse=True)
def reset_filter_state():
    pcap_router_module._filter_state = pcap_router_module._FilterState()
    yield


@pytest.fixture
def client(isolated_dbs):
    app = FastAPI()
    app.include_router(pcap_router_module.router)

    # Mirrors server.py's real exception handler: HTTPException(detail={
    # "error": {...}}) should surface as a top-level {"error": {...}} body,
    # not FastAPI's default {"detail": {"error": {...}}} wrapping. server.py
    # (owned by the orchestrator) registers the equivalent handler on the
    # real app; this keeps the isolated test app's behavior identical to
    # what this router will actually produce once mounted there.
    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException):
        detail = exc.detail
        if isinstance(detail, dict) and "error" in detail:
            body = detail
        else:
            body = {"error": {"code": "error", "message": str(detail)}}
        return JSONResponse(status_code=exc.status_code, content=body)

    return TestClient(app)
