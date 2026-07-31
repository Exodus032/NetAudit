"""FastAPI app factory + uvicorn entrypoint. `python -m netaudit.server`
starts the service on 127.0.0.1:8787 per API_CONTRACT.md."""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import config, ws
from .api import capture, connections, devices, health, interfaces, recommendations, stats, traffic
from .pipeline import Pipeline
from .store import db as dbmod


def create_app(db_path=None, autostart_capture: bool = True) -> FastAPI:
    db_path = db_path or config.DB_PATH

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        config.ensure_db_dir() if db_path == config.DB_PATH else db_path.parent.mkdir(parents=True, exist_ok=True)
        dbmod.get_conn(db_path)  # creates schema
        pipeline = app.state.pipeline
        if autostart_capture:
            pipeline.start()
            pipeline.spawn_background_tasks()
        yield
        await pipeline.shutdown()

    app = FastAPI(title="NetAudit", version=config.VERSION, lifespan=lifespan)
    app.state.db_path = db_path
    app.state.pipeline = Pipeline(db_path=db_path)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=config.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    for router in (
        health.router, interfaces.router, stats.router, connections.router,
        traffic.router, devices.router, recommendations.router, capture.router,
    ):
        app.include_router(router)
    app.include_router(ws.router)

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException):
        detail = exc.detail
        if isinstance(detail, dict) and "error" in detail:
            body = detail
        else:
            body = {"error": {"code": _code_for_status(exc.status_code), "message": str(detail)}}
        return JSONResponse(status_code=exc.status_code, content=body)

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        return JSONResponse(
            status_code=422,
            content={"error": {"code": "validation_error", "message": str(exc)}},
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception):
        return JSONResponse(
            status_code=500,
            content={"error": {"code": "internal_error", "message": str(exc)}},
        )

    if config.FRONTEND_DIST.exists():
        app.mount("/", StaticFiles(directory=str(config.FRONTEND_DIST), html=True), name="frontend")

    return app


def _code_for_status(status_code: int) -> str:
    return {
        400: "bad_request", 404: "not_found", 405: "method_not_allowed",
        422: "validation_error", 500: "internal_error",
    }.get(status_code, "error")


app = create_app()


def main() -> None:
    import uvicorn
    uvicorn.run(app, host=config.HOST, port=config.PORT, log_level="info")


if __name__ == "__main__":
    main()
