"""FastAPI app factory + uvicorn entrypoint. `python -m netaudit.server`
starts the service on 127.0.0.1:8787 per API_CONTRACT.md, hardened per
API_CONTRACT_V2_SECURITY.md Part C."""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import auth, config, ws
from .api import bootstrap, capture, connections, devices, health, interfaces, recommendations, stats, traffic
from .pipeline import Pipeline
from .ratelimit import RateLimiter
from .security import SecurityMiddleware
from .store import db as dbmod

logger = logging.getLogger("netaudit.server")


def create_app(
    db_path=None,
    token_path=None,
    autostart_capture: bool = True,
    wire_security_packages: bool = True,
) -> FastAPI:
    db_path = db_path or config.DB_PATH
    token_path = token_path or config.TOKEN_PATH

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        config.ensure_db_dir() if db_path == config.DB_PATH else db_path.parent.mkdir(parents=True, exist_ok=True)
        dbmod.get_conn(db_path)  # creates schema; raises (fails closed) if unopenable

        # Part C item 2 + 13: generate/verify the local auth token *before*
        # anything else starts. If this can't be secured, let the exception
        # propagate -- FastAPI/uvicorn will abort startup rather than serve
        # unauthenticated.
        app.state.token = auth.ensure_token(token_path)
        app.state.token_path = token_path

        monitor = getattr(app.state, "baseline_monitor", None)
        if monitor is not None:
            monitor.start()

        pipeline = app.state.pipeline
        if autostart_capture:
            pipeline.start()
            pipeline.spawn_background_tasks()
        yield
        if monitor is not None:
            await monitor.shutdown()
        await pipeline.shutdown()
        for attr in ("threat_scheduler", "arp_observer"):
            component = getattr(app.state, attr, None)
            if component is not None:
                component.stop()

    app = FastAPI(title="NetAudit", version=config.VERSION, lifespan=lifespan)
    app.state.db_path = db_path
    app.state.pipeline = Pipeline(db_path=db_path)
    app.state.rate_limiter = RateLimiter(
        capacity=config.RATE_LIMIT_CAPACITY, window_seconds=config.RATE_LIMIT_WINDOW_SECONDS,
    )
    # token is set during lifespan startup; None until then so any request
    # arriving before startup completes is refused rather than let through.
    app.state.token = None

    # Mounted in this order so that, on the way in, a request hits
    # CORSMiddleware first (it can fully answer a preflight OPTIONS itself)
    # and SecurityMiddleware second. Starlette applies the *last*-added
    # middleware outermost, so CORS is added last here.
    app.add_middleware(SecurityMiddleware)
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
        bootstrap.router,
    ):
        app.include_router(router)
    app.include_router(ws.router)

    if wire_security_packages:
        # Mounts the posture and threat routers and gives them live
        # dependencies. Kept out of create_app itself so the two packages
        # stay independently testable, and so a test can build a bare v1 app
        # without spinning up an ARP poller. Deliberately after the v1
        # routers and after the middleware, so these inherit auth, rate
        # limiting, CORS and security headers with no per-route work.
        from .integration import wire_security

        wire_security(app, db_path=db_path, start_background=autostart_capture)

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
        # Full details go to the local log only. The client gets a generic
        # message -- never a stack trace or filesystem path (Part C, tail
        # requirement on error responses).
        logger.exception("Unhandled exception on %s %s", request.method, request.url.path)
        return JSONResponse(
            status_code=500,
            content={"error": {"code": "internal_error", "message": "An internal error occurred."}},
        )

    if config.FRONTEND_DIST.exists():
        # Deliberately NOT `app.mount("/", ...)`. A Mount is itself a route,
        # and Starlette commits to the first *full* route match in
        # registration order -- a "/" mount registered here would shadow
        # every route any router added *after* create_app() returns,
        # including posture's and threat's, which the orchestrator mounts
        # later. Assigning the static app as the router's `default` instead
        # makes it a true last-resort fallback: Starlette always checks the
        # complete current route table (whatever it is at request time)
        # first, and only serves a static file / SPA index.html if nothing
        # -- present now or added later -- matched.
        app.router.default = StaticFiles(directory=str(config.FRONTEND_DIST), html=True)

    return app


def _code_for_status(status_code: int) -> str:
    return {
        400: "bad_request", 401: "unauthorized", 403: "forbidden", 404: "not_found",
        405: "method_not_allowed", 422: "validation_error", 429: "rate_limited",
        500: "internal_error",
    }.get(status_code, "error")


app = create_app()


_UNSAFE_BIND_WARNING = """
################################################################################
# WARNING: NetAudit is binding to a non-loopback address: %s
#
# This exposes the local network auditing API -- including live traffic,
# device, and recommendation data, and the local auth token bootstrap
# endpoint's loopback check -- to every other host that can reach this
# address. Anyone on that network segment who can reach this port can read
# your traffic metadata and LAN device list.
#
# This flag exists for advanced/debugging use only. Do not use it on a
# network you do not fully trust. The default (no flag) binds 127.0.0.1
# only, which is what you want on a normal desktop.
################################################################################
""".strip("\n")


def _parse_args(argv=None):
    import argparse

    parser = argparse.ArgumentParser(prog="netaudit")
    parser.add_argument(
        "--unsafe-bind",
        metavar="HOST",
        default=None,
        help="Bind to HOST instead of 127.0.0.1. DANGEROUS -- exposes the API beyond this machine.",
    )
    parser.add_argument(
        "--allow-lan-bootstrap",
        action="store_true",
        help="Allow same-origin dashboard bootstrap requests from LAN clients. Requires --unsafe-bind.",
    )
    return parser.parse_args(argv)


def main(argv=None) -> None:
    import uvicorn

    args = _parse_args(argv)
    if args.allow_lan_bootstrap and not args.unsafe_bind:
        raise SystemExit("--allow-lan-bootstrap requires --unsafe-bind.")
    host = config.HOST
    if args.unsafe_bind:
        host = args.unsafe_bind
        logger.warning(_UNSAFE_BIND_WARNING, host)
    # Kept on app state rather than in config so the secure, loopback-only
    # default remains unchanged for imports, tests, and normal launches.
    app.state.allow_lan_bootstrap = args.allow_lan_bootstrap
    uvicorn.run(app, host=host, port=config.PORT, log_level="info")


if __name__ == "__main__":
    main()
