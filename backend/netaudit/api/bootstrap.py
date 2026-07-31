"""GET /api/bootstrap (Part C item 2): the one `/api` endpoint the token
middleware exempts from requiring `X-NetAudit-Token`/`?token=`, because it's
what hands the dashboard its token in the first place. Everything else
about the request still has to look like it came from the dashboard itself:

- the TCP peer must be loopback,
- `Sec-Fetch-Site` (when the browser sends it) must be same-origin/same-site
  or absent entirely,
- `Origin` (when present) must be in the same allowlist CORS uses.

Any local process that can open a socket to 127.0.0.1 can satisfy all
three of these -- that's a documented residual risk, not a gap in this
check (see backend/SECURITY.md).
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from .. import config

router = APIRouter()

_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}
_OK_SEC_FETCH_SITE = {"same-origin", "same-site", "none"}


def _forbidden(message: str) -> HTTPException:
    return HTTPException(status_code=403, detail={"error": {"code": "forbidden", "message": message}})


@router.get("/api/bootstrap")
def get_bootstrap(request: Request):
    client = request.client
    peer_host = client.host if client else None
    if peer_host not in _LOOPBACK_HOSTS:
        raise _forbidden("Bootstrap is only served to loopback clients.")

    sec_fetch_site = request.headers.get("sec-fetch-site")
    if sec_fetch_site is not None and sec_fetch_site not in _OK_SEC_FETCH_SITE:
        raise _forbidden("Cross-site bootstrap requests are rejected.")

    origin = request.headers.get("origin")
    if origin is not None and origin not in config.CORS_ORIGINS:
        raise _forbidden("Origin is not in the allowlist.")

    pipeline = request.app.state.pipeline
    return {
        "token": request.app.state.token,
        "version": config.VERSION,
        "capture_mode": pipeline.mode,
    }
