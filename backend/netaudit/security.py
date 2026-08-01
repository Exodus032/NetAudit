"""App-level security hooks: the ASGI middleware that enforces auth, rate
limiting, and response headers on every `/api` and `/ws` path (Part C items
2, 9, 11), plus small stand-alone helpers used elsewhere (CSV injection
defence, item 5; payload redaction, item 8).

Deliberately implemented as a single raw ASGI middleware (not
`BaseHTTPMiddleware`, which can't see websocket scopes) mounted once in
`server.create_app`. Routers mounted later -- including `posture` and
`threat`, added by the orchestrator after this module is wired in -- pass
through this same middleware automatically because it wraps the whole ASGI
app, not any individual route. That's the property the "mount a dummy
router after the fact" test in test_hardening.py checks for.
"""
from __future__ import annotations

import secrets
import urllib.parse

from starlette.datastructures import Headers, MutableHeaders

from . import config

SECURITY_HEADERS: dict[str, str] = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self' ws://127.0.0.1:8787 ws://localhost:8787 "
        "http://127.0.0.1:8787 http://localhost:8787; "
        "frame-ancestors 'none'; "
        "base-uri 'none'"
    ),
}

_NO_STORE = "no-store"

# --- CSV injection defence (Part C item 5) ----------------------------------

_CSV_DANGEROUS_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def csv_safe_cell(value) -> str:
    """Prefix a cell with `'` if its first character could be interpreted
    as a formula by Excel/Sheets/LibreOffice when the CSV is opened there."""
    if value is None:
        return ""
    s = value if isinstance(value, str) else str(value)
    if s and s[0] in _CSV_DANGEROUS_PREFIXES:
        return "'" + s
    return s


# --- Payload redaction (Part C item 8) --------------------------------------

_CREDENTIAL_PATTERNS = (
    "authorization:",
    "authorization=",
    "basic ",
    "bearer ",
    "password=",
    "passwd=",
    "api_key=",
    "apikey=",
    "api-key:",
    "x-api-key:",
    "secret=",
    "token=",
)


def redact_payload_snippet(raw: bytes | str | None, max_bytes: int = config.PAYLOAD_SNIPPET_MAX_BYTES) -> str | None:
    """Truncate a captured payload snippet to `max_bytes` and redact it
    entirely if it looks like it carries credentials. NetAudit does not
    persist payload bytes by default (Part C item 8); this exists so that
    *if* a detector ever needs a short snippet for evidence, it can't leak
    a credential-bearing blob into the store."""
    if raw is None:
        return None
    text = raw.decode("utf-8", errors="replace") if isinstance(raw, (bytes, bytearray)) else raw
    lowered = text.lower()
    if any(p in lowered for p in _CREDENTIAL_PATTERNS):
        return "[redacted: credential-like content]"
    return text[:max_bytes]


# --- Token extraction --------------------------------------------------------

def _extract_token(headers: Headers, query_string: bytes) -> str | None:
    tok = headers.get(config.TOKEN_HEADER.lower())
    if tok:
        return tok
    if query_string:
        qs = urllib.parse.parse_qs(query_string.decode("latin-1"))
        vals = qs.get("token")
        if vals:
            return vals[0]
    return None


def _token_valid(candidate: str | None, expected: str | None) -> bool:
    if not candidate or not expected:
        return False
    return secrets.compare_digest(candidate, expected)


async def _send_json(send, status: int, body: dict, extra_headers: dict[str, str] | None = None) -> None:
    import json

    payload = json.dumps(body).encode("utf-8")
    headers = [(b"content-type", b"application/json")]
    for k, v in {**SECURITY_HEADERS, "Cache-Control": _NO_STORE, **(extra_headers or {})}.items():
        headers.append((k.encode("latin-1"), str(v).encode("latin-1")))
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": payload})


def _unauthorized_body() -> dict:
    return {"error": {"code": "unauthorized", "message": "Missing or invalid X-NetAudit-Token."}}


def _rate_limited_body() -> dict:
    return {"error": {"code": "rate_limited", "message": "Too many requests. Slow down and retry shortly."}}


class SecurityMiddleware:
    """Raw ASGI middleware enforcing, for every `/api` and `/ws` path:

    - a per-peer rate limit (item 9)
    - the local auth token via `X-NetAudit-Token` or `?token=` (item 2),
      except `GET /api/bootstrap` which applies its own loopback/origin
      check instead (see `netaudit.api.bootstrap`)
    - for websocket upgrades on `/ws*`: Origin allowlist + token, rejected
      *before* the handshake completes (item 11)
    - security response headers on everything, plus `Cache-Control: no-store`
      on `/api` responses (so the token/bootstrap response and any other API
      payload is never cached)

    Mounted once in `server.create_app`, so any router added later --
    including ones this agent must not touch -- inherits all of the above
    automatically without per-route decoration.
    """

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        app_state = scope["app"].state
        path = scope.get("path", "")

        if scope["type"] == "websocket":
            await self._handle_websocket(scope, receive, send, app_state, path)
            return

        await self._handle_http(scope, receive, send, app_state, path)

    async def _handle_http(self, scope, receive, send, app_state, path: str) -> None:
        method = scope.get("method", "GET")
        headers = Headers(scope=scope)

        # CORS preflight is handled entirely by CORSMiddleware, which we
        # mount *outside* this one (see server.create_app) so it can
        # short-circuit OPTIONS before auth/rate-limiting ever run. If one
        # slips through anyway, let it pass untouched.
        if method == "OPTIONS":
            await self.app(scope, receive, send)
            return

        protected = path.startswith("/api") or path.startswith("/ws")
        if not protected:
            await self._forward_with_headers(scope, receive, send, SECURITY_HEADERS)
            return

        client = scope.get("client")
        peer = client[0] if client else "unknown"

        limiter = getattr(app_state, "rate_limiter", None)
        if limiter is not None:
            allowed, retry_after = limiter.check(peer)
            if not allowed:
                await _send_json(send, 429, _rate_limited_body(), {"Retry-After": str(retry_after)})
                return

        is_bootstrap = path == "/api/bootstrap" and method == "GET"
        if not is_bootstrap:
            token = _extract_token(headers, scope.get("query_string", b""))
            expected = getattr(app_state, "token", None)
            if not _token_valid(token, expected):
                await _send_json(send, 401, _unauthorized_body())
                return

        extra = dict(SECURITY_HEADERS)
        if path.startswith("/api"):
            extra["Cache-Control"] = _NO_STORE
        await self._forward_with_headers(scope, receive, send, extra)

    async def _handle_websocket(self, scope, receive, send, app_state, path: str) -> None:
        if not path.startswith("/ws"):
            await self.app(scope, receive, send)
            return

        headers = Headers(scope=scope)
        client = scope.get("client")
        peer = client[0] if client else "unknown"

        limiter = getattr(app_state, "rate_limiter", None)
        if limiter is not None:
            allowed, _retry_after = limiter.check(peer)
            if not allowed:
                await send({"type": "websocket.close", "code": 1008})
                return

        origin = headers.get("origin")
        if origin is not None and origin not in config.CORS_ORIGINS:
            # In LAN sharing mode (--unsafe-bind) the dashboard is loaded
            # from http://<lan-ip>:<port>, an origin that can never be in
            # the static allowlist. Accept exactly the request's own origin
            # (Origin == http://<Host header>); foreign origins still close
            # with 1008. Default loopback-only launches never set lan_mode,
            # so their behavior is unchanged.
            lan_mode = getattr(app_state, "lan_mode", False)
            host = headers.get("host")
            if not (lan_mode and host is not None and origin == f"http://{host}"):
                await send({"type": "websocket.close", "code": 1008})
                return

        token = _extract_token(headers, scope.get("query_string", b""))
        expected = getattr(app_state, "token", None)
        if not _token_valid(token, expected):
            await send({"type": "websocket.close", "code": 1008})
            return

        await self.app(scope, receive, send)

    async def _forward_with_headers(self, scope, receive, send, extra_headers: dict[str, str]) -> None:
        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                mutable = MutableHeaders(scope=message)
                for k, v in extra_headers.items():
                    mutable.append(k, v)
            await send(message)

        await self.app(scope, receive, send_wrapper)
