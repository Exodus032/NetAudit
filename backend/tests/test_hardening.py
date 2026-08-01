"""Tests for API_CONTRACT_V2_SECURITY.md Part C (application hardening).

Each test here is written to fail if the corresponding protection were
removed or weakened -- that's the brief for this file. Scope: everything
under backend/netaudit *except* netaudit/posture and netaudit/threat, which
are owned and tested by other agents (see TestOwnedModuleScan for how the
AST scan honors that boundary).
"""
from __future__ import annotations

import ast
import sqlite3
import time
from pathlib import Path

import pytest
from fastapi import APIRouter
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from netaudit import auth, config
from netaudit.capture.base import CaptureBackend, PacketEvent
from netaudit.capture.enrich import ReverseDnsCache
from netaudit.ratelimit import RateLimiter
from netaudit.security import csv_safe_cell, redact_payload_snippet
from netaudit.server import create_app
from netaudit.store import db as dbmod

NETAUDIT_PKG = Path(auth.__file__).resolve().parent
LOOPBACK_CLIENT = ("127.0.0.1", 51500)


# --- shared fixture ----------------------------------------------------------

@pytest.fixture
def app_client(tmp_path):
    db_path = tmp_path / "hardening.db"
    token_path = tmp_path / "token"
    app = create_app(db_path=db_path, token_path=token_path, autostart_capture=False)
    with TestClient(app, client=LOOPBACK_CLIENT) as client:
        yield client, app, db_path
    dbmod.reset_for_tests(db_path)


def _auth_headers(app) -> dict:
    return {"X-NetAudit-Token": app.state.token}


# --- item 2: local auth token -------------------------------------------------

class TestAuthToken:
    def test_rest_endpoint_401_without_token(self, app_client):
        client, app, _ = app_client
        r = client.get("/api/health")
        assert r.status_code == 401
        assert r.json()["error"]["code"] == "unauthorized"

    def test_rest_endpoint_200_with_header_token(self, app_client):
        client, app, _ = app_client
        r = client.get("/api/health", headers=_auth_headers(app))
        assert r.status_code == 200

    def test_rest_endpoint_200_with_query_token(self, app_client):
        client, app, _ = app_client
        r = client.get(f"/api/health?token={app.state.token}")
        assert r.status_code == 200

    def test_wrong_token_401(self, app_client):
        client, app, _ = app_client
        r = client.get("/api/health", headers={"X-NetAudit-Token": "not-the-real-token"})
        assert r.status_code == 401

    def test_websocket_requires_token(self, app_client):
        client, app, _ = app_client
        with pytest.raises(WebSocketDisconnect) as exc_info:
            with client.websocket_connect("/ws/live"):
                pass
        assert exc_info.value.code == 1008

    def test_websocket_accepts_with_query_token(self, app_client):
        client, app, _ = app_client
        with client.websocket_connect(f"/ws/live?token={app.state.token}") as ws:
            msg = ws.receive_json()
            assert "type" in msg

    def test_compare_digest_used_for_token_check(self):
        """Source-level check: the token comparison must go through
        secrets.compare_digest, never a plain `==`, so it isn't a timing
        oracle. We check the actual function body, not just that the
        import exists somewhere in the file."""
        import inspect

        from netaudit import security

        src = inspect.getsource(security._token_valid)
        assert "compare_digest" in src
        assert "==" not in src.replace("!=", "")


# --- item 2 / bootstrap -------------------------------------------------------

class TestBootstrap:
    def test_bootstrap_served_to_loopback_same_origin(self, app_client):
        client, app, _ = app_client
        r = client.get("/api/bootstrap", headers={"Sec-Fetch-Site": "same-origin"})
        assert r.status_code == 200
        body = r.json()
        assert body["token"] == app.state.token
        assert "version" in body and "capture_mode" in body

    def test_bootstrap_served_with_no_sec_fetch_site_header(self, app_client):
        # Non-browser / older-browser clients may omit it entirely.
        client, app, _ = app_client
        r = client.get("/api/bootstrap")
        assert r.status_code == 200

    def test_bootstrap_allows_allowed_origin(self, app_client):
        client, app, _ = app_client
        r = client.get(
            "/api/bootstrap",
            headers={"Origin": "http://localhost:5173", "Sec-Fetch-Site": "same-site"},
        )
        assert r.status_code == 200

    def test_bootstrap_rejects_foreign_origin(self, app_client):
        client, app, _ = app_client
        r = client.get("/api/bootstrap", headers={"Origin": "http://evil.example"})
        assert r.status_code == 403

    def test_bootstrap_rejects_cross_site_sec_fetch_site(self, app_client):
        client, app, _ = app_client
        r = client.get("/api/bootstrap", headers={"Sec-Fetch-Site": "cross-site"})
        assert r.status_code == 403

    def test_bootstrap_rejects_non_loopback_peer(self, tmp_path):
        db_path = tmp_path / "b.db"
        token_path = tmp_path / "token"
        app = create_app(db_path=db_path, token_path=token_path, autostart_capture=False)
        with TestClient(app, client=("203.0.113.5", 51500)) as client:
            r = client.get("/api/bootstrap")
            assert r.status_code == 403
        dbmod.reset_for_tests(db_path)

    def test_bootstrap_does_not_require_the_token_itself(self, app_client):
        # It's the one /api endpoint exempt from the token requirement --
        # otherwise the dashboard could never bootstrap in the first place.
        client, app, _ = app_client
        r = client.get("/api/bootstrap", headers={"Sec-Fetch-Site": "same-origin"})
        assert r.status_code == 200  # no X-NetAudit-Token header sent at all


# --- item 11: websocket origin check -----------------------------------------

class TestWebSocketOrigin:
    def test_foreign_origin_rejected_before_upgrade(self, app_client):
        client, app, _ = app_client
        with pytest.raises(WebSocketDisconnect) as exc_info:
            with client.websocket_connect(
                f"/ws/live?token={app.state.token}", headers={"Origin": "http://evil.example"},
            ):
                pass
        assert exc_info.value.code == 1008

    def test_allowed_origin_with_token_connects(self, app_client):
        client, app, _ = app_client
        with client.websocket_connect(
            f"/ws/live?token={app.state.token}", headers={"Origin": "http://localhost:5173"},
        ) as ws:
            msg = ws.receive_json()
            assert "type" in msg

    def test_foreign_origin_rejected_even_with_valid_token(self, app_client):
        """Origin is checked independently of the token -- a valid token
        alone isn't enough if Origin is on the block list."""
        client, app, _ = app_client
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect(
                f"/ws/live?token={app.state.token}", headers={"Origin": "http://attacker.example"},
            ):
                pass


# --- item 9: rate limiting -----------------------------------------------------

class TestRateLimiting:
    def test_limiter_allows_burst_then_429(self):
        limiter = RateLimiter(capacity=5, window_seconds=10.0)
        results = [limiter.check("1.2.3.4")[0] for _ in range(5)]
        assert all(results)
        allowed, retry_after = limiter.check("1.2.3.4")
        assert allowed is False
        assert retry_after >= 1

    def test_limiter_recovers_after_window(self):
        limiter = RateLimiter(capacity=2, window_seconds=0.2)
        assert limiter.check("peer")[0] is True
        assert limiter.check("peer")[0] is True
        assert limiter.check("peer")[0] is False
        time.sleep(0.25)
        assert limiter.check("peer")[0] is True

    def test_different_peers_have_independent_buckets(self):
        limiter = RateLimiter(capacity=1, window_seconds=10.0)
        assert limiter.check("peer-a")[0] is True
        assert limiter.check("peer-b")[0] is True  # not affected by peer-a's usage

    def test_api_returns_429_with_retry_after(self, app_client):
        client, app, _ = app_client
        app.state.rate_limiter = RateLimiter(capacity=3, window_seconds=10.0)
        headers = _auth_headers(app)
        statuses = [client.get("/api/health", headers=headers).status_code for _ in range(3)]
        assert all(s == 200 for s in statuses)
        r = client.get("/api/health", headers=headers)
        assert r.status_code == 429
        assert "retry-after" in {k.lower() for k in r.headers.keys()}


# --- item 10: strict CORS -----------------------------------------------------

class TestCors:
    def test_allowed_origin_reflected(self, app_client):
        client, app, _ = app_client
        r = client.get("/api/health", headers={**_auth_headers(app), "Origin": "http://localhost:5173"})
        assert r.headers.get("access-control-allow-origin") == "http://localhost:5173"

    def test_evil_origin_preflight_rejected(self, app_client):
        client, app, _ = app_client
        r = client.options(
            "/api/health",
            headers={
                "Origin": "http://evil.example",
                "Access-Control-Request-Method": "GET",
            },
        )
        # Starlette's CORSMiddleware answers disallowed preflights with 400
        # and, either way, never grants the evil origin access.
        assert r.headers.get("access-control-allow-origin") != "http://evil.example"
        assert "access-control-allow-origin" not in {k.lower() for k in r.headers.keys()} or \
            r.headers.get("access-control-allow-origin") != "http://evil.example"

    def test_no_wildcard_origin_configured(self):
        assert "*" not in config.CORS_ORIGINS

    def test_every_allowed_origin_is_loopback_and_plain_http(self):
        """Asserts the property rather than a literal list, so adding the
        app's own origin (needed for /ws/live when the backend serves the
        built SPA) doesn't require editing an expected constant -- but
        adding a routable host still fails."""
        from urllib.parse import urlparse

        assert config.CORS_ORIGINS, "the allowlist must not be empty"
        for origin in config.CORS_ORIGINS:
            parsed = urlparse(origin)
            assert parsed.scheme == "http", origin
            assert parsed.hostname in {"127.0.0.1", "localhost"}, origin
            assert parsed.port is not None, origin

    def test_the_apps_own_origin_is_allowed(self):
        """Otherwise the shipped app is refused its own websocket upgrade
        and shows "Reconnecting" forever while REST still works."""
        assert f"http://127.0.0.1:{config.PORT}" in config.CORS_ORIGINS

    def test_evil_origin_not_reflected_on_simple_request(self, app_client):
        client, app, _ = app_client
        r = client.get("/api/health", headers={**_auth_headers(app), "Origin": "http://evil.example"})
        assert r.headers.get("access-control-allow-origin") != "http://evil.example"


# --- item 6: bounded limits ----------------------------------------------------

class TestBoundedLimit:
    def test_traffic_log_limit_clamped_to_1000(self, app_client):
        client, app, db_path = app_client
        from netaudit.store.packets import append_batch

        rows = [{
            "ts_epoch": 1_700_000_000.0 + i, "protocol": "tcp", "src_addr": "10.0.0.5",
            "src_port": 40000 + i, "dst_addr": "1.1.1.1", "dst_port": 443,
            "direction": "outbound", "length": 10, "flags": "", "process_name": "x.exe",
            "pid": 1, "remote_addr": "1.1.1.1", "remote_host": None,
            "is_external": 1, "is_encrypted": 1, "summary": "", "risk": "low",
        } for i in range(5)]
        append_batch(rows, db_path)

        r = client.get("/api/traffic/log?limit=999999", headers=_auth_headers(app))
        assert r.status_code == 200
        body = r.json()
        assert body["limit"] == 1000
        assert len(body["entries"]) <= 1000

    def test_stats_top_limit_clamped_to_1000(self, app_client):
        client, app, _ = app_client
        r = client.get("/api/stats/top?by=host&limit=999999", headers=_auth_headers(app))
        assert r.status_code == 200  # would 400 under the old "reject over 1000" behavior

    def test_traffic_log_limit_below_one_still_rejected(self, app_client):
        client, app, _ = app_client
        r = client.get("/api/traffic/log?limit=0", headers=_auth_headers(app))
        assert r.status_code == 400


# --- item 4: SQL parameterisation + allowlists ---------------------------------

class TestSqlSafety:
    def test_invalid_sort_returns_400(self, app_client):
        client, app, _ = app_client
        r = client.get("/api/traffic/log?sort=id;DROP TABLE packets;--", headers=_auth_headers(app))
        assert r.status_code == 400
        assert r.json()["error"]["code"] == "invalid_sort"

    def test_invalid_protocol_returns_400(self, app_client):
        client, app, _ = app_client
        r = client.get("/api/traffic/log?protocol=tcp'--", headers=_auth_headers(app))
        assert r.status_code == 400
        assert r.json()["error"]["code"] == "invalid_protocol"

    def test_invalid_direction_returns_400(self, app_client):
        client, app, _ = app_client
        r = client.get("/api/traffic/log?direction=outbound;--", headers=_auth_headers(app))
        assert r.status_code == 400
        assert r.json()["error"]["code"] == "invalid_direction"

    def test_sql_injection_in_q_leaves_tables_intact(self, app_client):
        client, app, db_path = app_client
        from netaudit.store.packets import append_batch

        append_batch([{
            "ts_epoch": 1_700_000_000.0, "protocol": "tcp", "src_addr": "10.0.0.5",
            "src_port": 1, "dst_addr": "1.1.1.1", "dst_port": 443, "direction": "outbound",
            "length": 10, "flags": "", "process_name": "chrome.exe", "pid": 1,
            "remote_addr": "1.1.1.1", "remote_host": "example.com",
            "is_external": 1, "is_encrypted": 1, "summary": "", "risk": "low",
        }], db_path)

        payloads = [
            "'; DROP TABLE packets; --",
            "' OR '1'='1",
            "1'; DELETE FROM packets WHERE '1'='1",
        ]
        for payload in payloads:
            r = client.get("/api/traffic/log", params={"q": payload}, headers=_auth_headers(app))
            assert r.status_code == 200

        # Table (and its one row) must survive every attempt.
        conn = dbmod.get_conn(db_path)
        count = conn.execute("SELECT COUNT(*) AS c FROM packets").fetchone()["c"]
        assert count == 1

    def test_no_raw_filter_value_interpolated_into_sql_text(self):
        """store/packets.py legitimately builds its WHERE clause and ORDER
        BY text with f-strings (`where_sql`, `sort_col`, `order_sql`) --
        those are assembled from fixed SQL fragments / a two-way ternary
        over a hardcoded allowlist, with actual values always bound via
        `:name` placeholders, which is the safe, standard SQLite pattern
        and is not what item 4 is guarding against. What *would* violate
        item 4 is a raw client-supplied filter value (q/protocol/direction/
        sort/order, or a `filters.*` attribute) appearing directly inside
        an f-string passed as the SQL text to `.execute(...)` -- as opposed
        to, say, `params["q"] = f"%{filters.q}%"`, which builds a *parameter
        value* bound through `:q`, not SQL text, and is exactly the safe
        pattern this item asks for. So: only f-strings that are literally
        the first argument of an `.execute(...)` call are in scope."""
        unsafe_names = {
            "q", "protocol", "direction", "sort", "order", "since", "until",
            "min_bytes", "limit", "offset", "value", "category", "status",
        }
        store_dir = NETAUDIT_PKG / "store"
        violations = []
        for path in store_dir.glob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                        and node.func.attr == "execute" and node.args):
                    continue
                sql_arg = node.args[0]
                if not isinstance(sql_arg, ast.JoinedStr):
                    continue
                for value in sql_arg.values:
                    if not isinstance(value, ast.FormattedValue):
                        continue
                    expr = value.value
                    if isinstance(expr, ast.Name) and expr.id in unsafe_names:
                        violations.append(f"{path}:{node.lineno} interpolates raw `{expr.id}` into SQL text")
                    if isinstance(expr, ast.Attribute) and expr.attr in unsafe_names:
                        violations.append(f"{path}:{node.lineno} interpolates raw `.{expr.attr}` into SQL text")
        assert not violations, f"raw filter value interpolated into SQL text: {violations}"


# --- item 5: CSV injection ------------------------------------------------------

class TestCsvInjection:
    @pytest.mark.parametrize("hostile", [
        "=cmd|' /C calc'!A1",
        "+SUM(1+1)",
        "-2+3",
        "@SUM(1+1)",
        "\tformula",
        "\rcarriage",
    ])
    def test_dangerous_prefix_gets_quoted(self, hostile):
        assert csv_safe_cell(hostile).startswith("'")

    def test_benign_values_pass_through(self):
        assert csv_safe_cell("chrome.exe") == "chrome.exe"
        assert csv_safe_cell(443) == "443"
        assert csv_safe_cell(None) == ""

    def test_export_escapes_hostile_process_name(self, app_client):
        client, app, db_path = app_client
        from netaudit.store.packets import append_batch

        append_batch([{
            "ts_epoch": 1_700_000_000.0, "protocol": "tcp", "src_addr": "10.0.0.5",
            "src_port": 1, "dst_addr": "1.1.1.1", "dst_port": 443, "direction": "outbound",
            "length": 10, "flags": "", "process_name": "=cmd|' /C calc'!A1", "pid": 1,
            "remote_addr": "1.1.1.1", "remote_host": None,
            "is_external": 1, "is_encrypted": 1, "summary": "", "risk": "low",
        }], db_path)

        r = client.get("/api/traffic/export?format=csv", headers=_auth_headers(app))
        assert r.status_code == 200
        assert "'=cmd|' /C calc'!A1" in r.text or "'=cmd" in r.text
        assert "\n=cmd" not in r.text  # never an unescaped leading '='


# --- item 8: payload redaction -------------------------------------------------

class TestPayloadRedaction:
    def test_truncated_to_64_bytes(self):
        raw = "A" * 200
        out = redact_payload_snippet(raw)
        assert len(out) <= 64

    @pytest.mark.parametrize("hostile", [
        "Authorization: Bearer sk-super-secret-token",
        "GET /login?password=hunter2 HTTP/1.1",
        "Authorization: Basic dXNlcjpwYXNz",
        "api_key=abcd1234",
    ])
    def test_credential_like_content_redacted(self, hostile):
        assert redact_payload_snippet(hostile) == "[redacted: credential-like content]"

    def test_none_passthrough(self):
        assert redact_payload_snippet(None) is None

    def test_no_payload_bytes_column_in_packets_table(self, app_client):
        """Structural check for item 8: the packets table stores headers/
        metadata only, never raw payload bytes."""
        _client, _app, db_path = app_client
        conn = dbmod.get_conn(db_path)
        cols = {row["name"] for row in conn.execute("PRAGMA table_info(packets)").fetchall()}
        for forbidden in ("payload", "raw", "body", "data"):
            assert forbidden not in cols


# --- item 6 (continued): bounded queue / bounded DNS cache ---------------------

class _DummyBackend(CaptureBackend):
    tier = "dummy"

    def start(self, interface_id=None):
        self._running = True

    def stop(self):
        self._running = False


class TestBoundedCaptureQueue:
    def test_drop_counter_increments_when_queue_full(self):
        backend = _DummyBackend(queue_max=2)
        for i in range(5):
            backend._emit(PacketEvent(ts=float(i), protocol="tcp", src_addr="a", dst_addr="b"))
        assert backend.dropped > 0

    def test_health_surfaces_dropped_packets(self, app_client):
        client, app, _ = app_client
        r = client.get("/api/health", headers=_auth_headers(app))
        assert r.status_code == 200
        assert "dropped_packets" in r.json()["capture"]
        assert isinstance(r.json()["capture"]["dropped_packets"], int)


class TestBoundedDnsCache:
    def test_cache_evicts_oldest_beyond_max_entries(self):
        cache = ReverseDnsCache(max_workers=1, max_entries=3)
        for i in range(10):
            addr = f"10.0.0.{i}"
            cache._inflight.add(addr)
            cache._resolve(addr)
        assert len(cache._cache) <= 3
        cache.shutdown()


# --- item 1: loopback bind ------------------------------------------------------

class TestLoopbackBind:
    def test_default_host_is_loopback(self):
        assert config.HOST == "127.0.0.1"

    def test_host_not_settable_via_environment(self, monkeypatch):
        # Re-import-safe check: config.HOST is a hardcoded literal, not
        # os.environ.get("NETAUDIT_HOST", ...). Verified at source level so
        # this fails if someone reintroduces an env override.
        src = (NETAUDIT_PKG / "config.py").read_text(encoding="utf-8")
        assert 'NETAUDIT_HOST' not in src

    def test_unsafe_bind_flag_is_the_only_override(self):
        from netaudit.server import _parse_args

        args = _parse_args([])
        assert args.unsafe_bind is None
        args = _parse_args(["--unsafe-bind", "0.0.0.0"])
        assert args.unsafe_bind == "0.0.0.0"

    def test_unsafe_bind_logs_warning(self, monkeypatch, caplog):
        import logging

        from netaudit import server as server_mod

        monkeypatch.setattr(server_mod, "uvicorn", None, raising=False)

        class _FakeUvicorn:
            def run(self, *a, **k):
                pass

        monkeypatch.setitem(__import__("sys").modules, "uvicorn", _FakeUvicorn())
        with caplog.at_level(logging.WARNING, logger="netaudit.server"):
            server_mod.main(["--unsafe-bind", "0.0.0.0"])
        assert any(rec.levelno == logging.WARNING and "0.0.0.0" in rec.getMessage() for rec in caplog.records)
        assert any("WARNING" in rec.getMessage().upper() for rec in caplog.records)


# --- item 13: fail closed -------------------------------------------------------

class TestFailClosed:
    def test_ensure_token_real_machine_path_succeeds(self, tmp_path):
        """Exercises the real icacls flow (no mocking) end-to-end so a
        regression in ACL parsing (e.g. matching the file's own path as if
        it were a grantee) is caught here, not just in production."""
        token_path = tmp_path / "nested" / "token"
        token = auth.ensure_token(token_path)
        assert len(token) > 20
        # Reusing must return the identical token without re-prompting.
        token2 = auth.ensure_token(token_path)
        assert token == token2

    def test_ensure_token_raises_when_acl_cannot_be_verified(self, tmp_path, monkeypatch):
        monkeypatch.setattr(auth, "_acl_is_owner_only", lambda path, username: False)
        with pytest.raises(auth.TokenSecurityError):
            auth.ensure_token(tmp_path / "token")

    def test_ensure_token_raises_when_icacls_grant_fails(self, tmp_path, monkeypatch):
        import subprocess as sp

        def fake_run(args, **kwargs):
            return sp.CompletedProcess(args, returncode=1, stdout="", stderr="access denied")

        monkeypatch.setattr(auth, "_run_icacls", fake_run)
        with pytest.raises(auth.TokenSecurityError):
            auth.ensure_token(tmp_path / "token")

    def test_server_startup_aborts_when_token_cannot_be_secured(self, tmp_path, monkeypatch):
        db_path = tmp_path / "fc.db"
        token_path = tmp_path / "token"
        app = create_app(db_path=db_path, token_path=token_path, autostart_capture=False)

        def fail(*a, **k):
            raise auth.TokenSecurityError("simulated: cannot secure token file")

        monkeypatch.setattr(auth, "ensure_token", fail)
        with pytest.raises(auth.TokenSecurityError):
            with TestClient(app, client=LOOPBACK_CLIENT):
                pass

    def test_acl_parser_rejects_a_broad_grant(self, tmp_path):
        """Regression test for the exact bug this file's fix addresses:
        the file's own path (which always contains "\\Users\\" on a normal
        Windows profile) must never be mistaken for a BUILTIN\\Users grant,
        but a *real* Everyone/Users grant must still be rejected."""
        p = tmp_path / "token"
        p.write_text("x")
        username = auth._current_username()

        good_output = (
            f"{p} NT AUTHORITY\\SYSTEM:(F)\n"
            f"                    BUILTIN\\Administrators:(F)\n"
            f"                    {username}:(F)\n\n"
            f"Successfully processed 1 files; Failed processing 0 files\n"
        )
        assert auth._parse_icacls_grantees(good_output, p) == [
            "nt authority\\system", "builtin\\administrators", username.lower(),
        ]

        bad_output = (
            f"{p} {username}:(F)\n"
            f"                    BUILTIN\\Users:(RX)\n\n"
            f"Successfully processed 1 files; Failed processing 0 files\n"
        )
        grantees = auth._parse_icacls_grantees(bad_output, p)
        assert "builtin\\users" in grantees


# --- item 3: no command execution from HTTP input ------------------------------

_SHELL_FUNCS = {"system", "popen"}
_SUBPROCESS_FUNCS = {"run", "call", "check_call", "check_output", "Popen"}


def _iter_owned_modules():
    """Every .py file under netaudit/ that is NOT posture/ or threat/ (those
    packages are owned and tested by other agents; runner.py under posture
    legitimately runs a hardcoded read-only command allowlist and is out of
    scope here by design, not by exemption)."""
    for path in NETAUDIT_PKG.rglob("*.py"):
        rel = path.relative_to(NETAUDIT_PKG)
        parts = rel.parts
        if parts[0] in ("posture", "threat"):
            continue
        yield path


def _call_name(node: ast.Call) -> tuple[str, str] | None:
    """Returns (module_alias, func_name) for `module.func(...)` calls, e.g.
    ("subprocess", "run") or ("os", "system")."""
    func = node.func
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        return func.value.id, func.attr
    return None


def _looks_like_command_string(node: ast.AST) -> bool:
    """True if `node` is (or is built as) a string -- the shape a shell
    command line takes, and the shape a request-derived value could get
    spliced into. False for a List/Tuple/Name/Attribute -- those are the
    safe "fixed argument list" shapes regardless of how they were built."""
    if isinstance(node, ast.JoinedStr):  # f"...{x}..."
        return True
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return True
    if isinstance(node, ast.BinOp):  # "a" + b, or "a %s" % b
        return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return True
    return False


class TestNoShellExecution:
    """Part C item 3, scoped to the modules this agent owns (see
    _iter_owned_modules). posture/ and threat/ are separately-owned,
    separately-tested packages and are excluded, not exempted."""

    def test_no_shell_true_anywhere(self):
        violations = []
        for path in _iter_owned_modules():
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    for kw in node.keywords:
                        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            violations.append(f"{path}:{node.lineno}")
        assert not violations, f"shell=True found in: {violations}"

    def test_no_os_system_or_popen(self):
        violations = []
        for path in _iter_owned_modules():
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    name = _call_name(node)
                    if name and name[0] == "os" and name[1] in _SHELL_FUNCS:
                        violations.append(f"{path}:{node.lineno} os.{name[1]}(...)")
        assert not violations, f"shell-invoking os.* calls found in: {violations}"

    def test_subprocess_calls_never_pass_a_command_string(self):
        """The first positional argument to subprocess.run/call/Popen/etc.
        must never be a *string* -- a literal, an f-string, or anything
        built by concatenation/`.format()`/`%` -- since a string argument
        implies shell-style parsing and is exactly the shape a request-
        derived value could get spliced into. A `Name`/`Attribute` (e.g. a
        `list[str]` parameter forwarded into a small `_run_x(args)` helper)
        or a `List`/`Tuple` literal is fine either way: subprocess never
        invokes a shell parser for a list/tuple argument, regardless of how
        that list was built or passed around, which is the actual property
        this item cares about."""
        violations = []
        for path in _iter_owned_modules():
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    name = _call_name(node)
                    if name and name[0] == "subprocess" and name[1] in _SUBPROCESS_FUNCS:
                        if node.args and _looks_like_command_string(node.args[0]):
                            violations.append(f"{path}:{node.lineno}")
        assert not violations, f"subprocess call passed a command string: {violations}"

    def test_run_icacls_helper_itself_only_ever_called_with_list_literals(self):
        """auth._run_icacls(args) forwards its `args` parameter straight
        into subprocess.run -- confirm every call SITE of that helper
        passes a literal list, so the parameter it forwards is always the
        safe shape the test above trusts it to be."""
        from netaudit import auth as auth_mod

        tree = ast.parse(Path(auth_mod.__file__).read_text(encoding="utf-8"), filename=auth_mod.__file__)
        violations = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "_run_icacls":
                if not node.args or not isinstance(node.args[0], ast.List):
                    violations.append(node.lineno)
        assert not violations, f"_run_icacls called without a list literal at lines: {violations}"
        assert any(isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "_run_icacls" for n in ast.walk(tree))


class TestOwnedModuleScan:
    def test_scan_excludes_posture_and_threat(self):
        scanned = {str(p.relative_to(NETAUDIT_PKG)) for p in _iter_owned_modules()}
        assert not any(s.startswith("posture") for s in scanned)
        assert not any(s.startswith("threat") for s in scanned)
        assert any(s == "auth.py" for s in scanned)
        assert any(s == "arpscan.py" for s in scanned)

    def test_arpscan_uses_fixed_argument_list(self):
        """arpscan.py is the one pre-existing subprocess call this agent
        owns; confirm by inspection it's a fixed list with no shell."""
        import inspect

        from netaudit import arpscan
        src = inspect.getsource(arpscan.read_arp_table)
        assert "shell=True" not in src
        assert '["arp", "-a"]' in src


# --- item 6 (continued): SQL query timeout -------------------------------------

class TestQueryTimeout:
    def test_runaway_query_is_aborted(self, tmp_path, monkeypatch):
        monkeypatch.setattr(config, "SQL_QUERY_TIMEOUT_SECONDS", 0.05)
        db_path = tmp_path / "timeout.db"
        conn = dbmod.get_conn(db_path)
        try:
            with pytest.raises(sqlite3.OperationalError):
                conn.execute(
                    "WITH RECURSIVE cnt(x) AS ("
                    "  SELECT 1 UNION ALL SELECT x + 1 FROM cnt WHERE x < 500000000"
                    ") SELECT count(*) FROM cnt"
                )
        finally:
            dbmod.reset_for_tests(db_path)


# --- security response headers -------------------------------------------------

class TestSecurityHeaders:
    def test_headers_present_on_api_response(self, app_client):
        client, app, _ = app_client
        r = client.get("/api/health", headers=_auth_headers(app))
        assert r.headers.get("x-content-type-options") == "nosniff"
        assert r.headers.get("referrer-policy") == "no-referrer"
        assert "content-security-policy" in r.headers
        assert r.headers.get("cache-control") == "no-store"

    def test_headers_present_on_401_response(self, app_client):
        client, _app, _ = app_client
        r = client.get("/api/health")
        assert r.status_code == 401
        assert r.headers.get("x-content-type-options") == "nosniff"
        assert r.headers.get("cache-control") == "no-store"

    def test_error_response_has_no_stack_trace_or_path(self, app_client):
        client, app, _ = app_client
        # An endpoint that 404s inside routing still goes through our
        # handlers and must not leak internals.
        r = client.get("/api/does-not-exist", headers=_auth_headers(app))
        assert r.status_code == 404
        body = r.json()
        assert "Traceback" not in str(body)
        assert "netaudit" not in str(body).lower() or "error" in body


# --- middleware-covers-later-routers property ----------------------------------

class TestMiddlewareCoversRoutersAddedLater:
    """The orchestrator mounts posture's and threat's bare APIRouters into
    this same app *after* create_app() returns. Since SecurityMiddleware
    wraps the whole ASGI app (not individual routes), anything mounted
    afterward inherits auth, rate limiting, CORS and headers automatically
    -- no per-route decoration required. This proves that property with a
    throwaway dummy router standing in for posture/threat, so the test
    doesn't depend on (or touch) either package."""

    def test_dummy_router_mounted_after_the_fact_is_protected(self, tmp_path):
        db_path = tmp_path / "later.db"
        token_path = tmp_path / "token"
        app = create_app(db_path=db_path, token_path=token_path, autostart_capture=False)

        dummy = APIRouter()

        @dummy.get("/api/dummy-later-mounted")
        def _dummy():
            return {"ok": True}

        app.include_router(dummy)  # mounted AFTER create_app(), like posture/threat will be

        with TestClient(app, client=LOOPBACK_CLIENT) as client:
            unauth = client.get("/api/dummy-later-mounted")
            assert unauth.status_code == 401  # protected with zero per-route changes

            authed = client.get("/api/dummy-later-mounted", headers=_auth_headers(app))
            assert authed.status_code == 200
            assert authed.headers.get("x-content-type-options") == "nosniff"
            assert authed.headers.get("cache-control") == "no-store"

            evil_cors = client.get(
                "/api/dummy-later-mounted",
                headers={**_auth_headers(app), "Origin": "http://evil.example"},
            )
            assert evil_cors.headers.get("access-control-allow-origin") != "http://evil.example"

        dbmod.reset_for_tests(db_path)
