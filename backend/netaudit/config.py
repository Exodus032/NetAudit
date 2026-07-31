"""Central settings for the NetAudit backend.

Kept as plain module-level constants (not pydantic-settings) so the module
has zero import-time side effects beyond reading environment variables and
computing the sqlite path -- makes it trivial to import from tests.
"""
from __future__ import annotations

import os
from pathlib import Path

VERSION = "1.0.0"

# Part C item 1: loopback-only by default. Deliberately NOT read from an
# environment variable -- the only supported way to bind anywhere else is
# the explicit `--unsafe-bind HOST` CLI flag handled in server.main(), which
# logs a loud warning when used. This makes 0.0.0.0 unreachable via
# config/env alone.
HOST = "127.0.0.1"
PORT = int(os.environ.get("NETAUDIT_PORT", "8787"))

CORS_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]

# Backend directory (…/backend), used to locate the built frontend.
BACKEND_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIST = BACKEND_DIR.parent / "frontend" / "dist"


def _default_db_path() -> Path:
    override = os.environ.get("NETAUDIT_DB_PATH")
    if override:
        return Path(override)
    local_app_data = os.environ.get("LOCALAPPDATA")
    if not local_app_data:
        local_app_data = str(Path.home() / "AppData" / "Local")
    return Path(local_app_data) / "NetAudit" / "netaudit.db"


DB_PATH = _default_db_path()

# --- Auth token (Part C item 2) ---------------------------------------------
# %LOCALAPPDATA%\NetAudit\token, owner-only ACL. Overridable for tests only
# (mirrors NETAUDIT_DB_PATH) so test runs never touch the real user profile
# and don't race each other over a shared file.
def _default_token_path() -> Path:
    override = os.environ.get("NETAUDIT_TOKEN_PATH")
    if override:
        return Path(override)
    local_app_data = os.environ.get("LOCALAPPDATA")
    if not local_app_data:
        local_app_data = str(Path.home() / "AppData" / "Local")
    return Path(local_app_data) / "NetAudit" / "token"


TOKEN_PATH = _default_token_path()
TOKEN_HEADER = "X-NetAudit-Token"

# --- Bounds (Part C item 6) --------------------------------------------------
MAX_LIMIT = 1000  # hard server-side cap regardless of what the client asks for
SQL_QUERY_TIMEOUT_SECONDS = 5.0  # aborts a runaway query batch on a connection
DNS_CACHE_MAX_ENTRIES = 5000  # bounded reverse-DNS cache with LRU eviction
PAYLOAD_SNIPPET_MAX_BYTES = 64  # any persisted payload snippet is truncated here

# --- Rate limiting (Part C item 9) ------------------------------------------
# ~120 requests / 10s per peer -- generous enough for 2s dashboard polling
# across several endpoints at once, tight enough to stop a hostile page from
# hammering the API in a loop.
RATE_LIMIT_CAPACITY = 120
RATE_LIMIT_WINDOW_SECONDS = 10.0

# --- Retention -------------------------------------------------------------
RETENTION_HOURS = float(os.environ.get("NETAUDIT_RETENTION_HOURS", "24"))
RETENTION_MAX_ROWS = int(os.environ.get("NETAUDIT_RETENTION_MAX_ROWS", "2000000"))
RETENTION_SWEEP_SECONDS = 60.0

# --- Capture -----------------------------------------------------------
DEFAULT_INTERFACE_ID = os.environ.get("NETAUDIT_INTERFACE", None)
POLL_INTERVAL_SECONDS = 2.0
CAPTURE_QUEUE_MAX = 20000
INGEST_BATCH_INTERVAL_SECONDS = 0.5
INGEST_BATCH_MAX = 1000

# --- WebSocket cadence (per contract section 13) ----------------------
WS_STATS_INTERVAL_SECONDS = 2.0
WS_CONNECTIONS_INTERVAL_SECONDS = 2.0
WS_LOG_INTERVAL_SECONDS = 1.0
WS_LOG_MAX_ENTRIES = 200

# --- Rules engine --------------------------------------------------------
RULES_INTERVAL_SECONDS = 5.0

# --- DNS / enrichment ------------------------------------------------------
DNS_CACHE_TTL_SECONDS = 3600
DNS_MAX_WORKERS = 4


def ensure_db_dir() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
