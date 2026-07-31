"""Central settings for the NetAudit backend.

Kept as plain module-level constants (not pydantic-settings) so the module
has zero import-time side effects beyond reading environment variables and
computing the sqlite path -- makes it trivial to import from tests.
"""
from __future__ import annotations

import os
from pathlib import Path

VERSION = "1.0.0"

HOST = os.environ.get("NETAUDIT_HOST", "127.0.0.1")
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
