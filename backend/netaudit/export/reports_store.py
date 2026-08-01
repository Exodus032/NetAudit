"""Filesystem storage for generated reports (E5), capped at 50 with
oldest-pruned, under `%LOCALAPPDATA%\\NetAudit\\reports\\`.

Each report is two files: the report content itself (`<id>.<ext>`) and a
small JSON metadata sidecar (`<id>.meta.json`) so `GET /api/reports` can
list without re-parsing report bodies.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import time
from pathlib import Path
from typing import Optional

MAX_REPORTS = 50

_EXT_FOR_FORMAT = {"html": "html", "markdown": "md", "json": "json"}

# Exactly the shape new_report_id() produces. Anything else (path
# separators, dots, %-escapes that decode to \ on Windows) is rejected
# before any Path is built, so a crafted id can never escape reports_dir.
_REPORT_ID_RE = re.compile(r"^report-\d{8}T\d{6}Z-[0-9a-f]{6}$")


def _default_reports_dir() -> Path:
    override = os.environ.get("NETAUDIT_REPORTS_DIR")
    if override:
        return Path(override)
    local_app_data = os.environ.get("LOCALAPPDATA")
    if not local_app_data:
        local_app_data = str(Path.home() / "AppData" / "Local")
    return Path(local_app_data) / "NetAudit" / "reports"


DEFAULT_REPORTS_DIR = _default_reports_dir()


def new_report_id() -> str:
    ts = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    return f"report-{ts}-{secrets.token_hex(3)}"


def _is_safe_report_id(report_id: str, reports_dir: Path) -> bool:
    if not _REPORT_ID_RE.fullmatch(report_id):
        return False
    # Defense in depth: even a regex-valid id must resolve inside reports_dir.
    resolved = (reports_dir / f"{report_id}.meta.json").resolve()
    return resolved.parent == reports_dir.resolve()


def _paths(reports_dir: Path, report_id: str, fmt: str) -> tuple[Path, Path]:
    ext = _EXT_FOR_FORMAT.get(fmt, "txt")
    content_path = reports_dir / f"{report_id}.{ext}"
    meta_path = reports_dir / f"{report_id}.meta.json"
    return content_path, meta_path


def save_report(
    content: str,
    fmt: str,
    title: str,
    window: str,
    sections: list[str],
    reports_dir: Optional[Path] = None,
) -> dict:
    reports_dir = reports_dir or DEFAULT_REPORTS_DIR
    reports_dir.mkdir(parents=True, exist_ok=True)

    report_id = new_report_id()
    content_path, meta_path = _paths(reports_dir, report_id, fmt)
    generated_at = time.time()

    ext = _EXT_FOR_FORMAT.get(fmt, "txt")
    filename = f"netaudit-report-{report_id}.{ext}"

    meta = {
        "id": report_id,
        "title": title,
        "format": fmt,
        "window": window,
        "sections": sections,
        "generated_at_epoch": generated_at,
        "filename": filename,
        "bytes": len(content.encode("utf-8")),
    }

    content_path.write_text(content, encoding="utf-8")
    meta_path.write_text(json.dumps(meta), encoding="utf-8")

    _prune_oldest(reports_dir)
    return meta


def _all_meta(reports_dir: Path) -> list[dict]:
    metas = []
    for meta_path in reports_dir.glob("*.meta.json"):
        try:
            metas.append(json.loads(meta_path.read_text(encoding="utf-8")))
        except (OSError, ValueError):
            continue
    return metas


def _prune_oldest(reports_dir: Path) -> None:
    metas = sorted(_all_meta(reports_dir), key=lambda m: m["generated_at_epoch"], reverse=True)
    for stale in metas[MAX_REPORTS:]:
        delete_report(stale["id"], reports_dir=reports_dir)


def list_reports(reports_dir: Optional[Path] = None) -> list[dict]:
    reports_dir = reports_dir or DEFAULT_REPORTS_DIR
    if not reports_dir.exists():
        return []
    return sorted(_all_meta(reports_dir), key=lambda m: m["generated_at_epoch"], reverse=True)


def get_report(report_id: str, reports_dir: Optional[Path] = None) -> Optional[tuple[str, dict]]:
    reports_dir = reports_dir or DEFAULT_REPORTS_DIR
    if not _is_safe_report_id(report_id, reports_dir):
        return None
    meta_path = reports_dir / f"{report_id}.meta.json"
    if not meta_path.exists():
        return None
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    content_path, _ = _paths(reports_dir, report_id, meta["format"])
    if not content_path.exists():
        return None
    return content_path.read_text(encoding="utf-8"), meta


def delete_report(report_id: str, reports_dir: Optional[Path] = None) -> bool:
    reports_dir = reports_dir or DEFAULT_REPORTS_DIR
    if not _is_safe_report_id(report_id, reports_dir):
        return False
    meta_path = reports_dir / f"{report_id}.meta.json"
    if not meta_path.exists():
        return False
    fmt = "txt"
    try:
        fmt = json.loads(meta_path.read_text(encoding="utf-8")).get("format", "txt")
    except (OSError, ValueError):
        pass
    content_path, _ = _paths(reports_dir, report_id, fmt)
    deleted = False
    for p in (content_path, meta_path):
        try:
            p.unlink()
            deleted = True
        except OSError:
            pass
    return deleted
