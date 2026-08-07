"""Config/channel/history orchestration plus the dispatch pipeline
(severity filter, rate limiting, quiet hours) for Part F3/F4.

`dispatch()` is a plain Python method, not an HTTP endpoint -- the frozen
contract only exposes `GET`/`PUT /api/alerts/config`, `POST
/api/alerts/test`, and `GET /api/alerts/history`. Whatever in the rest of
the backend decides "this is worth alerting on" (a new high-severity
threat, a posture regression, ...) calls `AlertService.dispatch(...)`
directly; this package has no visibility into posture/threat data itself
(decoupling), so it can't originate that decision on its own.
"""
from __future__ import annotations

import secrets
from datetime import datetime
from typing import Optional

from ..timeutil import iso_z, now_iso, parse_iso
from . import store
from .desktop import DesktopSender, send_desktop_notification
from .models import (
    AlertChannel,
    AlertHistoryChannelResult,
    AlertHistoryItem,
    AlertHistoryResponse,
    AlertsConfig,
    AlertsConfigUpdate,
    AlertTestResult,
    QuietHours,
    SEVERITY_ORDER,
)
from .slack import send_slack
from .webhook import Transport, WebhookRejected, send_webhook, validate_and_resolve


class AlertConfigError(Exception):
    """Raised by `update_config()` for a config the F3 rules reject
    outright (bad webhook scheme, SSRF-blocked host, enabled-without-a-URL).
    The router maps this to a 400."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(message)


def _row_to_channel(row: dict) -> AlertChannel:
    return AlertChannel(
        id=row["id"],
        kind=row["kind"],
        enabled=bool(row["enabled"]),
        url=row.get("url"),
        template=row.get("template"),
        last_status=row.get("last_status"),
        last_attempt=row.get("last_attempt"),
    )


def _row_to_config(config_row: dict, channel_rows: list[dict]) -> AlertsConfig:
    quiet = None
    if config_row.get("quiet_start") and config_row.get("quiet_end"):
        quiet = QuietHours(start=config_row["quiet_start"], end=config_row["quiet_end"])
    return AlertsConfig(
        enabled=bool(config_row["enabled"]),
        min_severity=config_row["min_severity"],
        channels=[_row_to_channel(r) for r in channel_rows],
        rate_limit_per_hour=config_row["rate_limit_per_hour"],
        quiet_hours=quiet,
    )


def _validate_channels(channels: list[AlertChannel]) -> None:
    seen_ids: set[str] = set()
    for ch in channels:
        if ch.id in seen_ids:
            raise AlertConfigError("duplicate_channel", f"duplicate channel id {ch.id!r}")
        seen_ids.add(ch.id)
        if ch.kind not in ("webhook", "slack"):
            continue
        if not ch.enabled:
            continue  # F3: disabled by default -- a disabled webhook's URL is never touched, even to validate it
        if not ch.url or not ch.url.strip():
            raise AlertConfigError("missing_url", f"{ch.kind} channel {ch.id!r} is enabled but has no url")
        try:
            validate_and_resolve(ch.url)
        except WebhookRejected as exc:
            raise AlertConfigError(exc.code, f"{ch.kind} channel {ch.id!r}: {exc.message}") from exc


def _send_remote_channel(
    kind: str,
    url: str,
    *,
    title: str,
    severity: str,
    source: str,
    source_id: str,
    ts: str,
    transport: Optional[Transport],
    extra: Optional[dict] = None,
) -> str:
    """POST one alert to a webhook/Slack URL through the single sanctioned
    outbound path (webhook.send_webhook). Returns 'delivered' or 'failed' --
    a rejected or failed send is a status, never an exception."""
    try:
        if kind == "slack":
            result = send_slack(
                url, title=title, severity=severity, source=source, source_id=source_id, ts=ts,
                transport=transport, enrichment=(extra or {}).get("enrichment"),
            )
        else:
            payload = {"title": title, "severity": severity, "source": source, "source_id": source_id, "ts": ts}
            if extra:
                payload.update(extra)
            result = send_webhook(url, payload, transport=transport)
    except WebhookRejected:
        return "failed"
    return "delivered" if result.ok else "failed"


def _is_quiet_now(quiet: Optional[QuietHours]) -> bool:
    if quiet is None:
        return False
    now = datetime.now().strftime("%H:%M")
    start, end = quiet.start, quiet.end
    if start <= end:
        return start <= now < end
    return now >= start or now < end  # wraps past midnight, e.g. 23:00-07:00


class AlertService:
    def __init__(self, db_path=None) -> None:
        self._db_path = db_path

    # -- config -----------------------------------------------------------

    def get_config(self) -> AlertsConfig:
        config_row = store.get_config_row(self._db_path)
        channel_rows = store.list_channels(self._db_path)
        return _row_to_config(config_row, channel_rows)

    def update_config(self, update: AlertsConfigUpdate) -> AlertsConfig:
        _validate_channels(update.channels)
        quiet_start = update.quiet_hours.start if update.quiet_hours else None
        quiet_end = update.quiet_hours.end if update.quiet_hours else None
        store.set_config_row(update.enabled, update.min_severity, update.rate_limit_per_hour, quiet_start, quiet_end, self._db_path)
        store.replace_channels([c.model_dump() for c in update.channels], self._db_path)
        return self.get_config()

    # -- test ---------------------------------------------------------------

    def test_channel(self, channel_id: str, transport: Optional[Transport] = None, desktop_sender: Optional[DesktopSender] = None) -> AlertTestResult:
        """Sends one real test alert to the named channel, bypassing
        `enabled`/`min_severity`/`quiet_hours`/`rate_limit_per_hour` -- this
        is a deliberate, explicit, one-off user action to check a channel
        actually works, not part of the automatic dispatch pipeline those
        filters govern."""
        row = store.get_channel(channel_id, self._db_path)
        attempted_at = now_iso()
        if row is None:
            return AlertTestResult(channel_id=channel_id, status="failed", detail="unknown channel id", attempted_at=attempted_at)

        if row["kind"] == "desktop":
            result = send_desktop_notification("NetAudit test alert", "This is a test alert from NetAudit.", sender=desktop_sender)
            store.update_channel_status(channel_id, result.status, self._db_path)
            return AlertTestResult(channel_id=channel_id, status=result.status, detail=result.detail, attempted_at=attempted_at)

        if row["kind"] in ("webhook", "slack"):
            url = row.get("url")
            if not url:
                store.update_channel_status(channel_id, "failed", self._db_path)
                return AlertTestResult(channel_id=channel_id, status="failed", detail="no url configured", attempted_at=attempted_at)
            try:
                if row["kind"] == "slack":
                    result = send_slack(
                        url,
                        title="NetAudit test alert", severity="info", source="alerts",
                        source_id="manual-test", ts=attempted_at,
                        transport=transport,
                    )
                else:
                    result = send_webhook(
                        url,
                        {"title": "NetAudit test alert", "severity": "info", "source": "alerts", "ts": attempted_at},
                        transport=transport,
                    )
            except WebhookRejected as exc:
                store.update_channel_status(channel_id, "failed", self._db_path)
                return AlertTestResult(channel_id=channel_id, status="failed", detail=exc.message, attempted_at=attempted_at)
            status = "delivered" if result.ok else "failed"
            store.update_channel_status(channel_id, status, self._db_path)
            return AlertTestResult(channel_id=channel_id, status=status, detail=result.detail, attempted_at=attempted_at)

        return AlertTestResult(channel_id=channel_id, status="failed", detail=f"unknown channel kind {row['kind']!r}", attempted_at=attempted_at)

    # -- history --------------------------------------------------------

    def history(self, limit: int = 200) -> AlertHistoryResponse:
        rows = store.list_history(limit, self._db_path)
        items = [
            AlertHistoryItem(
                id=r["id"],
                ts=r["ts"],
                severity=r["severity"],
                source=r["source"],
                source_id=r["source_id"],
                title=r["title"],
                channels=[AlertHistoryChannelResult(**c) for c in r["channels"]],
            )
            for r in rows
        ]
        return AlertHistoryResponse(alerts=items)

    # -- dispatch ---------------------------------------------------------

    def dispatch(
        self,
        severity: str,
        source: str,
        source_id: str,
        title: str,
        transport: Optional[Transport] = None,
        desktop_sender: Optional[DesktopSender] = None,
        extra: Optional[dict] = None,
    ) -> Optional[AlertHistoryItem]:
        """Called by whatever in the backend decided something is worth
        alerting on. Returns None (and writes nothing) if alerting is
        disabled or the severity is below `min_severity` -- those aren't
        "alerts that got suppressed", they were never eligible in the first
        place. Quiet hours and the rate limit, by contrast, *do* apply to
        an eligible alert and are recorded in history as `suppressed` /
        `rate_limited` per channel, so there's a visible record of what
        would have fired."""
        config = self.get_config()
        if not config.enabled:
            return None
        if SEVERITY_ORDER.get(severity, 0) < SEVERITY_ORDER.get(config.min_severity, 0):
            return None

        ts = now_iso()
        entry_id = f"al_{secrets.token_hex(6)}"

        quiet = _is_quiet_now(config.quiet_hours)
        rate_limited = False
        if config.rate_limit_per_hour > 0:
            one_hour_ago = parse_iso(ts) - 3600
            recent_count = store.count_history_since(iso_z(one_hour_ago), self._db_path)
            rate_limited = recent_count >= config.rate_limit_per_hour

        channel_results: list[AlertHistoryChannelResult] = []
        for ch in config.channels:
            if not ch.enabled:
                continue
            if quiet:
                channel_results.append(AlertHistoryChannelResult(id=ch.id, status="suppressed"))
                continue
            if rate_limited:
                channel_results.append(AlertHistoryChannelResult(id=ch.id, status="rate_limited"))
                continue
            if ch.kind == "desktop":
                result = send_desktop_notification(title, f"[{severity}] {source}: {title}", sender=desktop_sender)
                store.update_channel_status(ch.id, result.status, self._db_path)
                channel_results.append(AlertHistoryChannelResult(id=ch.id, status=result.status))
            elif ch.kind in ("webhook", "slack") and ch.url:
                status = _send_remote_channel(
                    ch.kind, ch.url, title=title, severity=severity,
                    source=source, source_id=source_id, ts=ts, transport=transport, extra=extra,
                )
                store.update_channel_status(ch.id, status, self._db_path)
                channel_results.append(AlertHistoryChannelResult(id=ch.id, status=status))

        store.insert_history(entry_id, ts, severity, source, source_id, title, [c.model_dump() for c in channel_results], self._db_path)
        return AlertHistoryItem(id=entry_id, ts=ts, severity=severity, source=source, source_id=source_id, title=title, channels=channel_results)


_default_service: Optional[AlertService] = None


def get_alert_service() -> AlertService:
    global _default_service
    if _default_service is None:
        _default_service = AlertService()
    return _default_service
