"""Slack Incoming Webhook support for alert channels.

A `slack` channel is a webhook URL (`https://hooks.slack.com/services/...`)
that receives a Slack-flavoured payload instead of the generic JSON payload
the `webhook` channel kind sends. This module only formats the payload and
hands the send to `webhook.send_webhook()`, so the single outbound path, the
https-only/SSRF checks, the 5s timeout, and the exactly-once discipline stay
exactly as documented in README.md -- a Slack channel adds formatting, not a
second network path.
"""
from __future__ import annotations

from typing import Optional

from .webhook import DEFAULT_TIMEOUT_SECONDS, Transport, WebhookResult, send_webhook

# Slack attachment color per NetAudit severity, matching the dashboard's
# severity colors so triage in Slack reads the same as in the app.
SEVERITY_COLORS = {
    "critical": "#e11d48",
    "high": "#f97316",
    "medium": "#eab308",
    "low": "#3b82f6",
    "info": "#64748b",
}


def build_slack_payload(*, title: str, severity: str, source: str, source_id: str, ts: str) -> dict:
    """Builds the JSON body for a Slack Incoming Webhook.

    Uses a plain `text` fallback plus a legacy attachment so the message is
    readable even in clients that do not render Block Kit, and carries the
    NetAudit fields (severity, source, source id, timestamp) as attachment
    fields.
    """
    color = SEVERITY_COLORS.get(severity, SEVERITY_COLORS["info"])
    return {
        "text": f"*[{severity}] {source}* - {title}",
        "attachments": [
            {
                "color": color,
                "title": title,
                "fields": [
                    {"title": "Severity", "value": severity, "short": True},
                    {"title": "Source", "value": source, "short": True},
                    {"title": "Source ID", "value": source_id, "short": True},
                    {"title": "Time", "value": ts, "short": True},
                ],
                "footer": "NetAudit",
            }
        ],
    }


def send_slack(
    url: str,
    *,
    title: str,
    severity: str,
    source: str,
    source_id: str,
    ts: str,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    transport: Optional[Transport] = None,
) -> WebhookResult:
    """Sends one Slack alert through the same validated outbound path as a
    generic webhook (`webhook.send_webhook`): fresh https-only + SSRF
    validation on every call, exactly one attempt, no retries."""
    payload = build_slack_payload(title=title, severity=severity, source=source, source_id=source_id, ts=ts)
    return send_webhook(url, payload, timeout=timeout, transport=transport)
