"""Assembles the plain-data structure both report renderers (HTML,
Markdown) and the JSON format share, from a `ReportDataProvider`.

Includes a locally-computed "prioritised findings" merge (posture + threats
+ recommendations, ranked by impact/effort) for the executive summary. This
package does not import `netaudit.learn` (which owns the real D6
`/api/findings/prioritised` endpoint) -- this is an independent, good-faith
approximation built only from data already available through
`ReportDataProvider`, not a reimplementation of D6's exact algorithm.
"""
from __future__ import annotations

from typing import Optional

from ..timeutil import now_iso
from .provider import ReportDataProvider

_SEVERITY_IMPACT = {"critical": 95, "high": 80, "medium": 55, "low": 30, "info": 10}
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _posture_effort(check: dict) -> str:
    commands = ((check.get("remediation") or {}).get("commands")) or []
    if not commands:
        return "medium"
    if len(commands) == 1 and not commands[0].get("requires_admin"):
        return "low"
    if len(commands) == 1:
        return "low"
    return "medium" if len(commands) <= 2 else "high"


def _build_prioritised_findings(provider: ReportDataProvider) -> list[dict]:
    items: list[dict] = []

    posture = provider.posture_report()
    for check in posture.get("checks", []):
        if check.get("status") not in ("fail", "warn"):
            continue
        severity = check.get("severity") or "info"
        base = _SEVERITY_IMPACT.get(severity, 10)
        impact = base if check.get("status") == "fail" else round(base * 0.6)
        effort = _posture_effort(check)
        items.append({
            "id": f"posture:{check.get('id')}",
            "source": "posture",
            "title": check.get("title") or check.get("id"),
            "severity": severity,
            "impact_score": impact,
            "effort": effort,
            "one_line_fix": (check.get("remediation") or {}).get("summary"),
        })

    for threat in provider.threats():
        if threat.get("status") != "active":
            continue
        severity = threat.get("severity") or "info"
        confidence = threat.get("confidence") or 0.5
        impact = round(_SEVERITY_IMPACT.get(severity, 10) * (0.5 + 0.5 * confidence))
        items.append({
            "id": f"threat:{threat.get('id')}",
            "source": "threat",
            "title": threat.get("title") or threat.get("detector_id"),
            "severity": severity,
            "impact_score": impact,
            "effort": "medium",
            "one_line_fix": threat.get("summary"),
        })

    for rec in provider.recommendations():
        if rec.get("dismissed"):
            continue
        severity = rec.get("severity") or "info"
        confidence = rec.get("confidence") or 0.5
        impact = round(_SEVERITY_IMPACT.get(severity, 10) * (0.5 + 0.5 * confidence))
        items.append({
            "id": f"recommendation:{rec.get('id')}",
            "source": "recommendation",
            "title": rec.get("title") or rec.get("rule_id"),
            "severity": severity,
            "impact_score": impact,
            "effort": "low" if severity in ("low", "info") else "medium",
            "one_line_fix": rec.get("summary"),
        })

    _EFFORT_ORDER = {"low": 0, "medium": 1, "high": 2}
    items.sort(key=lambda i: (-i["impact_score"], _EFFORT_ORDER.get(i["effort"], 1), i["id"]))
    for rank, item in enumerate(items, start=1):
        item["priority_rank"] = rank
        item["why_first"] = (
            f"{item['severity']} severity, {item['effort']} effort to fix "
            f"(impact score {item['impact_score']})."
        )
    return items


def build_report_data(
    provider: ReportDataProvider,
    sections: list[str],
    window: str,
    title: str,
) -> dict:
    data: dict = {
        "title": title,
        "window": window,
        "generated_at": now_iso(),
        "sections": sections,
    }

    if "summary" in sections:
        data["security_score"] = provider.security_score()
        data["prioritised_findings"] = _build_prioritised_findings(provider)
    if "posture" in sections:
        data["posture"] = provider.posture_report()
    if "threats" in sections:
        data["threats"] = provider.threats()
    if "recommendations" in sections:
        data["recommendations"] = provider.recommendations()
    if "traffic" in sections:
        data["traffic"] = provider.traffic_summary()
    if "devices" in sections:
        data["devices"] = provider.devices()

    return data
