"""E5 Markdown report renderer.

Most Markdown renderers pass raw HTML through untouched, so a hostile
`process_name`/`hostname` of `<script>...</script>` would execute exactly
as it would in a raw HTML report if left unescaped here. `_esc_md()`
neutralises angle brackets (so no tag can ever form) and escapes `|` and
newlines so a hostile value can't break out of a table cell either.
"""
from __future__ import annotations

from typing import Any


def _esc_md(value: Any) -> str:
    if value is None:
        return ""
    s = str(value)
    s = s.replace("<", "&lt;").replace(">", "&gt;")
    s = s.replace("|", "\\|").replace("\r\n", " ").replace("\n", " ").replace("\r", " ")
    return s


def _table(headers: list[str], rows: list[list[Any]]) -> str:
    if not rows:
        return "_None._\n"
    lines = ["| " + " | ".join(headers) + " |", "| " + " | ".join("---" for _ in headers) + " |"]
    for row in rows:
        lines.append("| " + " | ".join(_esc_md(cell) for cell in row) + " |")
    return "\n".join(lines) + "\n"


def _render_summary(data: dict) -> str:
    score = data.get("security_score") or {}
    findings = data.get("prioritised_findings") or []
    out = ["## Executive summary\n"]
    out.append(f"**Overall score: {_esc_md(score.get('overall', '-'))}** (grade {_esc_md(score.get('grade', '-'))})\n")
    components = score.get("components") or []
    if components:
        out.append("### Components\n")
        out.append(_table(
            ["Component", "Score", "Weight", "Grade"],
            [[c.get("label"), c.get("score"), c.get("weight"), c.get("grade")] for c in components],
        ))
    if findings:
        out.append("### Prioritised findings\n")
        out.append(_table(
            ["#", "Source", "Title", "Severity", "Impact", "Effort", "Why first"],
            [[f.get("priority_rank"), f.get("source"), f.get("title"), f.get("severity"),
              f.get("impact_score"), f.get("effort"), f.get("why_first")] for f in findings],
        ))
    return "\n".join(out)


def _render_posture(data: dict) -> str:
    posture = data.get("posture") or {}
    counts = posture.get("counts") or {}
    out = ["## Host security posture\n"]
    out.append(
        f"Score {_esc_md(posture.get('score', '-'))} (grade {_esc_md(posture.get('grade', '-'))}) -- "
        f"pass {_esc_md(counts.get('pass', 0))}, warn {_esc_md(counts.get('warn', 0))}, "
        f"fail {_esc_md(counts.get('fail', 0))}, error {_esc_md(counts.get('error', 0))}, "
        f"skipped {_esc_md(counts.get('skipped', 0))}\n"
    )
    checks = posture.get("checks") or []
    out.append(_table(
        ["Check", "Category", "Status", "Severity", "Observed"],
        [[c.get("title"), c.get("category"), c.get("status"), c.get("severity"), c.get("observed")] for c in checks],
    ))
    return "\n".join(out)


def _render_threats(data: dict) -> str:
    threats = data.get("threats") or []
    out = ["## Threats\n"]
    out.append(_table(
        ["Title", "Severity", "Confidence", "Category", "Status", "Summary"],
        [[t.get("title"), t.get("severity"), t.get("confidence"), t.get("category"),
          t.get("status"), t.get("summary")] for t in threats],
    ))
    return "\n".join(out)


def _render_recommendations(data: dict) -> str:
    recs = data.get("recommendations") or []
    out = ["## Recommendations\n"]
    out.append(_table(
        ["Title", "Severity", "Confidence", "Category", "Summary"],
        [[r.get("title"), r.get("severity"), r.get("confidence"), r.get("category"), r.get("summary")] for r in recs],
    ))
    return "\n".join(out)


def _render_traffic(data: dict) -> str:
    traffic = data.get("traffic") or {}
    out = ["## Traffic summary\n"]
    fields = [
        ("Window", "window"), ("Packets total", "packets_total"), ("Bytes total", "bytes_total"),
        ("Bytes in", "bytes_in"), ("Bytes out", "bytes_out"), ("Active flows", "active_flows"),
        ("Unique remote hosts", "unique_remote_hosts"), ("Encrypted bytes", "encrypted_bytes"),
        ("Plaintext bytes", "plaintext_bytes"), ("Open alerts", "open_alerts"),
    ]
    out.append(_table(["Field", "Value"], [[label, traffic.get(key)] for label, key in fields]))
    return "\n".join(out)


def _render_devices(data: dict) -> str:
    devices = data.get("devices") or []
    out = ["## Devices\n"]
    out.append(_table(
        ["IP", "MAC", "Vendor", "Hostname", "Risk"],
        [[d.get("ip"), d.get("mac"), d.get("vendor"), d.get("hostname"), d.get("risk")] for d in devices],
    ))
    return "\n".join(out)


_SECTION_RENDERERS = {
    "summary": _render_summary,
    "posture": _render_posture,
    "threats": _render_threats,
    "recommendations": _render_recommendations,
    "traffic": _render_traffic,
    "devices": _render_devices,
}


def render_markdown_report(data: dict) -> str:
    title = _esc_md(data.get("title") or "NetAudit report")
    generated_at = _esc_md(data.get("generated_at"))
    window = _esc_md(data.get("window"))
    sections = data.get("sections") or []

    parts = [f"# {title}\n", f"_Generated {generated_at} - window {window}_\n"]
    for s in sections:
        renderer = _SECTION_RENDERERS.get(s)
        if renderer:
            parts.append(renderer(data))
    parts.append("\n_Generated by NetAudit. No external requests were made to build this report._\n")
    return "\n".join(parts)
