"""E5 HTML report renderer: a single self-contained file, inlined CSS, no
external requests/CDN/remote fonts/images, printable to PDF from the
browser's own print dialog.

**Everything interpolated into the page is escaped** via `_esc()`
(`html.escape`, quoting on) -- a process name, hostname, or any other
string sourced from live data must never be able to execute as markup.
See `tests/export/test_report.py::TestHtmlEscaping` for a hostile record
containing `<script>` that must render as inert text.
"""
from __future__ import annotations

import html
from typing import Any


def _esc(value: Any) -> str:
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


_CSS = """
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body {
  font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
  margin: 0; padding: 2rem; max-width: 960px; margin-inline: auto;
  color: #1a1a1a; background: #ffffff; line-height: 1.5;
}
header { border-bottom: 3px solid #2b3a55; padding-bottom: 1rem; margin-bottom: 1.5rem; }
h1 { margin: 0 0 0.25rem 0; font-size: 1.6rem; }
h2 { margin-top: 2rem; border-bottom: 1px solid #ccc; padding-bottom: 0.3rem; font-size: 1.2rem; }
.meta { color: #555; font-size: 0.9rem; }
table { width: 100%; border-collapse: collapse; margin: 0.75rem 0 1.5rem 0; font-size: 0.88rem; }
th, td { text-align: left; padding: 0.45rem 0.6rem; border-bottom: 1px solid #e2e2e2; vertical-align: top; }
th { background: #f2f4f7; font-weight: 600; }
.score-badge {
  display: inline-block; font-size: 2rem; font-weight: 700; padding: 0.2rem 0.9rem;
  border-radius: 0.5rem; background: #2b3a55; color: #fff;
}
.grade { font-size: 1.1rem; color: #555; }
.sev { font-weight: 600; padding: 0.1rem 0.5rem; border-radius: 0.3rem; font-size: 0.8rem; }
.sev-critical { background: #fde2e1; color: #8a1c12; }
.sev-high { background: #fde8d2; color: #8a4b12; }
.sev-medium { background: #fdf3d0; color: #6b5900; }
.sev-low { background: #e3f0ff; color: #1c4a8a; }
.sev-info { background: #eee; color: #444; }
.status-fail { color: #8a1c12; font-weight: 600; }
.status-warn { color: #8a4b12; font-weight: 600; }
.status-pass { color: #1c6b3a; font-weight: 600; }
.status-error, .status-skipped { color: #666; }
footer { margin-top: 2.5rem; padding-top: 1rem; border-top: 1px solid #ddd; color: #888; font-size: 0.8rem; }
@media print {
  body { padding: 0; max-width: none; }
  h2 { break-after: avoid; }
  tr { break-inside: avoid; }
}
@media (prefers-color-scheme: dark) {
  body { background: #16181d; color: #e6e6e6; }
  th { background: #23262e; }
  th, td { border-bottom-color: #2c2f37; }
  h2 { border-bottom-color: #333; }
  .meta { color: #999; }
  footer { border-top-color: #333; color: #777; }
}
"""


def _severity_class(sev: Any) -> str:
    s = str(sev or "info").lower()
    return s if s in ("critical", "high", "medium", "low", "info") else "info"


def _sev_span(sev: Any) -> str:
    return f'<span class="sev sev-{_severity_class(sev)}">{_esc(sev)}</span>'


def _render_summary(data: dict) -> str:
    score = data.get("security_score") or {}
    findings = data.get("prioritised_findings") or []
    parts = ['<section id="summary"><h2>Executive summary</h2>']
    parts.append(
        f'<p><span class="score-badge">{_esc(score.get("overall", "-"))}</span> '
        f'<span class="grade">grade {_esc(score.get("grade", "-"))}</span></p>'
    )
    components = score.get("components") or []
    if components:
        parts.append("<table><thead><tr><th>Component</th><th>Score</th><th>Weight</th><th>Grade</th></tr></thead><tbody>")
        for c in components:
            parts.append(
                f"<tr><td>{_esc(c.get('label'))}</td><td>{_esc(c.get('score'))}</td>"
                f"<td>{_esc(c.get('weight'))}</td><td>{_esc(c.get('grade'))}</td></tr>"
            )
        parts.append("</tbody></table>")

    if findings:
        parts.append("<h3>Prioritised findings</h3>")
        parts.append(
            "<table><thead><tr><th>#</th><th>Source</th><th>Title</th><th>Severity</th>"
            "<th>Impact</th><th>Effort</th><th>Why first</th></tr></thead><tbody>"
        )
        for f in findings:
            parts.append(
                f"<tr><td>{_esc(f.get('priority_rank'))}</td><td>{_esc(f.get('source'))}</td>"
                f"<td>{_esc(f.get('title'))}</td><td>{_sev_span(f.get('severity'))}</td>"
                f"<td>{_esc(f.get('impact_score'))}</td><td>{_esc(f.get('effort'))}</td>"
                f"<td>{_esc(f.get('why_first'))}</td></tr>"
            )
        parts.append("</tbody></table>")
    parts.append("</section>")
    return "".join(parts)


def _render_posture(data: dict) -> str:
    posture = data.get("posture") or {}
    counts = posture.get("counts") or {}
    parts = ['<section id="posture"><h2>Host security posture</h2>']
    parts.append(
        f"<p>Score {_esc(posture.get('score', '-'))} (grade {_esc(posture.get('grade', '-'))}) -- "
        f"pass {_esc(counts.get('pass', 0))}, warn {_esc(counts.get('warn', 0))}, "
        f"fail {_esc(counts.get('fail', 0))}, error {_esc(counts.get('error', 0))}, "
        f"skipped {_esc(counts.get('skipped', 0))}</p>"
    )
    checks = posture.get("checks") or []
    if checks:
        parts.append(
            "<table><thead><tr><th>Check</th><th>Category</th><th>Status</th>"
            "<th>Severity</th><th>Observed</th></tr></thead><tbody>"
        )
        for c in checks:
            status = str(c.get("status") or "").lower()
            parts.append(
                f"<tr><td>{_esc(c.get('title'))}</td><td>{_esc(c.get('category'))}</td>"
                f'<td class="status-{_esc(status)}">{_esc(c.get("status"))}</td>'
                f"<td>{_sev_span(c.get('severity'))}</td><td>{_esc(c.get('observed'))}</td></tr>"
            )
        parts.append("</tbody></table>")
    parts.append("</section>")
    return "".join(parts)


def _render_threats(data: dict) -> str:
    threats = data.get("threats") or []
    parts = ['<section id="threats"><h2>Threats</h2>']
    if not threats:
        parts.append("<p>No active threats.</p>")
    else:
        parts.append(
            "<table><thead><tr><th>Title</th><th>Severity</th><th>Confidence</th>"
            "<th>Category</th><th>Status</th><th>Summary</th></tr></thead><tbody>"
        )
        for t in threats:
            parts.append(
                f"<tr><td>{_esc(t.get('title'))}</td><td>{_sev_span(t.get('severity'))}</td>"
                f"<td>{_esc(t.get('confidence'))}</td><td>{_esc(t.get('category'))}</td>"
                f"<td>{_esc(t.get('status'))}</td><td>{_esc(t.get('summary'))}</td></tr>"
            )
        parts.append("</tbody></table>")
    parts.append("</section>")
    return "".join(parts)


def _render_recommendations(data: dict) -> str:
    recs = data.get("recommendations") or []
    parts = ['<section id="recommendations"><h2>Recommendations</h2>']
    if not recs:
        parts.append("<p>No open recommendations.</p>")
    else:
        parts.append(
            "<table><thead><tr><th>Title</th><th>Severity</th><th>Confidence</th>"
            "<th>Category</th><th>Summary</th></tr></thead><tbody>"
        )
        for r in recs:
            parts.append(
                f"<tr><td>{_esc(r.get('title'))}</td><td>{_sev_span(r.get('severity'))}</td>"
                f"<td>{_esc(r.get('confidence'))}</td><td>{_esc(r.get('category'))}</td>"
                f"<td>{_esc(r.get('summary'))}</td></tr>"
            )
        parts.append("</tbody></table>")
    parts.append("</section>")
    return "".join(parts)


def _render_traffic(data: dict) -> str:
    traffic = data.get("traffic") or {}
    parts = ['<section id="traffic"><h2>Traffic summary</h2><table><tbody>']
    fields = [
        ("Window", "window"), ("Packets total", "packets_total"), ("Bytes total", "bytes_total"),
        ("Bytes in", "bytes_in"), ("Bytes out", "bytes_out"), ("Active flows", "active_flows"),
        ("Unique remote hosts", "unique_remote_hosts"), ("Encrypted bytes", "encrypted_bytes"),
        ("Plaintext bytes", "plaintext_bytes"), ("Open alerts", "open_alerts"),
    ]
    for label, key in fields:
        parts.append(f"<tr><th>{_esc(label)}</th><td>{_esc(traffic.get(key))}</td></tr>")
    parts.append("</tbody></table></section>")
    return "".join(parts)


def _render_devices(data: dict) -> str:
    devices = data.get("devices") or []
    parts = ['<section id="devices"><h2>Devices</h2>']
    if not devices:
        parts.append("<p>No devices observed.</p>")
    else:
        parts.append(
            "<table><thead><tr><th>IP</th><th>MAC</th><th>Vendor</th><th>Hostname</th>"
            "<th>Risk</th></tr></thead><tbody>"
        )
        for d in devices:
            parts.append(
                f"<tr><td>{_esc(d.get('ip'))}</td><td>{_esc(d.get('mac'))}</td>"
                f"<td>{_esc(d.get('vendor'))}</td><td>{_esc(d.get('hostname'))}</td>"
                f"<td>{_sev_span(d.get('risk'))}</td></tr>"
            )
        parts.append("</tbody></table>")
    parts.append("</section>")
    return "".join(parts)


_SECTION_RENDERERS = {
    "summary": _render_summary,
    "posture": _render_posture,
    "threats": _render_threats,
    "recommendations": _render_recommendations,
    "traffic": _render_traffic,
    "devices": _render_devices,
}


def render_html_report(data: dict) -> str:
    title = _esc(data.get("title") or "NetAudit report")
    generated_at = _esc(data.get("generated_at"))
    window = _esc(data.get("window"))
    sections = data.get("sections") or []

    body_sections = "".join(
        _SECTION_RENDERERS[s](data) for s in sections if s in _SECTION_RENDERERS
    )

    return (
        "<!doctype html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>{title}</title>\n"
        f"<style>{_CSS}</style>\n"
        "</head>\n"
        "<body>\n"
        "<header>\n"
        f"<h1>{title}</h1>\n"
        f'<p class="meta">Generated {generated_at} &middot; window {window}</p>\n'
        "</header>\n"
        f"{body_sections}\n"
        "<footer>Generated by NetAudit. No external requests were made to build this report.</footer>\n"
        "</body>\n"
        "</html>\n"
    )
