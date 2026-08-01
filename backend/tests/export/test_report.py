from __future__ import annotations

import pytest

from netaudit.export.provider import StaticReportDataProvider
from netaudit.export.report_data import build_report_data
from netaudit.export.report_html import render_html_report
from netaudit.export.report_markdown import render_markdown_report
from netaudit.export import reports_store

XSS_PAYLOAD = "<script>alert('xss')</script>"


def _hostile_provider() -> StaticReportDataProvider:
    return StaticReportDataProvider(
        security_score={
            "generated_at": "2026-07-31T14:00:00Z", "overall": 64, "grade": "C",
            "components": [{"id": "posture", "label": "Host configuration", "score": 68, "weight": 0.4, "grade": "C"}],
            "history": [], "top_wins": [],
        },
        posture_report={
            "generated_at": "2026-07-31T14:00:00Z", "scan_duration_ms": 100, "score": 68, "grade": "C",
            "counts": {"pass": 1, "warn": 0, "fail": 1, "error": 0, "skipped": 0},
            "categories": [],
            "checks": [
                {
                    "id": "smb_signing_required", "category": "smb",
                    "title": XSS_PAYLOAD, "status": "fail", "severity": "high",
                    "score_weight": 8, "observed": XSS_PAYLOAD, "expected": "True",
                    "remediation": {"summary": "Fix it", "commands": [{"command": "x", "requires_admin": True}]},
                    "checked_at": "2026-07-31T14:00:00Z",
                },
            ],
        },
        threats=[{
            "id": "beacon-1", "detector_id": "c2_beaconing", "title": XSS_PAYLOAD,
            "severity": "high", "confidence": 0.8, "category": "command_and_control",
            "status": "active", "summary": XSS_PAYLOAD, "mitre": [{"technique": "T1071.001"}],
        }],
        recommendations=[{
            "id": "rec1", "rule_id": "plaintext_http", "title": XSS_PAYLOAD,
            "severity": "medium", "confidence": 0.9, "category": "encryption",
            "summary": XSS_PAYLOAD, "dismissed": False,
        }],
        traffic_summary={
            "window": "24h", "packets_total": 100, "bytes_total": 5000, "bytes_in": 4000, "bytes_out": 1000,
            "active_flows": 3, "unique_remote_hosts": 2, "encrypted_bytes": 3000, "plaintext_bytes": 2000,
            "open_alerts": 1,
        },
        devices=[{
            "ip": "192.168.1.5", "mac": "AA:BB:CC:DD:EE:FF", "vendor": "Acme",
            "hostname": XSS_PAYLOAD, "risk": "high",
        }],
    )


_ALL_SECTIONS = ["summary", "posture", "threats", "recommendations", "traffic", "devices"]


class TestHtmlEscaping:
    def test_xss_payload_never_appears_unescaped(self):
        provider = _hostile_provider()
        data = build_report_data(provider, _ALL_SECTIONS, "24h", "Test report")
        html = render_html_report(data)
        assert "<script>" not in html
        assert "alert('xss')" not in html or "&lt;script&gt;" in html
        assert "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;" in html

    def test_html_is_self_contained_no_external_requests(self):
        provider = _hostile_provider()
        data = build_report_data(provider, _ALL_SECTIONS, "24h", "Test report")
        html = render_html_report(data)
        assert "http://" not in html
        assert "https://" not in html
        assert "<link" not in html
        assert "cdn." not in html

    def test_html_has_inlined_style_only(self):
        provider = _hostile_provider()
        data = build_report_data(provider, _ALL_SECTIONS, "24h", "Test report")
        html = render_html_report(data)
        assert "<style>" in html
        assert '<link rel="stylesheet"' not in html

    def test_title_field_escaped(self):
        provider = StaticReportDataProvider()
        data = build_report_data(provider, ["summary"], "24h", XSS_PAYLOAD)
        html = render_html_report(data)
        assert "<script>" not in html
        assert "&lt;script&gt;" in html


class TestMarkdownEscaping:
    def test_xss_payload_never_appears_as_raw_html(self):
        provider = _hostile_provider()
        data = build_report_data(provider, _ALL_SECTIONS, "24h", "Test report")
        md = render_markdown_report(data)
        assert "<script>" not in md
        assert "&lt;script&gt;" in md

    def test_pipe_in_value_does_not_break_table(self):
        provider = StaticReportDataProvider(
            recommendations=[{
                "id": "r1", "rule_id": "r", "title": "a | b", "severity": "low",
                "confidence": 0.5, "category": "hygiene", "summary": "x | y", "dismissed": False,
            }]
        )
        data = build_report_data(provider, ["recommendations"], "24h", "T")
        md = render_markdown_report(data)
        assert "a \\| b" in md


class TestReportDeterminism:
    def test_same_input_produces_same_content_modulo_timestamp(self):
        provider = _hostile_provider()
        data1 = build_report_data(provider, _ALL_SECTIONS, "24h", "Test report")
        data2 = build_report_data(provider, _ALL_SECTIONS, "24h", "Test report")
        html1 = render_html_report(data1)
        html2 = render_html_report(data2)
        # Strip the one field expected to vary (generated_at) before comparing.
        strip_ts = lambda s: s.split("Generated ")[0] + s.split("&middot;")[1]
        assert strip_ts(html1) == strip_ts(html2)

    def test_prioritised_findings_ranked_deterministically(self):
        provider = _hostile_provider()
        data = build_report_data(provider, ["summary"], "24h", "T")
        findings = data["prioritised_findings"]
        scores = [f["impact_score"] for f in findings]
        assert scores == sorted(scores, reverse=True)
        ranks = [f["priority_rank"] for f in findings]
        assert ranks == list(range(1, len(findings) + 1))


class TestReportsStorePruning:
    def test_50_report_cap_prunes_oldest(self, tmp_path):
        for i in range(55):
            reports_store.save_report(f"content {i}", "html", f"title {i}", "24h", ["summary"], reports_dir=tmp_path)
        remaining = reports_store.list_reports(reports_dir=tmp_path)
        assert len(remaining) == 50

    def test_pruning_keeps_newest(self, tmp_path):
        ids = []
        for i in range(55):
            meta = reports_store.save_report(f"content {i}", "html", f"title {i}", "24h", ["summary"], reports_dir=tmp_path)
            ids.append(meta["id"])
        remaining_ids = {m["id"] for m in reports_store.list_reports(reports_dir=tmp_path)}
        assert set(ids[-50:]) == remaining_ids
        assert ids[0] not in remaining_ids

    def test_get_delete_round_trip(self, tmp_path):
        meta = reports_store.save_report("hello world", "markdown", "T", "24h", ["summary"], reports_dir=tmp_path)
        content, got_meta = reports_store.get_report(meta["id"], reports_dir=tmp_path)
        assert content == "hello world"
        assert got_meta["id"] == meta["id"]

        assert reports_store.delete_report(meta["id"], reports_dir=tmp_path) is True
        assert reports_store.get_report(meta["id"], reports_dir=tmp_path) is None
        assert reports_store.delete_report(meta["id"], reports_dir=tmp_path) is False



class TestReportIdValidation:
    """report_id flows straight into filesystem paths; ids with path
    separators (/ on POSIX, \\ on Windows -- which survives URL routing
    as %5C in a single segment) must be rejected before any Path is
    built, or get/delete escape the reports dir."""

    @pytest.mark.parametrize("evil_id", [
        "../secret",
        "..\\secret",
        "..\\../secret",
        "report-20260101T000000Z-abcdef/../../secret",
    ])
    def test_traversal_id_cannot_read_or_delete_outside_reports_dir(self, tmp_path, evil_id):
        reports_dir = tmp_path / "reports"
        reports_dir.mkdir()
        secret_meta = tmp_path / "secret.meta.json"
        secret_meta.write_text('{"id": "secret", "format": "html"}', encoding="utf-8")
        secret_content = tmp_path / "secret.html"
        secret_content.write_text("top secret", encoding="utf-8")

        assert reports_store.get_report(evil_id, reports_dir=reports_dir) is None
        assert reports_store.delete_report(evil_id, reports_dir=reports_dir) is False
        assert secret_meta.exists()
        assert secret_content.exists()

    def test_generated_ids_still_round_trip(self, tmp_path):
        meta = reports_store.save_report("body", "html", "T", "24h", ["summary"], reports_dir=tmp_path)
        content, _ = reports_store.get_report(meta["id"], reports_dir=tmp_path)
        assert content == "body"
        assert reports_store.delete_report(meta["id"], reports_dir=tmp_path) is True