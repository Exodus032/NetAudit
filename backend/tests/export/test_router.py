from __future__ import annotations

import json
import threading

from netaudit.export import events as events_mod
from netaudit.export.provider import StaticReportDataProvider
from netaudit.store.packets import append_batch

BASE_TS = 1_700_000_000.0


def _row(i, **overrides):
    row = {
        "ts_epoch": BASE_TS + i, "protocol": "tcp", "src_addr": "10.0.0.5", "src_port": 40000 + i,
        "dst_addr": "1.1.1.1", "dst_port": 443, "direction": "outbound", "length": 100 + i, "flags": "ACK",
        "process_name": "chrome.exe", "pid": 111, "remote_addr": "1.1.1.1", "remote_host": "example.com",
        "is_external": 1, "is_encrypted": 1, "summary": "TLS data", "risk": "low",
    }
    row.update(overrides)
    return row


_SAMPLE_PROVIDER = StaticReportDataProvider(
    security_score={"generated_at": None, "overall": 70, "grade": "B", "components": [], "history": [], "top_wins": []},
    posture_report={
        "generated_at": None, "scan_duration_ms": 10, "score": 70, "grade": "B",
        "counts": {"pass": 1, "warn": 0, "fail": 1, "error": 0, "skipped": 0}, "categories": [],
        "checks": [{"id": "c1", "category": "firewall", "title": "Check 1", "status": "fail",
                    "severity": "high", "observed": "bad", "checked_at": "2026-07-31T14:00:00Z",
                    "remediation": {"summary": "fix", "commands": [{"command": "x"}]}}],
    },
    threats=[{"id": "t1", "detector_id": "d1", "title": "Threat 1", "severity": "high", "confidence": 0.8,
              "category": "command_and_control", "status": "active", "summary": "bad stuff",
              "last_seen": "2026-07-31T14:00:00Z", "mitre": [{"technique": "T1071.001"}],
              "indicators": [{"type": "ip", "value": "9.9.9.9"}]}],
    recommendations=[{"id": "r1", "rule_id": "rule1", "title": "Rec 1", "severity": "medium",
                       "confidence": 0.7, "category": "hygiene", "summary": "do this",
                       "last_seen": "2026-07-31T14:00:00Z", "dismissed": False}],
    traffic_summary={"window": "24h", "packets_total": 10},
    devices=[{"ip": "192.168.1.5", "mac": "AA:BB:CC:DD:EE:FF", "vendor": "Acme", "hostname": "h", "risk": "low"}],
)


# --- E5: reports ---------------------------------------------------------


class TestCreateReport:
    def test_default_html_report(self, client, override_provider):
        override_provider(_SAMPLE_PROVIDER)
        resp = client.post("/api/reports", json={})
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        assert "X-NetAudit-Report-Id" in resp.headers
        assert resp.text.startswith("<!doctype html>")
        assert "Threat 1" in resp.text
        assert "Rec 1" in resp.text

    def test_markdown_report(self, client, override_provider):
        override_provider(_SAMPLE_PROVIDER)
        resp = client.post("/api/reports", json={"format": "markdown", "sections": ["summary"]})
        assert resp.status_code == 200
        assert "text/markdown" in resp.headers["content-type"]
        assert resp.text.startswith("# ")

    def test_json_report(self, client, override_provider):
        override_provider(_SAMPLE_PROVIDER)
        resp = client.post("/api/reports", json={"format": "json", "sections": ["threats", "devices"]})
        assert resp.status_code == 200
        body = json.loads(resp.text)
        assert body["threats"][0]["title"] == "Threat 1"
        assert body["devices"][0]["ip"] == "192.168.1.5"
        assert "posture" not in body

    def test_invalid_format_is_400(self, client, override_provider):
        override_provider(_SAMPLE_PROVIDER)
        resp = client.post("/api/reports", json={"format": "pdf"})
        assert resp.status_code == 400
        assert resp.json()["error"]["code"] == "invalid_format"

    def test_invalid_section_is_400(self, client, override_provider):
        override_provider(_SAMPLE_PROVIDER)
        resp = client.post("/api/reports", json={"sections": ["nonsense"]})
        assert resp.status_code == 400

    def test_custom_title_and_window(self, client, override_provider):
        override_provider(_SAMPLE_PROVIDER)
        resp = client.post("/api/reports", json={"title": "Weekly network audit", "window": "7d", "sections": ["summary"]})
        assert "Weekly network audit" in resp.text


class TestReportsListGetDelete:
    def test_list_after_create(self, client, override_provider):
        override_provider(_SAMPLE_PROVIDER)
        create_resp = client.post("/api/reports", json={"sections": ["summary"]})
        report_id = create_resp.headers["X-NetAudit-Report-Id"]

        list_resp = client.get("/api/reports")
        assert list_resp.status_code == 200
        ids = [r["id"] for r in list_resp.json()["reports"]]
        assert report_id in ids

    def test_get_returns_same_content(self, client, override_provider):
        override_provider(_SAMPLE_PROVIDER)
        create_resp = client.post("/api/reports", json={"format": "markdown", "sections": ["summary"]})
        report_id = create_resp.headers["X-NetAudit-Report-Id"]

        get_resp = client.get(f"/api/reports/{report_id}")
        assert get_resp.status_code == 200
        assert get_resp.text == create_resp.text

    def test_get_unknown_is_404(self, client):
        resp = client.get("/api/reports/does-not-exist")
        assert resp.status_code == 404

    def test_delete_then_get_is_404(self, client, override_provider):
        override_provider(_SAMPLE_PROVIDER)
        create_resp = client.post("/api/reports", json={"sections": ["summary"]})
        report_id = create_resp.headers["X-NetAudit-Report-Id"]

        del_resp = client.delete(f"/api/reports/{report_id}")
        assert del_resp.status_code == 200
        assert del_resp.json() == {"id": report_id, "deleted": True}

        assert client.get(f"/api/reports/{report_id}").status_code == 404

    def test_delete_unknown_is_404(self, client):
        resp = client.delete("/api/reports/does-not-exist")
        assert resp.status_code == 404

    def test_get_traversal_id_is_404(self, client):
        # %5C decodes to a backslash but stays one path segment, so the
        # raw id reaches the handler with a Windows path separator in it.
        resp = client.get("/api/reports/..%5C..%5Csecret")
        assert resp.status_code == 404

    def test_delete_traversal_id_is_404(self, client):
        resp = client.delete("/api/reports/..%5C..%5Csecret")
        assert resp.status_code == 404


# --- E6: SIEM export -------------------------------------------------------


class TestExportEvents:
    def test_jsonl_includes_all_kinds(self, client, override_provider, isolated_env):
        override_provider(_SAMPLE_PROVIDER)
        append_batch([_row(0), _row(1)], isolated_env["live_db"])

        resp = client.get("/api/export/events", params={"format": "jsonl"})
        assert resp.status_code == 200
        assert "application/x-ndjson" in resp.headers["content-type"]
        lines = [ln for ln in resp.text.splitlines() if ln.strip()]
        kinds = {json.loads(ln)["kind"] for ln in lines}
        assert kinds == {"threat", "recommendation", "posture", "traffic"}

    def test_kinds_filter(self, client, override_provider, isolated_env):
        override_provider(_SAMPLE_PROVIDER)
        append_batch([_row(0)], isolated_env["live_db"])

        resp = client.get("/api/export/events", params={"format": "jsonl", "kinds": "threat,traffic"})
        lines = [json.loads(ln) for ln in resp.text.splitlines() if ln.strip()]
        kinds = {ln["kind"] for ln in lines}
        assert kinds == {"threat", "traffic"}

    def test_invalid_format_is_400(self, client):
        resp = client.get("/api/export/events", params={"format": "xml"})
        assert resp.status_code == 400

    def test_invalid_kinds_is_400(self, client):
        resp = client.get("/api/export/events", params={"format": "jsonl", "kinds": "bogus"})
        assert resp.status_code == 400

    def test_missing_format_is_422(self, client):
        resp = client.get("/api/export/events")
        assert resp.status_code == 422  # required query param

    def test_ecs_format(self, client, override_provider):
        override_provider(_SAMPLE_PROVIDER)
        resp = client.get("/api/export/events", params={"format": "ecs", "kinds": "threat"})
        assert resp.status_code == 200
        line = resp.text.splitlines()[0]
        parsed = json.loads(line)
        assert "@timestamp" in parsed
        assert parsed["event"]["kind"] == "threat"

    def test_cef_format(self, client, override_provider):
        override_provider(_SAMPLE_PROVIDER)
        resp = client.get("/api/export/events", params={"format": "cef", "kinds": "recommendation"})
        assert resp.status_code == 200
        assert resp.text.startswith("CEF:0|NetAudit|NetAudit|")

    def test_syslog_format(self, client, override_provider):
        override_provider(_SAMPLE_PROVIDER)
        resp = client.get("/api/export/events", params={"format": "syslog", "kinds": "posture"})
        assert resp.status_code == 200
        assert resp.text.startswith("<")
        assert "netaudit@" in resp.text

    def test_traffic_since_until_filters(self, client, override_provider, isolated_env):
        override_provider(_SAMPLE_PROVIDER)
        append_batch([_row(i) for i in range(10)], isolated_env["live_db"])

        from netaudit.timeutil import iso_z
        resp = client.get("/api/export/events", params={
            "format": "jsonl", "kinds": "traffic",
            "since": iso_z(BASE_TS + 3), "until": iso_z(BASE_TS + 6),
        })
        lines = [json.loads(ln) for ln in resp.text.splitlines() if ln.strip()]
        assert len(lines) == 4  # ts 3,4,5,6

    def test_content_disposition_filename(self, client, override_provider):
        override_provider(_SAMPLE_PROVIDER)
        resp = client.get("/api/export/events", params={"format": "jsonl", "kinds": "threat"})
        assert "netaudit-events-" in resp.headers["content-disposition"]

    def test_traffic_stream_survives_cross_thread_iteration(self, isolated_env):
        """StreamingResponse pulls each chunk of a sync generator through a
        threadpool, so successive next() calls can land on different
        threads. The sqlite connection is thread-local with
        check_same_thread=True; the traffic rows must be materialised in a
        single resume or iteration crashes mid-stream."""
        append_batch([_row(i) for i in range(5)], isolated_env["live_db"])
        it = events_mod.iter_events(
            _SAMPLE_PROVIDER, {"traffic"}, db_path=isolated_env["live_db"],
        )

        def next_on_fresh_thread():
            box = {}

            def _step():
                try:
                    box["value"] = next(it)
                except StopIteration:
                    pass
                except Exception as exc:  # pragma: no cover -- the regression itself
                    box["error"] = exc

            t = threading.Thread(target=_step)
            t.start()
            t.join()
            if "error" in box:
                raise box["error"]
            return box.get("value")

        events = []
        while (ev := next_on_fresh_thread()) is not None:
            events.append(ev)
        assert len(events) == 5
        assert all(ev["kind"] == "traffic" for ev in events)
