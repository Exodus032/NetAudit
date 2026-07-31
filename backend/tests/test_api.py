from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from netaudit.rules import engine as rules_engine
from netaudit.rules.base import RuleContext
from netaudit.rules.builtin import StaleCaptureTierRule
from netaudit.server import create_app
from netaudit.store import db as dbmod
from netaudit.store.packets import append_batch

NOW = 1_700_001_000.0


@pytest.fixture
def app_client(tmp_path):
    db_path = tmp_path / "api-test.db"
    app = create_app(db_path=db_path, autostart_capture=False)
    with TestClient(app) as client:
        yield client, db_path
    dbmod.reset_for_tests(db_path)


class TestHealth:
    def test_shape(self, app_client):
        client, _ = app_client
        r = client.get("/api/health")
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "ok"
        assert isinstance(body["uptime_seconds"], (int, float))
        cap = body["capture"]
        assert cap["mode"] in ("npcap", "rawsocket", "polling", "off")
        assert set(cap.keys()) == {"mode", "elevated", "interface", "running", "degraded_reason"}


class TestInterfaces:
    def test_shape(self, app_client):
        client, _ = app_client
        r = client.get("/api/interfaces")
        assert r.status_code == 200
        body = r.json()
        assert "interfaces" in body and "default_interface_id" in body
        assert isinstance(body["interfaces"], list)
        if body["interfaces"]:
            iface = body["interfaces"][0]
            assert {"id", "name", "description", "ipv4", "ipv6", "mac", "netmask",
                     "is_up", "is_loopback", "speed_mbps"} <= set(iface.keys())


class TestStats:
    def test_summary_shape_and_fields(self, app_client):
        client, _ = app_client
        r = client.get("/api/stats/summary?window=5m")
        assert r.status_code == 200
        body = r.json()
        expected = {
            "window", "generated_at", "packets_total", "bytes_total", "bytes_in", "bytes_out",
            "packets_in", "packets_out", "throughput_bps_in", "throughput_bps_out",
            "peak_throughput_bps", "active_flows", "unique_remote_hosts", "unique_processes",
            "tcp_packets", "udp_packets", "icmp_packets", "other_packets", "encrypted_bytes",
            "plaintext_bytes", "external_bytes", "internal_bytes", "open_alerts", "alerts_by_severity",
        }
        assert expected == set(body.keys())
        assert body["generated_at"].endswith("Z")

    def test_summary_invalid_window_errors(self, app_client):
        client, _ = app_client
        r = client.get("/api/stats/summary?window=bogus")
        assert r.status_code == 400
        assert "error" in r.json()
        assert "code" in r.json()["error"] and "message" in r.json()["error"]

    def test_timeseries_zero_fill_shape(self, app_client):
        client, _ = app_client
        r = client.get("/api/stats/timeseries?window=5m&bucket=60")
        assert r.status_code == 200
        body = r.json()
        assert body["bucket_seconds"] == 60
        assert len(body["points"]) >= 5
        ts = [p["t"] for p in body["points"]]
        assert ts == sorted(ts)
        for p in body["points"]:
            assert set(p.keys()) == {"t", "bytes_in", "bytes_out", "packets_in", "packets_out", "tcp", "udp", "icmp", "other"}

    def test_top_shape(self, app_client):
        client, _ = app_client
        r = client.get("/api/stats/top?by=host&limit=5&window=5m")
        assert r.status_code == 200
        body = r.json()
        assert body["by"] == "host"
        assert isinstance(body["items"], list)


class TestConnections:
    def test_shape(self, app_client):
        client, _ = app_client
        r = client.get("/api/connections")
        assert r.status_code == 200
        body = r.json()
        assert "generated_at" in body and "connections" in body


class TestTrafficLog:
    def test_log_and_export(self, app_client):
        client, db_path = app_client
        rows = [{
            "ts_epoch": NOW + i, "protocol": "tcp", "src_addr": "10.0.0.5", "src_port": 40000 + i,
            "dst_addr": "1.1.1.1", "dst_port": 443, "direction": "outbound", "length": 100, "flags": "",
            "process_name": "chrome.exe", "pid": 111, "remote_addr": "1.1.1.1", "remote_host": "example.com",
            "is_external": 1, "is_encrypted": 1, "summary": "TLS application data", "risk": "low",
        } for i in range(3)]
        append_batch(rows, db_path)

        r = client.get("/api/traffic/log?limit=2")
        assert r.status_code == 200
        body = r.json()
        assert body["total"] == 3
        assert body["limit"] == 2
        assert len(body["entries"]) == 2
        entry = body["entries"][0]
        assert set(entry.keys()) == {
            "id", "ts", "protocol", "src_addr", "src_port", "dst_addr", "dst_port", "direction",
            "length", "flags", "process_name", "pid", "remote_host", "is_external", "is_encrypted",
            "summary", "risk",
        }

        r_csv = client.get("/api/traffic/export?format=csv")
        assert r_csv.status_code == 200
        assert r_csv.headers["content-type"].startswith("text/csv")
        assert "attachment; filename=" in r_csv.headers["content-disposition"]
        assert "netaudit-log-" in r_csv.headers["content-disposition"]


class TestDevices:
    def test_shape(self, app_client):
        client, _ = app_client
        r = client.get("/api/devices")
        assert r.status_code == 200
        assert "devices" in r.json()


class TestRecommendations:
    def test_list_dismiss_restore(self, app_client):
        client, db_path = app_client
        ctx = RuleContext(now=NOW, window_seconds=3600.0, flows=[], packets=[], devices=[],
                           capture_mode="polling", elevated=True)
        rules_engine.run_once(ctx, db_path)

        r = client.get("/api/recommendations")
        assert r.status_code == 200
        body = r.json()
        assert "generated_at" in body
        assert len(body["recommendations"]) >= 1
        rec = body["recommendations"][0]
        assert {"id", "rule_id", "title", "severity", "confidence", "category", "summary", "detail",
                "evidence", "actions", "first_seen", "last_seen", "occurrences", "dismissed",
                "related_connection_ids"} <= set(rec.keys())

        rec_id = rec["id"]
        r_dismiss = client.post(f"/api/recommendations/{rec_id}/dismiss")
        assert r_dismiss.status_code == 200
        assert r_dismiss.json() == {"id": rec_id, "dismissed": True}

        r_list = client.get("/api/recommendations")
        assert all(r["id"] != rec_id for r in r_list.json()["recommendations"])

        r_list_all = client.get("/api/recommendations?include_dismissed=true")
        assert any(r["id"] == rec_id for r in r_list_all.json()["recommendations"])

        r_restore = client.post(f"/api/recommendations/{rec_id}/restore")
        assert r_restore.json() == {"id": rec_id, "dismissed": False}

    def test_dismiss_unknown_id_404(self, app_client):
        client, _ = app_client
        r = client.post("/api/recommendations/does-not-exist/dismiss")
        assert r.status_code == 404
        assert "error" in r.json()


class TestCaptureControl:
    def test_status_and_clear(self, app_client):
        client, db_path = app_client
        r = client.get("/api/capture/status")
        assert r.status_code == 200
        assert set(r.json().keys()) == {"mode", "elevated", "interface", "running", "degraded_reason"}

        append_batch([{
            "ts_epoch": NOW, "protocol": "tcp", "src_addr": "10.0.0.5", "src_port": 1,
            "dst_addr": "1.1.1.1", "dst_port": 443, "direction": "outbound", "length": 1, "flags": "",
            "process_name": None, "pid": None, "remote_addr": "1.1.1.1", "remote_host": None,
            "is_external": 1, "is_encrypted": 1, "summary": "", "risk": "low",
        }], db_path)

        r_clear = client.post("/api/capture/clear")
        assert r_clear.status_code == 200
        assert r_clear.json() == {"cleared": True}

        r_log = client.get("/api/traffic/log")
        assert r_log.json()["total"] == 0


class TestCors:
    def test_cors_headers_present_for_allowed_origin(self, app_client):
        client, _ = app_client
        r = client.get("/api/health", headers={"Origin": "http://localhost:5173"})
        assert r.headers.get("access-control-allow-origin") == "http://localhost:5173"
