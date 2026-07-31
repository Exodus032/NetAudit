from __future__ import annotations

import io

from netaudit.pcap import format as pcapfmt
from netaudit.pcap import import_pipeline
from netaudit.store.packets import append_batch

BASE_TS = 1_700_000_000.0


def _row(i, **overrides):
    row = {
        "ts_epoch": BASE_TS + i, "protocol": "tcp", "src_addr": "10.0.0.5", "src_port": 40000 + i,
        "dst_addr": "1.1.1.1", "dst_port": 443, "direction": "outbound", "length": 100 + i, "flags": "ACK",
        "process_name": "chrome.exe", "pid": 111, "remote_addr": "1.1.1.1", "remote_host": "example.com",
        "is_external": 1, "is_encrypted": 1, "summary": "", "risk": "low",
    }
    row.update(overrides)
    return row


def _valid_pcap_upload_bytes() -> bytes:
    buf = bytearray()
    buf += pcapfmt.write_global_header(snaplen=65535, linktype=1)
    for i in range(3):
        data = b"X" * (30 + i)
        buf += pcapfmt.write_packet_record(1700000000 + i, i, len(data), len(data), data)
    return bytes(buf)


# --- E1: export --------------------------------------------------------------


class TestExportPcap:
    def test_export_produces_a_real_pcap_file(self, client, isolated_dbs):
        append_batch([_row(i) for i in range(5)], isolated_dbs["live_db"])
        resp = client.get("/api/capture/pcap")
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/vnd.tcpdump.pcap"
        assert "attachment" in resp.headers["content-disposition"]
        assert "netaudit-" in resp.headers["content-disposition"]

        body = resp.content
        buf = io.BytesIO(body)
        header = pcapfmt.read_global_header(buf)
        assert header.network == 1
        records = list(pcapfmt.read_pcap_records(buf, header))
        assert len(records) == 5

    def test_export_respects_protocol_filter(self, client, isolated_dbs):
        append_batch([
            _row(0, protocol="tcp"), _row(1, protocol="udp"), _row(2, protocol="udp"),
        ], isolated_dbs["live_db"])
        resp = client.get("/api/capture/pcap", params={"protocol": "udp"})
        buf = io.BytesIO(resp.content)
        header = pcapfmt.read_global_header(buf)
        records = list(pcapfmt.read_pcap_records(buf, header))
        assert len(records) == 2

    def test_export_respects_port_filter(self, client, isolated_dbs):
        append_batch([
            _row(0, src_port=1111, dst_port=443),
            _row(1, src_port=2222, dst_port=8080),
        ], isolated_dbs["live_db"])
        resp = client.get("/api/capture/pcap", params={"port": 443})
        buf = io.BytesIO(resp.content)
        header = pcapfmt.read_global_header(buf)
        records = list(pcapfmt.read_pcap_records(buf, header))
        assert len(records) == 1

    def test_export_respects_peer_filter(self, client, isolated_dbs):
        append_batch([
            _row(0, src_addr="10.0.0.5", dst_addr="1.1.1.1"),
            _row(1, src_addr="10.0.0.5", dst_addr="9.9.9.9"),
        ], isolated_dbs["live_db"])
        resp = client.get("/api/capture/pcap", params={"peer": "9.9.9.9"})
        buf = io.BytesIO(resp.content)
        header = pcapfmt.read_global_header(buf)
        records = list(pcapfmt.read_pcap_records(buf, header))
        assert len(records) == 1

    def test_invalid_protocol_is_400(self, client, isolated_dbs):
        resp = client.get("/api/capture/pcap", params={"protocol": "bogus"})
        assert resp.status_code == 400
        assert resp.json()["error"]["code"] == "invalid_protocol"

    def test_invalid_port_is_400(self, client, isolated_dbs):
        resp = client.get("/api/capture/pcap", params={"port": 99999})
        assert resp.status_code == 400

    def test_zero_limit_is_400(self, client, isolated_dbs):
        resp = client.get("/api/capture/pcap", params={"limit": 0})
        assert resp.status_code == 400

    def test_limit_is_clamped_to_hard_cap(self, client, isolated_dbs):
        append_batch([_row(i) for i in range(3)], isolated_dbs["live_db"])
        resp = client.get("/api/capture/pcap", params={"limit": 999_999_999})
        assert resp.status_code == 200  # clamped, not rejected -- matches MAX_LIMIT-style behavior elsewhere

    def test_export_with_no_packets_still_produces_valid_empty_pcap(self, client, isolated_dbs):
        resp = client.get("/api/capture/pcap")
        assert resp.status_code == 200
        buf = io.BytesIO(resp.content)
        header = pcapfmt.read_global_header(buf)
        records = list(pcapfmt.read_pcap_records(buf, header))
        assert records == []


# --- E2: import ----------------------------------------------------------------


class TestImportPcap:
    def test_import_valid_pcap(self, client):
        raw = _valid_pcap_upload_bytes()
        resp = client.post(
            "/api/capture/pcap/import",
            files={"file": ("suspicious.pcap", raw, "application/vnd.tcpdump.pcap")},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["packets"] == 3
        assert body["filename"] == "suspicious.pcap"
        assert body["session_id"].startswith("imported-")
        assert body["linktype"] == "EN10MB"
        assert body["truncated"] is False
        assert body["parse_errors"] == 0
        assert body["first_packet"] is not None
        assert body["last_packet"] is not None

    def test_import_malformed_file_is_400(self, client):
        resp = client.post(
            "/api/capture/pcap/import",
            files={"file": ("bad.pcap", b"not a pcap file at all", "application/octet-stream")},
        )
        assert resp.status_code == 400
        assert resp.json()["error"]["code"] == "invalid_pcap"

    def test_import_oversized_upload_is_413(self, client, monkeypatch):
        monkeypatch.setattr(import_pipeline, "MAX_UPLOAD_BYTES", 100)
        raw = b"A" * 1000
        resp = client.post(
            "/api/capture/pcap/import",
            files={"file": ("big.pcap", raw, "application/octet-stream")},
        )
        assert resp.status_code == 413


# --- E3: sessions ----------------------------------------------------------------


class TestSessions:
    def test_live_session_always_present(self, client):
        resp = client.get("/api/sessions")
        assert resp.status_code == 200
        sessions = resp.json()["sessions"]
        assert any(s["id"] == "live" and s["kind"] == "live" and s["synthetic"] is True for s in sessions)

    def test_imported_session_appears_after_import(self, client):
        raw = _valid_pcap_upload_bytes()
        import_resp = client.post(
            "/api/capture/pcap/import",
            files={"file": ("evidence.pcap", raw, "application/octet-stream")},
        )
        session_id = import_resp.json()["session_id"]

        list_resp = client.get("/api/sessions")
        sessions = list_resp.json()["sessions"]
        imported = [s for s in sessions if s["id"] == session_id]
        assert len(imported) == 1
        assert imported[0]["kind"] == "imported"
        assert imported[0]["synthetic"] is False
        assert imported[0]["label"] == "evidence.pcap"
        assert "imported_at" in imported[0]

    def test_cannot_delete_live_session(self, client):
        resp = client.delete("/api/sessions/live")
        assert resp.status_code == 400

    def test_delete_unknown_session_is_404(self, client):
        resp = client.delete("/api/sessions/imported-2020-01-01-ffff")
        assert resp.status_code == 404

    def test_delete_imported_session_removes_it(self, client):
        raw = _valid_pcap_upload_bytes()
        import_resp = client.post(
            "/api/capture/pcap/import",
            files={"file": ("temp.pcap", raw, "application/octet-stream")},
        )
        session_id = import_resp.json()["session_id"]

        del_resp = client.delete(f"/api/sessions/{session_id}")
        assert del_resp.status_code == 200
        assert del_resp.json() == {"id": session_id, "deleted": True}

        list_resp = client.get("/api/sessions")
        ids = [s["id"] for s in list_resp.json()["sessions"]]
        assert session_id not in ids


# --- E4: capture filter ----------------------------------------------------------


class TestCaptureFilter:
    def test_default_state(self, client):
        resp = client.get("/api/capture/filter")
        assert resp.status_code == 200
        body = resp.json()
        assert body["expression"] == ""
        assert body["valid"] is True
        assert body["error"] is None
        assert body["active"] is False

    def test_put_valid_expression(self, client):
        resp = client.put("/api/capture/filter", json={"expression": "tcp port 443 or udp port 53"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["valid"] is True
        assert body["active"] is True
        assert body["expression"] == "tcp port 443 or udp port 53"
        assert body["compiled_summary"]

        get_resp = client.get("/api/capture/filter")
        assert get_resp.json()["expression"] == "tcp port 443 or udp port 53"

    def test_put_invalid_expression_is_400_and_does_not_change_state(self, client):
        first = client.put("/api/capture/filter", json={"expression": "tcp port 443"})
        assert first.status_code == 200

        bad = client.put("/api/capture/filter", json={"expression": "tcp and"})
        assert bad.status_code == 400
        err = bad.json()["error"]
        assert "position" in err

        still = client.get("/api/capture/filter")
        assert still.json()["expression"] == "tcp port 443"
        assert still.json()["active"] is True

    def test_put_empty_expression_clears_filter(self, client):
        client.put("/api/capture/filter", json={"expression": "tcp"})
        resp = client.put("/api/capture/filter", json={"expression": ""})
        assert resp.status_code == 200
        body = resp.json()
        assert body["active"] is False
        assert body["expression"] == ""
