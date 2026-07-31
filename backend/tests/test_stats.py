from __future__ import annotations

from netaudit.store import flows as flows_store
from netaudit.store import packets as packets_store
from netaudit.store import stats as stats_store

NOW = 1_700_001_000.0  # multiple of 60, keeps bucket math exact in tests


class TestTimeseriesZeroFill:
    def test_contiguous_and_zero_filled_minute_buckets(self, db_path):
        start = NOW - 300
        stats_store.record_batch(
            [{"ts_epoch": start + 120, "length": 1000, "direction": "inbound", "protocol": "tcp"}],
            db_path,
        )
        points = stats_store.get_timeseries("5m", 60, db_path, now=NOW)

        assert len(points) == 6
        ts = [p["t"] for p in points]
        assert ts == sorted(ts), "buckets must be oldest-first"

        nonzero = [p for p in points if p["bytes_in"] or p["packets_in"] or p["tcp"]]
        assert len(nonzero) == 1
        hit = nonzero[0]
        assert hit["bytes_in"] == 1000
        assert hit["packets_in"] == 1
        assert hit["tcp"] == 1
        assert hit["bytes_out"] == 0

        empties = [p for p in points if p is not hit]
        assert all(p["bytes_in"] == 0 and p["bytes_out"] == 0 and p["tcp"] == 0 for p in empties)

    def test_no_data_returns_all_zero_contiguous_buckets(self, db_path):
        points = stats_store.get_timeseries("5m", 60, db_path, now=NOW)
        assert len(points) == 6
        assert all(p["bytes_in"] == 0 and p["bytes_out"] == 0 for p in points)

    def test_sub_minute_buckets_use_raw_packets(self, db_path):
        start = NOW - 300
        packets_store.append_batch([{
            "ts_epoch": start + 65, "protocol": "udp", "src_addr": "10.0.0.5", "src_port": 51000,
            "dst_addr": "8.8.8.8", "dst_port": 53, "direction": "outbound", "length": 500, "flags": "",
            "process_name": None, "pid": None, "remote_addr": "8.8.8.8", "remote_host": None,
            "is_external": 1, "is_encrypted": 0, "summary": "DNS", "risk": "low",
        }], db_path)

        points = stats_store.get_timeseries("5m", 30, db_path, now=NOW)
        ts = [p["t"] for p in points]
        assert ts == sorted(ts)
        nonzero = [p for p in points if p["bytes_out"]]
        assert len(nonzero) == 1
        assert nonzero[0]["bytes_out"] == 500
        assert nonzero[0]["udp"] == 1


class TestSummary:
    def test_aggregates_within_window(self, db_path):
        start = NOW - 300
        rows = [
            {"ts_epoch": start + 10, "protocol": "tcp", "src_addr": "10.0.0.5", "src_port": 1,
             "dst_addr": "1.1.1.1", "dst_port": 443, "direction": "outbound", "length": 200, "flags": "",
             "process_name": "chrome.exe", "pid": 111, "remote_addr": "1.1.1.1", "remote_host": None,
             "is_external": 1, "is_encrypted": 1, "summary": "", "risk": "low"},
            {"ts_epoch": start + 20, "protocol": "tcp", "src_addr": "1.1.1.1", "src_port": 443,
             "dst_addr": "10.0.0.5", "dst_port": 2, "direction": "inbound", "length": 800, "flags": "",
             "process_name": "chrome.exe", "pid": 111, "remote_addr": "1.1.1.1", "remote_host": None,
             "is_external": 1, "is_encrypted": 1, "summary": "", "risk": "low"},
        ]
        packets_store.append_batch(rows, db_path)
        summary = stats_store.get_summary("5m", db_path, now=NOW)
        assert summary["packets_total"] == 2
        assert summary["bytes_total"] == 1000
        assert summary["bytes_in"] == 800
        assert summary["bytes_out"] == 200
        assert summary["tcp_packets"] == 2
        assert summary["encrypted_bytes"] == 1000
        assert summary["external_bytes"] == 1000
        assert summary["alerts_by_severity"] == {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    def test_old_data_outside_window_excluded(self, db_path):
        old = NOW - 10_000
        packets_store.append_batch([{
            "ts_epoch": old, "protocol": "tcp", "src_addr": "10.0.0.5", "src_port": 1,
            "dst_addr": "1.1.1.1", "dst_port": 443, "direction": "outbound", "length": 999, "flags": "",
            "process_name": None, "pid": None, "remote_addr": "1.1.1.1", "remote_host": None,
            "is_external": 1, "is_encrypted": 1, "summary": "", "risk": "low",
        }], db_path)
        summary = stats_store.get_summary("5m", db_path, now=NOW)
        assert summary["packets_total"] == 0
        assert summary["bytes_total"] == 0


class TestTop:
    def test_shares_sum_to_one(self, db_path):
        for i, (remote, b) in enumerate([("1.1.1.1", 100), ("2.2.2.2", 300), ("3.3.3.3", 600)]):
            flows_store.upsert_flow({
                "id": f"tcp-10.0.0.5:{5000+i}-{remote}:443", "protocol": "tcp", "state": "ESTABLISHED",
                "local_addr": "10.0.0.5", "local_port": 5000 + i, "remote_addr": remote, "remote_port": 443,
                "remote_host": None, "remote_org": None, "direction": "outbound", "pid": 100,
                "process_name": "chrome.exe", "process_path": None, "bytes_in": b, "bytes_out": 0,
                "ts_epoch": NOW - 5, "is_external": 1, "is_encrypted": 1, "risk": "low", "risk_reasons": "[]",
            }, db_path)
        items = stats_store.get_top("host", 10, "5m", db_path, now=NOW)
        assert len(items) == 3
        assert abs(sum(i["share"] for i in items) - 1.0) < 1e-6
        assert items[0]["key"] == "3.3.3.3"  # highest bytes first
