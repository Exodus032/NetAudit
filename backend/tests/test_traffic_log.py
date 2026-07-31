from __future__ import annotations

from netaudit.store.packets import LogFilters, append_batch, query_log

BASE_TS = 1_700_000_000.0


def _row(i, **overrides):
    row = {
        "ts_epoch": BASE_TS + i, "protocol": "tcp", "src_addr": "10.0.0.5", "src_port": 40000 + i,
        "dst_addr": "1.1.1.1", "dst_port": 443, "direction": "outbound", "length": 100 + i, "flags": "",
        "process_name": "chrome.exe", "pid": 111, "remote_addr": "1.1.1.1", "remote_host": "example.com",
        "is_external": 1, "is_encrypted": 1, "summary": "", "risk": "low",
    }
    row.update(overrides)
    return row


class TestPagination:
    def test_limit_offset_and_total(self, db_path):
        append_batch([_row(i) for i in range(25)], db_path)
        entries, total = query_log(LogFilters(limit=10, offset=0), db_path)
        assert total == 25
        assert len(entries) == 10

        entries2, total2 = query_log(LogFilters(limit=10, offset=20), db_path)
        assert total2 == 25
        assert len(entries2) == 5

    def test_default_sort_is_time_desc(self, db_path):
        append_batch([_row(i) for i in range(5)], db_path)
        entries, _ = query_log(LogFilters(limit=100, offset=0), db_path)
        tss = [e["ts"] for e in entries]
        assert tss == sorted(tss, reverse=True)

    def test_order_asc(self, db_path):
        append_batch([_row(i) for i in range(5)], db_path)
        entries, _ = query_log(LogFilters(limit=100, offset=0, order="asc"), db_path)
        tss = [e["ts"] for e in entries]
        assert tss == sorted(tss)


class TestFilters:
    def test_protocol_filter(self, db_path):
        append_batch([_row(0, protocol="tcp"), _row(1, protocol="udp"), _row(2, protocol="udp")], db_path)
        entries, total = query_log(LogFilters(limit=100, offset=0, protocol="udp"), db_path)
        assert total == 2
        assert all(e["protocol"] == "udp" for e in entries)

    def test_direction_filter(self, db_path):
        append_batch([_row(0, direction="outbound"), _row(1, direction="inbound")], db_path)
        entries, total = query_log(LogFilters(limit=100, offset=0, direction="inbound"), db_path)
        assert total == 1
        assert entries[0]["direction"] == "inbound"

    def test_min_bytes_filter(self, db_path):
        append_batch([_row(0, length=50), _row(1, length=500)], db_path)
        entries, total = query_log(LogFilters(limit=100, offset=0, min_bytes=100), db_path)
        assert total == 1
        assert entries[0]["length"] == 500

    def test_since_until_filter(self, db_path):
        append_batch([_row(i) for i in range(10)], db_path)
        entries, total = query_log(
            LogFilters(limit=100, offset=0, since=BASE_TS + 3, until=BASE_TS + 6), db_path,
        )
        assert total == 4  # ts 3,4,5,6

    def test_free_text_q_matches_host(self, db_path):
        append_batch([
            _row(0, remote_host="example.com"),
            _row(1, remote_host="other.net"),
        ], db_path)
        entries, total = query_log(LogFilters(limit=100, offset=0, q="example"), db_path)
        assert total == 1
        assert entries[0]["remote_host"] == "example.com"

    def test_free_text_q_matches_process(self, db_path):
        append_batch([
            _row(0, process_name="chrome.exe"),
            _row(1, process_name="curl.exe"),
        ], db_path)
        entries, total = query_log(LogFilters(limit=100, offset=0, q="curl"), db_path)
        assert total == 1
        assert entries[0]["process_name"] == "curl.exe"

    def test_free_text_q_matches_port(self, db_path):
        append_batch([_row(0, dst_port=8080), _row(1, dst_port=443)], db_path)
        entries, total = query_log(LogFilters(limit=100, offset=0, q="8080"), db_path)
        assert total == 1
        assert entries[0]["dst_port"] == 8080

    def test_sort_by_bytes(self, db_path):
        append_batch([_row(0, length=10), _row(1, length=999), _row(2, length=50)], db_path)
        entries, _ = query_log(LogFilters(limit=100, offset=0, sort="bytes", order="desc"), db_path)
        assert [e["length"] for e in entries] == [999, 50, 10]

    def test_combined_filters_and_total_reflects_filtered_set(self, db_path):
        append_batch([
            _row(0, protocol="tcp", direction="outbound", length=1000),
            _row(1, protocol="udp", direction="outbound", length=1000),
            _row(2, protocol="tcp", direction="inbound", length=1000),
            _row(3, protocol="tcp", direction="outbound", length=10),
        ], db_path)
        entries, total = query_log(
            LogFilters(limit=100, offset=0, protocol="tcp", direction="outbound", min_bytes=100), db_path,
        )
        assert total == 1
        assert entries[0]["protocol"] == "tcp"
        assert entries[0]["direction"] == "outbound"
