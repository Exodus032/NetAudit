from __future__ import annotations

import json

import psutil
import pytest

from netaudit.rules import builtin, engine
from netaudit.rules.base import RuleContext
from netaudit.store import db as dbmod
from netaudit.store import devices as devices_store
from netaudit.store import flows as flows_store
from netaudit.store import packets as packets_store

NOW = 1_700_001_000.0


def make_flow(db_path, **overrides):
    row = {
        "id": overrides.get("id") or f"tcp-10.0.0.5:{50000}-{overrides.get('remote_addr','1.1.1.1')}:{overrides.get('remote_port',443)}",
        "protocol": "tcp", "state": "ESTABLISHED", "local_addr": "10.0.0.5", "local_port": 50000,
        "remote_addr": "1.1.1.1", "remote_port": 443, "remote_host": None, "remote_org": None,
        "direction": "outbound", "pid": 100, "process_name": "app.exe", "process_path": None,
        "bytes_in": 0, "bytes_out": 0, "ts_epoch": NOW, "is_external": 1, "is_encrypted": 0,
        "risk": "low", "risk_reasons": "[]",
    }
    row.update(overrides)
    flows_store.upsert_flow(row, db_path)


def make_packet(db_path, **overrides):
    row = {
        "ts_epoch": NOW, "protocol": "tcp", "src_addr": "10.0.0.5", "src_port": 50000,
        "dst_addr": "1.1.1.1", "dst_port": 443, "direction": "outbound", "length": 100, "flags": "",
        "process_name": "app.exe", "pid": 100, "remote_addr": "1.1.1.1", "remote_host": None,
        "is_external": 1, "is_encrypted": 0, "summary": "", "risk": "low",
    }
    row.update(overrides)
    packets_store.append_batch([row], db_path)


def make_device(db_path, **overrides):
    row = {
        "ip": "192.168.1.50", "mac": "AA:BB:CC:DD:EE:FF", "vendor": "Unknown", "hostname": None,
        "ts_epoch": NOW, "bytes_total": 0, "is_gateway": 0, "is_self": 0, "open_ports": "[]", "risk": "low",
    }
    row.update(overrides)
    devices_store.upsert_device(row, db_path)


def build_ctx(db_path, capture_mode="npcap", elevated=True, window_seconds=3600.0):
    conn = dbmod.get_conn(db_path)
    return RuleContext(
        now=NOW, window_seconds=window_seconds,
        flows=conn.execute("SELECT * FROM flows").fetchall(),
        packets=conn.execute("SELECT * FROM packets").fetchall(),
        devices=conn.execute("SELECT * FROM devices").fetchall(),
        capture_mode=capture_mode, elevated=elevated,
    )


def keys(findings):
    return {f.key for f in findings}


class TestPlaintextHttp:
    def test_triggers_on_meaningful_volume(self, db_path):
        make_flow(db_path, remote_port=80, bytes_in=6000, bytes_out=0, is_external=1)
        findings = list(builtin.PlaintextHttpRule().evaluate(build_ctx(db_path)))
        assert len(findings) == 1
        assert findings[0].severity == "medium"

    def test_near_miss_below_volume_floor(self, db_path):
        make_flow(db_path, remote_port=80, bytes_in=100, bytes_out=0, is_external=1)
        findings = list(builtin.PlaintextHttpRule().evaluate(build_ctx(db_path)))
        assert findings == []

    def test_near_miss_internal_not_flagged(self, db_path):
        make_flow(db_path, remote_port=80, bytes_in=6000, bytes_out=0, is_external=0)
        findings = list(builtin.PlaintextHttpRule().evaluate(build_ctx(db_path)))
        assert findings == []


class TestPlaintextDns:
    def test_triggers_without_dot(self, db_path):
        make_flow(db_path, id="udp-a", remote_port=53, bytes_in=3000, bytes_out=0, protocol="udp")
        findings = list(builtin.PlaintextDnsRule().evaluate(build_ctx(db_path)))
        assert len(findings) == 1

    def test_near_miss_when_dot_present(self, db_path):
        make_flow(db_path, id="udp-a", remote_port=53, bytes_in=3000, bytes_out=0, protocol="udp")
        make_flow(db_path, id="tcp-dot", remote_port=853, bytes_in=100, bytes_out=0, protocol="tcp")
        findings = list(builtin.PlaintextDnsRule().evaluate(build_ctx(db_path)))
        assert findings == []


class TestListeningExposed:
    def test_triggers_on_all_interfaces_bind(self, db_path, monkeypatch):
        conn = _fake_conn(status=psutil.CONN_LISTEN, laddr_ip="0.0.0.0", laddr_port=445, pid=4)
        monkeypatch.setattr(psutil, "net_connections", lambda kind="inet": [conn])
        monkeypatch.setattr(psutil, "Process", lambda pid: _FakeProcess("smb.exe"))
        findings = list(builtin.ListeningExposedRule().evaluate(build_ctx(db_path)))
        assert len(findings) == 1
        assert findings[0].severity == "high"

    def test_near_miss_localhost_only(self, db_path, monkeypatch):
        conn = _fake_conn(status=psutil.CONN_LISTEN, laddr_ip="127.0.0.1", laddr_port=8000, pid=4)
        monkeypatch.setattr(psutil, "net_connections", lambda kind="inet": [conn])
        findings = list(builtin.ListeningExposedRule().evaluate(build_ctx(db_path)))
        assert findings == []


class TestUnusualPort:
    def test_triggers_on_sustained_uncommon_port(self, db_path, monkeypatch):
        monkeypatch.setattr(builtin.UnusualPortRule, "MIN_BYTES", 1000)
        monkeypatch.setattr(builtin.UnusualPortRule, "MIN_PACKETS", 1)
        make_flow(db_path, remote_port=54321, bytes_in=5000, bytes_out=0, is_external=1)
        findings = list(builtin.UnusualPortRule().evaluate(build_ctx(db_path)))
        assert len(findings) == 1

    def test_near_miss_recognized_service_port(self, db_path, monkeypatch):
        monkeypatch.setattr(builtin.UnusualPortRule, "MIN_BYTES", 1000)
        monkeypatch.setattr(builtin.UnusualPortRule, "MIN_PACKETS", 1)
        make_flow(db_path, remote_port=443, bytes_in=5000, bytes_out=0, is_external=1)
        findings = list(builtin.UnusualPortRule().evaluate(build_ctx(db_path)))
        assert findings == []


class TestBeaconing:
    def test_triggers_on_regular_small_payloads(self, db_path):
        for i in range(10):
            make_packet(db_path, ts_epoch=NOW + i * 30, length=200, remote_addr="9.9.9.9", pid=200, dst_addr="9.9.9.9")
        findings = list(builtin.BeaconingRule().evaluate(build_ctx(db_path)))
        assert len(findings) == 1

    def test_near_miss_irregular_intervals(self, db_path):
        import random
        rng = random.Random(1)
        t = NOW
        for i in range(10):
            t += rng.choice([5, 200, 2, 900, 40, 600, 3, 500, 10])
            make_packet(db_path, ts_epoch=t, length=200, remote_addr="9.9.9.8", pid=201, dst_addr="9.9.9.8")
        findings = list(builtin.BeaconingRule().evaluate(build_ctx(db_path)))
        assert findings == []

    def test_near_miss_too_few_samples(self, db_path):
        for i in range(5):
            make_packet(db_path, ts_epoch=NOW + i * 30, length=200, remote_addr="9.9.9.7", pid=202, dst_addr="9.9.9.7")
        findings = list(builtin.BeaconingRule().evaluate(build_ctx(db_path)))
        assert findings == []


class TestHeavyTalker:
    def test_triggers_when_process_dominates(self, db_path, monkeypatch):
        monkeypatch.setattr(builtin.HeavyTalkerRule, "MIN_WINDOW_BYTES", 1000)
        make_flow(db_path, id="a", pid=1, process_name="big.exe", remote_addr="1.1.1.1", bytes_in=9000, bytes_out=0)
        make_flow(db_path, id="b", pid=2, process_name="small.exe", remote_addr="2.2.2.2", bytes_in=100, bytes_out=0)
        findings = list(builtin.HeavyTalkerRule().evaluate(build_ctx(db_path)))
        assert any(f.key == "heavy_process_1" for f in findings)

    def test_near_miss_evenly_distributed(self, db_path, monkeypatch):
        monkeypatch.setattr(builtin.HeavyTalkerRule, "MIN_WINDOW_BYTES", 1000)
        for i in range(4):
            make_flow(db_path, id=f"f{i}", pid=i, process_name=f"p{i}.exe", remote_addr=f"1.1.1.{i}", bytes_in=1000, bytes_out=0)
        findings = list(builtin.HeavyTalkerRule().evaluate(build_ctx(db_path)))
        assert findings == []


class TestManyPeers:
    def test_triggers_on_large_peer_fanout(self, db_path, monkeypatch):
        monkeypatch.setattr(builtin.ManyPeersRule, "MIN_PEERS", 3)
        for i in range(5):
            make_flow(db_path, id=f"f{i}", pid=9, process_name="scanner.exe", remote_addr=f"5.5.5.{i}", is_external=1)
        findings = list(builtin.ManyPeersRule().evaluate(build_ctx(db_path)))
        assert len(findings) == 1

    def test_near_miss_few_peers(self, db_path, monkeypatch):
        monkeypatch.setattr(builtin.ManyPeersRule, "MIN_PEERS", 3)
        for i in range(2):
            make_flow(db_path, id=f"f{i}", pid=9, process_name="scanner.exe", remote_addr=f"5.5.5.{i}", is_external=1)
        findings = list(builtin.ManyPeersRule().evaluate(build_ctx(db_path)))
        assert findings == []


class TestInsecureLanService:
    def test_triggers_on_ftp_open(self, db_path):
        make_device(db_path, ip="192.168.1.60", open_ports=json.dumps([21, 80]))
        findings = list(builtin.InsecureLanServiceRule().evaluate(build_ctx(db_path)))
        assert len(findings) == 1

    def test_near_miss_only_safe_ports(self, db_path):
        make_device(db_path, ip="192.168.1.61", open_ports=json.dumps([443, 80]))
        findings = list(builtin.InsecureLanServiceRule().evaluate(build_ctx(db_path)))
        assert findings == []


class TestStaleCaptureTier:
    def test_triggers_when_polling(self, db_path):
        findings = list(builtin.StaleCaptureTierRule().evaluate(build_ctx(db_path, capture_mode="polling")))
        assert len(findings) == 1
        assert findings[0].severity == "info"

    def test_near_miss_when_npcap(self, db_path):
        findings = list(builtin.StaleCaptureTierRule().evaluate(build_ctx(db_path, capture_mode="npcap")))
        assert findings == []


class TestBroadcastNoise:
    def test_triggers_on_high_volume(self, db_path, monkeypatch):
        monkeypatch.setattr(builtin.BroadcastNoiseRule, "MIN_COUNT", 5)
        for i in range(10):
            make_packet(db_path, ts_epoch=NOW + i, dst_addr="192.168.1.5", dst_port=5355, protocol="udp")
        findings = list(builtin.BroadcastNoiseRule().evaluate(build_ctx(db_path)))
        assert len(findings) == 1

    def test_near_miss_low_volume(self, db_path, monkeypatch):
        monkeypatch.setattr(builtin.BroadcastNoiseRule, "MIN_COUNT", 50)
        for i in range(3):
            make_packet(db_path, ts_epoch=NOW + i, dst_addr="192.168.1.5", dst_port=5355, protocol="udp")
        findings = list(builtin.BroadcastNoiseRule().evaluate(build_ctx(db_path)))
        assert findings == []


class TestEngineDedupAndDismiss:
    def test_run_once_upserts_and_second_run_bumps_occurrences(self, db_path, monkeypatch):
        monkeypatch.setattr(psutil, "net_connections", lambda kind="inet": [])
        ctx = build_ctx(db_path, capture_mode="polling")
        engine.run_once(ctx, db_path)
        recs = engine.list_recommendations(True, db_path)
        stale = [r for r in recs if r["rule_id"] == "stale_capture_tier"]
        assert len(stale) == 1
        assert stale[0]["occurrences"] == 1

        engine.run_once(ctx, db_path)
        recs = engine.list_recommendations(True, db_path)
        stale = [r for r in recs if r["rule_id"] == "stale_capture_tier"]
        assert len(stale) == 1  # deduped, not a second row
        assert stale[0]["occurrences"] == 2

    def test_dismiss_hides_from_default_list_and_restore_brings_back(self, db_path, monkeypatch):
        monkeypatch.setattr(psutil, "net_connections", lambda kind="inet": [])
        ctx = build_ctx(db_path, capture_mode="polling")
        engine.run_once(ctx, db_path)
        rec_id = engine.list_recommendations(True, db_path)[0]["id"]

        result = engine.set_dismissed(rec_id, True, db_path)
        assert result == {"id": rec_id, "dismissed": True}
        assert engine.list_recommendations(False, db_path) == []
        assert len(engine.list_recommendations(True, db_path)) == 1

        engine.set_dismissed(rec_id, False, db_path)
        assert len(engine.list_recommendations(False, db_path)) == 1

    def test_dismiss_unknown_id_returns_none(self, db_path, monkeypatch):
        monkeypatch.setattr(psutil, "net_connections", lambda kind="inet": [])
        assert engine.set_dismissed("nope-0000", True, db_path) is None


# --- tiny fakes for psutil-dependent ListeningExposedRule tests ------------

class _FakeAddr:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port


class _FakeConn:
    def __init__(self, status, laddr, pid):
        self.status = status
        self.laddr = laddr
        self.pid = pid


class _FakeProcess:
    def __init__(self, name):
        self._name = name

    def name(self):
        return self._name

    def exe(self):
        return f"C:\\fake\\{self._name}"


def _fake_conn(status, laddr_ip, laddr_port, pid):
    return _FakeConn(status, _FakeAddr(laddr_ip, laddr_port), pid)
