"""nonstandard_port_service, new_external_peer, protocol_anomaly."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from netaudit.threat.detectors.anomaly import (
    NewExternalPeerDetector,
    NonstandardPortServiceDetector,
    ProtocolAnomalyDetector,
)
from netaudit.threat.source import FlowRecord, ListTrafficSource, PacketRecord

NOW = datetime(2026, 7, 31, 14, 0, 0, tzinfo=timezone.utc)


# -- nonstandard_port_service ---------------------------------------------

def test_nonstandard_port_service_fires_on_ssh_banner_on_port_443():
    detector = NonstandardPortServiceDetector()
    pkts = [
        PacketRecord(id=1, ts=NOW - timedelta(minutes=5), protocol="tcp", src_addr="192.168.1.42",
                     src_port=51000, dst_addr="203.0.113.9", dst_port=443, direction="outbound",
                     length=64, process_name="plink.exe", summary="SSH-2.0-OpenSSH_9.3"),
    ]
    source = ListTrafficSource(packets=pkts)
    since = NOW - timedelta(hours=1)

    findings = detector.run(source, since, NOW, {})

    assert len(findings) == 1
    assert findings[0].metrics["observed_port"] == 443


def test_nonstandard_port_service_does_not_fire_on_ssh_on_port_22():
    detector = NonstandardPortServiceDetector()
    pkts = [
        PacketRecord(id=1, ts=NOW - timedelta(minutes=5), protocol="tcp", src_addr="192.168.1.42",
                     src_port=51000, dst_addr="203.0.113.9", dst_port=22, direction="outbound",
                     length=64, process_name="ssh.exe", summary="SSH-2.0-OpenSSH_9.3"),
    ]
    source = ListTrafficSource(packets=pkts)
    since = NOW - timedelta(hours=1)

    findings = detector.run(source, since, NOW, {})

    assert findings == []


# -- new_external_peer ---------------------------------------------------

def _historical_flow(i, remote_addr, days_ago):
    ts = NOW - timedelta(days=days_ago, minutes=i)
    return FlowRecord(
        id=f"hist-{i}", protocol="tcp", state="ESTABLISHED", local_addr="192.168.1.42",
        local_port=51000 + i, remote_addr=remote_addr, remote_port=443, remote_host=None,
        remote_org=None, direction="outbound", pid=400, process_name="agent.exe",
        process_path="C:\\agent.exe", bytes_in=1000, bytes_out=1000, packets=5,
        first_seen=ts, last_seen=ts, is_external=True, is_encrypted=True,
    )


def test_new_external_peer_fires_on_first_contact():
    detector = NewExternalPeerDetector()
    baseline = [_historical_flow(i, "203.0.113.9", days_ago=i + 1) for i in range(15)]
    new_contact = FlowRecord(
        id="new", protocol="tcp", state="ESTABLISHED", local_addr="192.168.1.42",
        local_port=51999, remote_addr="198.51.100.200", remote_port=443, remote_host=None,
        remote_org=None, direction="outbound", pid=400, process_name="agent.exe",
        process_path="C:\\agent.exe", bytes_in=1000, bytes_out=1000, packets=5,
        first_seen=NOW - timedelta(minutes=5), last_seen=NOW - timedelta(minutes=5),
        is_external=True, is_encrypted=True,
    )
    source = ListTrafficSource(flows=[*baseline, new_contact])
    since = NOW - timedelta(hours=1)

    findings = detector.run(source, since, NOW, detector.default_tunable_values())

    assert len(findings) == 1
    assert findings[0].evidence[1].value == "198.51.100.200"


def test_new_external_peer_does_not_fire_on_known_peer():
    detector = NewExternalPeerDetector()
    baseline = [_historical_flow(i, "203.0.113.9", days_ago=i + 1) for i in range(15)]
    repeat_contact = FlowRecord(
        id="repeat", protocol="tcp", state="ESTABLISHED", local_addr="192.168.1.42",
        local_port=51999, remote_addr="203.0.113.9", remote_port=443, remote_host=None,
        remote_org=None, direction="outbound", pid=400, process_name="agent.exe",
        process_path="C:\\agent.exe", bytes_in=1000, bytes_out=1000, packets=5,
        first_seen=NOW - timedelta(minutes=5), last_seen=NOW - timedelta(minutes=5),
        is_external=True, is_encrypted=True,
    )
    source = ListTrafficSource(flows=[*baseline, repeat_contact])
    since = NOW - timedelta(hours=1)

    findings = detector.run(source, since, NOW, detector.default_tunable_values())

    assert findings == []


# -- protocol_anomaly ---------------------------------------------------

def test_protocol_anomaly_fires_on_syn_fin_combo():
    detector = ProtocolAnomalyDetector()
    pkts = [
        PacketRecord(id=i, ts=NOW - timedelta(seconds=60 - i * 5), protocol="tcp",
                     src_addr="192.168.1.42", src_port=51000, dst_addr="203.0.113.9",
                     dst_port=1000 + i, direction="outbound", length=40, flags="SYN,FIN")
        for i in range(3)
    ]
    source = ListTrafficSource(packets=pkts)
    since = NOW - timedelta(hours=1)

    findings = detector.run(source, since, NOW, detector.default_tunable_values())

    assert len(findings) == 1
    assert findings[0].metrics["events"] == 3


def test_protocol_anomaly_does_not_fire_on_normal_flags():
    detector = ProtocolAnomalyDetector()
    pkts = [
        PacketRecord(id=1, ts=NOW - timedelta(minutes=5), protocol="tcp", src_addr="192.168.1.42",
                     src_port=51000, dst_addr="203.0.113.9", dst_port=443, direction="outbound",
                     length=1000, flags="PSH,ACK"),
        PacketRecord(id=2, ts=NOW - timedelta(minutes=4), protocol="tcp", src_addr="192.168.1.42",
                     src_port=51000, dst_addr="203.0.113.9", dst_port=443, direction="outbound",
                     length=1000, flags="SYN"),
    ]
    source = ListTrafficSource(packets=pkts)
    since = NOW - timedelta(hours=1)

    findings = detector.run(source, since, NOW, detector.default_tunable_values())

    assert findings == []
