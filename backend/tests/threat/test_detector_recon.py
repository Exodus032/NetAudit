"""port_scan_outbound, port_scan_inbound, host_sweep."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from netaudit.threat.detectors.recon import HostSweepDetector, PortScanInboundDetector, PortScanOutboundDetector
from netaudit.threat.source import ListTrafficSource, PacketRecord

NOW = datetime(2026, 7, 31, 14, 0, 0, tzinfo=timezone.utc)


def _pkt(i, ts, src, sport, dst, dport, direction):
    return PacketRecord(id=i, ts=ts, protocol="tcp", src_addr=src, src_port=sport,
                         dst_addr=dst, dst_port=dport, direction=direction, length=64,
                         process_name="scanner.exe" if direction == "outbound" else None)


def test_port_scan_outbound_fires_on_many_ports_in_short_window():
    detector = PortScanOutboundDetector()
    pkts = [
        _pkt(i, NOW - timedelta(seconds=200 - i * 5), "192.168.1.42", 51000 + i,
             "93.184.216.34", 1000 + i, "outbound")
        for i in range(20)
    ]
    source = ListTrafficSource(packets=pkts)
    since = NOW - timedelta(hours=1)

    findings = detector.run(source, since, NOW, detector.default_tunable_values())

    assert len(findings) == 1
    assert findings[0].metrics["distinct_ports"] == 20


def test_port_scan_outbound_does_not_fire_on_normal_traffic():
    detector = PortScanOutboundDetector()
    # Same peer, but only ever port 443 -- a normal HTTPS session.
    pkts = [
        _pkt(i, NOW - timedelta(seconds=200 - i * 5), "192.168.1.42", 51000 + i,
             "93.184.216.34", 443, "outbound")
        for i in range(20)
    ]
    source = ListTrafficSource(packets=pkts)
    since = NOW - timedelta(hours=1)

    findings = detector.run(source, since, NOW, detector.default_tunable_values())

    assert findings == []


def test_port_scan_inbound_fires_on_many_ports_probed():
    detector = PortScanInboundDetector()
    pkts = [
        _pkt(i, NOW - timedelta(seconds=200 - i * 5), "203.0.113.50", 40000 + i,
             "192.168.1.42", 1000 + i, "inbound")
        for i in range(20)
    ]
    source = ListTrafficSource(packets=pkts)
    since = NOW - timedelta(hours=1)

    findings = detector.run(source, since, NOW, detector.default_tunable_values())

    assert len(findings) == 1
    assert findings[0].metrics["distinct_ports"] == 20


def test_port_scan_inbound_does_not_fire_on_single_port_traffic():
    detector = PortScanInboundDetector()
    pkts = [
        _pkt(i, NOW - timedelta(seconds=200 - i * 5), "203.0.113.50", 40000 + i,
             "192.168.1.42", 443, "inbound")
        for i in range(20)
    ]
    source = ListTrafficSource(packets=pkts)
    since = NOW - timedelta(hours=1)

    findings = detector.run(source, since, NOW, detector.default_tunable_values())

    assert findings == []


def test_host_sweep_fires_on_many_internal_hosts_contacted():
    detector = HostSweepDetector()
    pkts = [
        _pkt(i, NOW - timedelta(seconds=200 - i * 5), "203.0.113.50", 40000,
             f"192.168.1.{10 + i}", 445, "inbound")
        for i in range(10)
    ]
    source = ListTrafficSource(packets=pkts)
    since = NOW - timedelta(hours=1)

    findings = detector.run(source, since, NOW, detector.default_tunable_values())

    assert len(findings) == 1
    assert findings[0].metrics["hosts_contacted"] == 10


def test_host_sweep_does_not_fire_on_single_host_contact():
    detector = HostSweepDetector()
    pkts = [
        _pkt(i, NOW - timedelta(seconds=200 - i * 5), "203.0.113.50", 40000,
             "192.168.1.10", 445, "inbound")
        for i in range(10)
    ]
    source = ListTrafficSource(packets=pkts)
    since = NOW - timedelta(hours=1)

    findings = detector.run(source, since, NOW, detector.default_tunable_values())

    assert findings == []
