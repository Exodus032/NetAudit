"""arp_spoofing, mac_flapping, rogue_dhcp."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from netaudit.threat.detectors.spoofing import ArpSpoofingDetector, MacFlappingDetector, RogueDhcpDetector
from netaudit.threat.source import ArpRecord, ListTrafficSource

NOW = datetime(2026, 7, 31, 14, 0, 0, tzinfo=timezone.utc)


def test_arp_spoofing_fires_on_gateway_mac_change():
    detector = ArpSpoofingDetector()
    records = [
        ArpRecord(ts=NOW - timedelta(minutes=10), ip="192.168.1.1", mac="AA:BB:CC:11:22:33",
                  event="reply", is_gateway=True),
        ArpRecord(ts=NOW - timedelta(minutes=5), ip="192.168.1.1", mac="DE:AD:BE:EF:00:01",
                  event="gratuitous", is_gateway=True),
    ]
    source = ListTrafficSource(arp_events=records)
    since = NOW - timedelta(hours=1)

    findings = detector.run(source, since, NOW, detector.default_tunable_values())

    gateway_findings = [f for f in findings if f.key.startswith("arp-gateway-mac-change")]
    assert len(gateway_findings) == 1
    assert gateway_findings[0].severity == "critical"


def test_arp_spoofing_fires_on_one_mac_claiming_multiple_ips():
    detector = ArpSpoofingDetector()
    records = [
        ArpRecord(ts=NOW - timedelta(minutes=10), ip="192.168.1.50", mac="DE:AD:BE:EF:00:01", event="reply"),
        ArpRecord(ts=NOW - timedelta(minutes=8), ip="192.168.1.51", mac="DE:AD:BE:EF:00:01", event="reply"),
        ArpRecord(ts=NOW - timedelta(minutes=6), ip="192.168.1.52", mac="DE:AD:BE:EF:00:01", event="gratuitous"),
    ]
    source = ListTrafficSource(arp_events=records)
    since = NOW - timedelta(hours=1)

    findings = detector.run(source, since, NOW, detector.default_tunable_values())

    multi_ip_findings = [f for f in findings if f.key.startswith("arp-multi-ip")]
    assert len(multi_ip_findings) == 1
    assert multi_ip_findings[0].metrics["claimed_ip_count"] == 3


def test_arp_spoofing_does_not_fire_on_stable_bindings():
    detector = ArpSpoofingDetector()
    # One gateway, one MAC, no changes -- exactly what a healthy LAN looks like.
    records = [
        ArpRecord(ts=NOW - timedelta(minutes=m), ip="192.168.1.1", mac="AA:BB:CC:11:22:33",
                  event="reply", is_gateway=True)
        for m in range(10, 0, -2)
    ]
    source = ListTrafficSource(arp_events=records)
    since = NOW - timedelta(hours=1)

    findings = detector.run(source, since, NOW, detector.default_tunable_values())

    assert findings == []


def test_mac_flapping_fires_on_rapid_alternation():
    detector = MacFlappingDetector()
    macs = ["AA:AA:AA:AA:AA:AA", "BB:BB:BB:BB:BB:BB"]
    records = [
        ArpRecord(ts=NOW - timedelta(seconds=50 - i * 5), ip="192.168.1.77",
                  mac=macs[i % 2], event="reply")
        for i in range(10)
    ]
    source = ListTrafficSource(arp_events=records)
    since = NOW - timedelta(hours=1)

    findings = detector.run(source, since, NOW, detector.default_tunable_values())

    assert len(findings) == 1
    assert findings[0].metrics["transitions"] >= 3


def test_mac_flapping_does_not_fire_on_single_stable_binding():
    detector = MacFlappingDetector()
    records = [
        ArpRecord(ts=NOW - timedelta(seconds=50 - i * 5), ip="192.168.1.77",
                  mac="AA:AA:AA:AA:AA:AA", event="reply")
        for i in range(10)
    ]
    source = ListTrafficSource(arp_events=records)
    since = NOW - timedelta(hours=1)

    findings = detector.run(source, since, NOW, detector.default_tunable_values())

    assert findings == []


def test_rogue_dhcp_fires_on_second_server():
    detector = RogueDhcpDetector()
    records = [
        ArpRecord(ts=NOW - timedelta(minutes=m), ip="0.0.0.0", mac="AA:AA:AA:AA:AA:AA",
                  event="dhcp_offer", dhcp_server_ip="192.168.1.1")
        for m in range(10, 0, -1)
    ]
    # A rogue offer from an unexpected server.
    records.append(ArpRecord(ts=NOW - timedelta(minutes=1), ip="0.0.0.0", mac="DE:AD:BE:EF:00:02",
                              event="dhcp_offer", dhcp_server_ip="192.168.1.250"))
    source = ListTrafficSource(arp_events=records)
    since = NOW - timedelta(hours=1)

    findings = detector.run(source, since, NOW, detector.default_tunable_values())

    assert len(findings) == 1
    assert findings[0].metrics["known_server"] == "192.168.1.1"


def test_rogue_dhcp_does_not_fire_when_only_one_server_seen():
    detector = RogueDhcpDetector()
    records = [
        ArpRecord(ts=NOW - timedelta(minutes=m), ip="0.0.0.0", mac="AA:AA:AA:AA:AA:AA",
                  event="dhcp_offer", dhcp_server_ip="192.168.1.1")
        for m in range(10, 0, -1)
    ]
    source = ListTrafficSource(arp_events=records)
    since = NOW - timedelta(hours=1)

    findings = detector.run(source, since, NOW, detector.default_tunable_values())

    assert findings == []
