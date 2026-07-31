"""deprecated_protocol."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from netaudit.threat.detectors.policy import DeprecatedProtocolDetector
from netaudit.threat.source import ListTrafficSource, PacketRecord

NOW = datetime(2026, 7, 31, 14, 0, 0, tzinfo=timezone.utc)


def test_deprecated_protocol_fires_on_telnet():
    detector = DeprecatedProtocolDetector()
    pkts = [
        PacketRecord(id=1, ts=NOW - timedelta(minutes=5), protocol="tcp", src_addr="192.168.1.42",
                     src_port=51000, dst_addr="203.0.113.9", dst_port=23, direction="outbound",
                     length=64, process_name="telnet.exe"),
    ]
    source = ListTrafficSource(packets=pkts)
    since = NOW - timedelta(hours=1)

    findings = detector.run(source, since, NOW, detector.default_tunable_values())

    assert len(findings) == 1
    assert "Telnet" in findings[0].title


def test_deprecated_protocol_fires_on_sslv3():
    detector = DeprecatedProtocolDetector()
    pkts = [
        PacketRecord(id=1, ts=NOW - timedelta(minutes=5), protocol="tcp", src_addr="192.168.1.42",
                     src_port=51000, dst_addr="203.0.113.9", dst_port=8443, direction="outbound",
                     length=64, process_name="oldapp.exe", tls_version="SSLv3"),
    ]
    source = ListTrafficSource(packets=pkts)
    since = NOW - timedelta(hours=1)

    findings = detector.run(source, since, NOW, detector.default_tunable_values())

    assert len(findings) == 1
    assert "SSLv3" in findings[0].title


def test_deprecated_protocol_does_not_fire_on_modern_https():
    detector = DeprecatedProtocolDetector()
    pkts = [
        PacketRecord(id=1, ts=NOW - timedelta(minutes=5), protocol="tcp", src_addr="192.168.1.42",
                     src_port=51000, dst_addr="203.0.113.9", dst_port=443, direction="outbound",
                     length=64, process_name="chrome.exe", tls_version="TLSv1.3"),
    ]
    source = ListTrafficSource(packets=pkts)
    since = NOW - timedelta(hours=1)

    findings = detector.run(source, since, NOW, detector.default_tunable_values())

    assert findings == []
