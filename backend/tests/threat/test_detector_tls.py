"""suspicious_tls."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from netaudit.threat.detectors.tls import SuspiciousTlsDetector
from netaudit.threat.source import ListTrafficSource, PacketRecord

NOW = datetime(2026, 7, 31, 14, 0, 0, tzinfo=timezone.utc)


def test_suspicious_tls_fires_on_weak_version_and_self_signed_cert():
    detector = SuspiciousTlsDetector()
    pkts = [
        PacketRecord(id=1, ts=NOW - timedelta(minutes=5), protocol="tcp", src_addr="192.168.1.42",
                     src_port=51000, dst_addr="203.0.113.9", dst_port=8443, direction="outbound",
                     length=1000, process_name="oddapp.exe", is_encrypted=True,
                     tls_version="TLSv1.0", tls_cert_self_signed=True, tls_cert_expired=False),
    ]
    source = ListTrafficSource(packets=pkts)
    since = NOW - timedelta(hours=1)

    findings = detector.run(source, since, NOW, detector.default_tunable_values())

    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert findings[0].metrics["score"] >= 0.7


def test_suspicious_tls_does_not_fire_on_healthy_modern_tls():
    detector = SuspiciousTlsDetector()
    pkts = [
        PacketRecord(id=1, ts=NOW - timedelta(minutes=5), protocol="tcp", src_addr="192.168.1.42",
                     src_port=51000, dst_addr="93.184.216.34", dst_port=443, direction="outbound",
                     length=1000, process_name="chrome.exe", is_encrypted=True,
                     tls_version="TLSv1.3", tls_sni="example.com", tls_alpn="h2",
                     tls_cert_self_signed=False, tls_cert_expired=False),
    ]
    source = ListTrafficSource(packets=pkts)
    since = NOW - timedelta(hours=1)

    findings = detector.run(source, since, NOW, detector.default_tunable_values())

    assert findings == []


def test_suspicious_tls_skips_cleanly_without_handshake_metadata():
    detector = SuspiciousTlsDetector()
    # is_encrypted=True but the capture layer never parsed a handshake --
    # every tls_* field is None. Must not guess.
    pkts = [
        PacketRecord(id=1, ts=NOW - timedelta(minutes=5), protocol="tcp", src_addr="192.168.1.42",
                     src_port=51000, dst_addr="93.184.216.34", dst_port=443, direction="outbound",
                     length=1000, process_name="chrome.exe", is_encrypted=True),
    ]
    source = ListTrafficSource(packets=pkts)
    since = NOW - timedelta(hours=1)

    findings = detector.run(source, since, NOW, detector.default_tunable_values())

    assert findings == []
