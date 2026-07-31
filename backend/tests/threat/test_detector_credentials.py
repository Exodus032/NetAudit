"""credentials_plaintext."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from netaudit.threat.detectors.credentials import CredentialsPlaintextDetector
from netaudit.threat.source import ListTrafficSource, PacketRecord

NOW = datetime(2026, 7, 31, 14, 0, 0, tzinfo=timezone.utc)


def test_credentials_plaintext_fires_on_ftp_traffic():
    detector = CredentialsPlaintextDetector()
    pkts = [
        PacketRecord(id=1, ts=NOW - timedelta(minutes=5), protocol="tcp", src_addr="192.168.1.42",
                     src_port=51000, dst_addr="203.0.113.9", dst_port=21, direction="outbound",
                     length=64, process_name="ftp.exe", is_encrypted=False),
    ]
    source = ListTrafficSource(packets=pkts)
    since = NOW - timedelta(hours=1)

    findings = detector.run(source, since, NOW, detector.default_tunable_values())

    assert len(findings) == 1
    assert "FTP" in findings[0].title


def test_credentials_plaintext_fires_on_http_basic_auth_payload():
    detector = CredentialsPlaintextDetector()
    pkts = [
        PacketRecord(id=1, ts=NOW - timedelta(minutes=5), protocol="tcp", src_addr="192.168.1.42",
                     src_port=51000, dst_addr="203.0.113.9", dst_port=80, direction="outbound",
                     length=200, process_name="curl.exe", is_encrypted=False,
                     payload_snippet="GET /api HTTP/1.1\r\nAuthorization: Basic dXNlcjpwYXNz"),
    ]
    source = ListTrafficSource(packets=pkts)
    since = NOW - timedelta(hours=1)

    findings = detector.run(source, since, NOW, detector.default_tunable_values())

    assert len(findings) == 1
    assert "Basic" in findings[0].title


def test_credentials_plaintext_does_not_fire_on_encrypted_https_traffic():
    detector = CredentialsPlaintextDetector()
    pkts = [
        PacketRecord(id=1, ts=NOW - timedelta(minutes=5), protocol="tcp", src_addr="192.168.1.42",
                     src_port=51000, dst_addr="203.0.113.9", dst_port=443, direction="outbound",
                     length=1400, process_name="chrome.exe", is_encrypted=True),
    ]
    source = ListTrafficSource(packets=pkts)
    since = NOW - timedelta(hours=1)

    findings = detector.run(source, since, NOW, detector.default_tunable_values())

    assert findings == []


def test_credentials_plaintext_skips_http_basic_check_without_payload_snippet():
    detector = CredentialsPlaintextDetector()
    # Port 80 traffic but no payload_snippet available -- must not guess.
    pkts = [
        PacketRecord(id=1, ts=NOW - timedelta(minutes=5), protocol="tcp", src_addr="192.168.1.42",
                     src_port=51000, dst_addr="203.0.113.9", dst_port=80, direction="outbound",
                     length=200, process_name="curl.exe", is_encrypted=False, payload_snippet=None),
    ]
    source = ListTrafficSource(packets=pkts)
    since = NOW - timedelta(hours=1)

    findings = detector.run(source, since, NOW, detector.default_tunable_values())

    assert findings == []
