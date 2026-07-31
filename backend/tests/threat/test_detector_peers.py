"""known_bad_peer, tor_or_proxy, crypto_mining.

known_bad_peer reads through `intel.bundled`'s indicator index. It's tested
against a temporary fixture indicators file (not the real shipped
`data/indicators.json`) so these tests never depend on -- or need to be
updated when someone edits -- the real bundled data. The fixture entry
below is clearly a test-only marker, not a real IOC.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from netaudit.threat.detectors.peers import CryptoMiningDetector, KnownBadPeerDetector, TorOrProxyDetector
from netaudit.threat.intel import bundled
from netaudit.threat.source import FlowRecord, ListTrafficSource

NOW = datetime(2026, 7, 31, 14, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def fixture_index(tmp_path):
    data = [
        {
            "value": "198.51.100.77", "type": "ip", "category": "scanner", "confidence": 0.9,
            "source": "test-fixture", "note": "Test-only marker, not a real indicator.",
            "first_added": "2026-01-01",
        },
    ]
    path = tmp_path / "indicators.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return bundled.load(path)


def _flow(i, remote_addr, remote_port, process="app.exe", remote_host=None, minutes_ago=10, bytes_out=1000):
    ts = NOW - timedelta(minutes=minutes_ago)
    return FlowRecord(
        id=f"f-{i}", protocol="tcp", state="ESTABLISHED", local_addr="192.168.1.42",
        local_port=50000 + i, remote_addr=remote_addr, remote_port=remote_port,
        remote_host=remote_host, remote_org=None, direction="outbound", pid=300,
        process_name=process, process_path=f"C:\\{process}", bytes_in=500, bytes_out=bytes_out,
        packets=10, first_seen=ts, last_seen=ts, is_external=True, is_encrypted=True,
    )


def test_known_bad_peer_fires_on_bundled_match(fixture_index, monkeypatch):
    monkeypatch.setattr(bundled, "_default_index", fixture_index)
    detector = KnownBadPeerDetector()
    flows = [_flow(0, "198.51.100.77", 443)]
    source = ListTrafficSource(flows=flows)
    since = NOW - timedelta(hours=1)

    findings = detector.run(source, since, NOW, {})

    assert len(findings) == 1
    assert findings[0].metrics["match_count"] == 1


def test_known_bad_peer_does_not_fire_on_unlisted_peer(fixture_index, monkeypatch):
    monkeypatch.setattr(bundled, "_default_index", fixture_index)
    detector = KnownBadPeerDetector()
    flows = [_flow(0, "203.0.113.44", 443)]
    source = ListTrafficSource(flows=flows)
    since = NOW - timedelta(hours=1)

    findings = detector.run(source, since, NOW, {})

    assert findings == []


def test_tor_or_proxy_fires_on_known_proxy_port():
    detector = TorOrProxyDetector()
    flows = [_flow(0, "203.0.113.44", 9050)]
    source = ListTrafficSource(flows=flows)
    since = NOW - timedelta(hours=1)

    findings = detector.run(source, since, NOW, {})

    assert len(findings) == 1
    assert findings[0].metrics["port"] == 9050


def test_tor_or_proxy_does_not_fire_on_ordinary_https_port():
    detector = TorOrProxyDetector()
    flows = [_flow(0, "203.0.113.44", 443)]
    source = ListTrafficSource(flows=flows)
    since = NOW - timedelta(hours=1)

    findings = detector.run(source, since, NOW, {})

    assert findings == []


def test_crypto_mining_fires_on_known_pool_domain():
    detector = CryptoMiningDetector()
    flows = [_flow(0, "203.0.113.44", 4444, remote_host="minexmr.com")]
    source = ListTrafficSource(flows=flows)
    since = NOW - timedelta(hours=1)

    findings = detector.run(source, since, NOW, detector.default_tunable_values())

    assert len(findings) == 1
    assert findings[0].metrics["port"] == 4444


def test_crypto_mining_does_not_fire_on_unrelated_traffic():
    detector = CryptoMiningDetector()
    flows = [_flow(0, "93.184.216.34", 443, remote_host="example.com")]
    source = ListTrafficSource(flows=flows)
    since = NOW - timedelta(hours=1)

    findings = detector.run(source, since, NOW, detector.default_tunable_values())

    assert findings == []
