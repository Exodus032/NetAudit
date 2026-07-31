"""c2_beaconing: fires on a regular low-jitter interval with uniform
payloads, must not fire on high-jitter/random-size traffic."""
from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

from netaudit.threat.detectors.c2 import C2BeaconingDetector
from netaudit.threat.source import ListTrafficSource, PacketRecord

NOW = datetime(2026, 7, 31, 14, 0, 0, tzinfo=timezone.utc)


def _make_packets(n, interval, jitter, length, length_jitter, start_offset_minutes=60):
    rng = random.Random(42)
    pkts = []
    t = NOW - timedelta(minutes=start_offset_minutes)
    for i in range(n):
        t = t + timedelta(seconds=interval + rng.uniform(-jitter, jitter))
        pkts.append(PacketRecord(
            id=i, ts=t, protocol="tcp", src_addr="192.168.1.42", src_port=51000,
            dst_addr="93.184.216.34", dst_port=443, direction="outbound",
            length=int(length + rng.uniform(-length_jitter, length_jitter)),
            process_name="svchost.exe", pid=1204, is_external=True,
        ))
    return pkts


def test_c2_beaconing_fires_on_regular_interval():
    detector = C2BeaconingDetector()
    pkts = _make_packets(n=20, interval=60, jitter=1.0, length=512, length_jitter=5)
    source = ListTrafficSource(packets=pkts)
    since = NOW - timedelta(hours=2)

    findings = detector.run(source, since, NOW, detector.default_tunable_values())

    assert len(findings) == 1
    f = findings[0]
    assert f.metrics["contacts"] == 20
    assert f.metrics["cv"] < 0.15
    assert f.severity == "high"
    assert "93.184.216.34" in f.title


def test_c2_beaconing_does_not_fire_on_high_jitter():
    detector = C2BeaconingDetector()
    # Same average interval but jitter comparable to the interval itself --
    # this is what ordinary bursty user-driven traffic looks like.
    pkts = _make_packets(n=20, interval=60, jitter=55.0, length=512, length_jitter=400)
    source = ListTrafficSource(packets=pkts)
    since = NOW - timedelta(hours=2)

    findings = detector.run(source, since, NOW, detector.default_tunable_values())

    assert findings == []


def test_c2_beaconing_does_not_fire_below_min_contacts():
    detector = C2BeaconingDetector()
    pkts = _make_packets(n=4, interval=60, jitter=1.0, length=512, length_jitter=5)
    source = ListTrafficSource(packets=pkts)
    since = NOW - timedelta(hours=2)

    findings = detector.run(source, since, NOW, detector.default_tunable_values())

    assert findings == []


def test_c2_beaconing_ignores_ntp_port():
    detector = C2BeaconingDetector()
    pkts = _make_packets(n=20, interval=60, jitter=1.0, length=512, length_jitter=5)
    pkts = [
        PacketRecord(**{**p.__dict__, "dst_port": 123})
        for p in pkts
    ]
    source = ListTrafficSource(packets=pkts)
    since = NOW - timedelta(hours=2)

    findings = detector.run(source, since, NOW, detector.default_tunable_values())

    assert findings == []
