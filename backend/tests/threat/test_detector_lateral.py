"""lateral_smb_rdp."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from netaudit.threat.detectors.lateral import LateralSmbRdpDetector
from netaudit.threat.source import FlowRecord, ListTrafficSource

NOW = datetime(2026, 7, 31, 14, 0, 0, tzinfo=timezone.utc)


def _flow(i, remote_addr, remote_port, minutes_ago):
    ts = NOW - timedelta(minutes=minutes_ago)
    return FlowRecord(
        id=f"lat-{i}", protocol="tcp", state="ESTABLISHED", local_addr="192.168.1.42",
        local_port=50000 + i, remote_addr=remote_addr, remote_port=remote_port, remote_host=None,
        remote_org=None, direction="outbound", pid=200, process_name="psexec.exe",
        process_path="C:\\psexec.exe", bytes_in=1000, bytes_out=1000, packets=10,
        first_seen=ts, last_seen=ts, is_external=False, is_encrypted=False,
    )


def test_lateral_smb_rdp_fires_on_multiple_internal_hosts():
    detector = LateralSmbRdpDetector()
    flows = [_flow(i, f"192.168.1.{10 + i}", 445, minutes_ago=20 - i) for i in range(5)]
    source = ListTrafficSource(flows=flows)
    since = NOW - timedelta(hours=1)

    findings = detector.run(source, since, NOW, detector.default_tunable_values())

    assert len(findings) == 1
    assert findings[0].metrics["hosts_reached"] == 5


def test_lateral_smb_rdp_does_not_fire_on_single_host():
    detector = LateralSmbRdpDetector()
    flows = [_flow(i, "192.168.1.10", 445, minutes_ago=20 - i) for i in range(5)]
    source = ListTrafficSource(flows=flows)
    since = NOW - timedelta(hours=1)

    findings = detector.run(source, since, NOW, detector.default_tunable_values())

    assert findings == []


def test_lateral_smb_rdp_does_not_fire_on_external_hosts():
    detector = LateralSmbRdpDetector()
    flows = []
    for i in range(5):
        ts = NOW - timedelta(minutes=20 - i)
        flows.append(FlowRecord(
            id=f"ext-{i}", protocol="tcp", state="ESTABLISHED", local_addr="192.168.1.42",
            local_port=50000 + i, remote_addr=f"203.0.113.{10 + i}", remote_port=445,
            remote_host=None, remote_org=None, direction="outbound", pid=200,
            process_name="psexec.exe", process_path="C:\\psexec.exe", bytes_in=1000,
            bytes_out=1000, packets=10, first_seen=ts, last_seen=ts, is_external=True,
            is_encrypted=False,
        ))
    source = ListTrafficSource(flows=flows)
    since = NOW - timedelta(hours=1)

    findings = detector.run(source, since, NOW, detector.default_tunable_values())

    assert findings == []
