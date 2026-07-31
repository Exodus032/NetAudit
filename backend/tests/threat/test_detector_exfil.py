"""dns_exfil_volume, data_exfiltration, off_hours_transfer."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from netaudit.threat.detectors.exfil import (
    DataExfiltrationDetector,
    DnsExfilVolumeDetector,
    OffHoursTransferDetector,
)
from netaudit.threat.source import DnsRecord, FlowRecord, ListTrafficSource

NOW = datetime(2026, 7, 31, 14, 0, 0, tzinfo=timezone.utc)


def _flow(i, process, remote_addr, bytes_out, bytes_in=0, minutes_ago=30, is_external=True):
    ts = NOW - timedelta(minutes=minutes_ago)
    return FlowRecord(
        id=f"tcp-{i}", protocol="tcp", state="ESTABLISHED", local_addr="192.168.1.42",
        local_port=51000 + i, remote_addr=remote_addr, remote_port=443, remote_host=None,
        remote_org=None, direction="outbound", pid=100, process_name=process,
        process_path=f"C:\\{process}", bytes_in=bytes_in, bytes_out=bytes_out, packets=10,
        first_seen=ts, last_seen=ts, is_external=is_external, is_encrypted=True,
    )


# -- dns_exfil_volume ---------------------------------------------------

def test_dns_exfil_volume_fires_on_dns_heavy_egress():
    detector = DnsExfilVolumeDetector()
    records = [
        DnsRecord(ts=NOW - timedelta(seconds=i * 10), query=f"chunk{i}.exfil.example",
                  qtype="TXT", process_name="agent.exe", query_bytes=1500, response_bytes=1500)
        for i in range(40)
    ]
    # Only a trivial amount of non-DNS egress -- DNS dominates this process's traffic.
    flows = [_flow(0, "agent.exe", "10.0.0.5", bytes_out=500, is_external=False)]
    source = ListTrafficSource(dns_events=records, flows=flows)
    since = NOW - timedelta(hours=1)

    findings = detector.run(source, since, NOW, detector.default_tunable_values())

    assert len(findings) == 1
    assert findings[0].metrics["ratio"] > 0.1


def test_dns_exfil_volume_does_not_fire_on_normal_dns_use():
    detector = DnsExfilVolumeDetector()
    records = [
        DnsRecord(ts=NOW - timedelta(seconds=i * 10), query="example.com", qtype="A",
                  process_name="chrome.exe", query_bytes=40, response_bytes=60)
        for i in range(25)
    ]
    # Large ordinary HTTPS egress dwarfs the tiny DNS volume.
    flows = [_flow(0, "chrome.exe", "93.184.216.34", bytes_out=50_000_000)]
    source = ListTrafficSource(dns_events=records, flows=flows)
    since = NOW - timedelta(hours=1)

    findings = detector.run(source, since, NOW, detector.default_tunable_values())

    assert findings == []


# -- data_exfiltration ---------------------------------------------------

def test_data_exfiltration_fires_far_above_baseline():
    detector = DataExfiltrationDetector()
    baseline_flows = [
        _flow(i, "backup.exe", "203.0.113.9", bytes_out=1_000_000, minutes_ago=60 * 24 * (i + 1))
        for i in range(10)
    ]
    spike_flow = _flow(999, "backup.exe", "203.0.113.9", bytes_out=200_000_000, minutes_ago=5)
    source = ListTrafficSource(flows=[*baseline_flows, spike_flow])
    since = NOW - timedelta(hours=1)
    tunables = {**detector.default_tunable_values(), "lookback_hours": 400}

    findings = detector.run(source, since, NOW, tunables)

    assert len(findings) == 1
    assert findings[0].metrics["bytes_out"] == 200_000_000
    assert findings[0].metrics["baseline_samples"] == 10


def test_data_exfiltration_does_not_fire_within_baseline():
    detector = DataExfiltrationDetector()
    baseline_flows = [
        _flow(i, "backup.exe", "203.0.113.9", bytes_out=10_000_000, minutes_ago=60 * 24 * (i + 1))
        for i in range(10)
    ]
    normal_flow = _flow(999, "backup.exe", "203.0.113.9", bytes_out=10_500_000, minutes_ago=5)
    source = ListTrafficSource(flows=[*baseline_flows, normal_flow])
    since = NOW - timedelta(hours=1)

    findings = detector.run(source, since, NOW, detector.default_tunable_values())

    assert findings == []


def test_data_exfiltration_does_not_fire_without_enough_baseline_samples():
    detector = DataExfiltrationDetector()
    # Only 2 historical samples -- below min_samples=5, so no baseline yet.
    baseline_flows = [
        _flow(i, "newapp.exe", "203.0.113.9", bytes_out=1_000_000, minutes_ago=60 * 24 * (i + 1))
        for i in range(2)
    ]
    spike_flow = _flow(999, "newapp.exe", "203.0.113.9", bytes_out=200_000_000, minutes_ago=5)
    source = ListTrafficSource(flows=[*baseline_flows, spike_flow])
    since = NOW - timedelta(hours=1)

    findings = detector.run(source, since, NOW, detector.default_tunable_values())

    assert findings == []


# -- off_hours_transfer ---------------------------------------------------

def test_off_hours_transfer_fires_at_historically_silent_hour():
    detector = OffHoursTransferDetector()
    # Historical activity for this process only ever happens at hour 9 (09:xx).
    baseline_flows = []
    for day in range(1, 15):
        ts = (NOW - timedelta(days=day)).replace(hour=9, minute=0, second=0, microsecond=0)
        baseline_flows.append(FlowRecord(
            id=f"hist-{day}", protocol="tcp", state="ESTABLISHED", local_addr="192.168.1.42",
            local_port=51000, remote_addr="203.0.113.20", remote_port=443, remote_host=None,
            remote_org=None, direction="outbound", pid=100, process_name="nightjob.exe",
            process_path="C:\\nightjob.exe", bytes_in=0, bytes_out=100_000, packets=5,
            first_seen=ts, last_seen=ts, is_external=True, is_encrypted=True,
        ))
    # Current window: a big transfer at 03:00, an hour with zero history.
    off_hour_ts = NOW.replace(hour=3, minute=0, second=0, microsecond=0)
    spike = FlowRecord(
        id="spike", protocol="tcp", state="ESTABLISHED", local_addr="192.168.1.42",
        local_port=51999, remote_addr="203.0.113.20", remote_port=443, remote_host=None,
        remote_org=None, direction="outbound", pid=100, process_name="nightjob.exe",
        process_path="C:\\nightjob.exe", bytes_in=0, bytes_out=5_000_000, packets=50,
        first_seen=off_hour_ts, last_seen=off_hour_ts, is_external=True, is_encrypted=True,
    )
    source = ListTrafficSource(flows=[*baseline_flows, spike])
    since = off_hour_ts - timedelta(minutes=5)
    until = off_hour_ts + timedelta(minutes=5)

    findings = detector.run(source, since, until, detector.default_tunable_values())

    assert len(findings) == 1
    assert findings[0].metrics["hour"] == 3


def test_off_hours_transfer_does_not_fire_during_active_hour():
    detector = OffHoursTransferDetector()
    baseline_flows = []
    for day in range(1, 15):
        ts = (NOW - timedelta(days=day)).replace(hour=9, minute=0, second=0, microsecond=0)
        baseline_flows.append(FlowRecord(
            id=f"hist-{day}", protocol="tcp", state="ESTABLISHED", local_addr="192.168.1.42",
            local_port=51000, remote_addr="203.0.113.20", remote_port=443, remote_host=None,
            remote_org=None, direction="outbound", pid=100, process_name="nightjob.exe",
            process_path="C:\\nightjob.exe", bytes_in=0, bytes_out=100_000, packets=5,
            first_seen=ts, last_seen=ts, is_external=True, is_encrypted=True,
        ))
    # Same hour (9am) as the established baseline -- expected, not off-hours.
    active_hour_ts = NOW.replace(hour=9, minute=30, second=0, microsecond=0)
    normal = FlowRecord(
        id="normal", protocol="tcp", state="ESTABLISHED", local_addr="192.168.1.42",
        local_port=51999, remote_addr="203.0.113.20", remote_port=443, remote_host=None,
        remote_org=None, direction="outbound", pid=100, process_name="nightjob.exe",
        process_path="C:\\nightjob.exe", bytes_in=0, bytes_out=5_000_000, packets=50,
        first_seen=active_hour_ts, last_seen=active_hour_ts, is_external=True, is_encrypted=True,
    )
    source = ListTrafficSource(flows=[*baseline_flows, normal])
    since = active_hour_ts - timedelta(minutes=35)
    until = active_hour_ts + timedelta(minutes=5)

    findings = detector.run(source, since, until, detector.default_tunable_values())

    assert findings == []
