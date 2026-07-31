"""dns_exfil_volume, data_exfiltration, off_hours_transfer: three ways
"too many bytes left in a way that doesn't match how this host normally
behaves" can show up. The first uses a fixed expected-ratio heuristic
(DNS is a low-bandwidth control-plane protocol; no amount of history makes
a large fraction of egress over DNS normal). The other two compare against
a rolling per-process/per-peer baseline and must not fire until it has
enough samples -- see baseline.py."""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta

from ..baseline import Baseline
from ..mitre import mitre_ref
from ..models import Action, Evidence, Indicator, TunableSpec
from ..source import DnsRecord, FlowRecord, TrafficSource
from .base import Detector, Finding


class DnsExfilVolumeDetector(Detector):
    id = "dns_exfil_volume"
    label = "DNS exfiltration volume"
    category = "exfiltration"
    description = "Outbound bytes over DNS far exceeding a normal ratio of total egress."
    default_severity = "high"
    mitre = [mitre_ref("TA0010", "T1048.003")]
    tunables = [
        TunableSpec(key="max_normal_ratio", value=0.1, type="float", min=0.01, max=1.0,
                    description="DNS bytes as a fraction of total egress bytes above which this is abnormal. DNS is a control-plane protocol -- even with no history, a large share of egress over it is not normal."),
        TunableSpec(key="min_dns_bytes", value=50000, type="int", min=1000, max=100000000,
                    description="Minimum absolute DNS byte volume before this is worth reporting (avoids flagging trivial resolution overhead)."),
        TunableSpec(key="min_queries", value=20, type="int", min=5, max=5000,
                    description="Minimum query count before this is worth reporting."),
    ]

    def run(self, source: TrafficSource, since: datetime, until: datetime, tunables: dict) -> list[Finding]:
        max_ratio = float(tunables["max_normal_ratio"])
        min_dns_bytes = int(tunables["min_dns_bytes"])
        min_queries = int(tunables["min_queries"])

        dns_by_process: dict[str, list[DnsRecord]] = defaultdict(list)
        for d in source.dns_events(since, until):
            dns_by_process[d.process_name or "unknown"].append(d)

        other_bytes_by_process: dict[str, int] = defaultdict(int)
        for f in source.flows(since, until):
            other_bytes_by_process[f.process_name or "unknown"] += f.bytes_out

        findings: list[Finding] = []
        for process, records in dns_by_process.items():
            if len(records) < min_queries:
                continue
            dns_bytes = sum((r.query_bytes or 0) + (r.response_bytes or 0) for r in records)
            if dns_bytes < min_dns_bytes:
                continue
            other_bytes = other_bytes_by_process.get(process, 0)
            total = dns_bytes + other_bytes
            ratio = dns_bytes / total if total > 0 else 1.0
            if ratio < max_ratio:
                continue

            confidence = round(min(0.9, 0.4 + min(ratio / (max_ratio * 4), 1.0) * 0.35 + min(len(records) / 200, 1.0) * 0.15), 2)

            findings.append(Finding(
                key=f"dns-exfil|{process}",
                title=f"{process} sent {dns_bytes / 1024:.0f} KB over DNS ({ratio:.0%} of its egress)",
                severity=self.default_severity,
                confidence=confidence,
                summary=f"{dns_bytes / 1024:.0f} KB of this process's egress went out over DNS, {ratio:.0%} of its total.",
                detail=(
                    f"{process} generated {len(records)} DNS queries totalling {dns_bytes} bytes of query+response "
                    f"traffic, {ratio:.0%} of its total observed egress in this window. DNS is a low-bandwidth "
                    f"control-plane protocol: even without a learned baseline, a large share of a process's "
                    f"egress moving over DNS instead of its normal application protocol is abnormal on its own, "
                    f"and is a known technique for exfiltrating data past firewalls that allow DNS but "
                    f"restrict everything else."
                ),
                observed_at=max(r.ts for r in records),
                evidence=[
                    Evidence(label="Process", value=process),
                    Evidence(label="DNS bytes", value=f"{dns_bytes} ({dns_bytes / 1024:.0f} KB)"),
                    Evidence(label="Ratio of egress", value=f"{ratio:.0%}"),
                    Evidence(label="Queries", value=str(len(records))),
                ],
                indicators=[Indicator(type="process", value=process, context="high DNS-egress process")],
                metrics={"dns_bytes": dns_bytes, "ratio": round(ratio, 4), "queries": len(records)},
                occurrence_count=len(records),
                false_positive_notes=(
                    "Some enterprise security/EDR agents and ad-blocking DNS filters legitimately generate "
                    "large DNS volumes. A process that makes almost no other network connections (so its "
                    "'other_bytes' baseline is near zero) will show a high ratio even with normal DNS use -- "
                    "check the absolute DNS byte count too, not just the ratio."
                ),
                recommended_actions=[
                    Action(label="Review recent queries for this process", kind="manual",
                           detail="Look for unusually long or high-entropy query names, which is how data typically gets encoded into DNS."),
                    Action(label="Identify the process", kind="command", shell="powershell",
                           command=f"Get-Process | Where-Object {{ $_.ProcessName -eq '{process.replace('.exe', '')}' }} | Select-Object Id,ProcessName,Path",
                           requires_admin=False, detail="Confirm what this process is before blocking anything."),
                    Action(label="Block the process's outbound DNS", kind="command", shell="powershell",
                           command=f"New-NetFirewallRule -DisplayName 'NetAudit block DNS for {process}' -Direction Outbound -Program '{process}' -RemotePort 53 -Action Block",
                           requires_admin=True, reversible=True, detail="Stops this process resolving any domain until you allow it again."),
                ],
            ))
        return findings


class DataExfiltrationDetector(Detector):
    id = "data_exfiltration"
    label = "Data exfiltration"
    category = "exfiltration"
    description = "Egress volume to a single external peer far above the historical baseline for that process."
    default_severity = "high"
    mitre = [mitre_ref("TA0010", "T1048")]
    tunables = [
        TunableSpec(key="lookback_hours", value=168, type="int", min=24, max=720,
                    description="How far back to build the per-process/per-peer baseline (default 7 days)."),
        TunableSpec(key="min_samples", value=5, type="int", min=3, max=100,
                    description="Minimum historical flows to this peer before a baseline is trusted."),
        TunableSpec(key="min_zscore", value=4.0, type="float", min=2.0, max=10.0,
                    description="Minimum z-score above the historical mean to fire when the baseline has variance."),
        TunableSpec(key="min_ratio", value=5.0, type="float", min=2.0, max=50.0,
                    description="Minimum ratio to the historical mean to fire when the baseline has ~zero variance."),
        TunableSpec(key="min_bytes", value=5000000, type="int", min=100000, max=1000000000,
                    description="Absolute floor (bytes) below which this is never worth reporting, regardless of baseline."),
    ]

    def run(self, source: TrafficSource, since: datetime, until: datetime, tunables: dict) -> list[Finding]:
        lookback_hours = int(tunables["lookback_hours"])
        min_samples = int(tunables["min_samples"])
        min_zscore = float(tunables["min_zscore"])
        min_ratio = float(tunables["min_ratio"])
        min_bytes = int(tunables["min_bytes"])

        baseline_start = since - timedelta(hours=lookback_hours)
        baseline = Baseline.from_flows(source.flows(baseline_start, since), min_samples=min_samples)

        current: dict[tuple[str, str], list[FlowRecord]] = defaultdict(list)
        for f in source.flows(since, until):
            if not f.is_external or not f.remote_addr:
                continue
            current[(f.process_name or "unknown", f.remote_addr)].append(f)

        findings: list[Finding] = []
        for (process, peer), flows in current.items():
            total_out = sum(f.bytes_out for f in flows)
            if total_out < min_bytes:
                continue
            if not baseline.has_peer_baseline(process, peer):
                continue
            base_mean, base_stdev = baseline.peer_volume_stats(process, peer)
            if base_stdev > 0:
                z = (total_out - base_mean) / base_stdev
                if z < min_zscore:
                    continue
                metric_label, metric_value = "zscore", round(z, 2)
            else:
                ratio = total_out / base_mean if base_mean > 0 else float("inf")
                if ratio < min_ratio:
                    continue
                metric_label, metric_value = "ratio_to_baseline", round(ratio, 2)

            samples = baseline.peer_sample_count(process, peer)
            confidence = round(min(0.92, 0.5 + min(samples / 30, 1.0) * 0.2 + min(total_out / (min_bytes * 4), 1.0) * 0.2), 2)

            findings.append(Finding(
                key=f"exfil|{process}|{peer}",
                title=f"{total_out / 1_000_000:.1f} MB sent to {peer} by {process}, far above baseline",
                severity=self.default_severity,
                confidence=confidence,
                summary=f"{process} sent {total_out / 1_000_000:.1f} MB to {peer}, well above its historical baseline for that peer.",
                detail=(
                    f"{process} sent {total_out} bytes to {peer} in this window, against a baseline mean of "
                    f"{base_mean:.0f} bytes (stdev {base_stdev:.0f}) computed from {samples} historical flows "
                    f"between this process and this peer over the last {lookback_hours}h. This comparison is "
                    f"against that learned baseline, not a fixed threshold, and only fires once the baseline "
                    f"has at least {min_samples} samples. A jump this far above a process's own established "
                    f"pattern for one peer is the core signal for exfiltration."
                ),
                observed_at=max(f.last_seen for f in flows),
                evidence=[
                    Evidence(label="Process", value=process),
                    Evidence(label="Peer", value=peer),
                    Evidence(label="Bytes this window", value=f"{total_out} ({total_out / 1_000_000:.1f} MB)"),
                    Evidence(label="Baseline mean", value=f"{base_mean:.0f} bytes over {samples} samples"),
                ],
                indicators=[
                    Indicator(type="ip", value=peer, context="exfiltration destination"),
                    Indicator(type="process", value=process, context="source process"),
                ],
                metrics={"bytes_out": total_out, "baseline_mean_bytes": round(base_mean, 1),
                         "baseline_stdev_bytes": round(base_stdev, 1), "baseline_samples": samples,
                         metric_label: metric_value},
                related_connection_ids=[f.id for f in flows],
                occurrence_count=len(flows),
                false_positive_notes=(
                    "Backup software, large one-off downloads/uploads a user initiated, cloud sync clients "
                    "catching up after being offline, and VM/container image pulls all produce large transfers "
                    "that are entirely legitimate but still far above a process's typical baseline. Confirm the "
                    "user intended this transfer before treating it as exfiltration."
                ),
                recommended_actions=[
                    Action(label="Review the connection", kind="manual",
                           detail=f"Check the traffic log for the flow(s) to {peer} and confirm whether this transfer was expected."),
                    Action(label="Identify the process", kind="command", shell="powershell",
                           command=f"Get-Process | Where-Object {{ $_.ProcessName -eq '{process.replace('.exe', '')}' }} | Select-Object Id,ProcessName,Path",
                           requires_admin=False, detail="Confirm what this process is before blocking anything."),
                    Action(label="Block the destination", kind="command", shell="powershell",
                           command=f"New-NetFirewallRule -DisplayName 'NetAudit block {peer}' -Direction Outbound -RemoteAddress {peer} -Action Block",
                           requires_admin=True, reversible=True, detail="Blocks all outbound traffic to this address."),
                ],
            ))
        return findings


class OffHoursTransferDetector(Detector):
    id = "off_hours_transfer"
    label = "Off-hours transfer"
    category = "exfiltration"
    description = "Large transfers during hours with historically no activity for that process."
    default_severity = "medium"
    mitre = [mitre_ref("TA0010", "T1029")]
    tunables = [
        TunableSpec(key="lookback_hours", value=336, type="int", min=48, max=2160,
                    description="How far back to learn a process's normal hour-of-day activity pattern (default 14 days)."),
        TunableSpec(key="min_samples", value=10, type="int", min=3, max=200,
                    description="Minimum historical flows for a process before its active-hours baseline is trusted."),
        TunableSpec(key="min_bytes", value=1000000, type="int", min=10000, max=1000000000,
                    description="Minimum bytes transferred in the off-hour to be worth reporting."),
    ]

    def run(self, source: TrafficSource, since: datetime, until: datetime, tunables: dict) -> list[Finding]:
        lookback_hours = int(tunables["lookback_hours"])
        min_samples = int(tunables["min_samples"])
        min_bytes = int(tunables["min_bytes"])

        baseline_start = since - timedelta(hours=lookback_hours)
        baseline = Baseline.from_flows(source.flows(baseline_start, since), min_samples=min_samples)

        by_process_hour: dict[tuple[str, int], list[FlowRecord]] = defaultdict(list)
        for f in source.flows(since, until):
            proc = f.process_name or "unknown"
            by_process_hour[(proc, f.first_seen.hour)].append(f)

        findings: list[Finding] = []
        for (process, hour), flows in by_process_hour.items():
            if not baseline.has_hour_baseline(process):
                continue
            if baseline.is_active_hour(process, hour):
                continue
            total_bytes = sum(f.bytes_in + f.bytes_out for f in flows)
            if total_bytes < min_bytes:
                continue

            confidence = round(min(0.88, 0.45 + min(total_bytes / (min_bytes * 5), 1.0) * 0.3), 2)
            peers = sorted({f.remote_addr for f in flows if f.remote_addr})

            findings.append(Finding(
                key=f"off-hours|{process}|{hour}",
                title=f"{process} transferred {total_bytes / 1_000_000:.1f} MB at an hour it's never active",
                severity=self.default_severity,
                confidence=confidence,
                summary=f"{process} moved {total_bytes / 1_000_000:.1f} MB during hour {hour:02d}:00, a time it has no historical activity in.",
                detail=(
                    f"{process} transferred {total_bytes} bytes to {len(peers)} peer(s) during the {hour:02d}:00 "
                    f"hour. Across {lookback_hours}h of history for this process, this hour-of-day has never had "
                    f"activity from it. A large transfer landing precisely in a historically-silent window is "
                    f"consistent with an attacker (or scheduled malware task) deliberately operating when a user "
                    f"is unlikely to notice."
                ),
                observed_at=max(f.last_seen for f in flows),
                evidence=[
                    Evidence(label="Process", value=process),
                    Evidence(label="Hour (local capture time)", value=f"{hour:02d}:00"),
                    Evidence(label="Bytes", value=f"{total_bytes} ({total_bytes / 1_000_000:.1f} MB)"),
                    Evidence(label="Peers", value=", ".join(peers) if peers else "n/a"),
                ],
                indicators=[Indicator(type="process", value=process, context="off-hours transfer process")],
                metrics={"bytes_total": total_bytes, "hour": hour, "peer_count": len(peers)},
                related_connection_ids=[f.id for f in flows],
                occurrence_count=len(flows),
                false_positive_notes=(
                    "Scheduled backups, overnight OS/software updates, cloud sync/replication jobs, and "
                    "timezone-shifted remote work all produce legitimate off-hours transfers. This only fires "
                    "once a process has enough history to establish it normally does NOT run at that hour, "
                    "but a newly-installed backup tool will look identical to this on its first night."
                ),
                recommended_actions=[
                    Action(label="Check what's scheduled at this hour", kind="command", shell="powershell",
                           command="Get-ScheduledTask | Where-Object { $_.State -eq 'Ready' } | Select-Object TaskName,TaskPath",
                           requires_admin=False, detail="Rule out a legitimate scheduled task before treating this as suspicious."),
                    Action(label="Identify the process", kind="command", shell="powershell",
                           command=f"Get-Process | Where-Object {{ $_.ProcessName -eq '{process.replace('.exe', '')}' }} | Select-Object Id,ProcessName,Path",
                           requires_admin=False, detail="Confirm what this process is before blocking anything."),
                ],
            ))
        return findings
