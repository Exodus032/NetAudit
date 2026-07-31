"""c2_beaconing: peers contacted on a low-variance interval with uniform
payload sizes -- the classic signature of an automated check-in rather than
user-driven traffic. Coefficient of variation is used for both interval
regularity and payload uniformity per the detection-quality spec."""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from statistics import fmean

from ..mitre import mitre_ref
from ..models import Action, Evidence, Indicator, TunableSpec
from ..source import TrafficSource
from ..stats import coefficient_of_variation, inter_arrival_times, payload_uniformity
from .base import Detector, Finding


class C2BeaconingDetector(Detector):
    id = "c2_beaconing"
    label = "C2 beaconing"
    category = "command_and_control"
    description = "Finds peers contacted on a low-variance interval with uniform payload sizes."
    default_severity = "high"
    mitre = [mitre_ref("TA0011", "T1071.001")]
    tunables = [
        TunableSpec(key="min_contacts", value=8, type="int", min=4, max=100,
                    description="Minimum contacts to a peer before the detector fires."),
        TunableSpec(key="max_interval_cv", value=0.15, type="float", min=0.01, max=1.0,
                    description="Maximum coefficient of variation of inter-arrival times to call the interval regular."),
        TunableSpec(key="max_payload_cv", value=0.35, type="float", min=0.01, max=2.0,
                    description="Maximum coefficient of variation of payload sizes to call them uniform."),
        TunableSpec(key="ignore_ports", value="123", type="str", min=None, max=None,
                    description="Comma-separated destination ports to exclude (known-noisy regular protocols, e.g. NTP)."),
    ]

    def run(self, source: TrafficSource, since: datetime, until: datetime, tunables: dict) -> list[Finding]:
        min_contacts = int(tunables["min_contacts"])
        max_interval_cv = float(tunables["max_interval_cv"])
        max_payload_cv = float(tunables["max_payload_cv"])
        ignore_ports = {p.strip() for p in str(tunables.get("ignore_ports", "")).split(",") if p.strip()}

        groups: dict[tuple, list] = defaultdict(list)
        for p in source.packets(since, until):
            if p.direction != "outbound" or p.dst_port is None:
                continue
            if str(p.dst_port) in ignore_ports:
                continue
            key = (p.process_name or "unknown", p.dst_addr, p.dst_port)
            groups[key].append(p)

        findings: list[Finding] = []
        for (process, dst_addr, dst_port), pkts in groups.items():
            if len(pkts) < min_contacts:
                continue
            pkts.sort(key=lambda x: x.ts)
            timestamps = [pk.ts.timestamp() for pk in pkts]
            gaps = inter_arrival_times(timestamps)
            interval_cv = coefficient_of_variation(gaps)
            if interval_cv is None or interval_cv > max_interval_cv:
                continue
            lengths = [float(pk.length) for pk in pkts]
            uniformity = payload_uniformity(lengths)
            payload_cv = coefficient_of_variation(lengths)
            if payload_cv is None or payload_cv > max_payload_cv:
                continue

            mean_interval = fmean(gaps)
            confidence = _confidence(interval_cv, max_interval_cv, len(pkts))
            pid = next((pk.pid for pk in pkts if pk.pid), None)
            proc_label = f"{process} (pid {pid})" if pid else process

            findings.append(Finding(
                key=f"{process}|{dst_addr}:{dst_port}",
                title=f"Regular beaconing to {dst_addr} every {mean_interval:.0f}s",
                severity=self.default_severity,
                confidence=confidence,
                summary=f"{process} contacted {dst_addr}:{dst_port} {len(pkts)} times at a near-constant {mean_interval:.0f}s interval.",
                detail=(
                    f"Inter-arrival times had a coefficient of variation of {interval_cv:.2f} across "
                    f"{len(pkts)} contacts, with payload sizes averaging {fmean(lengths):.0f} bytes "
                    f"(CV {payload_cv:.2f}, uniformity score {uniformity:.2f}). Regular low-variance "
                    f"intervals with uniform payload sizes are characteristic of automated "
                    f"command-and-control check-ins rather than user-driven traffic."
                ),
                observed_at=pkts[-1].ts,
                evidence=[
                    Evidence(label="Peer", value=f"{dst_addr}:{dst_port}"),
                    Evidence(label="Interval", value=f"{mean_interval:.1f}s (CV {interval_cv:.2f})"),
                    Evidence(label="Contacts", value=str(len(pkts))),
                    Evidence(label="Process", value=proc_label),
                ],
                indicators=[
                    Indicator(type="ip", value=dst_addr, context="beacon destination"),
                    Indicator(type="port", value=str(dst_port), context="beacon destination port"),
                    Indicator(type="process", value=process, context="beaconing process"),
                ],
                metrics={
                    "interval_seconds": round(mean_interval, 2),
                    "cv": round(interval_cv, 4),
                    "contacts": len(pkts),
                    "bytes_total": int(sum(lengths)),
                    "payload_cv": round(payload_cv, 4),
                },
                related_log_ids=[pk.id for pk in pkts],
                occurrence_count=len(pkts),
                false_positive_notes=(
                    "Software update checkers, telemetry/analytics agents, and chat/mail clients doing "
                    "keepalive polling all beacon on fixed intervals with similar-sized requests. Confirm "
                    "the process and destination before acting -- regularity alone is not proof of C2."
                ),
                recommended_actions=[
                    Action(label="Identify the process", kind="command", shell="powershell",
                           command=f"Get-Process | Where-Object {{ $_.ProcessName -eq '{process.replace('.exe', '')}' }} | Select-Object Id,ProcessName,Path,StartTime",
                           requires_admin=False, detail="Confirm what this process is before blocking anything."),
                    Action(label="Check what the destination resolves to", kind="command", shell="powershell",
                           command=f"Resolve-DnsName -Name {dst_addr} -ErrorAction SilentlyContinue",
                           requires_admin=False, detail="Reverse-resolve the peer to see if it's a recognizable service."),
                    Action(label="Block the destination", kind="command", shell="powershell",
                           command=f"New-NetFirewallRule -DisplayName 'NetAudit block {dst_addr}' -Direction Outbound -RemoteAddress {dst_addr} -Action Block",
                           requires_admin=True, reversible=True, detail="Blocks all outbound traffic to this address."),
                ],
            ))
        return findings


def _confidence(interval_cv: float, max_cv: float, contacts: int) -> float:
    regularity = max(0.0, 1.0 - interval_cv / max_cv) if max_cv > 0 else 0.0
    volume = min(contacts, 50) / 50.0
    return round(min(0.95, 0.45 + regularity * 0.35 + volume * 0.15), 2)
