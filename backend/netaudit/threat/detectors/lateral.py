"""lateral_smb_rdp: SMB/RDP/WinRM connections to multiple internal hosts in
a short window -- the classic shape of an attacker (or worm) that has
gained a foothold and is now reaching out to move to other machines on the
LAN using built-in remote-administration protocols."""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime

from ..mitre import mitre_ref
from ..models import Action, Evidence, Indicator, TunableSpec
from ..source import FlowRecord, TrafficSource
from .base import Detector, Finding

LATERAL_PORTS = {445: "SMB", 3389: "RDP", 5985: "WinRM (HTTP)", 5986: "WinRM (HTTPS)"}


class LateralSmbRdpDetector(Detector):
    id = "lateral_smb_rdp"
    label = "Lateral movement (SMB/RDP/WinRM)"
    category = "lateral_movement"
    description = "SMB/RDP/WinRM connections to multiple internal hosts in a short window."
    default_severity = "high"
    mitre = [mitre_ref("TA0008", "T1021")]
    tunables = [
        TunableSpec(key="min_hosts", value=3, type="int", min=2, max=50,
                    description="Minimum distinct internal hosts reached over SMB/RDP/WinRM before this fires."),
        TunableSpec(key="max_span_seconds", value=1800, type="int", min=60, max=86400,
                    description="Maximum time span the connections must fall within."),
    ]

    def run(self, source: TrafficSource, since: datetime, until: datetime, tunables: dict) -> list[Finding]:
        min_hosts = int(tunables["min_hosts"])
        max_span = float(tunables["max_span_seconds"])

        by_process: dict[str, list[FlowRecord]] = defaultdict(list)
        for f in source.flows(since, until):
            if f.direction != "outbound" or f.is_external or f.remote_port not in LATERAL_PORTS:
                continue
            by_process[f.process_name or "unknown"].append(f)

        findings: list[Finding] = []
        for process, flows in by_process.items():
            flows.sort(key=lambda f: f.first_seen)
            hosts = {f.remote_addr for f in flows if f.remote_addr}
            if len(hosts) < min_hosts:
                continue
            span = (flows[-1].first_seen - flows[0].first_seen).total_seconds()
            if span > max_span:
                continue

            protocols = sorted({LATERAL_PORTS[f.remote_port] for f in flows})
            confidence = round(min(0.92, 0.55 + min(len(hosts) / (min_hosts * 4), 1.0) * 0.35), 2)

            findings.append(Finding(
                key=f"lateral|{process}",
                title=f"{process} reached {len(hosts)} internal hosts over {'/'.join(protocols)}",
                severity=self.default_severity,
                confidence=confidence,
                summary=f"{process} opened {'/'.join(protocols)} connections to {len(hosts)} internal hosts within {span:.0f}s.",
                detail=(
                    f"{process} initiated outbound {'/'.join(protocols)} connections to {len(hosts)} distinct "
                    f"internal hosts ({', '.join(sorted(hosts))}) within a {span:.0f}s span. Reaching multiple "
                    f"internal hosts over remote-administration protocols in a short time is how lateral "
                    f"movement looks once an attacker has one foothold: they use built-in Windows remote "
                    f"management (SMB shares, RDP, WinRM) to spread to other machines, since those protocols "
                    f"are expected on most corporate/home networks and rarely blocked internally."
                ),
                observed_at=flows[-1].last_seen,
                evidence=[
                    Evidence(label="Process", value=process),
                    Evidence(label="Protocols", value="/".join(protocols)),
                    Evidence(label="Hosts reached", value=", ".join(sorted(hosts))),
                    Evidence(label="Span", value=f"{span:.0f}s"),
                ],
                indicators=[Indicator(type="process", value=process, context="lateral movement source process")] + [
                    Indicator(type="ip", value=h, context="internal host reached") for h in sorted(hosts)
                ],
                metrics={"hosts_reached": len(hosts), "span_seconds": round(span, 1), "flows": len(flows)},
                related_connection_ids=[f.id for f in flows],
                occurrence_count=len(flows),
                false_positive_notes=(
                    "IT/sysadmin tools (deployment software, remote monitoring, backup agents pulling from "
                    "multiple machines, a domain controller doing Group Policy work) legitimately touch many "
                    "internal hosts over these same ports. A known admin workstation or management server "
                    "doing this is expected; an ordinary user's laptop or an unfamiliar process is not."
                ),
                recommended_actions=[
                    Action(label="Identify the process", kind="command", shell="powershell",
                           command=f"Get-Process | Where-Object {{ $_.ProcessName -eq '{process.replace('.exe', '')}' }} | Select-Object Id,ProcessName,Path",
                           requires_admin=False, detail="Confirm this is expected admin/IT tooling before treating it as an intrusion."),
                    Action(label="Review recent SMB/RDP sessions on the targets", kind="manual",
                           detail="Check the reached hosts' own event logs (Security 4624/4625 for logons, RDP session events) for unexpected authentication."),
                    Action(label="Restrict outbound SMB/RDP/WinRM from this host", kind="command", shell="powershell",
                           command="New-NetFirewallRule -DisplayName 'NetAudit block lateral movement ports' -Direction Outbound -RemotePort 445,3389,5985,5986 -Protocol TCP -Action Block",
                           requires_admin=True, reversible=True, detail="Blocks this host from initiating SMB/RDP/WinRM to anything, internal or external."),
                ],
            ))
        return findings
