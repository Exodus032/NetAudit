"""port_scan_outbound, port_scan_inbound, host_sweep: reconnaissance
detectors. All three look for the same underlying shape -- one party
touching an unusually large number of distinct targets (ports or hosts) in
a short span -- just with the roles reversed."""
from __future__ import annotations

import ipaddress
from collections import defaultdict
from datetime import datetime

from ..mitre import mitre_ref
from ..models import Action, Evidence, Indicator, TunableSpec
from ..source import PacketRecord, TrafficSource
from .base import Detector, Finding


def _is_internal(addr: str) -> bool:
    try:
        return ipaddress.ip_address(addr).is_private
    except ValueError:
        return False


class PortScanOutboundDetector(Detector):
    id = "port_scan_outbound"
    label = "Outbound port scan"
    category = "reconnaissance"
    description = "This host touching many ports on one peer in a short window."
    default_severity = "medium"
    mitre = [mitre_ref("TA0007", "T1046")]
    tunables = [
        TunableSpec(key="min_ports", value=15, type="int", min=5, max=200,
                    description="Minimum distinct destination ports on one peer before this fires."),
        TunableSpec(key="max_span_seconds", value=300, type="int", min=10, max=3600,
                    description="Maximum time span the port touches must fall within."),
    ]

    def run(self, source: TrafficSource, since: datetime, until: datetime, tunables: dict) -> list[Finding]:
        min_ports = int(tunables["min_ports"])
        max_span = float(tunables["max_span_seconds"])

        by_peer: dict[str, list[PacketRecord]] = defaultdict(list)
        for p in source.packets(since, until):
            if p.direction == "outbound" and p.dst_port is not None:
                by_peer[p.dst_addr].append(p)

        findings: list[Finding] = []
        for peer, pkts in by_peer.items():
            pkts.sort(key=lambda x: x.ts)
            ports = {pk.dst_port for pk in pkts}
            if len(ports) < min_ports:
                continue
            span = (pkts[-1].ts - pkts[0].ts).total_seconds()
            if span > max_span:
                continue

            confidence = round(min(0.9, 0.5 + min(len(ports) / (min_ports * 4), 1.0) * 0.35), 2)
            process = next((pk.process_name for pk in pkts if pk.process_name), "unknown")

            findings.append(Finding(
                key=f"portscan-out|{peer}",
                title=f"This host touched {len(ports)} ports on {peer} in {span:.0f}s",
                severity=self.default_severity,
                confidence=confidence,
                summary=f"{len(ports)} distinct ports on {peer} were contacted within {span:.0f}s.",
                detail=(
                    f"{len(ports)} distinct destination ports on {peer} were touched within a {span:.0f}s span "
                    f"({len(pkts)} packets total), by process {process}. Sweeping many ports on one host in a "
                    f"short window is how port scanners enumerate what's listening; normal application traffic "
                    f"talks to a small, stable set of ports on any given peer."
                ),
                observed_at=pkts[-1].ts,
                evidence=[
                    Evidence(label="Peer", value=peer),
                    Evidence(label="Distinct ports", value=str(len(ports))),
                    Evidence(label="Span", value=f"{span:.0f}s"),
                    Evidence(label="Process", value=process),
                ],
                indicators=[Indicator(type="ip", value=peer, context="scan target")],
                metrics={"distinct_ports": len(ports), "span_seconds": round(span, 1), "packets": len(pkts)},
                related_log_ids=[pk.id for pk in pkts],
                occurrence_count=len(pkts),
                false_positive_notes=(
                    "Vulnerability scanners you run yourself, network monitoring tools, and some peer-to-peer "
                    "or game traffic that hunts for an open port also produce this pattern. Confirm the process "
                    "before treating this as an attacker's reconnaissance."
                ),
                recommended_actions=[
                    Action(label="Identify the process", kind="command", shell="powershell",
                           command=f"Get-Process | Where-Object {{ $_.ProcessName -eq '{process.replace('.exe', '')}' }} | Select-Object Id,ProcessName,Path",
                           requires_admin=False, detail="Confirm this wasn't your own scanning tool before acting."),
                    Action(label="Block the peer", kind="command", shell="powershell",
                           command=f"New-NetFirewallRule -DisplayName 'NetAudit block {peer}' -Direction Outbound -RemoteAddress {peer} -Action Block",
                           requires_admin=True, reversible=True, detail="Blocks all outbound traffic to this address."),
                ],
            ))
        return findings


class PortScanInboundDetector(Detector):
    id = "port_scan_inbound"
    label = "Inbound port scan"
    category = "reconnaissance"
    description = "One peer touching many ports on this host."
    default_severity = "medium"
    mitre = [mitre_ref("TA0043", "T1595.001")]
    tunables = [
        TunableSpec(key="min_ports", value=15, type="int", min=5, max=200,
                    description="Minimum distinct local ports one peer must touch before this fires."),
        TunableSpec(key="max_span_seconds", value=300, type="int", min=10, max=3600,
                    description="Maximum time span the port touches must fall within."),
    ]

    def run(self, source: TrafficSource, since: datetime, until: datetime, tunables: dict) -> list[Finding]:
        min_ports = int(tunables["min_ports"])
        max_span = float(tunables["max_span_seconds"])

        by_peer: dict[str, list[PacketRecord]] = defaultdict(list)
        for p in source.packets(since, until):
            if p.direction == "inbound" and p.dst_port is not None:
                by_peer[p.src_addr].append(p)

        findings: list[Finding] = []
        for peer, pkts in by_peer.items():
            pkts.sort(key=lambda x: x.ts)
            ports = {pk.dst_port for pk in pkts}
            if len(ports) < min_ports:
                continue
            span = (pkts[-1].ts - pkts[0].ts).total_seconds()
            if span > max_span:
                continue

            confidence = round(min(0.92, 0.55 + min(len(ports) / (min_ports * 4), 1.0) * 0.35), 2)

            findings.append(Finding(
                key=f"portscan-in|{peer}",
                title=f"{peer} touched {len(ports)} ports on this host in {span:.0f}s",
                severity=self.default_severity,
                confidence=confidence,
                summary=f"{peer} probed {len(ports)} distinct local ports within {span:.0f}s.",
                detail=(
                    f"{peer} sent packets to {len(ports)} distinct ports on this host within a {span:.0f}s span "
                    f"({len(pkts)} packets total). Unsolicited probing across many local ports from one remote "
                    f"host in a short time is the signature of port-scanning reconnaissance, either an attacker "
                    f"mapping what's open or an internet-wide scanner sweeping this address."
                ),
                observed_at=pkts[-1].ts,
                evidence=[
                    Evidence(label="Peer", value=peer),
                    Evidence(label="Distinct ports", value=str(len(ports))),
                    Evidence(label="Span", value=f"{span:.0f}s"),
                ],
                indicators=[Indicator(type="ip", value=peer, context="scanning peer")],
                metrics={"distinct_ports": len(ports), "span_seconds": round(span, 1), "packets": len(pkts)},
                related_log_ids=[pk.id for pk in pkts],
                occurrence_count=len(pkts),
                false_positive_notes=(
                    "Mass internet scanners (research projects, security vendors, and plenty of less benign "
                    "operators) constantly sweep the whole public IPv4 space; if this host has any exposed "
                    "port, an inbound scan like this is common and often unrelated to being specifically "
                    "targeted. Check /api/intel/lookup for the peer before escalating."
                ),
                recommended_actions=[
                    Action(label="Look up the peer", kind="manual",
                           detail=f"Check GET /api/intel/lookup?value={peer}&type=ip for known scanner/proxy classification."),
                    Action(label="Confirm the firewall blocks unsolicited inbound", kind="command", shell="powershell",
                           command="Get-NetFirewallProfile | Select-Object Name,DefaultInboundAction",
                           requires_admin=False, detail="Verify inbound is default-block; a scan that finds nothing open is low-risk."),
                    Action(label="Block the peer", kind="command", shell="powershell",
                           command=f"New-NetFirewallRule -DisplayName 'NetAudit block {peer}' -Direction Inbound -RemoteAddress {peer} -Action Block",
                           requires_admin=True, reversible=True, detail="Blocks all inbound traffic from this address."),
                ],
            ))
        return findings


class HostSweepDetector(Detector):
    id = "host_sweep"
    label = "Host sweep"
    category = "reconnaissance"
    description = "One peer contacting many hosts on the subnet."
    default_severity = "medium"
    mitre = [mitre_ref("TA0043", "T1595.001")]
    tunables = [
        TunableSpec(key="min_hosts", value=5, type="int", min=3, max=100,
                    description="Minimum distinct internal hosts one peer must contact before this fires."),
        TunableSpec(key="max_span_seconds", value=300, type="int", min=10, max=3600,
                    description="Maximum time span the host touches must fall within."),
    ]

    def run(self, source: TrafficSource, since: datetime, until: datetime, tunables: dict) -> list[Finding]:
        min_hosts = int(tunables["min_hosts"])
        max_span = float(tunables["max_span_seconds"])

        by_peer: dict[str, list[PacketRecord]] = defaultdict(list)
        for p in source.packets(since, until):
            if p.direction == "inbound" and _is_internal(p.dst_addr):
                by_peer[p.src_addr].append(p)

        findings: list[Finding] = []
        for peer, pkts in by_peer.items():
            pkts.sort(key=lambda x: x.ts)
            hosts = {pk.dst_addr for pk in pkts}
            if len(hosts) < min_hosts:
                continue
            span = (pkts[-1].ts - pkts[0].ts).total_seconds()
            if span > max_span:
                continue

            confidence = round(min(0.9, 0.5 + min(len(hosts) / (min_hosts * 4), 1.0) * 0.35), 2)

            findings.append(Finding(
                key=f"host-sweep|{peer}",
                title=f"{peer} contacted {len(hosts)} hosts on the subnet in {span:.0f}s",
                severity=self.default_severity,
                confidence=confidence,
                summary=f"{peer} reached {len(hosts)} distinct internal hosts within {span:.0f}s.",
                detail=(
                    f"{peer} sent packets to {len(hosts)} distinct internal addresses within a {span:.0f}s span "
                    f"({len(pkts)} packets total). One source contacting a large fraction of the subnet in a "
                    f"short window is the signature of network discovery sweeps (e.g. ping/ARP/service sweeps) "
                    f"used to map out what else is on the LAN before choosing a target."
                ),
                observed_at=pkts[-1].ts,
                evidence=[
                    Evidence(label="Peer", value=peer),
                    Evidence(label="Hosts contacted", value=str(len(hosts))),
                    Evidence(label="Span", value=f"{span:.0f}s"),
                ],
                indicators=[Indicator(type="ip", value=peer, context="sweeping peer")],
                metrics={"hosts_contacted": len(hosts), "span_seconds": round(span, 1), "packets": len(pkts)},
                related_log_ids=[pk.id for pk in pkts],
                occurrence_count=len(pkts),
                false_positive_notes=(
                    "Network management tools, the router/DHCP server itself, backup software doing LAN "
                    "discovery, and corporate asset-inventory scanners all sweep the subnet legitimately. "
                    "A sweep from a known device (router, NAS, admin workstation) is much less concerning than "
                    "one from an unrecognized peer."
                ),
                recommended_actions=[
                    Action(label="Check devices for this peer", kind="manual",
                           detail=f"Look up {peer} in GET /api/devices to see if it's a known/recognized device on the network."),
                    Action(label="Block the peer", kind="command", shell="powershell",
                           command=f"New-NetFirewallRule -DisplayName 'NetAudit block {peer}' -Direction Inbound -RemoteAddress {peer} -Action Block",
                           requires_admin=True, reversible=True, detail="Blocks all inbound traffic from this address."),
                ],
            ))
        return findings
