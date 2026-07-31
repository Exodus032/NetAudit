"""nonstandard_port_service, new_external_peer, protocol_anomaly: three
detectors that don't fit the other categories. All three are conservative
by design -- they key off signals the capture layer already provides
(a human-readable `summary` string, TCP `flags`, and process history) and
skip rather than guess when those signals aren't there."""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta

from ..baseline import Baseline
from ..mitre import mitre_ref
from ..models import Action, Evidence, Indicator, TunableSpec
from ..source import FlowRecord, PacketRecord, TrafficSource
from .base import Detector, Finding

# banner/summary keyword -> (protocol label, expected ports)
PROTOCOL_SIGNATURES: list[tuple[str, str, frozenset]] = [
    ("SSH-", "SSH", frozenset({22})),
    ("220 ", "FTP", frozenset({21})),
    ("HTTP/1.", "HTTP", frozenset({80, 8080, 8000})),
    ("GET /", "HTTP", frozenset({80, 8080, 8000})),
    ("POST /", "HTTP", frozenset({80, 8080, 8000})),
]


class NonstandardPortServiceDetector(Detector):
    id = "nonstandard_port_service"
    label = "Nonstandard port service"
    category = "anomaly"
    description = "A known protocol running on an unexpected port (SSH on 443, HTTP on 8443, etc.)."
    default_severity = "medium"
    mitre = [mitre_ref("TA0005", "T1571")]
    tunables: list[TunableSpec] = []

    def run(self, source: TrafficSource, since: datetime, until: datetime, tunables: dict) -> list[Finding]:
        findings: list[Finding] = []
        seen_keys: set[tuple] = set()
        for p in source.packets(since, until):
            if not p.summary or p.dst_port is None:
                continue
            for needle, label, expected_ports in PROTOCOL_SIGNATURES:
                if needle not in p.summary:
                    continue
                if p.dst_port in expected_ports:
                    continue
                key = (label, p.dst_addr, p.dst_port)
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                process = p.process_name or "unknown"
                findings.append(Finding(
                    key=f"nonstandard-port|{label}|{p.dst_addr}:{p.dst_port}",
                    title=f"{label} traffic seen on port {p.dst_port} (expected {sorted(expected_ports)})",
                    severity=self.default_severity,
                    confidence=0.6,
                    summary=f"Traffic matching {label}'s protocol signature was seen on port {p.dst_port} to {p.dst_addr}, not {label}'s usual port.",
                    detail=(
                        f"A packet to {p.dst_addr}:{p.dst_port} carried a recognizable {label} protocol banner "
                        f"(matched on '{needle.strip()}'), but {label} is normally expected on port(s) "
                        f"{sorted(expected_ports)}. Running a service on a port other than its default is a "
                        f"common evasion technique to slip past port-based firewall rules and monitoring that "
                        f"only inspects traffic on the 'expected' ports for a given protocol."
                    ),
                    observed_at=p.ts,
                    evidence=[
                        Evidence(label="Protocol signature", value=label),
                        Evidence(label="Observed port", value=str(p.dst_port)),
                        Evidence(label="Expected ports", value=", ".join(str(x) for x in sorted(expected_ports))),
                        Evidence(label="Peer", value=p.dst_addr),
                        Evidence(label="Process", value=process),
                    ],
                    indicators=[
                        Indicator(type="ip", value=p.dst_addr, context="nonstandard-port peer"),
                        Indicator(type="port", value=str(p.dst_port), context="nonstandard port"),
                    ],
                    metrics={"observed_port": p.dst_port, "expected_ports": sorted(expected_ports)},
                    related_log_ids=[p.id],
                    occurrence_count=1,
                    false_positive_notes=(
                        "Plenty of legitimate services deliberately run on alternate ports (dev servers on "
                        "8080/8000, SSH moved off 22 specifically to cut down on scanner noise, HTTP proxies). "
                        "This is a weak signal by protocol-signature matching alone -- confirm before acting."
                    ),
                    recommended_actions=[
                        Action(label="Confirm what's actually listening", kind="manual",
                               detail=f"Check what service is really running on {p.dst_addr}:{p.dst_port} before assuming evasion."),
                        Action(label="Identify the process", kind="command", shell="powershell",
                               command=f"Get-Process | Where-Object {{ $_.ProcessName -eq '{process.replace('.exe', '')}' }} | Select-Object Id,ProcessName,Path",
                               requires_admin=False, detail="Confirm what this process is before blocking anything."),
                    ],
                ))
        return findings


class NewExternalPeerDetector(Detector):
    id = "new_external_peer"
    label = "New external peer"
    category = "anomaly"
    description = "First-ever contact with an external peer by a process that has a stable history."
    default_severity = "low"
    # Genuinely ambiguous: could be entirely benign (new website) or the
    # first sign of anything from C2 to exfiltration. Tactic-only per the
    # "don't invent an id" guidance.
    mitre = [mitre_ref("TA0011")]
    tunables = [
        TunableSpec(key="lookback_hours", value=720, type="int", min=24, max=4320,
                    description="How far back to build the process's known-peers baseline (default 30 days)."),
        TunableSpec(key="min_samples", value=10, type="int", min=3, max=500,
                    description="Minimum historical flows before a process is considered to have a 'stable history'."),
    ]

    def run(self, source: TrafficSource, since: datetime, until: datetime, tunables: dict) -> list[Finding]:
        lookback_hours = int(tunables["lookback_hours"])
        min_samples = int(tunables["min_samples"])

        baseline_start = since - timedelta(hours=lookback_hours)
        baseline = Baseline.from_flows(source.flows(baseline_start, since), min_samples=min_samples)

        by_process_peer: dict[tuple, list[FlowRecord]] = defaultdict(list)
        for f in source.flows(since, until):
            if f.is_external and f.remote_addr:
                by_process_peer[(f.process_name or "unknown", f.remote_addr)].append(f)

        findings: list[Finding] = []
        for (process, peer), flows in by_process_peer.items():
            if not baseline.has_process_baseline(process):
                continue
            if baseline.is_known_peer(process, peer):
                continue

            samples = baseline.process_sample_count(process)
            findings.append(Finding(
                key=f"new-peer|{process}|{peer}",
                title=f"{process} contacted a new external peer: {peer}",
                severity=self.default_severity,
                confidence=0.5,
                summary=f"{process} has {samples} historical connections but has never contacted {peer} before now.",
                detail=(
                    f"{process} has an established history of {samples} flows over the last {lookback_hours}h "
                    f"but none of them were to {peer}, which it contacted for the first time in this window. "
                    f"A brand-new destination from a process with an otherwise stable, predictable pattern of "
                    f"peers is only weak evidence of anything wrong on its own -- most new-peer events are just "
                    f"the user visiting something new -- but it is exactly the kind of event that turns out to "
                    f"matter in hindsight after a compromise, so it's surfaced here rather than only in a log."
                ),
                observed_at=max(f.last_seen for f in flows),
                evidence=[
                    Evidence(label="Process", value=process),
                    Evidence(label="New peer", value=peer),
                    Evidence(label="Historical flows for this process", value=str(samples)),
                ],
                indicators=[Indicator(type="ip", value=peer, context="first-contact peer")],
                metrics={"historical_samples": samples},
                related_connection_ids=[f.id for f in flows],
                occurrence_count=len(flows),
                false_positive_notes=(
                    "Browsers, package managers, and any process that talks to a large or changing set of "
                    "servers (CDNs, load-balanced services) will trip this constantly and is exactly why this "
                    "detector defaults to low severity and low confidence. It's most useful for processes that "
                    "normally only ever talk to a small, fixed set of peers (background agents, IoT-like "
                    "services, anything install-and-forget)."
                ),
                recommended_actions=[
                    Action(label="Check what this new destination is", kind="manual",
                           detail=f"Resolve/lookup {peer} and confirm it's an expected destination for {process}."),
                ],
            ))
        return findings


class ProtocolAnomalyDetector(Detector):
    id = "protocol_anomaly"
    label = "Protocol anomaly"
    category = "anomaly"
    description = "Malformed headers, impossible TCP flag combinations, fragmentation abuse."
    default_severity = "medium"
    # No single ATT&CK technique fits "malformed packet shapes" cleanly;
    # tactic-only per the "don't invent an id" guidance.
    mitre = [mitre_ref("TA0005")]
    tunables = [
        TunableSpec(key="min_events", value=2, type="int", min=1, max=50,
                    description="Minimum anomalous packets from one peer before this fires."),
    ]

    def run(self, source: TrafficSource, since: datetime, until: datetime, tunables: dict) -> list[Finding]:
        min_events = int(tunables["min_events"])
        by_peer: dict[str, list[tuple[PacketRecord, str]]] = defaultdict(list)

        for p in source.packets(since, until):
            if p.protocol != "tcp" or not p.flags:
                continue
            flags = {f.strip().upper() for f in p.flags.split(",")}
            reason = None
            if "SYN" in flags and "FIN" in flags:
                reason = "SYN+FIN set together (never legitimate; classic scanner/evasion signature)"
            elif {"FIN", "PSH", "URG"} <= flags and "ACK" not in flags:
                reason = "FIN+PSH+URG set with no ACK ('Xmas scan' pattern)"
            elif p.flags.strip() == "" and p.protocol == "tcp":
                reason = "no TCP flags set at all ('NULL scan' pattern)"
            if reason:
                by_peer[p.src_addr if p.direction == "inbound" else p.dst_addr].append((p, reason))

        findings: list[Finding] = []
        for peer, entries in by_peer.items():
            if len(entries) < min_events:
                continue
            reasons = sorted({r for _, r in entries})
            pkts = [p for p, _ in entries]
            findings.append(Finding(
                key=f"protocol-anomaly|{peer}",
                title=f"Malformed TCP flag combinations from/to {peer}",
                severity=self.default_severity,
                confidence=round(min(0.85, 0.5 + min(len(entries) / (min_events * 5), 1.0) * 0.3), 2),
                summary=f"{len(entries)} packet(s) involving {peer} had impossible/scan-signature TCP flag combinations.",
                detail=(
                    f"{len(entries)} packet(s) to/from {peer} had TCP flag combinations that don't occur in "
                    f"normal traffic: {'; '.join(reasons)}. These specific combinations are not produced by "
                    f"standard TCP stacks during ordinary connections -- they're deliberately crafted, almost "
                    f"always by a scanning tool (nmap and similar) probing for how a firewall or host responds "
                    f"to malformed segments, which can reveal information a normal SYN scan wouldn't."
                ),
                observed_at=max(p.ts for p, _ in entries),
                evidence=[Evidence(label="Peer", value=peer), Evidence(label="Occurrences", value=str(len(entries)))] +
                         [Evidence(label="Pattern", value=r) for r in reasons],
                indicators=[Indicator(type="ip", value=peer, context="malformed-packet peer")],
                metrics={"events": len(entries)},
                related_log_ids=[p.id for p in pkts],
                occurrence_count=len(entries),
                false_positive_notes=(
                    "Some buggy or very old TCP/IP stacks (embedded devices, old printers) occasionally produce "
                    "unusual flag combinations without any scanning intent. A single stray packet is not "
                    "meaningful; the pattern matters more than any one occurrence, which is why this only fires "
                    "above a minimum event count."
                ),
                recommended_actions=[
                    Action(label="Look up the peer", kind="manual",
                           detail=f"Check GET /api/intel/lookup?value={peer}&type=ip for known scanner classification."),
                    Action(label="Block the peer", kind="command", shell="powershell",
                           command=f"New-NetFirewallRule -DisplayName 'NetAudit block {peer}' -Direction Inbound -RemoteAddress {peer} -Action Block",
                           requires_admin=True, reversible=True, detail="Blocks all inbound traffic from this address."),
                ],
            ))
        return findings
