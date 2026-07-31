"""deprecated_protocol: SMBv1, Telnet, FTP, SSLv3, NTLMv1 observed on the
wire. Port-based checks (Telnet, FTP) fire on presence alone since the
protocol itself is deprecated regardless of payload. Checks that need a
textual signal the capture layer might not provide (SMBv1 dialect,
SSLv3 via tls_version, NTLMv1 via a summary marker) skip cleanly when
that signal is absent rather than guessing."""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime

from ..mitre import mitre_ref
from ..models import Action, Evidence, Indicator, TunableSpec
from ..source import PacketRecord, TrafficSource
from .base import Detector, Finding


class DeprecatedProtocolDetector(Detector):
    id = "deprecated_protocol"
    label = "Deprecated protocol"
    category = "policy_violation"
    description = "SMBv1, Telnet, FTP, SSLv3, or NTLMv1 observed on the wire."
    default_severity = "medium"
    # Presence of a deprecated protocol is a policy/exposure finding, not an
    # attack technique in itself; tactic-only per the "don't invent an id"
    # guidance (it's the same weak-auth-protocol family as credentials_plaintext).
    mitre = [mitre_ref("TA0006")]
    tunables = [
        TunableSpec(key="min_events", value=1, type="int", min=1, max=50,
                    description="Minimum packets for a given protocol/peer before this fires."),
    ]

    def run(self, source: TrafficSource, since: datetime, until: datetime, tunables: dict) -> list[Finding]:
        min_events = int(tunables["min_events"])
        groups: dict[tuple, list[PacketRecord]] = defaultdict(list)

        for p in source.packets(since, until):
            if p.direction != "outbound" or p.dst_port is None:
                continue
            label = None
            if p.dst_port == 23:
                label = "Telnet"
            elif p.dst_port == 21:
                label = "FTP"
            elif p.tls_version == "SSLv3":
                label = "SSLv3"
            elif p.summary and "smb1" in p.summary.lower():
                label = "SMBv1"
            elif p.summary and "ntlmv1" in p.summary.lower():
                label = "NTLMv1"
            if label:
                groups[(label, p.dst_addr, p.dst_port)].append(p)

        findings: list[Finding] = []
        for (label, peer, port), pkts in groups.items():
            if len(pkts) < min_events:
                continue
            process = next((pk.process_name for pk in pkts if pk.process_name), "unknown")
            findings.append(Finding(
                key=f"deprecated|{label}|{peer}:{port}",
                title=f"{label} observed to {peer}:{port}",
                severity=self.default_severity,
                confidence=0.8,
                summary=f"{process} used {label}, a deprecated protocol, when talking to {peer}:{port}.",
                detail=(
                    f"{len(pkts)} packet(s) identified {label} traffic between {process} and {peer}:{port}. "
                    f"{label} has known, unfixable weaknesses (cleartext auth for Telnet/FTP, broken crypto for "
                    f"SSLv3, weak/relayable hashing for NTLMv1, no encryption or signing for SMBv1) that current "
                    f"protocol versions were specifically designed to fix. Its presence is a policy/hygiene "
                    f"finding rather than proof of an active attack, but it's exploitable infrastructure sitting "
                    f"on the network."
                ),
                observed_at=max(pk.ts for pk in pkts),
                evidence=[
                    Evidence(label="Protocol", value=label),
                    Evidence(label="Peer", value=f"{peer}:{port}"),
                    Evidence(label="Process", value=process),
                    Evidence(label="Packets", value=str(len(pkts))),
                ],
                indicators=[
                    Indicator(type="ip", value=peer, context=f"{label} peer"),
                    Indicator(type="port", value=str(port), context=f"{label} port"),
                ],
                metrics={"packets": len(pkts), "port": port},
                related_log_ids=[pk.id for pk in pkts],
                occurrence_count=len(pkts),
                false_positive_notes=(
                    "Legacy devices (old printers, NAS boxes, industrial/building control systems, embedded "
                    "equipment) frequently only support these older protocols and can't be upgraded. The right "
                    "response is often network segmentation rather than an outright block if the device is "
                    "otherwise trusted and can't be replaced."
                ),
                recommended_actions=[
                    Action(label="Identify what's using this protocol", kind="manual",
                           detail=f"Confirm what device/service is at {peer}:{port} before changing anything."),
                    Action(label="Disable the deprecated protocol/feature", kind="manual",
                           detail="SMBv1 can be disabled via 'Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol' (run separately after confirming nothing depends on it)."),
                    Action(label="Block the port outbound", kind="command", shell="powershell",
                           command=f"New-NetFirewallRule -DisplayName 'NetAudit block deprecated {label}' -Direction Outbound -RemotePort {port} -Protocol TCP -Action Block",
                           requires_admin=True, reversible=True, detail=f"Blocks outbound {label} traffic on this port; may break the legacy device using it."),
                ],
            ))
        return findings
