"""credentials_plaintext: auth-bearing protocols observed in the clear.
FTP, Telnet, IMAP/POP3, and LDAP simple bind are flagged purely by port
(the protocol itself is inherently cleartext at that port, regardless of
payload visibility). HTTP Basic auth is only flagged when a payload
snippet is actually available and contains the header -- the detector
skips that sub-check cleanly when the capture layer never gave it one."""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime

from ..mitre import mitre_ref
from ..models import Action, Evidence, Indicator, TunableSpec
from ..source import PacketRecord, TrafficSource
from .base import Detector, Finding

# port -> (protocol label, whether presence alone is enough evidence)
PLAINTEXT_AUTH_PORTS = {
    21: "FTP (control channel, cleartext login)",
    23: "Telnet (fully cleartext)",
    110: "POP3 (cleartext)",
    143: "IMAP (cleartext)",
    389: "LDAP (simple bind, cleartext)",
}


class CredentialsPlaintextDetector(Detector):
    id = "credentials_plaintext"
    label = "Plaintext credentials"
    category = "credential_exposure"
    description = "Auth-bearing protocols in the clear: FTP, Telnet, HTTP Basic, IMAP/POP3, LDAP simple bind."
    default_severity = "high"
    mitre = [mitre_ref("TA0006", "T1040")]
    tunables = [
        TunableSpec(key="min_events", value=1, type="int", min=1, max=50,
                    description="Minimum packets on a plaintext-auth port before this fires for that peer."),
    ]

    def run(self, source: TrafficSource, since: datetime, until: datetime, tunables: dict) -> list[Finding]:
        min_events = int(tunables["min_events"])
        findings: list[Finding] = []

        by_port_peer: dict[tuple, list[PacketRecord]] = defaultdict(list)
        http_basic: dict[tuple, list[PacketRecord]] = defaultdict(list)

        for p in source.packets(since, until):
            if p.direction != "outbound" or p.dst_port is None:
                continue
            if p.dst_port in PLAINTEXT_AUTH_PORTS:
                by_port_peer[(p.dst_port, p.dst_addr)].append(p)
            elif p.payload_snippet and "authorization: basic" in p.payload_snippet.lower():
                http_basic[(p.dst_port, p.dst_addr)].append(p)

        for (port, peer), pkts in by_port_peer.items():
            if len(pkts) < min_events:
                continue
            protocol = PLAINTEXT_AUTH_PORTS[port]
            process = next((pk.process_name for pk in pkts if pk.process_name), "unknown")
            findings.append(_finding(protocol, port, peer, pkts, process,
                                      confidence=0.75, mitre_note="port-identified protocol"))

        for (port, peer), pkts in http_basic.items():
            if len(pkts) < min_events:
                continue
            process = next((pk.process_name for pk in pkts if pk.process_name), "unknown")
            findings.append(_finding("HTTP Basic authentication", port, peer, pkts, process,
                                      confidence=0.9, mitre_note="Authorization: Basic header observed in payload"))

        return findings


def _finding(protocol: str, port: int, peer: str, pkts: list[PacketRecord], process: str,
             confidence: float, mitre_note: str) -> Finding:
    return Finding(
        key=f"plaintext-cred|{peer}:{port}",
        title=f"{protocol} traffic to {peer}:{port} carries credentials in the clear",
        severity="high",
        confidence=confidence,
        summary=f"{process} exchanged {len(pkts)} {protocol} packet(s) with {peer}:{port}, which is unencrypted.",
        detail=(
            f"{len(pkts)} packet(s) of {protocol} traffic were observed between {process} and {peer}:{port} "
            f"({mitre_note}). This protocol/configuration sends authentication credentials over the network "
            f"without encryption -- anyone who can observe traffic on the path (a shared Wi-Fi network, a "
            f"compromised switch, an on-path attacker) can read the username and password directly."
        ),
        observed_at=max(pk.ts for pk in pkts),
        evidence=[
            Evidence(label="Protocol", value=protocol),
            Evidence(label="Peer", value=f"{peer}:{port}"),
            Evidence(label="Process", value=process),
            Evidence(label="Packets", value=str(len(pkts))),
        ],
        indicators=[
            Indicator(type="ip", value=peer, context="plaintext-auth peer"),
            Indicator(type="port", value=str(port), context="plaintext-auth port"),
        ],
        metrics={"packets": len(pkts), "port": port},
        related_log_ids=[pk.id for pk in pkts],
        occurrence_count=len(pkts),
        false_positive_notes=(
            "Legacy internal devices (printers, NAS boxes, building/industrial control systems) often only "
            "support these older protocols and are used intentionally on trusted internal networks. The risk "
            "is real either way, but urgency depends on whether this crosses an untrusted network segment."
        ),
        recommended_actions=[
            Action(label="Confirm what's using this protocol", kind="manual",
                   detail=f"Identify the process/device behind this {protocol} traffic before changing anything."),
            Action(label="Switch to the encrypted equivalent", kind="manual",
                   detail="FTPS/SFTP instead of FTP, SSH instead of Telnet, IMAPS/POP3S instead of IMAP/POP3, LDAPS instead of plain LDAP bind."),
            Action(label="Block the plaintext port outbound", kind="command", shell="powershell",
                   command=f"New-NetFirewallRule -DisplayName 'NetAudit block plaintext {port}' -Direction Outbound -RemotePort {port} -Protocol TCP -Action Block",
                   requires_admin=True, reversible=True, detail="Blocks this specific plaintext port; may break the legacy device/service using it."),
        ],
    )
