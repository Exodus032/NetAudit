"""known_bad_peer, tor_or_proxy, crypto_mining: all three classify peers
using the bundled offline indicator set (threat/intel), never a network
call. known_bad_peer fires on any bundled match at all; tor_or_proxy and
crypto_mining fire on their own specific categories and add a
traffic-shape heuristic (mining reuses c2_beaconing's regularity math,
since Stratum share submissions are themselves a regular, uniform-size
check-in)."""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from statistics import fmean

from ..intel import bundled
from ..mitre import mitre_ref
from ..models import Action, Evidence, Indicator, TunableSpec
from ..source import FlowRecord, PacketRecord, TrafficSource
from ..stats import coefficient_of_variation, inter_arrival_times, payload_uniformity
from .base import Detector, Finding


class KnownBadPeerDetector(Detector):
    id = "known_bad_peer"
    label = "Known bad peer"
    category = "malicious_peer"
    description = "Peer matches the bundled offline indicator set."
    default_severity = "high"
    mitre = [mitre_ref("TA0011")]  # generic: the bundled set spans several categories, no single technique fits
    tunables: list[TunableSpec] = []

    def run(self, source: TrafficSource, since: datetime, until: datetime, tunables: dict) -> list[Finding]:
        peers: dict[str, list[FlowRecord]] = defaultdict(list)
        for f in source.flows(since, until):
            if f.is_external and f.remote_addr:
                peers[f.remote_addr].append(f)

        findings: list[Finding] = []
        for peer, flows in peers.items():
            matches = bundled.find_matches(peer, "ip")
            if not matches:
                continue
            best = max(matches, key=lambda m: m.confidence)
            severity = "critical" if best.confidence >= 0.85 else ("high" if best.confidence >= 0.6 else "medium")
            categories = sorted({m.category for m in matches})
            process = next((f.process_name for f in flows if f.process_name), "unknown")

            findings.append(Finding(
                key=f"known-bad|{peer}",
                title=f"Contact with known-listed peer {peer}",
                severity=severity,
                confidence=round(best.confidence, 2),
                summary=f"{process} contacted {peer}, which matches the bundled indicator set ({', '.join(categories)}).",
                detail=(
                    f"{process} exchanged traffic with {peer}, which matches {len(matches)} entr{'y' if len(matches) == 1 else 'ies'} "
                    f"in the bundled offline indicator set: {'; '.join(f'{m.category} (source: {m.source}, confidence {m.confidence:.2f})' for m in matches)}. "
                    f"This is a local, static lookup against a small starter set (see threat/README.md) -- it is "
                    f"not a live threat feed and should be treated as one input, not a verdict."
                ),
                observed_at=max(f.last_seen for f in flows),
                evidence=[
                    Evidence(label="Peer", value=peer),
                    Evidence(label="Categories", value=", ".join(categories)),
                    Evidence(label="Process", value=process),
                    Evidence(label="Notes", value="; ".join(m.note for m in matches)),
                ],
                indicators=[Indicator(type="ip", value=peer, context="bundled indicator match")],
                metrics={"match_count": len(matches), "best_confidence": round(best.confidence, 3)},
                related_connection_ids=[f.id for f in flows],
                occurrence_count=len(flows),
                false_positive_notes=(
                    "The bundled indicator set is a small, honest starter list built only from publicly "
                    "documented, non-sensitive infrastructure facts (reserved ranges, mining pool ports/domains, "
                    "proxy ports) -- it contains no attributed malware infrastructure. A match here reflects "
                    "what category of address this is, not proof of compromise."
                ),
                recommended_actions=[
                    Action(label="Look up the peer for full detail", kind="manual",
                           detail=f"GET /api/intel/lookup?value={peer}&type=ip for the full match record."),
                    Action(label="Identify the process", kind="command", shell="powershell",
                           command=f"Get-Process | Where-Object {{ $_.ProcessName -eq '{process.replace('.exe', '')}' }} | Select-Object Id,ProcessName,Path",
                           requires_admin=False, detail="Confirm what this process is before blocking anything."),
                    Action(label="Block the peer", kind="command", shell="powershell",
                           command=f"New-NetFirewallRule -DisplayName 'NetAudit block {peer}' -Direction Outbound -RemoteAddress {peer} -Action Block",
                           requires_admin=True, reversible=True, detail="Blocks all outbound traffic to this address."),
                ],
            ))
        return findings


class TorOrProxyDetector(Detector):
    id = "tor_or_proxy"
    label = "Tor / open proxy"
    category = "malicious_peer"
    description = "Traffic to known Tor entry ranges or open-proxy ports."
    default_severity = "medium"
    mitre = [mitre_ref("TA0011", "T1090.003")]
    tunables: list[TunableSpec] = []

    def run(self, source: TrafficSource, since: datetime, until: datetime, tunables: dict) -> list[Finding]:
        by_key: dict[tuple, list[FlowRecord]] = defaultdict(list)
        for f in source.flows(since, until):
            if f.remote_port is None:
                continue
            matches = bundled.find_matches(str(f.remote_port), "port")
            proxy_matches = [m for m in matches if m.category == "proxy_port"]
            if proxy_matches:
                by_key[(f.remote_addr, f.remote_port)].append(f)

        findings: list[Finding] = []
        for (peer, port), flows in by_key.items():
            matches = [m for m in bundled.find_matches(str(port), "port") if m.category == "proxy_port"]
            best = max(matches, key=lambda m: m.confidence)
            process = next((f.process_name for f in flows if f.process_name), "unknown")

            findings.append(Finding(
                key=f"tor-proxy|{peer}:{port}",
                title=f"Traffic to proxy/Tor port {port} on {peer}",
                severity=self.default_severity,
                confidence=round(best.confidence, 2),
                summary=f"{process} connected to {peer}:{port}, a known SOCKS/Tor/proxy port.",
                detail=(
                    f"{process} opened a connection to {peer}:{port}. Port {port} is commonly used for "
                    f"{best.note} This is weak evidence on its own -- the port is also used by legitimate "
                    f"proxy/VPN software -- but combined with an unexpected process or destination it is worth "
                    f"reviewing, since it's a common way to route traffic anonymously or bypass egress "
                    f"monitoring."
                ),
                observed_at=max(f.last_seen for f in flows),
                evidence=[
                    Evidence(label="Peer", value=f"{peer}:{port}"),
                    Evidence(label="Process", value=process),
                    Evidence(label="Note", value=best.note),
                ],
                indicators=[
                    Indicator(type="ip", value=peer, context="proxy/Tor peer"),
                    Indicator(type="port", value=str(port), context="proxy/Tor port"),
                ],
                metrics={"port": port, "confidence": round(best.confidence, 3)},
                related_connection_ids=[f.id for f in flows],
                occurrence_count=len(flows),
                false_positive_notes=(
                    "Corporate VPN clients, legitimate SOCKS proxies, and privacy tools the user runs "
                    "intentionally (including Tor Browser itself) use exactly these ports. This bundled set "
                    "does not include a Tor exit-node/relay IP list -- those rotate too fast to ship as a "
                    "static file -- so detection here is port-based only, which is a known limitation."
                ),
                recommended_actions=[
                    Action(label="Confirm whether this proxy use is intentional", kind="manual",
                           detail="Check if the user or a known application (VPN client, Tor Browser) is expected to be running."),
                    Action(label="Identify the process", kind="command", shell="powershell",
                           command=f"Get-Process | Where-Object {{ $_.ProcessName -eq '{process.replace('.exe', '')}' }} | Select-Object Id,ProcessName,Path",
                           requires_admin=False, detail="Confirm what this process is before blocking anything."),
                ],
            ))
        return findings


class CryptoMiningDetector(Detector):
    id = "crypto_mining"
    label = "Crypto mining"
    category = "malicious_peer"
    description = "Stratum ports / known pool endpoints / mining-shaped traffic."
    default_severity = "medium"
    mitre = [mitre_ref("TA0040", "T1496")]
    tunables = [
        TunableSpec(key="min_contacts_for_shape", value=6, type="int", min=3, max=100,
                    description="Minimum packet contacts to a candidate mining peer before checking share-submission regularity."),
        TunableSpec(key="max_interval_cv", value=0.4, type="float", min=0.05, max=2.0,
                    description="Interval CV below which contact regularity boosts confidence (Stratum share submissions are periodic)."),
    ]

    def run(self, source: TrafficSource, since: datetime, until: datetime, tunables: dict) -> list[Finding]:
        min_contacts = int(tunables["min_contacts_for_shape"])
        max_interval_cv = float(tunables["max_interval_cv"])

        candidates: dict[tuple, list[FlowRecord]] = defaultdict(list)
        for f in source.flows(since, until):
            if f.remote_port is None:
                continue
            matches = bundled.find_matches(str(f.remote_port), "port")
            domain_matches = bundled.find_matches(f.remote_host, "domain") if f.remote_host else []
            all_matches = [m for m in matches if m.category == "mining_pool_port"] + \
                          [m for m in domain_matches if m.category == "mining_pool_domain"]
            if all_matches:
                candidates[(f.remote_addr, f.remote_port, f.remote_host)].append(f)

        packets_by_peer: dict[str, list[PacketRecord]] = defaultdict(list)
        for p in source.packets(since, until):
            if p.direction == "outbound" and p.dst_port is not None:
                packets_by_peer[f"{p.dst_addr}:{p.dst_port}"].append(p)

        findings: list[Finding] = []
        for (peer, port, host), flows in candidates.items():
            port_matches = [m for m in bundled.find_matches(str(port), "port") if m.category == "mining_pool_port"]
            domain_matches = [m for m in bundled.find_matches(host, "domain") if m.category == "mining_pool_domain"] if host else []
            best_conf = max([m.confidence for m in port_matches + domain_matches], default=0.3)
            process = next((f.process_name for f in flows if f.process_name), "unknown")

            shape_note = ""
            pkts = packets_by_peer.get(f"{peer}:{port}", [])
            if len(pkts) >= min_contacts:
                pkts_sorted = sorted(pkts, key=lambda pk: pk.ts)
                gaps = inter_arrival_times([pk.ts.timestamp() for pk in pkts_sorted])
                cv = coefficient_of_variation(gaps)
                if cv is not None and cv <= max_interval_cv:
                    best_conf = min(0.9, best_conf + 0.25)
                    lengths = [float(pk.length) for pk in pkts_sorted]
                    uniformity = payload_uniformity(lengths)
                    shape_note = (
                        f" Traffic to this peer also showed {len(pkts)} contacts at a regular interval "
                        f"(CV {cv:.2f}) with payload uniformity {uniformity:.2f}, consistent with periodic "
                        f"Stratum share submissions rather than a one-off connection."
                    )

            match_notes = "; ".join(m.note for m in (port_matches + domain_matches))
            findings.append(Finding(
                key=f"mining|{peer}:{port}",
                title=f"Possible crypto mining traffic to {host or peer}:{port}",
                severity=self.default_severity,
                confidence=round(best_conf, 2),
                summary=f"{process} connected to {host or peer}:{port}, matching known mining pool infrastructure.",
                detail=(
                    f"{process} connected to {host or peer}:{port}, which matches the bundled mining-pool "
                    f"indicator set ({match_notes}).{shape_note} Presence alone does not mean this machine is "
                    f"compromised -- it could be an intentional miner the user is running -- but it's worth "
                    f"confirming, since cryptojacking malware uses exactly this port/domain family."
                ),
                observed_at=max(f.last_seen for f in flows),
                evidence=[
                    Evidence(label="Peer", value=f"{host or peer}:{port}"),
                    Evidence(label="Process", value=process),
                    Evidence(label="Match basis", value=match_notes),
                ],
                indicators=[
                    Indicator(type="ip", value=peer, context="mining pool peer"),
                    Indicator(type="port", value=str(port), context="mining pool port"),
                ] + ([Indicator(type="domain", value=host, context="mining pool domain")] if host else []),
                metrics={"port": port, "confidence": round(best_conf, 3), "shape_contacts": len(pkts)},
                related_connection_ids=[f.id for f in flows],
                occurrence_count=len(flows),
                false_positive_notes=(
                    "A user intentionally running a miner (their own hardware, their own electricity) is "
                    "common and entirely legitimate. Low-numbered mining ports (3333, 4444, 5555, 7777, 8888) "
                    "are also reused by unrelated software, so port-only matches here carry low confidence -- "
                    "see the confidence value and the bundled indicator notes."
                ),
                recommended_actions=[
                    Action(label="Confirm whether mining is intentional", kind="manual",
                           detail="Check if the user knowingly installed mining software (or a game/app bundling one)."),
                    Action(label="Identify the process", kind="command", shell="powershell",
                           command=f"Get-Process | Where-Object {{ $_.ProcessName -eq '{process.replace('.exe', '')}' }} | Select-Object Id,ProcessName,Path,CPU",
                           requires_admin=False, detail="Sustained high CPU alongside this traffic supports a mining hypothesis."),
                    Action(label="Block the peer", kind="command", shell="powershell",
                           command=f"New-NetFirewallRule -DisplayName 'NetAudit block {peer}' -Direction Outbound -RemoteAddress {peer} -Action Block",
                           requires_admin=True, reversible=True, detail="Blocks all outbound traffic to this address."),
                ],
            ))
        return findings
