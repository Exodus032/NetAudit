"""arp_spoofing, mac_flapping, rogue_dhcp: three L2 detectors, all reading
the ArpRecord stream (see source.py for why DHCP offers ride along in that
same stream). These are the closest thing to "ground truth" in the whole
catalogue -- a gateway IP legitimately changing MAC address, or two DHCP
servers answering on one LAN, essentially never happens without either a
hardware swap the user knows about or an active attacker."""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime

from ..mitre import mitre_ref
from ..models import Action, Evidence, Indicator, TunableSpec
from ..source import ArpRecord, TrafficSource
from .base import Detector, Finding


class ArpSpoofingDetector(Detector):
    id = "arp_spoofing"
    label = "ARP spoofing"
    category = "spoofing"
    description = "One MAC claiming multiple IPs, or a gateway IP changing MAC address."
    default_severity = "critical"
    mitre = [mitre_ref("TA0006", "T1557.002")]
    cooldown_seconds = 600.0
    tunables = [
        TunableSpec(key="min_ips_per_mac", value=2, type="int", min=2, max=20,
                    description="Minimum distinct IPs one MAC must claim (via reply/gratuitous ARP) before this fires."),
    ]

    def run(self, source: TrafficSource, since: datetime, until: datetime, tunables: dict) -> list[Finding]:
        min_ips = int(tunables["min_ips_per_mac"])
        records = [r for r in source.arp_events(since, until) if r.event in ("reply", "gratuitous")]

        findings: list[Finding] = []

        # -- one MAC claiming multiple IPs -----------------------------
        by_mac: dict[str, list[ArpRecord]] = defaultdict(list)
        for r in records:
            by_mac[r.mac].append(r)
        for mac, recs in by_mac.items():
            ips = sorted({r.ip for r in recs})
            if len(ips) < min_ips:
                continue
            findings.append(Finding(
                key=f"arp-multi-ip|{mac}",
                title=f"MAC {mac} claimed {len(ips)} different IPs",
                severity=self.default_severity,
                confidence=round(min(0.95, 0.55 + min(len(ips) / 6, 1.0) * 0.35), 2),
                summary=f"{mac} answered ARP for {len(ips)} different IP addresses: {', '.join(ips)}.",
                detail=(
                    f"MAC address {mac} sent ARP replies or gratuitous ARP claiming ownership of {len(ips)} "
                    f"different IP addresses ({', '.join(ips)}) within this window. A single network interface "
                    f"legitimately owns one (or occasionally a small fixed set of) IP; one MAC answering for "
                    f"many IPs is the core mechanism of ARP cache poisoning, where an attacker's machine "
                    f"answers on behalf of other hosts (often the gateway) to intercept their traffic."
                ),
                observed_at=max(r.ts for r in recs),
                evidence=[
                    Evidence(label="MAC", value=mac),
                    Evidence(label="Claimed IPs", value=", ".join(ips)),
                    Evidence(label="ARP events", value=str(len(recs))),
                ],
                indicators=[Indicator(type="mac", value=mac, context="MAC claiming multiple IPs")] + [
                    Indicator(type="ip", value=ip, context="claimed IP") for ip in ips
                ],
                metrics={"claimed_ip_count": len(ips), "events": len(recs)},
                occurrence_count=len(recs),
                false_positive_notes=(
                    "Virtual machine hosts, hypervisors, and routers doing NAT/failover can legitimately answer "
                    "ARP for several IPs from one MAC (e.g. a hotel/office gateway multiplexing addresses). "
                    "VPN software and some VM bridged-network adapters also do this. Confirm the device before "
                    "treating this as an attack."
                ),
                recommended_actions=[
                    Action(label="Check the device against known hardware", kind="manual",
                           detail=f"Look up {mac} in GET /api/devices and confirm it matches a device you recognize (router, VM host, etc.)."),
                    Action(label="Pin the gateway's ARP entry", kind="command", shell="powershell",
                           command="Get-NetNeighbor -State Reachable,Permanent",
                           requires_admin=False, detail="Review current ARP table entries before making any static."),
                ],
            ))

        # -- gateway IP changing MAC -----------------------------------
        gateway_recs = [r for r in records if r.is_gateway]
        by_ip: dict[str, list[ArpRecord]] = defaultdict(list)
        for r in gateway_recs:
            by_ip[r.ip].append(r)
        for ip, recs in by_ip.items():
            recs.sort(key=lambda r: r.ts)
            macs_seen = list(dict.fromkeys(r.mac for r in recs))
            if len(macs_seen) < 2:
                continue
            findings.append(Finding(
                key=f"arp-gateway-mac-change|{ip}",
                title=f"Gateway {ip} changed MAC address",
                severity="critical",
                confidence=0.9,
                summary=f"Gateway IP {ip} was claimed by {len(macs_seen)} different MAC addresses in this window.",
                detail=(
                    f"The gateway address {ip} was seen bound to {len(macs_seen)} different MAC addresses "
                    f"({', '.join(macs_seen)}) within this window. The default gateway's MAC almost never "
                    f"changes outside of a router reboot/replacement the user initiated; an unexplained change "
                    f"is the textbook signature of an attacker impersonating the gateway to intercept all "
                    f"outbound traffic (a man-in-the-middle position)."
                ),
                observed_at=recs[-1].ts,
                evidence=[
                    Evidence(label="Gateway IP", value=ip),
                    Evidence(label="MACs seen", value=", ".join(macs_seen)),
                ],
                indicators=[Indicator(type="ip", value=ip, context="gateway")] + [
                    Indicator(type="mac", value=m, context="gateway MAC candidate") for m in macs_seen
                ],
                metrics={"mac_count": len(macs_seen)},
                occurrence_count=len(recs),
                false_positive_notes=(
                    "Replacing your router, a router reboot that renegotiates DHCP/ARP, or switching to a "
                    "backup/failover gateway all legitimately change the gateway's MAC. If you just changed "
                    "hardware, acknowledge this finding rather than blocking anything."
                ),
                recommended_actions=[
                    Action(label="Confirm you didn't change router hardware", kind="manual",
                           detail="If you replaced or rebooted your router recently, this is expected -- acknowledge it."),
                    Action(label="Check the current gateway MAC", kind="command", shell="powershell",
                           command=f"Get-NetNeighbor -IPAddress {ip}",
                           requires_admin=False, detail="See which MAC is currently answering for the gateway."),
                ],
            ))
        return findings


class MacFlappingDetector(Detector):
    id = "mac_flapping"
    label = "MAC flapping"
    category = "spoofing"
    description = "An IP rapidly alternating between MAC addresses."
    default_severity = "high"
    mitre = [mitre_ref("TA0006", "T1557")]
    cooldown_seconds = 600.0
    tunables = [
        TunableSpec(key="min_transitions", value=3, type="int", min=2, max=50,
                    description="Minimum MAC-to-MAC transitions for one IP before this fires."),
        TunableSpec(key="max_span_seconds", value=60, type="int", min=5, max=3600,
                    description="Maximum time span the transitions must fall within to count as 'rapid'."),
    ]

    def run(self, source: TrafficSource, since: datetime, until: datetime, tunables: dict) -> list[Finding]:
        min_transitions = int(tunables["min_transitions"])
        max_span = float(tunables["max_span_seconds"])

        by_ip: dict[str, list[ArpRecord]] = defaultdict(list)
        for r in source.arp_events(since, until):
            if r.event in ("reply", "gratuitous"):
                by_ip[r.ip].append(r)

        findings: list[Finding] = []
        for ip, recs in by_ip.items():
            recs.sort(key=lambda r: r.ts)
            transitions = []
            for a, b in zip(recs, recs[1:]):
                if a.mac != b.mac:
                    transitions.append(b)
            if len(transitions) < min_transitions:
                continue
            span = (transitions[-1].ts - transitions[0].ts).total_seconds()
            if span > max_span:
                continue

            macs = list(dict.fromkeys(r.mac for r in recs))
            findings.append(Finding(
                key=f"mac-flap|{ip}",
                title=f"{ip} flapped between {len(macs)} MACs {len(transitions)} times",
                severity=self.default_severity,
                confidence=round(min(0.9, 0.5 + min(len(transitions) / (min_transitions * 4), 1.0) * 0.35), 2),
                summary=f"{ip} alternated MAC address {len(transitions)} times within {span:.0f}s.",
                detail=(
                    f"{ip} switched which MAC address it was bound to {len(transitions)} times within a "
                    f"{span:.0f}s span, cycling between {len(macs)} distinct MACs ({', '.join(macs)}). Rapid "
                    f"alternation like this is not how normal DHCP renewal or roaming looks (those change MAC "
                    f"binding once, then hold steady) -- it's consistent with two devices actively racing to "
                    f"claim the same address, which happens during active ARP spoofing or IP conflict abuse."
                ),
                observed_at=transitions[-1].ts,
                evidence=[
                    Evidence(label="IP", value=ip),
                    Evidence(label="Transitions", value=str(len(transitions))),
                    Evidence(label="Span", value=f"{span:.0f}s"),
                    Evidence(label="MACs involved", value=", ".join(macs)),
                ],
                indicators=[Indicator(type="ip", value=ip, context="flapping IP")] + [
                    Indicator(type="mac", value=m, context="flapping MAC") for m in macs
                ],
                metrics={"transitions": len(transitions), "span_seconds": round(span, 1), "mac_count": len(macs)},
                occurrence_count=len(transitions),
                false_positive_notes=(
                    "Fast-roaming Wi-Fi clients moving between access points that share an IP via mobility "
                    "features, NIC teaming/failover, and some load balancers can also flap. A single legitimate "
                    "MAC swap (e.g. one device replaced) will not meet the transition-count threshold here."
                ),
                recommended_actions=[
                    Action(label="Check for an IP conflict warning", kind="manual",
                           detail="Windows will show 'IP address conflict' notifications on affected hosts -- check if this is a benign duplicate static IP."),
                    Action(label="Identify both devices", kind="manual",
                           detail=f"Look up each MAC in GET /api/devices to identify both devices claiming {ip}."),
                ],
            ))
        return findings


class RogueDhcpDetector(Detector):
    id = "rogue_dhcp"
    label = "Rogue DHCP server"
    category = "spoofing"
    description = "DHCP offers from an address that is not the known/majority server."
    default_severity = "critical"
    mitre = [mitre_ref("TA0006", "T1557.003")]
    cooldown_seconds = 600.0
    tunables = [
        TunableSpec(key="known_server_ip", value="", type="str", min=None, max=None,
                    description="If set, the trusted DHCP server IP. If blank, the majority offerer in the window is inferred as trusted."),
        TunableSpec(key="min_offers", value=3, type="int", min=1, max=100,
                    description="Minimum total DHCP offers observed before a majority server can be inferred."),
        TunableSpec(key="min_dominance_ratio", value=0.6, type="float", min=0.5, max=1.0,
                    description="Minimum share of offers the majority server must hold before it's trusted as 'known'."),
    ]

    def run(self, source: TrafficSource, since: datetime, until: datetime, tunables: dict) -> list[Finding]:
        known_server = str(tunables.get("known_server_ip", "")).strip()
        min_offers = int(tunables["min_offers"])
        min_dominance = float(tunables["min_dominance_ratio"])

        offers = [r for r in source.arp_events(since, until) if r.event == "dhcp_offer" and r.dhcp_server_ip]
        if len(offers) < min_offers:
            return []

        if not known_server:
            counts = Counter(r.dhcp_server_ip for r in offers)
            server, count = counts.most_common(1)[0]
            if count / len(offers) < min_dominance:
                # No clear majority -- not enough signal to call anything "rogue".
                return []
            known_server = server

        rogue = [r for r in offers if r.dhcp_server_ip != known_server]
        if not rogue:
            return []

        by_rogue: dict[str, list] = defaultdict(list)
        for r in rogue:
            by_rogue[r.dhcp_server_ip].append(r)

        findings: list[Finding] = []
        for rogue_ip, recs in by_rogue.items():
            macs = sorted({r.mac for r in recs})
            findings.append(Finding(
                key=f"rogue-dhcp|{rogue_ip}",
                title=f"DHCP offers from unexpected server {rogue_ip}",
                severity=self.default_severity,
                confidence=0.85,
                summary=f"{len(recs)} DHCP offer(s) came from {rogue_ip}, not the known server {known_server}.",
                detail=(
                    f"{len(recs)} DHCP OFFER packet(s) were seen from {rogue_ip} (MAC {', '.join(macs)}), while "
                    f"{known_server} is the network's established DHCP server ({'configured' if str(tunables.get('known_server_ip', '')).strip() else 'inferred from a clear majority of offers'} "
                    f"in this window). A second DHCP server answering client requests can hand out a malicious "
                    f"gateway/DNS server to any device that accepts its offer, which is a direct path to "
                    f"intercepting or redirecting that device's entire traffic."
                ),
                observed_at=max(r.ts for r in recs),
                evidence=[
                    Evidence(label="Rogue server", value=rogue_ip),
                    Evidence(label="Known server", value=known_server),
                    Evidence(label="Offers seen", value=str(len(recs))),
                    Evidence(label="Source MAC(s)", value=", ".join(macs)),
                ],
                indicators=[Indicator(type="ip", value=rogue_ip, context="rogue DHCP server")] + [
                    Indicator(type="mac", value=m, context="rogue DHCP server MAC") for m in macs
                ],
                metrics={"offers": len(recs), "known_server": known_server},
                occurrence_count=len(recs),
                false_positive_notes=(
                    "A second legitimate DHCP server (a newly added router in bridge mode, a misconfigured "
                    "Wi-Fi access point, a phone's mobile hotspot/ICS sharing, or a lab/test VLAN leaking onto "
                    "the main network) is a common and entirely non-malicious cause. Confirm no new network "
                    "hardware was added before treating this as an attack."
                ),
                recommended_actions=[
                    Action(label="Check for newly added network hardware", kind="manual",
                           detail="A second router, access point, or a phone's hotspot/Internet Connection Sharing enabled by accident are the most common benign causes."),
                    Action(label="Identify the device", kind="manual",
                           detail=f"Look up MAC {', '.join(macs)} in GET /api/devices to identify the physical device."),
                    Action(label="Disable DHCP on the rogue device or disconnect it", kind="manual",
                           detail="If the device is unrecognized, disconnect it from the network immediately."),
                ],
            ))
        return findings
