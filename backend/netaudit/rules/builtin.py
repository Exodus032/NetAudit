"""The actual recommendation rules. Each is its own class with a stable
rule_id, pulls real evidence from the RuleContext, and produces
genuinely-actionable `actions`. Thresholds are chosen to suppress noise on
a quiet home LAN (see the comment on each rule) -- they're deliberately
conservative rather than maximally sensitive.
"""
from __future__ import annotations

import ipaddress
import statistics
from collections import defaultdict

import psutil

from ..format import human_bytes
from .base import Rule, RuleContext, RuleFinding
from ..store.stats import service_name

PLAINTEXT_PORTS = {80: "http", 21: "ftp", 23: "telnet", 143: "imap", 110: "pop3", 389: "ldap"}
ENCRYPTED_ALT_PORTS = {443, 8443}


def _is_broadcast_or_multicast(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    if ip.is_multicast:
        return True
    if isinstance(ip, ipaddress.IPv4Address) and str(ip).endswith(".255"):
        return True
    return False


class PlaintextHttpRule(Rule):
    rule_id = "plaintext_http"
    MIN_BYTES = 5_000

    def evaluate(self, ctx: RuleContext):
        groups: dict[tuple, dict] = defaultdict(lambda: {"bytes": 0, "flow_ids": [], "sample": None})
        for f in ctx.flows:
            if not f["is_external"] or f["remote_port"] not in PLAINTEXT_PORTS:
                continue
            key = (f["remote_addr"], f["remote_port"])
            g = groups[key]
            g["bytes"] += f["bytes_in"] + f["bytes_out"]
            g["flow_ids"].append(f["id"])
            g["sample"] = f

        hits = {k: v for k, v in groups.items() if v["bytes"] >= self.MIN_BYTES}
        if not hits:
            return
        total_bytes = sum(v["bytes"] for v in hits.values())
        host_count = len(hits)
        sample = next(iter(hits.values()))["sample"]
        service = PLAINTEXT_PORTS.get(sample["remote_port"], "plaintext")
        yield RuleFinding(
            key="plaintext_http",
            title=f"Unencrypted {service} traffic to {host_count} external host(s)",
            severity="medium",
            confidence=0.9,
            category="encryption",
            summary=f"{human_bytes(total_bytes)} left this machine over plain {service} recently.",
            detail=(
                f"Traffic to {sample['remote_addr']}:{sample['remote_port']} "
                f"({sample['remote_host'] or 'unknown host'}) from "
                f"{sample['process_name'] or 'an unknown process'} is not encrypted and can be "
                f"read or modified on the path."
            ),
            evidence=[
                {"label": "Peer", "value": f"{sample['remote_addr']}:{sample['remote_port']} ({sample['remote_host'] or 'unknown'})"},
                {"label": "Bytes", "value": human_bytes(total_bytes)},
                {"label": "Hosts affected", "value": str(host_count)},
                {"label": "Process", "value": f"{sample['process_name'] or 'unknown'} (pid {sample['pid']})"},
            ],
            actions=[
                {"label": "Force HTTPS for this site", "kind": "manual",
                 "detail": "Enable HTTPS-Only mode in your browser settings, or check if the service offers a TLS port."},
                {"label": f"Block port {sample['remote_port']} outbound", "kind": "command",
                 "command": f"New-NetFirewallRule -DisplayName 'NetAudit block {service}' -Direction Outbound -Protocol TCP -RemotePort {sample['remote_port']} -Action Block",
                 "requires_admin": True,
                 "detail": f"Blocks all outbound plain {service}. May break sites/services that only offer it."},
            ],
            related_connection_ids=[fid for v in hits.values() for fid in v["flow_ids"]][:20],
        )


class PlaintextDnsRule(Rule):
    rule_id = "plaintext_dns"
    MIN_BYTES = 2_000

    def evaluate(self, ctx: RuleContext):
        dns_flows = [f for f in ctx.flows if f["remote_port"] == 53 and f["is_external"]]
        if not dns_flows:
            return
        total_bytes = sum(f["bytes_in"] + f["bytes_out"] for f in dns_flows)
        if total_bytes < self.MIN_BYTES:
            return
        has_dot = any(f["remote_port"] == 853 for f in ctx.flows)
        if has_dot:
            return
        resolvers = {f["remote_addr"] for f in dns_flows}
        sample = dns_flows[0]
        yield RuleFinding(
            key="plaintext_dns",
            title=f"Plain DNS to {len(resolvers)} external resolver(s)",
            severity="low",
            confidence=0.7,
            category="encryption",
            summary=f"{human_bytes(total_bytes)} of DNS queries went out unencrypted; no DoH/DoT was observed.",
            detail=(
                "DNS lookups over port 53 are visible and spoofable by anyone on the path (including "
                "your ISP). Switching to DNS-over-HTTPS or DNS-over-TLS hides query contents."
            ),
            evidence=[
                {"label": "Resolvers", "value": ", ".join(sorted(resolvers)[:5])},
                {"label": "Bytes", "value": human_bytes(total_bytes)},
            ],
            actions=[
                {"label": "Enable DNS-over-HTTPS in your browser", "kind": "manual",
                 "detail": "Most browsers offer a 'Secure DNS' setting using Cloudflare or Google as the DoH resolver."},
                {"label": "Set a DoH/DoT resolver system-wide", "kind": "link", "url": "https://www.cloudflare.com/learning/dns/dns-over-tls/",
                 "detail": "Windows 11 supports DoH natively in adapter DNS settings."},
            ],
            related_connection_ids=[f["id"] for f in dns_flows][:20],
        )


class ListeningExposedRule(Rule):
    rule_id = "listening_exposed"
    NOTABLE = {445: "SMB", 3389: "RDP", 5985: "WinRM", 5986: "WinRM (HTTPS)", 22: "SSH"}

    def evaluate(self, ctx: RuleContext):
        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError, OSError):
            return
        seen_ports: dict[int, dict] = {}
        for c in conns:
            if c.status != psutil.CONN_LISTEN or not c.laddr:
                continue
            if c.laddr.ip not in ("0.0.0.0", "::", ""):
                continue
            if c.laddr.port in seen_ports:
                continue
            name = path = None
            if c.pid:
                try:
                    p = psutil.Process(c.pid)
                    name, path = p.name(), p.exe()
                except Exception:
                    pass
            seen_ports[c.laddr.port] = {"pid": c.pid, "name": name, "path": path}

        for port, info in seen_ports.items():
            label = self.NOTABLE.get(port)
            is_notable = label is not None
            severity = "high" if port in (445, 3389) else ("medium" if is_notable else "info")
            confidence = 0.85 if is_notable else 0.5
            service_label = label or (info["name"] or f"port {port}")
            yield RuleFinding(
                key=f"listening_{port}",
                title=f"{service_label} listening on all interfaces ({port})",
                severity=severity,
                confidence=confidence,
                category="exposure",
                summary=f"{service_label} is reachable from any network this machine is on, not just localhost.",
                detail=(
                    f"Process {info['name'] or 'unknown'} (pid {info['pid']}) is bound to 0.0.0.0:{port}, "
                    f"which accepts connections from every interface -- including untrusted networks like "
                    f"public Wi-Fi, not just your LAN."
                ),
                evidence=[
                    {"label": "Port", "value": str(port)},
                    {"label": "Process", "value": f"{info['name'] or 'unknown'} (pid {info['pid']})"},
                    {"label": "Bind address", "value": "0.0.0.0"},
                ],
                actions=[
                    {"label": "Restrict with Windows Firewall to your LAN subnet", "kind": "command",
                     "command": f"New-NetFirewallRule -DisplayName 'NetAudit restrict {port}' -Direction Inbound -Protocol TCP -LocalPort {port} -RemoteAddress LocalSubnet -Action Allow",
                     "requires_admin": True,
                     "detail": "Add this rule, then set the default inbound rule for the port to Block for other scopes."},
                    {"label": "Disable the service if unused", "kind": "manual",
                     "detail": "If you don't need remote access, turn the service off entirely."},
                ],
            )


class UnusualPortRule(Rule):
    rule_id = "unusual_port"
    MIN_BYTES = 200_000
    MIN_PACKETS = 20

    def evaluate(self, ctx: RuleContext):
        for f in ctx.flows:
            port = f["remote_port"]
            if port is None or port <= 1024 or not f["is_external"]:
                continue
            if service_name(port) != str(port):
                continue  # it's a recognized service
            total_bytes = f["bytes_in"] + f["bytes_out"]
            if total_bytes < self.MIN_BYTES or f["packets"] < self.MIN_PACKETS:
                continue
            yield RuleFinding(
                key=f"unusual_port_{f['remote_addr']}_{port}",
                title=f"Sustained traffic to uncommon port {port}",
                severity="low",
                confidence=0.55,
                category="suspicious_peer",
                summary=f"{human_bytes(total_bytes)} exchanged with {f['remote_addr']}:{port}, which isn't a recognized service.",
                detail=(
                    f"{f['process_name'] or 'A process'} (pid {f['pid']}) has sustained traffic to "
                    f"{f['remote_addr']}:{port} ({f['remote_host'] or 'no reverse DNS'}). This may be "
                    f"legitimate (a game, VPN, or custom API) or worth a second look."
                ),
                evidence=[
                    {"label": "Peer", "value": f"{f['remote_addr']}:{port}"},
                    {"label": "Bytes", "value": human_bytes(total_bytes)},
                    {"label": "Packets", "value": str(f["packets"])},
                    {"label": "Process", "value": f"{f['process_name'] or 'unknown'} (pid {f['pid']})"},
                ],
                actions=[
                    {"label": "Confirm this process should be talking to this host", "kind": "manual",
                     "detail": "Check the process's publisher/signature and whether you recognize the destination."},
                    {"label": "Block the peer if unexpected", "kind": "command",
                     "command": f"New-NetFirewallRule -DisplayName 'NetAudit block {f['remote_addr']}' -Direction Outbound -RemoteAddress {f['remote_addr']} -Action Block",
                     "requires_admin": True,
                     "detail": "Blocks all outbound traffic to this specific address."},
                ],
                related_connection_ids=[f["id"]],
            )


class BeaconingRule(Rule):
    rule_id = "beaconing"
    MIN_SAMPLES = 8
    MAX_CV = 0.15  # coefficient of variation (stdev/mean) of inter-arrival times
    MAX_AVG_PAYLOAD = 2000

    def evaluate(self, ctx: RuleContext):
        by_peer: dict[tuple, list] = defaultdict(list)
        for p in ctx.packets:
            if not p["is_external"]:
                continue
            by_peer[(p["remote_addr"], p["pid"])].append(p)

        for (remote, pid), pkts in by_peer.items():
            if len(pkts) < self.MIN_SAMPLES:
                continue
            times = sorted(p["ts_epoch"] for p in pkts)
            deltas = [b - a for a, b in zip(times, times[1:]) if (b - a) > 0]
            if len(deltas) < self.MIN_SAMPLES - 1:
                continue
            mean = statistics.mean(deltas)
            if mean <= 0:
                continue
            stdev = statistics.pstdev(deltas)
            cv = stdev / mean
            avg_len = statistics.mean(p["length"] for p in pkts)
            if cv > self.MAX_CV or avg_len > self.MAX_AVG_PAYLOAD:
                continue
            proc = next((p["process_name"] for p in pkts if p["process_name"]), None)
            yield RuleFinding(
                key=f"beaconing_{remote}_{pid}",
                title=f"Regular check-in pattern to {remote}",
                severity="medium",
                confidence=round(min(0.9, 0.5 + (1 - cv)), 2),
                category="suspicious_peer",
                summary=f"{len(pkts)} contacts to {remote} every ~{mean:.0f}s with small, consistent payloads.",
                detail=(
                    f"Traffic to {remote} from {proc or 'an unknown process'} (pid {pid}) repeats at a "
                    f"suspiciously regular interval (~{mean:.1f}s, variation {cv:.0%}) with small payloads "
                    f"(avg {avg_len:.0f} bytes) -- a pattern associated with malware check-ins, but also with "
                    f"legitimate heartbeats, sync clients, and telemetry."
                ),
                evidence=[
                    {"label": "Peer", "value": remote},
                    {"label": "Interval", "value": f"~{mean:.1f}s (cv {cv:.0%})"},
                    {"label": "Samples", "value": str(len(pkts))},
                    {"label": "Avg payload", "value": f"{avg_len:.0f} bytes"},
                    {"label": "Process", "value": f"{proc or 'unknown'} (pid {pid})"},
                ],
                actions=[
                    {"label": "Identify the process and confirm it's expected", "kind": "manual",
                     "detail": "Sync clients, chat apps, and monitoring agents all beacon; malware C2 does too."},
                    {"label": "Block the peer if unrecognized", "kind": "command",
                     "command": f"New-NetFirewallRule -DisplayName 'NetAudit block {remote}' -Direction Outbound -RemoteAddress {remote} -Action Block",
                     "requires_admin": True,
                     "detail": "Blocks all outbound traffic to this address pending investigation."},
                ],
            )


class HeavyTalkerRule(Rule):
    rule_id = "heavy_talker"
    MIN_WINDOW_BYTES = 1_000_000
    SHARE_THRESHOLD = 0.4

    def evaluate(self, ctx: RuleContext):
        total = sum(f["bytes_in"] + f["bytes_out"] for f in ctx.flows)
        if total < self.MIN_WINDOW_BYTES:
            return

        by_pid: dict[int, dict] = defaultdict(lambda: {"bytes": 0, "name": None, "ids": []})
        by_peer: dict[str, dict] = defaultdict(lambda: {"bytes": 0, "host": None, "ids": []})
        for f in ctx.flows:
            b = f["bytes_in"] + f["bytes_out"]
            if f["pid"] is not None:
                g = by_pid[f["pid"]]
                g["bytes"] += b
                g["name"] = g["name"] or f["process_name"]
                g["ids"].append(f["id"])
            g2 = by_peer[f["remote_addr"]]
            g2["bytes"] += b
            g2["host"] = g2["host"] or f["remote_host"]
            g2["ids"].append(f["id"])

        for pid, g in by_pid.items():
            share = g["bytes"] / total
            if share >= self.SHARE_THRESHOLD:
                yield RuleFinding(
                    key=f"heavy_process_{pid}",
                    title=f"{g['name'] or 'A process'} dominates egress traffic",
                    severity="info",
                    confidence=0.75,
                    category="volume",
                    summary=f"{g['name'] or 'pid ' + str(pid)} accounts for {share:.0%} of traffic in this window.",
                    detail=f"Process pid {pid} ({g['name'] or 'unknown'}) moved {human_bytes(g['bytes'])}, "
                           f"{share:.0%} of all observed bytes in the window.",
                    evidence=[
                        {"label": "Process", "value": f"{g['name'] or 'unknown'} (pid {pid})"},
                        {"label": "Bytes", "value": human_bytes(g["bytes"])},
                        {"label": "Share of window", "value": f"{share:.0%}"},
                    ],
                    actions=[
                        {"label": "Check if this volume is expected", "kind": "manual",
                         "detail": "Large transfers, backups, and streaming are normal; unexpected volume is worth investigating."},
                    ],
                    related_connection_ids=g["ids"][:20],
                )
        for peer, g in by_peer.items():
            share = g["bytes"] / total
            if share >= self.SHARE_THRESHOLD:
                yield RuleFinding(
                    key=f"heavy_peer_{peer}",
                    title=f"Single peer dominates egress traffic",
                    severity="info",
                    confidence=0.75,
                    category="volume",
                    summary=f"{g['host'] or peer} accounts for {share:.0%} of traffic in this window.",
                    detail=f"Peer {peer} ({g['host'] or 'no reverse DNS'}) accounted for {human_bytes(g['bytes'])}, "
                           f"{share:.0%} of all observed bytes.",
                    evidence=[
                        {"label": "Peer", "value": f"{peer} ({g['host'] or 'unknown'})"},
                        {"label": "Bytes", "value": human_bytes(g["bytes"])},
                        {"label": "Share of window", "value": f"{share:.0%}"},
                    ],
                    actions=[
                        {"label": "Check if this volume is expected", "kind": "manual",
                         "detail": "A single dominant peer is often a CDN, backup target, or cloud drive -- but confirm it."},
                    ],
                    related_connection_ids=g["ids"][:20],
                )


class ManyPeersRule(Rule):
    rule_id = "many_peers"
    MIN_PEERS = 25

    def evaluate(self, ctx: RuleContext):
        by_pid: dict[int, dict] = defaultdict(lambda: {"peers": set(), "name": None, "ids": []})
        for f in ctx.flows:
            if f["pid"] is None or not f["is_external"]:
                continue
            g = by_pid[f["pid"]]
            g["peers"].add(f["remote_addr"])
            g["name"] = g["name"] or f["process_name"]
            g["ids"].append(f["id"])

        for pid, g in by_pid.items():
            n = len(g["peers"])
            if n < self.MIN_PEERS:
                continue
            yield RuleFinding(
                key=f"many_peers_{pid}",
                title=f"{g['name'] or 'A process'} is contacting an unusually large number of hosts",
                severity="low",
                confidence=0.6,
                category="suspicious_peer",
                summary=f"{g['name'] or 'pid ' + str(pid)} has talked to {n} distinct external hosts recently.",
                detail=(
                    f"Process pid {pid} ({g['name'] or 'unknown'}) contacted {n} distinct external addresses "
                    f"in this window. This is normal for browsers and P2P/CDN-backed apps, unusual for most "
                    f"other software."
                ),
                evidence=[
                    {"label": "Process", "value": f"{g['name'] or 'unknown'} (pid {pid})"},
                    {"label": "Distinct hosts", "value": str(n)},
                ],
                actions=[
                    {"label": "Confirm this matches the app's normal behavior", "kind": "manual",
                     "detail": "Browsers, torrent clients, and CDN-backed apps legitimately do this."},
                ],
                related_connection_ids=g["ids"][:20],
            )


class InsecureLanServiceRule(Rule):
    rule_id = "insecure_lan_service"
    RISKY_PORTS = {21: "FTP", 23: "Telnet", 445: "SMB"}

    def evaluate(self, ctx: RuleContext):
        for d in ctx.devices:
            import json
            ports = json.loads(d["open_ports"] or "[]")
            risky = [p for p in ports if p in self.RISKY_PORTS]
            if not risky:
                continue
            names = ", ".join(self.RISKY_PORTS[p] for p in risky)
            yield RuleFinding(
                key=f"insecure_lan_{d['ip']}",
                title=f"{d['hostname'] or d['ip']} exposes {names} on the LAN",
                severity="medium",
                confidence=0.7,
                category="discovery",
                summary=f"{d['hostname'] or d['ip']} has {names} open, which sends credentials/data unencrypted.",
                detail=(
                    f"Device {d['ip']} ({d['vendor'] or 'unknown vendor'}) has legacy unencrypted service(s) "
                    f"{names} reachable on the LAN. Anyone else on this network can potentially intercept "
                    f"traffic to it."
                ),
                evidence=[
                    {"label": "Device", "value": f"{d['ip']} ({d['hostname'] or 'no hostname'})"},
                    {"label": "Open ports", "value": names},
                ],
                actions=[
                    {"label": "Disable the legacy service if not needed", "kind": "manual",
                     "detail": "Replace FTP with SFTP, Telnet with SSH, and restrict SMB to trusted hosts only."},
                ],
            )


class StaleCaptureTierRule(Rule):
    rule_id = "stale_capture_tier"

    def evaluate(self, ctx: RuleContext):
        if ctx.capture_mode not in ("polling", "rawsocket"):
            return
        if ctx.capture_mode == "polling":
            summary = "Running in polling mode: traffic is estimated from connection tables, not real packets."
            steps = "Install Npcap and restart NetAudit as Administrator for full per-packet visibility."
        else:
            summary = "Running in raw-socket mode: IPv4 packet headers only, no Npcap-level detail."
            steps = "Install Npcap for full protocol decoding and non-IPv4 traffic."
        yield RuleFinding(
            key="capture_tier",
            title="Capture is running in a reduced-visibility mode",
            severity="info",
            confidence=1.0,
            category="hygiene",
            summary=summary,
            detail=f"{summary} {steps}",
            evidence=[
                {"label": "Active tier", "value": ctx.capture_mode},
                {"label": "Elevated", "value": "yes" if ctx.elevated else "no"},
            ],
            actions=[
                {"label": "Install Npcap", "kind": "link", "url": "https://npcap.com",
                 "detail": "Free, widely used packet capture driver for Windows."},
                {"label": "Restart NetAudit as Administrator", "kind": "manual",
                 "detail": "Right-click the terminal/shortcut and choose 'Run as administrator'."},
            ],
        )


class BroadcastNoiseRule(Rule):
    rule_id = "broadcast_noise"
    NOISY_PORTS = {137: "NBNS", 138: "NBNS", 5353: "mDNS", 5355: "LLMNR"}
    MIN_COUNT = 300

    def evaluate(self, ctx: RuleContext):
        counts: dict[str, int] = defaultdict(int)
        for p in ctx.packets:
            if p["dst_port"] in self.NOISY_PORTS:
                counts[self.NOISY_PORTS[p["dst_port"]]] += 1
            elif _is_broadcast_or_multicast(p["dst_addr"]):
                counts["broadcast/multicast"] += 1

        total = sum(counts.values())
        if total < self.MIN_COUNT:
            return
        breakdown = ", ".join(f"{k}: {v}" for k, v in sorted(counts.items(), key=lambda kv: -kv[1]))
        yield RuleFinding(
            key="broadcast_noise",
            title="Excessive broadcast/multicast chatter",
            severity="low",
            confidence=0.6,
            category="configuration",
            summary=f"{total} broadcast/multicast/name-resolution packets observed in this window.",
            detail=(
                f"High volumes of NBNS/LLMNR/mDNS or broadcast traffic ({breakdown}) usually indicate a "
                f"misconfigured device, a chatty IoT gadget, or legacy name resolution that could be disabled."
            ),
            evidence=[{"label": k, "value": str(v)} for k, v in counts.items()],
            actions=[
                {"label": "Disable NetBIOS/LLMNR if unused", "kind": "command",
                 "command": "Disable-NetAdapterBinding -Name '*' -ComponentID ms_netbios",
                 "requires_admin": True,
                 "detail": "Turns off legacy NetBIOS name resolution, reducing broadcast chatter and spoofing risk."},
                {"label": "Identify the noisy device", "kind": "manual",
                 "detail": "Check the LAN devices list for the source of repeated broadcast traffic."},
            ],
        )


ALL_RULES: list[type[Rule]] = [
    PlaintextHttpRule,
    PlaintextDnsRule,
    ListeningExposedRule,
    UnusualPortRule,
    BeaconingRule,
    HeavyTalkerRule,
    ManyPeersRule,
    InsecureLanServiceRule,
    StaleCaptureTierRule,
    BroadcastNoiseRule,
]
