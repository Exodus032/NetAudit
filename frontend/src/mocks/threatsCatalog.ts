// Mock threat detections — docs/API_CONTRACT_V2_SECURITY.md Part B. A modest,
// hand-written spread across severities, categories, and statuses, each with
// the reasoning/evidence/metrics/indicators/false-positive-notes shape the
// contract requires. Actions are ordered investigate-first: a read-only
// command before anything that would block traffic.

import type { Threat } from "../api/types";

interface ThreatSpec {
  id: string;
  detector_id: string;
  title: string;
  severity: Threat["severity"];
  confidence: number;
  category: Threat["category"];
  status: Threat["status"];
  mitre: Threat["mitre"];
  summary: string;
  detail: string;
  evidence: Threat["evidence"];
  indicators: Threat["indicators"];
  metrics: Threat["metrics"];
  ageMs: number;
  occurrences: number;
  false_positive_notes: string;
  recommended_actions: Threat["recommended_actions"];
  related_log_ids?: number[];
  tags?: string[];
  enrichment?: Threat["enrichment"];
}

const SPECS: ThreatSpec[] = [
  {
    id: "beacon-45.83.64.11-a91f",
    detector_id: "c2_beaconing",
    title: "Regular beaconing to 45.83.64.11 every ~60s",
    severity: "critical",
    confidence: 0.85,
    category: "command_and_control",
    status: "active",
    mitre: [{ tactic: "TA0011", tactic_name: "Command and Control", technique: "T1071.001", technique_name: "Application Layer Protocol: Web Protocols" }],
    summary: "node.exe contacted 45.83.64.11:3333 41 times at a near-constant 60s interval.",
    detail: "Inter-arrival times had a coefficient of variation of 0.04 across 41 contacts, with a consistent request size. Regular low-variance intervals with uniform payload sizes are characteristic of automated command-and-control check-ins rather than user-driven traffic. The destination has no reverse DNS and no ASN reputation data.",
    evidence: [
      { label: "Peer", value: "45.83.64.11:3333" },
      { label: "Interval", value: "60.2s (CV 0.04)" },
      { label: "Contacts", value: "41" },
      { label: "Process", value: "node.exe (pid 9910)" },
    ],
    indicators: [{ type: "ip", value: "45.83.64.11", context: "beacon destination" }, { type: "port", value: "3333/tcp", context: "stratum-like port" }],
    metrics: { interval_seconds: 60.2, cv: 0.04, contacts: 41, bytes_total: 30_180 },
    tags: ["abuseipdb-malicious", "tor-exit", "vt-malicious"],
    enrichment: {
      "45.83.64.11": {
        abuseipdb: { abuse_confidence_score: 94, is_tor: true, country_code: "NL" },
        virustotal: { reputation: -8, last_analysis_stats: { malicious: 3, suspicious: 1, harmless: 80, undetected: 14 } },
      },
    },
    ageMs: 24 * 60_000,
    occurrences: 41,
    false_positive_notes: "Software update checks, telemetry agents, and some game clients also beacon on fixed intervals. Confirm what node.exe is actually running (a legitimate long-running Node service vs. something dropped into a temp/user directory) before assuming malicious intent.",
    recommended_actions: [
      { label: "Identify the process", kind: "command", shell: "powershell", command: "Get-Process -Id 9910 | Select-Object Id,ProcessName,Path,StartTime", requires_admin: false, detail: "Confirm what this process is and where it was launched from before acting." },
      { label: "Check the destination's reputation", kind: "link", url: "https://www.abuseipdb.com/check/45.83.64.11", detail: "Look up any existing abuse reports for this address." },
      { label: "Block the destination", kind: "command", shell: "powershell", command: "New-NetFirewallRule -DisplayName 'NetAudit block 45.83.64.11' -Direction Outbound -RemoteAddress 45.83.64.11 -Action Block", requires_admin: true, reversible: true, detail: "Blocks all outbound traffic to this single address. Do this only after confirming the process is unwanted." },
    ],
    related_log_ids: [48120, 48155],
  },
  {
    id: "exfil-93.184.216.34-c220",
    detector_id: "data_exfiltration",
    title: "Egress volume to a single peer far above baseline",
    severity: "high",
    confidence: 0.71,
    category: "exfiltration",
    status: "active",
    mitre: [{ tactic: "TA0010", tactic_name: "Exfiltration", technique: "T1041", technique_name: "Exfiltration Over C2 Channel" }],
    summary: "chrome.exe sent 340 MB to 93.184.216.34 in the last hour, ~9x its 7-day baseline for that peer.",
    detail: "Outbound volume to this specific destination is far above the rolling 7-day baseline for the same process/peer pair, while overall system upload volume is only mildly elevated. This pattern — one peer spiking while others stay flat — is more specific to that destination than a general network issue.",
    evidence: [
      { label: "Peer", value: "93.184.216.34:443" },
      { label: "Baseline", value: "38 MB/hr avg (peer-specific)" },
      { label: "Current", value: "340 MB/hr" },
      { label: "Process", value: "chrome.exe (pid 8842)" },
    ],
    indicators: [{ type: "ip", value: "93.184.216.34", context: "high-volume destination" }],
    metrics: { baseline_mb_per_hr: 38, current_mb_per_hr: 340, ratio: 8.9 },
    ageMs: 40 * 60_000,
    occurrences: 6,
    false_positive_notes: "Large legitimate transfers — cloud backups, video calls with screen share, big file uploads/downloads — commonly look exactly like this. Check what tab or extension was active in chrome.exe before treating this as exfiltration.",
    recommended_actions: [
      { label: "Check active tabs/downloads", kind: "manual", detail: "Look for an in-progress upload, backup, or large download in the browser before assuming anything adversarial." },
      { label: "Inspect recent connections from this process", kind: "command", shell: "powershell", command: "Get-NetTCPConnection -OwningProcess 8842 | Select-Object LocalPort,RemoteAddress,RemotePort,State", requires_admin: false, detail: "See what else this process is currently connected to." },
    ],
  },
  {
    id: "portscan-out-203.0.113.55-99a2",
    detector_id: "port_scan_outbound",
    title: "This host touched 47 ports on one peer in 12 seconds",
    severity: "high",
    confidence: 0.78,
    category: "reconnaissance",
    status: "active",
    mitre: [{ tactic: "TA0007", tactic_name: "Discovery", technique: "T1046", technique_name: "Network Service Discovery" }],
    summary: "firefox.exe (or a process impersonating it) probed 47 distinct ports on 203.0.113.55 in 12 seconds.",
    detail: "A short burst of connection attempts across many sequential ports to a single peer is a classic port-scanning signature, whether performed by malware, a security tool running locally, or a misbehaving script.",
    evidence: [
      { label: "Peer", value: "203.0.113.55" },
      { label: "Ports touched", value: "47 (mostly refused/reset)" },
      { label: "Duration", value: "12s" },
      { label: "Process", value: "firefox.exe (pid 2210)" },
    ],
    indicators: [{ type: "ip", value: "203.0.113.55", context: "scan target" }],
    metrics: { ports_touched: 47, duration_seconds: 12 },
    ageMs: 90 * 60_000,
    occurrences: 1,
    false_positive_notes: "Some legitimate network diagnostic tools (and a few browser extensions that probe for local dev servers) generate scan-shaped traffic. If you were just running a port scanner or diagnostic tool yourself, this is expected.",
    recommended_actions: [
      { label: "Confirm what ran the scan", kind: "command", shell: "powershell", command: "Get-Process -Id 2210 | Select-Object Id,ProcessName,Path", requires_admin: false, detail: "Verify this is actually your browser and not a process reusing its name." },
    ],
  },
  {
    id: "cleartext-ftp-203.0.113.55-71bd",
    detector_id: "credentials_plaintext",
    title: "FTP credentials observed in the clear",
    severity: "critical",
    confidence: 0.9,
    category: "credential_exposure",
    status: "acknowledged",
    mitre: [{ tactic: "TA0006", tactic_name: "Credential Access", technique: "T1040", technique_name: "Network Sniffing" }],
    summary: "A username/password pair was observed unencrypted on the FTP control channel to 203.0.113.55:21.",
    detail: "FTP transmits credentials as plaintext in the control channel. Anyone able to observe traffic on the path between this machine and the peer — another device on this LAN, a compromised router, or an ISP-level observer — can read them.",
    evidence: [{ label: "Peer", value: "203.0.113.55:21" }, { label: "Process", value: "explorer.exe" }],
    indicators: [{ type: "ip", value: "203.0.113.55", context: "FTP server" }, { type: "port", value: "21/tcp", context: "FTP control" }],
    metrics: { contacts: 3 },
    ageMs: 3 * 60 * 60_000,
    occurrences: 3,
    false_positive_notes: "This is a real protocol-level exposure any time it fires — there's no benign version of \"credentials sent in the clear.\" The only judgment call is whether this FTP server needs to exist at all.",
    recommended_actions: [
      { label: "Switch to SFTP/FTPS", kind: "manual", detail: "Use an encrypted transfer protocol instead of plain FTP for this destination." },
    ],
    related_log_ids: [47990],
  },
  {
    id: "arpspoof-192.168.1.1-77f0",
    detector_id: "arp_spoofing",
    title: "Gateway IP now resolving to a new MAC address",
    severity: "critical",
    confidence: 0.9,
    category: "spoofing",
    status: "active",
    mitre: [{ tactic: "TA0009", tactic_name: "Collection", technique: "T1557.002", technique_name: "Adversary-in-the-Middle: ARP Cache Poisoning" }],
    summary: "192.168.1.1 (the gateway) switched from its known MAC to a previously-unseen one, flapping between the two 6 times in 90 seconds.",
    detail: "The gateway's IP address began resolving to a different, previously-unseen MAC address, then flapped between the two several times in under two minutes. A legitimate router does not change its hardware address in normal operation; this flapping pattern is the signature of ARP cache poisoning, where an attacker on the local segment answers ARP requests for the gateway's IP with their own MAC to intercept traffic in the middle.",
    evidence: [
      { label: "Gateway IP", value: "192.168.1.1" },
      { label: "Known MAC", value: "AA:BB:CC:11:22:33" },
      { label: "New MAC", value: "DE:AD:BE:EF:13:37" },
      { label: "Flaps", value: "6 in 90s" },
    ],
    indicators: [
      { type: "ip", value: "192.168.1.1", context: "spoofed gateway address" },
      { type: "mac", value: "DE:AD:BE:EF:13:37", context: "claimed gateway MAC" },
    ],
    metrics: { flaps: 6, window_seconds: 90 },
    ageMs: 5 * 60_000,
    occurrences: 6,
    false_positive_notes: "A router replacement, a firmware update that regenerates the WAN/LAN MAC, or a failover to a secondary gateway can look identical to this. Confirm — physically, or via the router's own admin page — that the gateway's hardware address hasn't actually changed before treating this as an attack.",
    recommended_actions: [
      { label: "Check the router's real MAC address", kind: "manual", detail: "Compare the MAC printed on the router or shown in its admin UI against both addresses above." },
      { label: "View this host's current ARP table", kind: "command", shell: "powershell", command: "Get-NetNeighbor -IPAddress 192.168.1.1", requires_admin: false, detail: "Confirm which MAC this host currently has cached for the gateway." },
    ],
  },
  {
    id: "dnstunnel-updates-cdn-relay-3a10",
    detector_id: "dns_tunneling",
    title: "High-volume, high-entropy DNS queries to a single domain",
    severity: "high",
    confidence: 0.95,
    category: "dns_abuse",
    status: "active",
    mitre: [
      { tactic: "TA0011", tactic_name: "Command and Control", technique: "T1071.004", technique_name: "Application Layer Protocol: DNS" },
      { tactic: "TA0010", tactic_name: "Exfiltration", technique: "T1048.003", technique_name: "Exfiltration Over Unencrypted Non-C2 Protocol" },
    ],
    summary: "svchost.exe issued 1,240 TXT/NULL queries in 10 minutes for long, high-entropy subdomains of a single domain.",
    detail: "Query volume, subdomain label length, and per-label entropy are all far outside normal DNS usage for a single domain, and the record types requested (TXT, NULL) are unusual for anything but tooling rather than browsing. This combination — volume, entropy, and record type together — is a textbook signature of DNS tunneling, where data is encoded into subdomain labels to move it through a channel that's rarely inspected or blocked.",
    evidence: [
      { label: "Domain", value: "updates-cdn-relay.net" },
      { label: "Queries", value: "1,240 in 10 min" },
      { label: "Record types", value: "TXT (81%), NULL (19%)" },
      { label: "Avg label entropy", value: "4.3 bits/char" },
      { label: "Process", value: "svchost.exe (pid 4512)" },
    ],
    indicators: [{ type: "domain", value: "updates-cdn-relay.net", context: "tunneling target domain" }],
    metrics: { queries: 1240, window_seconds: 600, avg_entropy: 4.3, txt_ratio: 0.81 },
    ageMs: 8 * 60_000,
    occurrences: 1240,
    false_positive_notes: "Some legitimate security and MDM agents use DNS TXT records for lightweight command channels or licensing checks — this is nonetheless the highest-confidence detector in the catalogue when it fires. Still worth confirming which service is actually driving svchost.exe before assuming compromise, since the service host process itself is never the true origin.",
    recommended_actions: [
      { label: "Identify what's driving svchost.exe", kind: "command", shell: "powershell", command: "Get-CimInstance Win32_Service | Where-Object { $_.ProcessId -eq 4512 } | Select-Object Name,DisplayName,PathName", requires_admin: false, detail: "svchost.exe hosts many services — find which one is generating this traffic before acting." },
      { label: "Block the destination domain at the resolver", kind: "command", shell: "powershell", command: "Add-DnsClientNrptRule -Namespace 'updates-cdn-relay.net' -NameServers '0.0.0.0'", requires_admin: true, reversible: true, detail: "Stops resolution for this domain. Confirm the responsible service first — this may break a legitimate agent that depends on it." },
    ],
  },
  {
    id: "knownbad-198.51.100.23-2b6c",
    detector_id: "known_bad_peer",
    title: "Contact with a peer on the bundled indicator list",
    severity: "medium",
    confidence: 0.15,
    category: "malicious_peer",
    status: "active",
    mitre: [],
    summary: "One brief connection to 198.51.100.23, which appears in NetAudit's bundled offline indicator set tagged as a scanner.",
    detail: "This address matches an entry in the bundled offline threat-indicator list, but that entry itself is low-confidence: mass-scanning infrastructure that also serves legitimate research and monitoring traffic. A single brief connection is weak evidence on its own — this is deliberately the lowest-confidence detector in the catalogue, meant to surface a possible lead rather than a verdict.",
    evidence: [
      { label: "Peer", value: "198.51.100.23" },
      { label: "Indicator source", value: "bundled-ioc-v1" },
      { label: "Indicator category", value: "scanner" },
      { label: "Contacts", value: "1" },
    ],
    indicators: [{ type: "ip", value: "198.51.100.23", context: "bundled indicator match" }],
    metrics: { contacts: 1, indicator_source_confidence: 0.3 },
    ageMs: 45 * 60_000,
    occurrences: 1,
    false_positive_notes: "This is the least certain detector NetAudit ships: many entries on the bundled indicator list are mass-scanning or research infrastructure that ordinary services also share address space with. A single low-volume contact like this one is usually nothing. Treat it as a prompt to glance at the connection, not a reason to block anything.",
    recommended_actions: [
      { label: "Review the connection", kind: "manual", detail: "Check the Connections & devices view for what process made this contact before deciding it needs attention." },
    ],
  },
  {
    id: "dgadomain-9f21x7-b410",
    detector_id: "dga_domains",
    title: "High-entropy domain lookups consistent with a DGA",
    severity: "medium",
    confidence: 0.62,
    category: "dns_abuse",
    status: "active",
    mitre: [{ tactic: "TA0011", tactic_name: "Command and Control", technique: "T1568.002", technique_name: "Dynamic Resolution: Domain Generation Algorithms" }],
    summary: "12 lookups for consonant-heavy, high-entropy subdomains under a single TLD in the last 30 minutes.",
    detail: "Domain generation algorithms produce large numbers of algorithmically-generated, pronounceable-but-nonsensical hostnames as a fallback C2 channel. This volume and entropy profile is a moderate-confidence signal on its own, not a certainty.",
    evidence: [{ label: "Example", value: "xqz7vpmalu.example-cdn.net" }, { label: "Example", value: "b91ntkzolf.example-cdn.net" }, { label: "Lookups", value: "12 in 30 min" }],
    indicators: [{ type: "domain", value: "xqz7vpmalu.example-cdn.net", context: "high-entropy lookup" }],
    metrics: { lookups: 12, avg_entropy: 3.8 },
    ageMs: 20 * 60_000,
    occurrences: 12,
    false_positive_notes: "CDN and ad-tech infrastructure legitimately uses randomized subdomains for cache-busting and load distribution. This detector has a meaningfully higher false-positive rate than most others here — treat it as a lead to investigate, not a verdict.",
    recommended_actions: [
      { label: "Look up the parent domain", kind: "link", url: "https://www.abuseipdb.com/check/example-cdn.net", detail: "Confirm whether this is known CDN/ad-tech infrastructure before treating it as DGA activity." },
    ],
  },
  {
    id: "hostsweep-192.168.1.166-2c3d",
    detector_id: "host_sweep",
    title: "One peer contacted 9 hosts on the subnet in 40 seconds",
    severity: "medium",
    confidence: 0.55,
    category: "reconnaissance",
    status: "resolved",
    mitre: [{ tactic: "TA0007", tactic_name: "Discovery", technique: "T1018", technique_name: "Remote System Discovery" }],
    summary: "192.168.1.166 (device-8504.local) pinged or connected to 9 of 14 known hosts on the subnet in under a minute.",
    detail: "A single device rapidly contacting most of the subnet's known hosts can indicate a network scan, though it's also normal behavior for network monitoring tools, media servers doing discovery, or a phone rejoining Wi-Fi and re-resolving cached devices.",
    evidence: [{ label: "Source", value: "192.168.1.166 (device-8504.local)" }, { label: "Hosts contacted", value: "9 of 14" }, { label: "Window", value: "40s" }],
    indicators: [{ type: "ip", value: "192.168.1.166", context: "sweeping host" }],
    metrics: { hosts_contacted: 9, hosts_known: 14, window_seconds: 40 },
    ageMs: 6 * 60 * 60_000,
    occurrences: 1,
    false_positive_notes: "This detector's cooldown has passed without a repeat — most likely a phone or media device doing normal service discovery after reconnecting to Wi-Fi. Marked resolved automatically.",
    recommended_actions: [
      { label: "Identify the device", kind: "manual", detail: "Check the Connections & devices view for device-8504.local to confirm what it is." },
    ],
  },
  {
    id: "suspicious-tls-printer-6a90",
    detector_id: "suspicious_tls",
    title: "Legacy TLS 1.0 handshake to an external update server",
    severity: "low",
    confidence: 0.6,
    category: "anomaly",
    status: "active",
    mitre: [{ tactic: "TA0040", tactic_name: "Impact", technique: "T1600", technique_name: "Weaken Encryption" }],
    summary: "printer.local negotiated TLS 1.0 with an external update server instead of TLS 1.2+.",
    detail: "TLS 1.0 has known cryptographic weaknesses and is deprecated by most modern clients; a device still offering it may be running outdated firmware, making it an easier target for on-path interference.",
    evidence: [{ label: "Device", value: "192.168.1.55 (printer.local)" }, { label: "Negotiated version", value: "TLS 1.0" }],
    indicators: [{ type: "mac", value: "07:FD:29:79:E1:E6", context: "printer.local" }],
    metrics: { tls_version: 1.0 },
    ageMs: 5 * 60 * 60_000,
    occurrences: 6,
    false_positive_notes: "Many embedded/IoT devices genuinely only support TLS 1.0 firmware-side and this is a hygiene issue rather than an active attack. Low severity reflects that.",
    recommended_actions: [
      { label: "Update printer firmware", kind: "manual", detail: "Check the manufacturer's site for firmware that supports modern TLS." },
    ],
  },
  {
    id: "newpeer-cloudfront-9b71",
    detector_id: "new_external_peer",
    title: "First-ever contact with a new external peer",
    severity: "info",
    confidence: 0.4,
    category: "anomaly",
    status: "active",
    mitre: [],
    summary: "code.exe contacted 52.84.150.21 (cloudfront.net) for the first time in its observed history.",
    detail: "This process has a stable multi-week history of destinations and just added a new one. Almost always benign (a new dependency, CDN edge rotation, or an updated tool) — informational only.",
    evidence: [{ label: "Peer", value: "52.84.150.21 (cloudfront.net)" }, { label: "Process", value: "code.exe (pid 2244)" }],
    indicators: [{ type: "domain", value: "cloudfront.net", context: "new destination" }],
    metrics: { process_history_days: 34 },
    ageMs: 15 * 60_000,
    occurrences: 1,
    false_positive_notes: "This is nearly always benign — CDNs rotate edge IPs constantly and tools regularly add new update/telemetry endpoints. Included for visibility, not because it's likely to be a problem.",
    recommended_actions: [],
  },
];

export function buildThreats(): Threat[] {
  const now = Date.now();
  return SPECS.map((s) => ({
    id: s.id,
    detector_id: s.detector_id,
    title: s.title,
    severity: s.severity,
    confidence: s.confidence,
    category: s.category,
    status: s.status,
    mitre: s.mitre,
    summary: s.summary,
    detail: s.detail,
    evidence: s.evidence,
    indicators: s.indicators,
    metrics: s.metrics,
    first_seen: new Date(now - s.ageMs).toISOString(),
    last_seen: new Date(now - Math.min(s.ageMs, 60_000)).toISOString(),
    occurrences: s.occurrences,
    related_connection_ids: [],
    related_log_ids: s.related_log_ids ?? [],
    false_positive_notes: s.false_positive_notes,
    recommended_actions: s.recommended_actions,
    tags: s.tags,
    enrichment: s.enrichment,
  }));
}
