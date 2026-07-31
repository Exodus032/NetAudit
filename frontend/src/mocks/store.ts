// In-memory, self-ticking mock backend. Used both for one-shot REST responses
// (VITE_USE_MOCKS=1 or automatic fallback) and to drive the mock websocket so
// the whole app is demoable with no backend running.

import { mulberry32, pick, randInt, randFloat } from "./rng";
import {
  REMOTE_HOSTS,
  PROCESSES,
  LOCAL_ADDR,
  SUMMARIES,
  FLAGS_BY_PROTO,
  type HostFixture,
} from "./fixtures";
import type {
  CaptureStatus,
  Connection,
  Device,
  NetInterface,
  Recommendation,
  RiskLevel,
  TrafficLogEntry,
} from "../api/types";

const rand = mulberry32(20260731);

function isoNow(offsetMs = 0): string {
  return new Date(Date.now() + offsetMs).toISOString();
}

function weightedProtocol(): "tcp" | "udp" | "icmp" | "other" {
  const r = rand();
  if (r < 0.78) return "tcp";
  if (r < 0.94) return "udp";
  if (r < 0.98) return "icmp";
  return "other";
}

function riskFor(host: HostFixture, isPlain: boolean): RiskLevel {
  if (host.label.includes("miner-pool") || host.label.includes("unknown-host")) return "high";
  if (isPlain && host.isExternal) return "medium";
  if (host.label.includes("ad-tracker")) return "medium";
  return "low";
}

let logIdCounter = 50000;

function makeLogEntry(tsOffsetMs: number): TrafficLogEntry {
  const host = pick(rand, REMOTE_HOSTS);
  const proc = pick(rand, PROCESSES);
  const protocol = weightedProtocol();
  const outbound = rand() < 0.62;
  const useEncrypted = host.encryptedPorts.length > 0 && (rand() < 0.75 || host.plainPorts.length === 0);
  const port = useEncrypted
    ? pick(rand, host.encryptedPorts.length ? host.encryptedPorts : [443])
    : host.plainPorts.length
      ? pick(rand, host.plainPorts)
      : pick(rand, host.encryptedPorts.length ? host.encryptedPorts : [443]);
  const isEncrypted = host.encryptedPorts.includes(port);
  const summaries = SUMMARIES[protocol] ?? SUMMARIES.tcp;
  const flagsPool = FLAGS_BY_PROTO[protocol] ?? [""];

  logIdCounter += 1;
  return {
    id: logIdCounter,
    ts: isoNow(tsOffsetMs),
    protocol,
    src_addr: outbound ? LOCAL_ADDR : host.ip,
    src_port: outbound ? randInt(rand, 1024, 65535) : port,
    dst_addr: outbound ? host.ip : LOCAL_ADDR,
    dst_port: outbound ? port : randInt(rand, 1024, 65535),
    direction: host.isExternal ? (outbound ? "outbound" : "inbound") : "local",
    length: randInt(rand, 64, 1500),
    flags: pick(rand, flagsPool),
    process_name: proc.name,
    pid: proc.pid,
    remote_host: host.label,
    is_external: host.isExternal,
    is_encrypted: isEncrypted,
    summary: pick(rand, summaries),
    risk: riskFor(host, !isEncrypted),
  };
}

function seedLogs(count: number): TrafficLogEntry[] {
  const entries: TrafficLogEntry[] = [];
  // spread seed entries over the last ~2 hours, oldest first here, then reverse
  for (let i = count; i > 0; i--) {
    entries.push(makeLogEntry(-i * 14_000 - randInt(rand, 0, 4000)));
  }
  entries.sort((a, b) => a.ts.localeCompare(b.ts));
  return entries.reverse(); // newest first
}

function makeConnection(idx: number): Connection {
  const host = pick(rand, REMOTE_HOSTS);
  const proc = pick(rand, PROCESSES);
  const useEncrypted = host.encryptedPorts.length > 0 && (rand() < 0.8 || host.plainPorts.length === 0);
  const port = useEncrypted
    ? pick(rand, host.encryptedPorts.length ? host.encryptedPorts : [443])
    : host.plainPorts.length
      ? pick(rand, host.plainPorts)
      : 443;
  const isEncrypted = host.encryptedPorts.includes(port);
  const protocol = rand() < 0.85 ? "tcp" : "udp";
  const bytesIn = randInt(rand, 512, 900_000);
  const bytesOut = randInt(rand, 256, 300_000);
  const risk = riskFor(host, !isEncrypted);
  const reasons: string[] = [];
  if (risk === "high") reasons.push("Peer on threat intelligence watchlist");
  if (!isEncrypted && host.isExternal) reasons.push("Unencrypted traffic to external host");
  if (host.label.includes("ad-tracker")) reasons.push("Known tracking/analytics endpoint");

  const firstSeenAgoMs = randInt(rand, 5_000, 3_600_000);
  return {
    id: `${protocol}-${LOCAL_ADDR}:${randInt(rand, 1024, 65535)}-${host.ip}:${port}-${idx}`,
    protocol,
    state: protocol === "udp" ? "ACTIVE" : pick(rand, ["ESTABLISHED", "ESTABLISHED", "ESTABLISHED", "TIME_WAIT", "CLOSE_WAIT"]),
    local_addr: LOCAL_ADDR,
    local_port: randInt(rand, 1024, 65535),
    remote_addr: host.ip,
    remote_port: port,
    remote_host: host.label,
    remote_org: host.sublabel,
    direction: host.isExternal ? "outbound" : "local",
    pid: proc.pid,
    process_name: proc.name,
    process_path: proc.path,
    bytes_in: bytesIn,
    bytes_out: bytesOut,
    packets: Math.round((bytesIn + bytesOut) / 800) + randInt(rand, 1, 40),
    first_seen: isoNow(-firstSeenAgoMs),
    last_seen: isoNow(-randInt(rand, 0, 2000)),
    is_external: host.isExternal,
    is_encrypted: isEncrypted,
    risk,
    risk_reasons: reasons,
  };
}

function macFor(rand: () => number): string {
  const bytes = Array.from({ length: 6 }, () => randInt(rand, 0, 255).toString(16).padStart(2, "0"));
  return bytes.join(":").toUpperCase();
}

function seedDevices(): Device[] {
  const vendors = ["Netgear", "Synology", "HP Inc.", "Google LLC", "Apple, Inc.", "Intel Corporate", "Dell Inc.", "TP-Link Systems", "Espressif Inc.", "Samsung Electronics"];
  const internalHosts = REMOTE_HOSTS.filter((h) => !h.isExternal);
  const devices: Device[] = internalHosts.map((h, i) => ({
    ip: h.ip,
    mac: macFor(rand),
    vendor: h.sublabel,
    hostname: h.label,
    first_seen: isoNow(-randInt(rand, 3_600_000, 20 * 3_600_000)),
    last_seen: isoNow(-randInt(rand, 0, 60_000)),
    bytes_total: randInt(rand, 1_000_000, 900_000_000),
    is_gateway: h.ip.endsWith(".1"),
    is_self: h.ip === LOCAL_ADDR,
    open_ports: h.plainPorts.concat(h.encryptedPorts).sort((a, b) => a - b),
    risk: i === 2 ? "medium" : "low",
  }));
  devices.push({
    ip: LOCAL_ADDR,
    mac: macFor(rand),
    vendor: "Intel Corporate",
    hostname: "DESKTOP-LUKAB",
    first_seen: isoNow(-30 * 3_600_000),
    last_seen: isoNow(0),
    bytes_total: randInt(rand, 900_000_000, 4_000_000_000),
    is_gateway: false,
    is_self: true,
    open_ports: [135, 445, 5040],
    risk: "low",
  });
  // a couple of unclassified guest devices
  for (let i = 0; i < 3; i++) {
    devices.push({
      ip: `192.168.1.${randInt(rand, 100, 199)}`,
      mac: macFor(rand),
      vendor: pick(rand, vendors),
      hostname: `device-${randInt(rand, 1000, 9999)}.local`,
      first_seen: isoNow(-randInt(rand, 600_000, 5 * 3_600_000)),
      last_seen: isoNow(-randInt(rand, 0, 300_000)),
      bytes_total: randInt(rand, 50_000, 40_000_000),
      is_gateway: false,
      is_self: false,
      open_ports: rand() < 0.4 ? [randInt(rand, 1, 65535)] : [],
      risk: rand() < 0.15 ? "medium" : "low",
    });
  }
  return devices;
}

function seedRecommendations(): Recommendation[] {
  const now = Date.now();
  const mk = (
    id: string,
    rule_id: string,
    title: string,
    severity: Recommendation["severity"],
    confidence: number,
    category: Recommendation["category"],
    summary: string,
    detail: string,
    evidence: Recommendation["evidence"],
    actions: Recommendation["actions"],
    ageMs: number,
    occurrences: number,
  ): Recommendation => ({
    id,
    rule_id,
    title,
    severity,
    confidence,
    category,
    summary,
    detail,
    evidence,
    actions,
    first_seen: new Date(now - ageMs).toISOString(),
    last_seen: new Date(now - Math.min(ageMs, randInt(rand, 0, 60_000))).toISOString(),
    occurrences,
    dismissed: false,
    related_connection_ids: [],
  });

  return [
    mk(
      "plaintext-http-4f2a",
      "plaintext_http",
      "Unencrypted HTTP traffic to 3 external hosts",
      "medium",
      0.9,
      "encryption",
      "18.4 MB left this machine over plain HTTP in the last hour.",
      "Traffic to 93.184.216.34:80 (example.com) from chrome.exe is not encrypted and can be read or modified on the path.",
      [
        { label: "Peer", value: "93.184.216.34:80 (example.com)" },
        { label: "Bytes", value: "18.4 MB" },
        { label: "Process", value: "chrome.exe (pid 8842)" },
      ],
      [
        { label: "Force HTTPS for this site", kind: "manual", detail: "Enable HTTPS-Only mode in your browser settings." },
        {
          label: "Block port 80 outbound",
          kind: "command",
          command: "New-NetFirewallRule -DisplayName 'NetAudit block HTTP' -Direction Outbound -Protocol TCP -RemotePort 80 -Action Block",
          requires_admin: true,
          detail: "Blocks all outbound plain HTTP. May break captive portals.",
        },
      ],
      3_180_000,
      412,
    ),
    mk(
      "suspicious-peer-9c31",
      "suspicious_peer_beacon",
      "Periodic beaconing to an unrated host",
      "critical",
      0.82,
      "suspicious_peer",
      "node.exe is contacting 45.83.64.11 every ~60s outside business hours.",
      "Regular fixed-interval connections to an address with no reverse DNS and no ASN reputation data are a common indicator of C2 beaconing or unwanted mining software.",
      [
        { label: "Peer", value: "45.83.64.11:3333" },
        { label: "Interval", value: "~60s, 41 occurrences" },
        { label: "Process", value: "node.exe (pid 9910)" },
      ],
      [
        { label: "Research this host", kind: "link", url: "https://www.abuseipdb.com/check/45.83.64.11", detail: "Look up reputation data before acting." },
        {
          label: "Block outbound to this peer",
          kind: "command",
          command: "New-NetFirewallRule -DisplayName 'NetAudit block 45.83.64.11' -Direction Outbound -RemoteAddress 45.83.64.11 -Action Block",
          requires_admin: true,
          detail: "Blocks all outbound traffic to this single address.",
        },
      ],
      1_500_000,
      41,
    ),
    mk(
      "open-port-2210",
      "exposed_service",
      "NAS exposing management port to the LAN",
      "high",
      0.76,
      "exposure",
      "nas.local (192.168.1.20) has port 5000 reachable from the whole subnet.",
      "The Synology DSM management interface on port 5000 is unencrypted and reachable from any device on the LAN, not just trusted hosts.",
      [
        { label: "Host", value: "192.168.1.20 (nas.local)" },
        { label: "Port", value: "5000/tcp (http)" },
      ],
      [
        { label: "Restrict management to HTTPS", kind: "manual", detail: "In DSM Control Panel > Network, disable HTTP and require HTTPS for admin access." },
      ],
      7_200_000,
      88,
    ),
    mk(
      "weak-dns-771a",
      "plaintext_dns",
      "DNS queries sent unencrypted",
      "low",
      0.65,
      "encryption",
      "All DNS lookups are going out over plain UDP/53 to your router.",
      "DNS-over-HTTPS or DNS-over-TLS would prevent on-path observation or tampering of the domains you look up.",
      [{ label: "Resolver", value: "192.168.1.1:53" }],
      [
        { label: "Enable DNS over HTTPS", kind: "manual", detail: "Turn on secure DNS in your browser or set a DoH resolver at the OS level." },
      ],
      5_400_000,
      1204,
    ),
    mk(
      "volume-spike-33e0",
      "upload_volume_spike",
      "Unusual sustained upload volume from Discord.exe",
      "medium",
      0.58,
      "volume",
      "Outbound traffic from Discord.exe is 6x its 24h baseline for the last 20 minutes.",
      "Sustained high-volume uploads can indicate a large screen-share/stream, or an unexpected background transfer worth confirming.",
      [
        { label: "Baseline", value: "1.2 Mbps avg" },
        { label: "Current", value: "7.4 Mbps avg" },
      ],
      [{ label: "No action needed if you're screen sharing", kind: "manual", detail: "Confirm in-app that a call or stream is active." }],
      1_200_000,
      1,
    ),
    mk(
      "new-device-a812",
      "new_device_discovered",
      "New device joined the LAN",
      "info",
      0.95,
      "discovery",
      "A device with MAC vendor TP-Link Systems appeared on the network for the first time.",
      "This may be a new phone, IoT device, or a guest. Confirm you recognize it.",
      [{ label: "IP", value: "192.168.1.147" }],
      [{ label: "Review connected devices", kind: "manual", detail: "Check the Connections & devices view to identify the device." }],
      900_000,
      1,
    ),
    mk(
      "weak-tls-56ab",
      "outdated_tls",
      "Legacy TLS 1.0 handshake observed",
      "high",
      0.71,
      "hygiene",
      "printer.local negotiated TLS 1.0 with an external update server.",
      "TLS 1.0 has known cryptographic weaknesses and is deprecated by most modern clients; a device still offering it may be running outdated firmware.",
      [{ label: "Device", value: "192.168.1.55 (printer.local)" }],
      [{ label: "Update printer firmware", kind: "manual", detail: "Check the manufacturer's site for the latest firmware." }],
      10_800_000,
      6,
    ),
    mk(
      "cleartext-ftp-c204",
      "cleartext_credentials",
      "Cleartext credentials observed on FTP control channel",
      "critical",
      0.88,
      "exposure",
      "A username/password pair was observed unencrypted on port 21 to 203.0.113.55.",
      "FTP transmits credentials in plain text. Anyone on the network path between this machine and the peer can read them.",
      [
        { label: "Peer", value: "203.0.113.55:21" },
        { label: "Process", value: "explorer.exe" },
      ],
      [
        { label: "Switch to SFTP/FTPS", kind: "manual", detail: "Use an encrypted transfer protocol instead of plain FTP." },
      ],
      600_000,
      3,
    ),
    mk(
      "gateway-config-71dd",
      "router_default_creds",
      "Router admin page reachable with default port",
      "low",
      0.4,
      "configuration",
      "192.168.1.1 exposes its admin UI on the default port 80.",
      "Leaving router management on a well-known default port and protocol makes it an easier target if an attacker gains LAN access.",
      [{ label: "Host", value: "192.168.1.1" }],
      [{ label: "Change the admin port and enable HTTPS", kind: "manual", detail: "Check your router's admin settings for a custom management port." }],
      14_400_000,
      1,
    ),
    mk(
      "quic-adopt-9910",
      "protocol_shift_quic",
      "Growing share of QUIC (UDP/443) traffic",
      "info",
      0.5,
      "hygiene",
      "22% of encrypted traffic now uses QUIC instead of TCP+TLS.",
      "Informational only: QUIC is encrypted and expected from modern browsers; noted here for visibility into protocol mix.",
      [{ label: "Share", value: "22% of encrypted bytes" }],
      [],
      2_400_000,
      1,
    ),
  ];
}

export interface MockState {
  logs: TrafficLogEntry[];
  connections: Connection[];
  devices: Device[];
  recommendations: Recommendation[];
  capture: CaptureStatus;
  interfaces: NetInterface[];
  startedAt: number;
}

const state: MockState = {
  logs: seedLogs(650),
  connections: Array.from({ length: 34 }, (_, i) => makeConnection(i)),
  devices: seedDevices(),
  recommendations: seedRecommendations(),
  capture: {
    mode: "npcap",
    elevated: true,
    interface: "Ethernet",
    running: true,
    degraded_reason: null,
  },
  interfaces: [
    {
      id: "Ethernet",
      name: "Ethernet",
      description: "Intel(R) Ethernet Connection I219-V",
      ipv4: LOCAL_ADDR,
      ipv6: "fe80::1c2d:9a3f:22b1:44ee",
      mac: "AA:BB:CC:DD:EE:FF",
      netmask: "255.255.255.0",
      is_up: true,
      is_loopback: false,
      speed_mbps: 1000,
    },
    {
      id: "Wi-Fi",
      name: "Wi-Fi",
      description: "Intel(R) Wi-Fi 6 AX201",
      ipv4: "192.168.1.87",
      ipv6: "fe80::a1b2:c3d4:e5f6:7788",
      mac: "11:22:33:44:55:66",
      netmask: "255.255.255.0",
      is_up: true,
      is_loopback: false,
      speed_mbps: 866,
    },
  ],
  startedAt: Date.now(),
};

const MAX_LOGS = 4000;

// Degraded-mode toggle: flip via window.__netaudit_degrade for manual testing;
// otherwise stays healthy so the demo path looks its best by default.
export function setDegraded(reason: string | null): void {
  if (reason) {
    state.capture = { ...state.capture, mode: "polling", elevated: false, degraded_reason: reason };
  } else {
    state.capture = { ...state.capture, mode: "npcap", elevated: true, degraded_reason: null };
  }
}

type Listener = (frame: { type: string; data: unknown }) => void;
const listeners = new Set<Listener>();

export function subscribe(fn: Listener): () => void {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

function emit(type: string, data: unknown) {
  for (const l of listeners) l({ type, data });
}

function tickLog() {
  const n = randInt(rand, 1, 8);
  const fresh: TrafficLogEntry[] = [];
  for (let i = 0; i < n; i++) fresh.push(makeLogEntry(0));
  state.logs = [...fresh.reverse(), ...state.logs].slice(0, MAX_LOGS);
  emit("log", fresh);
}

function tickConnections() {
  state.connections = state.connections.map((c) => {
    if (rand() < 0.15) return c; // idle flows stay put
    return {
      ...c,
      bytes_in: c.bytes_in + randInt(rand, 0, 40_000),
      bytes_out: c.bytes_out + randInt(rand, 0, 15_000),
      packets: c.packets + randInt(rand, 1, 30),
      last_seen: isoNow(0),
    };
  });
  // occasionally rotate a connection out and a fresh one in
  if (rand() < 0.1) {
    const idx = randInt(rand, 0, state.connections.length - 1);
    state.connections[idx] = makeConnection(1000 + Math.floor(rand() * 100000));
  }
  emit("connections", state.connections);
}

let statsWindowMs = 5 * 60_000;

// Throughput is a *current rate*, not a window average: averaging bytes over
// up to 24h of window against a comparatively sparse historical seed would
// read as ~0 bps right after load and ramp up for minutes as fresher, denser
// live-ticked entries entered the window. A short trailing slice reflects the
// live ticker's actual rate immediately, matching the historical timeseries
// chart's scale from the first frame.
const THROUGHPUT_SLICE_MS = 12_000;

function computeStatsSummary() {
  const cutoff = Date.now() - statsWindowMs;
  const inWindow = state.logs.filter((e) => new Date(e.ts).getTime() >= cutoff);
  const throughputCutoff = Date.now() - THROUGHPUT_SLICE_MS;
  let sliceBytesIn = 0;
  let sliceBytesOut = 0;
  for (const e of state.logs) {
    if (new Date(e.ts).getTime() < throughputCutoff) break; // logs are newest-first
    if (e.direction === "inbound") sliceBytesIn += e.length;
    else sliceBytesOut += e.length;
  }
  let bytes_in = 0,
    bytes_out = 0,
    packets_in = 0,
    packets_out = 0,
    tcp_packets = 0,
    udp_packets = 0,
    icmp_packets = 0,
    other_packets = 0,
    encrypted_bytes = 0,
    plaintext_bytes = 0,
    external_bytes = 0,
    internal_bytes = 0;
  const remoteHosts = new Set<string>();
  const processes = new Set<number>();
  for (const e of inWindow) {
    if (e.direction === "inbound") {
      bytes_in += e.length;
      packets_in += 1;
    } else {
      bytes_out += e.length;
      packets_out += 1;
    }
    if (e.protocol === "tcp") tcp_packets += 1;
    else if (e.protocol === "udp") udp_packets += 1;
    else if (e.protocol === "icmp") icmp_packets += 1;
    else other_packets += 1;
    if (e.is_encrypted) encrypted_bytes += e.length;
    else plaintext_bytes += e.length;
    if (e.is_external) external_bytes += e.length;
    else internal_bytes += e.length;
    remoteHosts.add(e.remote_host);
    processes.add(e.pid);
  }
  const sliceSeconds = THROUGHPUT_SLICE_MS / 1000;
  const throughputBpsIn = Math.round((sliceBytesIn * 8) / sliceSeconds);
  const throughputBpsOut = Math.round((sliceBytesOut * 8) / sliceSeconds);
  const openBySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  let open = 0;
  for (const r of state.recommendations) {
    if (!r.dismissed) {
      open += 1;
      openBySeverity[r.severity] += 1;
    }
  }
  return {
    window: windowLabel(),
    generated_at: isoNow(0),
    packets_total: packets_in + packets_out,
    bytes_total: bytes_in + bytes_out,
    bytes_in,
    bytes_out,
    packets_in,
    packets_out,
    throughput_bps_in: throughputBpsIn,
    throughput_bps_out: throughputBpsOut,
    peak_throughput_bps: Math.round(Math.max(throughputBpsIn, throughputBpsOut) * 1.7) + 20_000,
    active_flows: state.connections.length,
    unique_remote_hosts: remoteHosts.size,
    unique_processes: processes.size,
    tcp_packets,
    udp_packets,
    icmp_packets,
    other_packets,
    encrypted_bytes,
    plaintext_bytes,
    external_bytes,
    internal_bytes,
    open_alerts: open,
    alerts_by_severity: openBySeverity,
  };
}

function windowLabel(): "5m" | "15m" | "1h" | "24h" | "all" {
  if (statsWindowMs <= 5 * 60_000) return "5m";
  if (statsWindowMs <= 15 * 60_000) return "15m";
  if (statsWindowMs <= 60 * 60_000) return "1h";
  if (statsWindowMs <= 24 * 60 * 60_000) return "24h";
  return "all";
}

export function setStatsWindow(w: "5m" | "15m" | "1h" | "24h" | "all") {
  statsWindowMs =
    w === "5m" ? 5 * 60_000 : w === "15m" ? 15 * 60_000 : w === "1h" ? 60 * 60_000 : w === "24h" ? 24 * 60 * 60_000 : 7 * 24 * 60 * 60_000;
}

let tickHandle: ReturnType<typeof setInterval> | null = null;
let logTickHandle: ReturnType<typeof setInterval> | null = null;
export function startMockTicker() {
  if (tickHandle) return;
  tickHandle = setInterval(() => {
    tickConnections();
    emit("stats", computeStatsSummary());
    if (rand() < 0.02) {
      emit("capture", state.capture);
    }
  }, 2000);
  // log frames batch every 1s per the contract's cadence
  logTickHandle = setInterval(() => {
    tickLog();
  }, 1000);
}

export function stopMockTicker() {
  if (tickHandle) clearInterval(tickHandle);
  if (logTickHandle) clearInterval(logTickHandle);
  tickHandle = null;
  logTickHandle = null;
}

export { state, computeStatsSummary, randFloat };
