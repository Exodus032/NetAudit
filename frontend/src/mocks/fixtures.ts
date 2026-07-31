// Static fixture pools used to build realistic mock data: real-looking IPs,
// process names, hosts, ports. Kept separate from the generator so both the
// REST snapshot and the live WS ticker draw from the same pools.

export interface HostFixture {
  ip: string;
  label: string;
  sublabel: string;
  isExternal: boolean;
  encryptedPorts: number[];
  plainPorts: number[];
}

export const REMOTE_HOSTS: HostFixture[] = [
  { ip: "142.250.185.78", label: "google.com", sublabel: "Google LLC", isExternal: true, encryptedPorts: [443], plainPorts: [80] },
  { ip: "13.107.42.14", label: "outlook.office365.com", sublabel: "Microsoft Corporation", isExternal: true, encryptedPorts: [443], plainPorts: [] },
  { ip: "151.101.1.140", label: "reddit.com", sublabel: "Fastly", isExternal: true, encryptedPorts: [443], plainPorts: [] },
  { ip: "104.16.132.229", label: "cloudflare.com", sublabel: "Cloudflare, Inc.", isExternal: true, encryptedPorts: [443], plainPorts: [] },
  { ip: "140.82.112.3", label: "github.com", sublabel: "GitHub, Inc.", isExternal: true, encryptedPorts: [443, 22], plainPorts: [] },
  { ip: "17.248.163.10", label: "api.apple.com", sublabel: "Apple Inc.", isExternal: true, encryptedPorts: [443], plainPorts: [] },
  { ip: "31.13.71.36", label: "edge-star.facebook.com", sublabel: "Meta Platforms", isExternal: true, encryptedPorts: [443], plainPorts: [] },
  { ip: "52.84.150.21", label: "cloudfront.net", sublabel: "Amazon.com, Inc.", isExternal: true, encryptedPorts: [443], plainPorts: [] },
  { ip: "20.42.65.92", label: "login.microsoftonline.com", sublabel: "Microsoft Corporation", isExternal: true, encryptedPorts: [443], plainPorts: [] },
  { ip: "93.184.216.34", label: "example.com", sublabel: "Edgecast Inc.", isExternal: true, encryptedPorts: [], plainPorts: [80] },
  { ip: "185.199.108.153", label: "raw.githubusercontent.com", sublabel: "GitHub, Inc.", isExternal: true, encryptedPorts: [443], plainPorts: [] },
  { ip: "199.232.44.42", label: "npmjs.org", sublabel: "Fastly", isExternal: true, encryptedPorts: [443], plainPorts: [] },
  { ip: "203.0.113.55", label: "unknown-host.net", sublabel: "Unregistered ASN", isExternal: true, encryptedPorts: [], plainPorts: [8080, 6667] },
  { ip: "198.51.100.23", label: "ad-tracker.example", sublabel: "AdNet Analytics", isExternal: true, encryptedPorts: [], plainPorts: [80] },
  { ip: "45.83.64.11", label: "telemetry.miner-pool.io", sublabel: "Unknown ASN 202425", isExternal: true, encryptedPorts: [], plainPorts: [3333] },
  { ip: "192.168.1.1", label: "router.local", sublabel: "Netgear", isExternal: false, encryptedPorts: [443], plainPorts: [53, 80] },
  { ip: "192.168.1.20", label: "nas.local", sublabel: "Synology", isExternal: false, encryptedPorts: [443, 5001], plainPorts: [5000] },
  { ip: "192.168.1.55", label: "printer.local", sublabel: "HP Inc.", isExternal: false, encryptedPorts: [], plainPorts: [9100, 80] },
  { ip: "192.168.1.34", label: "chromecast.local", sublabel: "Google LLC", isExternal: false, encryptedPorts: [8009], plainPorts: [] },
];

export interface ProcessFixture {
  pid: number;
  name: string;
  path: string;
}

export const PROCESSES: ProcessFixture[] = [
  { pid: 8842, name: "chrome.exe", path: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" },
  { pid: 4410, name: "msedge.exe", path: "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe" },
  { pid: 2210, name: "firefox.exe", path: "C:\\Program Files\\Mozilla Firefox\\firefox.exe" },
  { pid: 9021, name: "Discord.exe", path: "C:\\Users\\lukab\\AppData\\Local\\Discord\\app-1.0.9187\\Discord.exe" },
  { pid: 5502, name: "Slack.exe", path: "C:\\Users\\lukab\\AppData\\Local\\slack\\slack.exe" },
  { pid: 1188, name: "svchost.exe", path: "C:\\Windows\\System32\\svchost.exe" },
  { pid: 7734, name: "OneDrive.exe", path: "C:\\Users\\lukab\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe" },
  { pid: 3391, name: "spotify.exe", path: "C:\\Users\\lukab\\AppData\\Roaming\\Spotify\\Spotify.exe" },
  { pid: 6672, name: "steam.exe", path: "C:\\Program Files (x86)\\Steam\\steam.exe" },
  { pid: 2244, name: "code.exe", path: "C:\\Users\\lukab\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe" },
  { pid: 1290, name: "System", path: "System" },
  { pid: 8801, name: "backgroundTaskHost.exe", path: "C:\\Windows\\System32\\backgroundTaskHost.exe" },
  { pid: 9910, name: "node.exe", path: "C:\\Program Files\\nodejs\\node.exe" },
  { pid: 4471, name: "SearchIndexer.exe", path: "C:\\Windows\\System32\\SearchIndexer.exe" },
];

export const LOCAL_ADDR = "192.168.1.42";

export const PROTOCOLS = ["tcp", "udp", "icmp", "other"] as const;

export const SUMMARIES: Record<string, string[]> = {
  tcp: ["TLS application data", "TCP handshake SYN", "HTTP GET request", "TLS client hello", "TCP ACK", "HTTP response 200 OK", "TLS session resumption"],
  udp: ["DNS query A record", "DNS response", "QUIC handshake", "mDNS announcement", "NTP sync"],
  icmp: ["Echo request", "Echo reply", "Destination unreachable"],
  other: ["GRE tunnel packet", "Unrecognized L4 protocol"],
};

export const FLAGS_BY_PROTO: Record<string, string[]> = {
  tcp: ["SYN", "SYN,ACK", "ACK", "PSH,ACK", "FIN,ACK", "RST"],
  udp: [""],
  icmp: [""],
  other: [""],
};
