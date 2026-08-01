# NetAudit

A local network auditing and security tool for Windows. It captures traffic on your
own machine, shows you what's actually happening on the wire, audits how the host is
configured, flags suspicious behaviour, and tells you what to do about it.

Everything runs on localhost against your own network. Nothing is uploaded, and the
tool makes no outbound requests of its own.

## Platform support

Windows 10/11 is the supported platform and is required for full packet capture and
the Windows security-posture checks. Linux and macOS can run the dashboard and the
connection-table **polling** tier, but their posture results and remediation advice
are Windows-focused; packet capture with Npcap/raw sockets is unavailable there.

## What it does

**Traffic statistics** — live throughput in and out, protocol breakdown, encrypted vs
plaintext split, top talkers by host, process, port and protocol, over windows from
5 minutes to 24 hours.

**Traffic logger** — every observed packet or flow in a searchable, filterable,
virtualized table: time, protocol, direction, peer, resolved hostname, owning process,
byte count and risk. Live tail, detail drawer, CSV export.

**Host security posture** — around 40 read-only checks across firewall, SMB, remote
access, name resolution, network config, Wi-Fi, TLS, listening services, patching and
accounts. Each check reports what was found, why it matters, and the exact command to
fix it. Scored and graded.

**Threat detection** — 22 behavioural detectors mapped to MITRE ATT&CK: C2 beaconing,
DNS tunnelling and DGA lookups, data exfiltration, port scans and host sweeps, ARP
spoofing and rogue DHCP, lateral movement over SMB/RDP/WinRM, plaintext credentials,
mining and Tor traffic, TLS anomalies, deprecated protocols. Each detection explains
its reasoning, shows its numbers, and states its known false positives.

**Recommended actions** — hygiene and configuration advice derived from what was
actually observed, with copy-pasteable PowerShell. NetAudit never executes a
remediation command; it shows you the command and you decide.

## Layout

```
backend/
  netaudit/
    capture/    three-tier packet capture
    store/      SQLite log, flows, stats, devices, retention
    rules/      hygiene recommendations
    posture/    host security posture checks
    threat/     threat detection engine + offline indicators
    api/        HTTP routers
frontend/       React + Vite dashboard
docs/           API_CONTRACT.md, API_CONTRACT_V2_SECURITY.md (frozen interfaces)
start.ps1       launcher
```

## Capture tiers

The capture layer degrades gracefully depending on what the host allows:

| Tier | Requirement | What you get |
|---|---|---|
| `npcap` | [Npcap](https://npcap.com) installed + admin | Full packet headers, all protocols, both directions |
| `rawsocket` | Admin only | IPv4 packet headers via `SIO_RCVALL` promiscuous raw sockets |
| `polling` | Nothing | Connection-table deltas from `psutil` — flows and byte counts, no per-packet detail |

`GET /api/health` reports the active tier and why it fell back, and the dashboard shows
a banner telling you what you're missing.

## Running

### Windows

```powershell
.\start.ps1
```

Run it from an **Administrator** PowerShell to get real packet capture. Without
elevation it still works, on the polling tier, with reduced detail.

### Linux

Requires Python 3.11+ and Node.js 20+ with npm. This starts the portable polling
tier; it does not provide Npcap/raw-socket capture or Windows posture checks.

```bash
git clone https://github.com/Exodus032/NetAudit.git
cd NetAudit
python3 -m venv backend/.venv
source backend/.venv/bin/activate
pip install -r backend/requirements.txt
(cd frontend && npm install && npm run build)
(cd backend && python -m netaudit.server)
```

Open `http://127.0.0.1:8787`.

### macOS

Install Python 3.11+ and Node.js 20+ (for example with Homebrew), then use the same
commands as the Linux section above. macOS runs the polling tier only; macOS firewall,
packet-capture, and host-posture checks are not currently implemented.

### Share the dashboard on Linux or macOS

After building the frontend as above, start the backend only on a trusted network:

```bash
cd backend
python -m netaudit.server --unsafe-bind 0.0.0.0 --allow-lan-bootstrap
```

Open `http://<computer-ip>:8787` from another device on that network. If the host
firewall blocks it, allow inbound TCP port 8787 only from your local subnet. On macOS,
you may need to allow the virtual-environment Python executable through the Application
Firewall. Do not expose this port to the internet: LAN mode shares live audit data with
any device that can reach it.

### Share the dashboard on your LAN

To open the dashboard from another device on the same trusted network, run this
from an elevated PowerShell:

```powershell
.\start.ps1 -Lan
```

The launcher builds the dashboard, serves it on port 8787, prints its LAN URL,
and creates a Windows Firewall rule limited to the **Private** profile and the
local subnet. Open the printed `http://<PC-IP>:8787` address from another
device on that network. LAN mode intentionally exposes the dashboard's audit
data to devices that can reach that address, so use it only on a network you
trust. Stop the launcher to end access; remove the `NetAudit LAN dashboard`
firewall rule when you no longer want to share it.

Manual:

```powershell
cd backend; python -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt; python -m netaudit.server   # 127.0.0.1:8787

cd frontend; npm install; npm run dev                        # localhost:5173
```

## Security of the tool itself

NetAudit binds loopback only, requires a locally generated auth token on every API and
WebSocket call, parameterises all SQL, never passes request input to a shell, caps
query sizes, escapes CSV export fields, rate-limits the API, and validates WebSocket
origins. It stores packet headers and metadata, not payloads. See Part C of
`docs/API_CONTRACT_V2_SECURITY.md` for the full list — every item there has a test.

## What it can and cannot see

Detection quality is bounded by the capture tier, and the tool is explicit about
this rather than quietly degrading.

**On the polling tier (no admin, no Npcap)** the connection table is sampled on a
fixed interval, so every long-lived connection arrives as a perfectly regular
series. Timing-based detection is meaningless on that data, so `c2_beaconing` is
switched off automatically and reported as disabled in `/api/threats/detectors`.
Run elevated to get it back.

**DNS detectors are inert against live traffic.** The capture layer records packet
headers only and never parses DNS payloads, so there is no query name, type or
response code to hand to `dns_tunneling`, `dga_domains` or `dns_exfil_volume`.
They are fully unit-tested but will not fire on real traffic until a DNS payload
parser exists. Synthesising plausible-looking queries from port-53 traffic would
let them appear to work while feeding them fabricated input, which is worse.

**TLS inspection is limited** for the same reason: nothing parses ClientHello, so
`tls_version`, JA3 and certificate flags are never populated and `suspicious_tls`
skips rather than guessing.

**`rogue_dhcp` cannot fire.** ARP visibility comes from polling the OS ARP cache
for IP-to-MAC changes, which is enough for `arp_spoofing` and `mac_flapping` but
carries no DHCP traffic.

**Loopback and broadcast traffic are excluded** from threat detection. Both
produced confident false positives in testing: the machine appearing to port-scan
itself across 113 loopback ports, and the broadcast MAC `FF:FF:FF:FF:FF:FF`
appearing to "claim" two broadcast addresses as a critical ARP spoofing event.
Local listener exposure is covered by the `listening_exposed` rule and the
posture `listening_services` checks instead.

**The bundled indicator set is a starter set, not a threat feed.** It contains
only publicly documented infrastructure facts, each with its source. Tor exit
lists and scanner ranges are deliberately absent because they rotate faster than
a static bundled file can honestly track.

**12 of the 43 posture checks never return `fail`** — they are informational or
heuristic, and a hard fail would overstate the risk. `promiscuous_adapters` in
particular is a heuristic: Windows exposes no true promiscuous-mode API, so it
detects Npcap/WinPcap driver bindings instead.

## Scope

This tool observes traffic on interfaces you own and audits the machine you run it on.
It does not attack, block, or modify anything, and its discovery is limited to passive
observation plus ARP-level visibility of devices already talking on your subnet.
