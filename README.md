# NetAudit

A local network auditing and security tool for Windows. It captures traffic on your
own machine, shows you what's actually happening on the wire, audits how the host is
configured, flags suspicious behaviour, and tells you what to do about it.

Everything runs on localhost against your own network. Nothing is uploaded, and the
tool makes no outbound requests of its own.

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

```powershell
.\start.ps1
```

Run it from an **Administrator** PowerShell to get real packet capture. Without
elevation it still works, on the polling tier, with reduced detail.

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

## Scope

This tool observes traffic on interfaces you own and audits the machine you run it on.
It does not attack, block, or modify anything, and its discovery is limited to passive
observation plus ARP-level visibility of devices already talking on your subnet.
