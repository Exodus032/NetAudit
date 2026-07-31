# NetAudit backend

FastAPI service implementing `docs/API_CONTRACT.md`. Serves on
`http://127.0.0.1:8787`.

## Setup

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m netaudit.server
```

The server starts capture automatically on launch, using whatever tier your
privileges allow (see below), and creates its SQLite database at
`%LOCALAPPDATA%\NetAudit\netaudit.db` (override with the `NETAUDIT_DB_PATH`
env var, mainly useful for testing).

If `../frontend/dist` exists it's served as static files at `/`. The backend
works fine standalone with no frontend build present.

## Admin / Npcap note

**Run the terminal as Administrator, and install [Npcap](https://npcap.com),
to get full packet capture.** Without both, NetAudit still works, but sees
less:

| Tier | Requirement | What you get |
|---|---|---|
| `npcap` | Npcap installed + admin | Full IP/TCP/UDP/ICMP headers, both directions, via scapy |
| `rawsocket` | Admin only (no Npcap) | IPv4 header parsing via `SIO_RCVALL` raw sockets (own parser in `capture/parse.py`) |
| `polling` | Nothing | Connection-table snapshots (`psutil.net_connections` + `psutil.net_io_counters`) sampled every 2s; byte counts are **estimated** by splitting the interface's byte-count delta evenly across concurrently active connections, not measured per-flow. No packet-level detail (flags, exact per-packet size) is available in this tier. |

`GET /api/health` reports `capture.mode`, `capture.elevated`, and
`capture.degraded_reason` (a human-readable explanation whenever a lower
tier is active). The `stale_capture_tier` recommendation also surfaces this
in the UI with instructions to fix it.

Tier selection (`netaudit/capture/selector.py`) probes npcap, then raw
sockets, then falls back to polling -- it never crashes; polling always
works with zero privileges.

## Architecture

```
netaudit/
  server.py         FastAPI app factory, CORS, exception handling, static frontend mount, uvicorn entrypoint
  config.py          all settings (ports, DB path, retention, cadences)
  pipeline.py        owns the running capture backend + background asyncio tasks
                      (ingest, retention sweep, rules tick, ARP device discovery)
  models.py          pydantic models mirroring the contract
  netinfo.py          interface enumeration (psutil)
  arpscan.py          `arp -a` parsing for LAN device discovery
  risk.py, format.py, timeutil.py   small shared helpers
  ws.py               /ws/live broadcaster
  api/                one router module per contract section
  capture/
    base.py           CaptureBackend ABC + PacketEvent
    parse.py           pure-python IPv4/TCP/UDP/ICMP header parser (unit-tested against byte fixtures)
    npcap.py            scapy-based sniffer
    rawsock.py           SIO_RCVALL raw-socket sniffer
    polling.py            psutil-based zero-privilege tier
    selector.py             probes tiers in order, never raises
    enrich.py                 PID<->process mapping, reverse DNS cache, MAC vendor table, port/IP classification
  store/
    db.py             SQLite schema (WAL mode) + thread-local connections
    packets.py          raw packet/flow log: append + filtered/paginated query
    flows.py              flow aggregation table (feeds /api/connections)
    stats.py                minute-granularity aggregates (survive packet-row pruning) + timeseries/summary/top queries
    devices.py                LAN device table
    retention.py               prunes packets by age (default 24h) and row cap (default 2,000,000)
  rules/
    base.py            Rule ABC + RuleFinding/RuleContext
    builtin.py           the 10 rules (below)
    engine.py              runs all rules, dedupes findings into stable IDs, persists first_seen/last_seen/occurrences/dismissed
```

Capture runs on a background thread per tier, pushing into a bounded queue;
`pipeline.py`'s ingest loop drains it every 0.5s off the asyncio event loop
(via `asyncio.to_thread`) so capture and DNS lookups never block requests.

## Recommendation rules

All in `netaudit/rules/builtin.py`, each with a stable `rule_id`, evidence
pulled from real observed data, and copy-pasteable (never executed)
PowerShell actions where applicable:

- **plaintext_http** -- meaningful volume (>5KB) over 80/21/23/143/110/389 to external hosts.
- **plaintext_dns** -- DNS to external resolvers with no DoT (port 853) observed.
- **listening_exposed** -- a process listening on 0.0.0.0/:: ; SMB/RDP/WinRM/SSH called out by name and rated higher severity.
- **unusual_port** -- sustained (>200KB, >20 packets) outbound traffic to a high port with no recognized service name.
- **beaconing** -- >=8 contacts to one peer with low inter-arrival variance (cv <= 0.15) and small payloads (<2KB avg).
- **heavy_talker** -- one process or peer accounts for >40% of window bytes (window must exceed 1MB total, to skip idle noise).
- **many_peers** -- one process contacts an abnormally large number (>=25) of distinct external hosts.
- **insecure_lan_service** -- a discovered LAN device has FTP/Telnet/SMB open.
- **stale_capture_tier** -- running in `polling` or `rawsocket`; severity `info`; points at Npcap + admin.
- **broadcast_noise** -- high volume of NBNS/LLMNR/mDNS/broadcast traffic (>=300 packets in the rules window).

The engine (`rules/engine.py`) ticks every 5s over the last hour of data,
hashes each finding's stable key into a short id (e.g. `plaintext-http-4f2a`),
and upserts into SQLite: new findings get `first_seen`/`occurrences=1`,
repeat findings bump `last_seen`/`occurrences`. Dismissals persist across
restarts and survive re-triggering (a dismissed finding that recurs updates
its data but stays dismissed until explicitly restored).

**The backend never executes a recommended action** -- `actions[].command`
strings are for the user to review and run themselves.

## Known limitations (be honest about these)

- **Polling-tier byte counts are estimated**, not measured -- see the table above.
- **`by=country` in `/api/stats/top` has no real GeoIP.** No local database is bundled (keeps the tool fully offline), so it falls back to an Internal/External split, which is the honest signal actually available.
- **`is_gateway` for LAN devices is a heuristic** (`ip` ends in `.1`), not a real routing-table lookup.
- **MAC addresses are only captured via the OS ARP cache** (`arp -a`), refreshed every 15s -- devices that haven't exchanged ARP recently may show without a MAC/vendor.
- **`/api/stats/summary` and per-packet fields for windows longer than the retention period** (default 24h) will undercount, since only `stats_minutely` (bytes/packet counts, not host/process uniqueness) survives packet-row pruning. Long-window `timeseries` stays accurate; long-window `summary`'s `active_flows`/`unique_remote_hosts` do too (flows table isn't pruned) -- only the raw packet-derived counters are affected.
- **No IPv6 header parsing in the raw-socket tier** -- `SIO_RCVALL` on an `AF_INET` socket only observes IPv4. npcap tier (scapy) is limited to IP/TCP/UDP/ICMP in this build; no L2 MAC capture from the npcap tier is currently emitted into device records (only ARP-cache MACs are).

## Testing

```powershell
python -m pytest
```

72 tests: pure-logic unit tests (IPv4/TCP/UDP/ICMP header parsing against
handcrafted byte fixtures, including malformed/truncated input that must
never raise; stats bucketing and zero-fill; traffic-log filtering,
pagination, and `total`; each rule with a trigger case and a near-miss
case; tier-selector fallback under mocked elevation/probe failures) plus
FastAPI endpoint tests via `TestClient` asserting response shapes against
the contract field-for-field. A fake/injectable rule context and monkeypatched
`psutil` calls mean none of this needs real packets or admin.

## Troubleshooting

- **"Access is denied" on startup as non-admin**: expected -- you're on the
  `polling` tier. Check `/api/health` to confirm.
- **Npcap tier never selected even when elevated**: install Npcap from
  https://npcap.com (WinPcap-compatible mode not required). Check
  `capture.degraded_reason` in `/api/health` for the specific probe error.
- **No LAN devices show up**: the device table is seeded from your OS's ARP
  cache (`arp -a`), which only contains hosts you've recently talked to.
  Generate some LAN traffic (e.g. open your router's admin page) and wait
  ~15s for the next ARP refresh.
- **Port 8787 already in use**: another NetAudit instance (or something
  else) is bound to it. Stop it, or set `NETAUDIT_PORT`.
- **DB grows unexpectedly large**: check `NETAUDIT_RETENTION_HOURS` /
  `NETAUDIT_RETENTION_MAX_ROWS`; retention only prunes the raw `packets`
  table, not aggregates.
