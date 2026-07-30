# NetAudit API Contract (v1) — FROZEN

This file is the single source of truth shared by the backend and frontend agents.
**Neither agent may change this file.** If something here is genuinely unworkable,
stop and report it instead of editing.

- Backend serves on `http://127.0.0.1:8787`
- All REST endpoints are under `/api`
- All responses are JSON, `Content-Type: application/json`
- All timestamps are ISO-8601 UTC strings with `Z` (e.g. `2026-07-31T14:03:11.482Z`)
- All byte counts are integers (bytes, not KB)
- Errors: HTTP status + `{"error": {"code": "string", "message": "human readable"}}`
- CORS: backend allows origin `http://localhost:5173` and `http://127.0.0.1:5173`

Frontend dev server runs on port 5173 and proxies `/api` and `/ws` to `127.0.0.1:8787`.

---

## 1. `GET /api/health`

```json
{
  "status": "ok",
  "version": "1.0.0",
  "uptime_seconds": 412.5,
  "capture": {
    "mode": "npcap",
    "elevated": true,
    "interface": "Ethernet",
    "running": true,
    "degraded_reason": null
  }
}
```

`capture.mode` is one of `"npcap"`, `"rawsocket"`, `"polling"`, `"off"`.
`degraded_reason` is `null` or a human-readable string explaining why a lower
tier is in use (e.g. `"Npcap not installed; falling back to raw sockets"`).

## 2. `GET /api/interfaces`

```json
{
  "interfaces": [
    {
      "id": "Ethernet",
      "name": "Ethernet",
      "description": "Intel(R) Ethernet Connection",
      "ipv4": "192.168.1.42",
      "ipv6": "fe80::1c2d:...",
      "mac": "AA:BB:CC:DD:EE:FF",
      "netmask": "255.255.255.0",
      "is_up": true,
      "is_loopback": false,
      "speed_mbps": 1000
    }
  ],
  "default_interface_id": "Ethernet"
}
```

## 3. `GET /api/stats/summary?window=5m`

`window` ∈ `5m` | `15m` | `1h` | `24h` | `all`. Default `5m`.

```json
{
  "window": "5m",
  "generated_at": "2026-07-31T14:03:11.482Z",
  "packets_total": 184223,
  "bytes_total": 219884412,
  "bytes_in": 180221100,
  "bytes_out": 39663312,
  "packets_in": 121004,
  "packets_out": 63219,
  "throughput_bps_in": 4812221,
  "throughput_bps_out": 918110,
  "peak_throughput_bps": 9911002,
  "active_flows": 87,
  "unique_remote_hosts": 43,
  "unique_processes": 19,
  "tcp_packets": 150221,
  "udp_packets": 31882,
  "icmp_packets": 210,
  "other_packets": 1910,
  "encrypted_bytes": 200112400,
  "plaintext_bytes": 19772012,
  "external_bytes": 210221004,
  "internal_bytes": 9663408,
  "open_alerts": 4,
  "alerts_by_severity": { "critical": 0, "high": 1, "medium": 2, "low": 1, "info": 0 }
}
```

`encrypted_bytes` = traffic on 443/8443/993/995/22/etc; `plaintext_bytes` = the rest.
`internal_bytes` = RFC1918/link-local peers; `external_bytes` = routable peers.

## 4. `GET /api/stats/timeseries?window=1h&bucket=60`

`bucket` = seconds per bucket (integer, 1–3600). Buckets are contiguous, oldest first,
and zero-filled for idle periods so the frontend can plot without gap handling.

```json
{
  "window": "1h",
  "bucket_seconds": 60,
  "points": [
    {
      "t": "2026-07-31T13:03:00Z",
      "bytes_in": 4021110,
      "bytes_out": 812210,
      "packets_in": 3120,
      "packets_out": 1880,
      "tcp": 4210, "udp": 690, "icmp": 4, "other": 96
    }
  ]
}
```

## 5. `GET /api/stats/top?by=host&limit=10&window=5m`

`by` ∈ `host` | `process` | `port` | `protocol` | `country`.

```json
{
  "by": "host",
  "window": "5m",
  "items": [
    {
      "key": "142.250.185.78",
      "label": "google.com",
      "sublabel": "Google LLC",
      "bytes_in": 40221100,
      "bytes_out": 2211004,
      "bytes_total": 42432104,
      "packets": 31002,
      "flows": 12,
      "share": 0.31,
      "is_external": true,
      "risk": "low"
    }
  ]
}
```

`share` is 0–1 of the total for that dimension. `risk` ∈ `low` | `medium` | `high`.
For `by=process`, `key` is `"pid:name"`, `label` is the process name, `sublabel` the exe path.
For `by=port`, `key` is `"443/tcp"`, `label` the service name (`"https"`).

## 6. `GET /api/connections`

Live connection/flow table, refreshed by the backend at least every 2s.

```json
{
  "generated_at": "2026-07-31T14:03:11.482Z",
  "connections": [
    {
      "id": "tcp-192.168.1.42:51422-142.250.185.78:443",
      "protocol": "tcp",
      "state": "ESTABLISHED",
      "local_addr": "192.168.1.42",
      "local_port": 51422,
      "remote_addr": "142.250.185.78",
      "remote_port": 443,
      "remote_host": "google.com",
      "remote_org": "Google LLC",
      "direction": "outbound",
      "pid": 8842,
      "process_name": "chrome.exe",
      "process_path": "C:\\Program Files\\Google\\Chrome\\chrome.exe",
      "bytes_in": 401120,
      "bytes_out": 88210,
      "packets": 902,
      "first_seen": "2026-07-31T13:58:02Z",
      "last_seen": "2026-07-31T14:03:10Z",
      "is_external": true,
      "is_encrypted": true,
      "risk": "low",
      "risk_reasons": []
    }
  ]
}
```

`state` for UDP flows is `"ACTIVE"`. `direction` ∈ `inbound` | `outbound` | `local`.

## 7. `GET /api/traffic/log`

Paginated packet/flow log — the traffic logger view.

Query params (all optional):
`limit` (default 100, max 1000), `offset` (default 0), `protocol`, `q` (free-text
match on host/process/port), `since`, `until` (ISO-8601), `direction`,
`min_bytes`, `sort` (`time` | `bytes`, default `time`), `order` (`asc` | `desc`, default `desc`).

```json
{
  "total": 48221,
  "limit": 100,
  "offset": 0,
  "entries": [
    {
      "id": 48221,
      "ts": "2026-07-31T14:03:11.482Z",
      "protocol": "tcp",
      "src_addr": "192.168.1.42",
      "src_port": 51422,
      "dst_addr": "142.250.185.78",
      "dst_port": 443,
      "direction": "outbound",
      "length": 1420,
      "flags": "PSH,ACK",
      "process_name": "chrome.exe",
      "pid": 8842,
      "remote_host": "google.com",
      "is_external": true,
      "is_encrypted": true,
      "summary": "TLS application data",
      "risk": "low"
    }
  ]
}
```

## 8. `GET /api/traffic/export?format=csv` (also `json`)

Returns the current log (respecting the same filters as `/api/traffic/log`) as a
file download. `Content-Disposition: attachment; filename="netaudit-log-<ts>.csv"`.

## 9. `GET /api/devices`

LAN devices seen via ARP/packet observation.

```json
{
  "devices": [
    {
      "ip": "192.168.1.1",
      "mac": "AA:BB:CC:11:22:33",
      "vendor": "Netgear",
      "hostname": "router.local",
      "first_seen": "2026-07-31T12:00:00Z",
      "last_seen": "2026-07-31T14:03:00Z",
      "bytes_total": 88221004,
      "is_gateway": true,
      "is_self": false,
      "open_ports": [53, 80, 443],
      "risk": "low"
    }
  ]
}
```

## 10. `GET /api/recommendations`

The "recommended actions" panel. Sorted by severity then confidence.

```json
{
  "generated_at": "2026-07-31T14:03:11.482Z",
  "recommendations": [
    {
      "id": "plaintext-http-4f2a",
      "rule_id": "plaintext_http",
      "title": "Unencrypted HTTP traffic to 3 external hosts",
      "severity": "medium",
      "confidence": 0.9,
      "category": "encryption",
      "summary": "18.4 MB left this machine over plain HTTP in the last hour.",
      "detail": "Traffic to 93.184.216.34:80 (example.com) from chrome.exe is not encrypted and can be read or modified on the path.",
      "evidence": [
        { "label": "Peer", "value": "93.184.216.34:80 (example.com)" },
        { "label": "Bytes", "value": "18.4 MB" },
        { "label": "Process", "value": "chrome.exe (pid 8842)" }
      ],
      "actions": [
        {
          "label": "Force HTTPS for this site",
          "kind": "manual",
          "detail": "Enable HTTPS-Only mode in your browser settings."
        },
        {
          "label": "Block port 80 outbound",
          "kind": "command",
          "command": "New-NetFirewallRule -DisplayName 'NetAudit block HTTP' -Direction Outbound -Protocol TCP -RemotePort 80 -Action Block",
          "requires_admin": true,
          "detail": "Blocks all outbound plain HTTP. May break captive portals."
        }
      ],
      "first_seen": "2026-07-31T13:10:00Z",
      "last_seen": "2026-07-31T14:03:00Z",
      "occurrences": 412,
      "dismissed": false,
      "related_connection_ids": ["tcp-192.168.1.42:51402-93.184.216.34:80"]
    }
  ]
}
```

`severity` ∈ `critical` | `high` | `medium` | `low` | `info`.
`category` ∈ `encryption` | `exposure` | `suspicious_peer` | `configuration` | `volume` | `discovery` | `hygiene`.
`actions[].kind` ∈ `manual` | `command` | `link`. For `link`, an extra `url` field is present.

**The backend never executes an action.** `command` strings are for the user to copy.

## 11. `POST /api/recommendations/{id}/dismiss` and `.../restore`

Body: none. Response: `{ "id": "...", "dismissed": true }`.
Dismissed items are excluded from `/api/recommendations` unless `?include_dismissed=true`.

## 12. Capture control

- `GET /api/capture/status` → the `capture` object from `/api/health`
- `POST /api/capture/start` body `{ "interface_id": "Ethernet" }` → capture object
- `POST /api/capture/stop` → capture object
- `POST /api/capture/clear` → `{ "cleared": true }` (wipes stored log + stats)

## 13. `WS /ws/live`

Server pushes JSON frames. The frontend never sends anything except an optional
`{"type":"subscribe","channels":["stats","log","alerts"]}` on open (backend may ignore it
and send everything).

Frame shapes:

```json
{ "type": "stats", "data": { ...same shape as /api/stats/summary... } }
{ "type": "log", "data": [ ...array of /api/traffic/log entries, newest first... ] }
{ "type": "alert", "data": { ...same shape as one recommendation... } }
{ "type": "connections", "data": [ ...same shape as /api/connections connections... ] }
{ "type": "capture", "data": { ...capture object... } }
```

Cadence: `stats` and `connections` every 2s, `log` batched every 1s (max 200 entries
per frame), `alert` on change. Frontend must tolerate any order, missing frame types,
and reconnect with backoff if the socket closes.
