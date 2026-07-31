# NetAudit API Contract v2 — Security Extensions (FROZEN)

Additive to `API_CONTRACT.md`. All conventions from v1 apply unchanged: same host
`127.0.0.1:8787`, `/api` prefix, ISO-8601 UTC `Z` timestamps, integer byte counts,
`{"error":{"code","message"}}` on failure.

**Nobody may edit this file.** If something is unworkable, report it, don't change it.

Severity vocabulary is shared with v1: `critical` | `high` | `medium` | `low` | `info`.

---

# Part A — Host security posture

Read-only audit of how this machine is configured for network exposure. Never
changes system state. Every check reports what it found, why it matters, and the
exact command the user could run to fix it — the backend does not run it.

## A1. `GET /api/posture`

```json
{
  "generated_at": "2026-07-31T14:03:11.482Z",
  "scan_duration_ms": 2140,
  "score": 68,
  "grade": "C",
  "counts": { "pass": 21, "warn": 6, "fail": 3, "error": 1, "skipped": 2 },
  "categories": [
    {
      "id": "firewall",
      "label": "Firewall",
      "score": 55,
      "checks": ["firewall_profiles_enabled", "firewall_inbound_default_block"]
    }
  ],
  "checks": [
    {
      "id": "smb_signing_required",
      "category": "smb",
      "title": "SMB signing is not required",
      "status": "fail",
      "severity": "high",
      "score_weight": 8,
      "observed": "RequireSecuritySignature = False on the SMB client and server",
      "expected": "RequireSecuritySignature = True",
      "why_it_matters": "Without required signing, an attacker on the same network can relay or tamper with SMB sessions.",
      "evidence": [
        { "label": "Client", "value": "RequireSecuritySignature: False" },
        { "label": "Server", "value": "RequireSecuritySignature: False" }
      ],
      "remediation": {
        "summary": "Require SMB signing on both the client and the server.",
        "commands": [
          {
            "shell": "powershell",
            "command": "Set-SmbClientConfiguration -RequireSecuritySignature $true -Force; Set-SmbServerConfiguration -RequireSecuritySignature $true -Force",
            "requires_admin": true,
            "reversible": true,
            "risk_note": "May reduce throughput slightly and can break very old SMBv1 devices."
          }
        ],
        "docs_url": "https://learn.microsoft.com/windows-server/storage/file-server/smb-signing"
      },
      "references": ["CIS Microsoft Windows 11 v3.0.0 2.3.9.2"],
      "checked_at": "2026-07-31T14:03:10.100Z",
      "duration_ms": 34
    }
  ]
}
```

`status` ∈ `pass` | `warn` | `fail` | `error` | `skipped`.
- `error` = the check itself could not run (permissions, cmdlet missing). Put the reason in `observed`.
- `skipped` = not applicable to this host (e.g. no Wi-Fi adapter).
- `score` is 0–100 overall and per category. `grade` ∈ `A` | `B` | `C` | `D` | `F`.
- Score formula: `100 * (sum of score_weight for pass + 0.5 * warn) / (sum of score_weight for pass|warn|fail)`. `error` and `skipped` are excluded from both sides. Round to nearest int.

Query params: `?category=firewall` filters; `?include_pass=false` omits passing checks.

## A2. `GET /api/posture/checks/{id}`

A single check object, same shape as an element of `checks`.

## A3. `POST /api/posture/rescan`

Body: `{ "categories": ["firewall","smb"] }` (optional; omit for all).
Returns the full `/api/posture` payload. Must be safe to call repeatedly.
Results are cached; a plain `GET /api/posture` serves cache and reports `generated_at`.

## A4. Required check catalogue

Category ids and the checks each must contain, at minimum:

| Category | Checks |
|---|---|
| `firewall` | `firewall_profiles_enabled`, `firewall_inbound_default_block`, `firewall_allow_rules_broad`, `firewall_logging_enabled` |
| `smb` | `smb1_disabled`, `smb_signing_required`, `smb_guest_auth_disabled`, `smb_shares_exposed` |
| `remote_access` | `rdp_disabled_or_nla`, `winrm_exposure`, `remote_registry_disabled`, `psremoting_scope` |
| `name_resolution` | `llmnr_disabled`, `netbios_disabled`, `mdns_exposure`, `wpad_disabled`, `dns_over_https`, `dns_servers_trusted` |
| `network_config` | `ipv6_state`, `ip_forwarding_disabled`, `promiscuous_adapters`, `unused_adapters_enabled`, `network_profile_public` |
| `wifi` | `wifi_encryption_strength`, `wifi_open_networks_saved`, `wifi_autoconnect_open` |
| `tls` | `tls10_11_disabled`, `ssl3_disabled`, `weak_ciphers_disabled`, `certificate_store_anomalies` |
| `listening_services` | `listening_on_all_interfaces`, `high_risk_ports_open`, `unexpected_listeners`, `upnp_disabled` |
| `updates_and_defense` | `defender_realtime_enabled`, `defender_signatures_current`, `windows_update_current`, `uac_enabled`, `bitlocker_status` |
| `accounts` | `guest_account_disabled`, `local_admin_count`, `blank_passwords`, `autologon_disabled` |

Implement every check. Where a check genuinely cannot be determined without admin,
return `status: "error"` with a clear `observed` string rather than guessing.

## A5. `GET /api/security/score`

Composite of posture, live threats, and traffic hygiene.

```json
{
  "generated_at": "2026-07-31T14:03:11.482Z",
  "overall": 64,
  "grade": "C",
  "components": [
    { "id": "posture",  "label": "Host configuration", "score": 68, "weight": 0.4, "grade": "C" },
    { "id": "threats",  "label": "Active threats",     "score": 55, "weight": 0.35, "grade": "D" },
    { "id": "hygiene",  "label": "Traffic hygiene",    "score": 74, "weight": 0.25, "grade": "B" }
  ],
  "history": [ { "t": "2026-07-31T13:00:00Z", "overall": 61 } ],
  "top_wins": [
    { "id": "smb_signing_required", "kind": "posture", "title": "Require SMB signing", "score_gain": 8, "effort": "low" }
  ]
}
```

`kind` ∈ `posture` | `threat` | `recommendation`. `effort` ∈ `low` | `medium` | `high`.
`history` holds up to 168 hourly points. `overall` is the weighted sum, rounded.

---

# Part B — Threat detection

Behavioural and signature detections over captured traffic. Distinct from v1
`/api/recommendations`, which stays as hygiene/config advice. Threats are things
that look actively bad.

## B1. `GET /api/threats`

Query params: `limit` (default 100), `offset`, `severity`, `category`, `status`,
`since`, `until`, `q`, `include_acknowledged` (default false).

```json
{
  "total": 12,
  "limit": 100,
  "offset": 0,
  "threats": [
    {
      "id": "beacon-93.184.216.34-a91f",
      "detector_id": "c2_beaconing",
      "title": "Regular beaconing to 93.184.216.34 every 60s",
      "severity": "high",
      "confidence": 0.82,
      "category": "command_and_control",
      "status": "active",
      "mitre": [
        { "tactic": "TA0011", "tactic_name": "Command and Control",
          "technique": "T1071.001", "technique_name": "Application Layer Protocol: Web Protocols" }
      ],
      "summary": "svchost.exe contacted 93.184.216.34:443 41 times at a near-constant 60s interval.",
      "detail": "Inter-arrival times had a coefficient of variation of 0.04 across 41 contacts, with a consistent 512-byte request size. Regular low-variance intervals with uniform payload sizes are characteristic of automated command-and-control check-ins rather than user-driven traffic.",
      "evidence": [
        { "label": "Peer", "value": "93.184.216.34:443" },
        { "label": "Interval", "value": "60.2s (CV 0.04)" },
        { "label": "Contacts", "value": "41" },
        { "label": "Process", "value": "svchost.exe (pid 1204)" }
      ],
      "indicators": [
        { "type": "ip", "value": "93.184.216.34", "context": "beacon destination" }
      ],
      "metrics": { "interval_seconds": 60.2, "cv": 0.04, "contacts": 41, "bytes_total": 20992 },
      "first_seen": "2026-07-31T13:22:00Z",
      "last_seen": "2026-07-31T14:02:10Z",
      "occurrences": 41,
      "related_connection_ids": ["tcp-192.168.1.42:52201-93.184.216.34:443"],
      "related_log_ids": [48120, 48155],
      "false_positive_notes": "Software update checks and telemetry agents also beacon on fixed intervals. Confirm the process and destination before acting.",
      "recommended_actions": [
        {
          "label": "Identify the process",
          "kind": "command",
          "shell": "powershell",
          "command": "Get-Process -Id 1204 | Select-Object Id,ProcessName,Path,StartTime",
          "requires_admin": false,
          "detail": "Confirm what this process is before blocking anything."
        },
        {
          "label": "Block the destination",
          "kind": "command",
          "shell": "powershell",
          "command": "New-NetFirewallRule -DisplayName 'NetAudit block 93.184.216.34' -Direction Outbound -RemoteAddress 93.184.216.34 -Action Block",
          "requires_admin": true,
          "reversible": true,
          "detail": "Blocks all outbound traffic to this address."
        }
      ]
    }
  ]
}
```

`status` ∈ `active` | `resolved` | `acknowledged`. A threat becomes `resolved` when its
detector has not re-fired for its configured cooldown.
`category` ∈ `command_and_control` | `exfiltration` | `reconnaissance` | `lateral_movement` |
`credential_exposure` | `dns_abuse` | `spoofing` | `malicious_peer` | `policy_violation` | `anomaly`.
`indicators[].type` ∈ `ip` | `domain` | `url` | `port` | `process` | `mac` | `ja3` | `hash`.

**No action is ever executed by the backend.** `command` strings are copy-only.

## B2. `GET /api/threats/{id}` — one threat, same shape.

## B3. `POST /api/threats/{id}/acknowledge` and `.../unacknowledge`

Body: optional `{ "note": "known telemetry agent" }`.
Response: `{ "id": "...", "status": "acknowledged", "note": "..." }`. Persisted.

## B4. `GET /api/threats/timeline?window=24h&bucket=3600`

```json
{
  "window": "24h",
  "bucket_seconds": 3600,
  "points": [
    { "t": "2026-07-31T13:00:00Z", "critical": 0, "high": 1, "medium": 3, "low": 2, "info": 0 }
  ]
}
```

Contiguous, zero-filled, oldest first.

## B5. `GET /api/threats/detectors`

```json
{
  "detectors": [
    {
      "id": "c2_beaconing",
      "label": "C2 beaconing",
      "category": "command_and_control",
      "description": "Finds peers contacted on a low-variance interval with uniform payload sizes.",
      "enabled": true,
      "default_severity": "high",
      "mitre": [{ "tactic": "TA0011", "technique": "T1071.001" }],
      "tunables": [
        { "key": "min_contacts", "value": 8, "type": "int", "min": 4, "max": 100,
          "description": "Minimum contacts before the detector fires." }
      ],
      "fired_count": 3,
      "last_fired": "2026-07-31T14:02:10Z"
    }
  ]
}
```

## B6. `PATCH /api/threats/detectors/{id}`

Body: `{ "enabled": false }` or `{ "tunables": { "min_contacts": 12 } }`.
Returns the updated detector. Validate against declared `min`/`max`/`type`; reject
out-of-range with HTTP 400 and the standard error body. Persisted.

## B7. Required detector catalogue

| id | Category | What it finds |
|---|---|---|
| `c2_beaconing` | command_and_control | Low-variance contact intervals with uniform payload sizes |
| `dns_tunneling` | dns_abuse | High query volume, long labels, high entropy subdomains, TXT/NULL-heavy to one domain |
| `dga_domains` | dns_abuse | High-entropy, consonant-heavy, unpronounceable domain lookups |
| `dns_exfil_volume` | exfiltration | Outbound bytes over DNS far exceeding a normal ratio |
| `data_exfiltration` | exfiltration | Egress volume to a single external peer far above baseline for that process |
| `off_hours_transfer` | exfiltration | Large transfers during hours with historically no activity |
| `port_scan_outbound` | reconnaissance | This host touching many ports on one peer in a short window |
| `port_scan_inbound` | reconnaissance | One peer touching many ports on this host |
| `host_sweep` | reconnaissance | One peer contacting many hosts on the subnet |
| `arp_spoofing` | spoofing | One MAC claiming multiple IPs, or a gateway IP changing MAC |
| `mac_flapping` | spoofing | An IP rapidly alternating between MACs |
| `rogue_dhcp` | spoofing | DHCP offers from an address that is not the known server |
| `lateral_smb_rdp` | lateral_movement | SMB/RDP/WinRM connections to multiple internal hosts in a short window |
| `credentials_plaintext` | credential_exposure | Auth-bearing protocols in the clear: FTP, Telnet, HTTP Basic, IMAP/POP3, LDAP simple bind |
| `known_bad_peer` | malicious_peer | Peer matches the bundled offline indicator set |
| `tor_or_proxy` | malicious_peer | Traffic to known Tor entry ranges or open-proxy ports |
| `crypto_mining` | malicious_peer | Stratum ports / known pool endpoints / mining-shaped traffic |
| `suspicious_tls` | anomaly | Self-signed or expired certs, TLS < 1.2, unusual SNI/ALPN, JA3 on the watchlist |
| `nonstandard_port_service` | anomaly | A known protocol running on an unexpected port (SSH on 443, HTTP on 8443, etc.) |
| `new_external_peer` | anomaly | First-ever contact with an external peer by a process that has a stable history |
| `protocol_anomaly` | anomaly | Malformed headers, impossible flag combinations, fragmentation abuse |
| `deprecated_protocol` | policy_violation | SMBv1, Telnet, FTP, SSLv3, NTLMv1 observed on the wire |

Every detector must be individually unit-tested with a positive case that fires and
a near-miss that does not. Detectors run on stored data, never on live sockets, so
they are deterministic and testable.

## B8. Threat intelligence — offline only

`GET /api/intel/lookup?value=93.184.216.34&type=ip`

```json
{
  "value": "93.184.216.34",
  "type": "ip",
  "found": true,
  "matches": [
    { "source": "bundled-ioc-v1", "category": "scanner", "confidence": 0.7,
      "first_added": "2026-01-04", "note": "Mass-scanning infrastructure" }
  ],
  "classification": { "is_private": false, "is_bogon": false, "is_multicast": false,
                      "is_tor_exit": false, "asn": null, "org": null, "country": null },
  "reputation": "suspicious"
}
```

`reputation` ∈ `clean` | `unknown` | `suspicious` | `malicious`.

**Hard constraint: the tool makes no outbound network requests of its own.** Indicator
data ships as a local bundled file. Any enrichment that would require calling a third
party must be absent, not stubbed with a live call. `asn`/`org`/`country` may be `null`
unless a local database is present.

---

# Part C — Application hardening requirements

These are requirements on NetAudit itself, not features. They are testable.

1. **Bind loopback only.** Listener binds `127.0.0.1`. Binding to `0.0.0.0` must be
   impossible without an explicit `--unsafe-bind` flag that logs a loud warning.
2. **Local auth token.** On start, generate a random 32-byte token, write it to
   `%LOCALAPPDATA%\NetAudit\token` with owner-only ACLs, and require it on every
   `/api` and `/ws` request via `X-NetAudit-Token` header or `?token=`. The frontend
   reads it from a `GET /api/bootstrap` endpoint that is only served to loopback
   with a same-origin `Origin`/`Sec-Fetch-Site` check. Reject everything else 401.
3. **No command execution from HTTP input, ever.** No endpoint may pass any part of a
   request into a shell, `subprocess`, `os.system`, or a PowerShell string. Posture
   checks run a fixed allowlist of parameterless commands defined in code as argument
   lists, never as concatenated strings.
4. **SQL is parameterised everywhere.** No f-string or `%` formatting into SQL. Sort
   and filter fields map through a hardcoded allowlist dict, never interpolated.
5. **CSV injection defence.** On export, any field beginning with `=`, `+`, `-`, `@`,
   tab or CR is prefixed with `'`.
6. **Bounded everything.** `limit` capped at 1000. Query timeouts. Bounded capture
   queue with explicit drop accounting surfaced in `/api/health` as `dropped_packets`.
   Bounded DNS resolution concurrency and cache size. No unbounded in-memory growth.
7. **Path safety.** No endpoint accepts a filesystem path from the client. Export
   filenames are server-generated.
8. **Secrets never logged or stored.** Packet payloads are not persisted by default;
   only headers and metadata. If a payload snippet is captured for a detection, it is
   truncated to 64 bytes and redacted for anything matching credential patterns.
9. **Rate limiting.** Per-IP token bucket on `/api`, since a local browser page from a
   malicious site could otherwise hammer it. Reject with 429.
10. **CORS is strict.** Only `http://localhost:5173` and `http://127.0.0.1:5173`.
    No wildcard, no credential-bearing wildcard, no reflecting arbitrary `Origin`.
11. **WebSocket origin check.** `/ws/live` validates `Origin` against the same list and
    requires the token. Reject otherwise before the upgrade completes.
12. **Dependency hygiene.** Pinned versions in `requirements.txt`. No package that
    phones home. Document why each dependency is present.
13. **Fail closed.** If the auth token file cannot be created with correct permissions,
    the server refuses to start rather than serving unauthenticated.

Every numbered item above must have a corresponding test that would fail if the
protection were removed.
