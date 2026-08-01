# NetAudit API Contract v3 (FROZEN)

Additive to `API_CONTRACT.md` (v1) and `API_CONTRACT_V2_SECURITY.md` (v2). All
existing conventions carry over unchanged: `127.0.0.1:8787`, `/api` prefix,
ISO-8601 UTC `Z` timestamps, integer byte counts, `{"error":{"code","message"}}`
on failure, `X-NetAudit-Token` on every request, severity vocabulary
`critical|high|medium|low|info`.

**Nobody may edit this file.** If something is unworkable, report it.

Two hard rules inherited from v2 and extended to everything here:

1. **NetAudit never executes a remediation or an attack.** Commands are strings
   the user copies. The one exception is Part E's active port scan, which is
   opt-in, rate-limited, restricted to the local subnet, and described below.
2. **No outbound network requests except those the user explicitly triggers.**
   Alert webhooks (Part F) are user-configured and user-enabled. Nothing phones
   home, no feed downloads, no telemetry.

---

# Part D — Learning mode (making this usable by a student)

The premise: someone who has never heard of ARP should be able to open this and
learn something true, without the tool dumbing down what it reports to a
professional.

## D1. `GET /api/glossary`

```json
{
  "terms": [
    {
      "id": "arp",
      "term": "ARP",
      "expansion": "Address Resolution Protocol",
      "short": "How a device finds the hardware address that belongs to an IP address on the local network.",
      "detail": "Devices on the same network segment talk to each other using MAC addresses, not IPs. ARP is the shout-and-answer protocol that maps one to the other: 'who has 192.168.1.1?' 'I do, here's my MAC.' It has no authentication at all, which is why ARP spoofing works.",
      "why_it_matters": "If something can lie about ARP, it can silently sit between you and your router and read everything you send.",
      "see_also": ["mac_address", "arp_spoofing", "gateway"],
      "category": "protocol",
      "difficulty": "beginner"
    }
  ]
}
```

`category` ∈ `protocol` | `security` | `networking` | `tool`.
`difficulty` ∈ `beginner` | `intermediate` | `advanced`.

Required coverage, at minimum: `ip_address`, `mac_address`, `port`, `tcp`, `udp`,
`icmp`, `dns`, `dhcp`, `arp`, `gateway`, `subnet`, `nat`, `packet`, `flow`,
`bandwidth`, `latency`, `tls`, `https`, `certificate`, `encryption`, `plaintext`,
`vpn`, `proxy`, `tor`, `firewall`, `port_scan`, `beaconing`, `c2`, `exfiltration`,
`lateral_movement`, `arp_spoofing`, `mitm`, `dns_tunneling`, `dga`, `smb`, `rdp`,
`llmnr`, `netbios`, `wpad`, `promiscuous_mode`, `pcap`, `bpf`, `mitre_attack`,
`false_positive`, `baseline`, `loopback`, `broadcast`, `multicast`.

## D2. `GET /api/glossary/{id}` — one term, same shape. 404 if unknown.

## D3. `GET /api/explain/{kind}/{id}`

Plain-language explanation of something the tool is currently showing.
`kind` ∈ `detector` | `rule` | `check` | `metric` | `field`.

```json
{
  "kind": "detector",
  "id": "c2_beaconing",
  "title": "What 'C2 beaconing' means",
  "plain": "Malware usually needs to phone home to ask for instructions. Because it's a program, it tends to check in on a timer -- every 60 seconds, exactly. People don't browse the web like that. This detector looks for that machine-like regularity.",
  "how_it_decides": "It measures the gaps between contacts to the same peer and calculates how much those gaps vary. Very little variation, across enough contacts, plus consistent payload sizes, is the signature.",
  "what_would_make_it_wrong": "Software update checkers, telemetry agents, and some games also poll on a fixed timer. That is why this detector reports a confidence rather than a verdict.",
  "worked_example": {
    "scenario": "A process contacts 45.33.32.156 at 14:00:00, 14:01:00, 14:02:01, 14:03:00 ...",
    "walkthrough": [
      "Gaps between contacts: 60s, 61s, 59s",
      "Average gap: 60s. Variation (coefficient of variation): 0.01 -- almost none.",
      "Payload sizes are all within a few bytes of 512.",
      "Both signals agree, and there are 44 contacts, so the detector fires at high confidence."
    ]
  },
  "glossary_terms": ["c2", "beaconing", "baseline"],
  "learn_more": "MITRE ATT&CK T1071.001"
}
```

Every one of the 22 detectors, 10 hygiene rules, and 43 posture checks must have
an entry. Metrics that need explaining (`throughput_bps`, `coefficient of
variation`, `entropy`, `confidence`, `severity`, `risk`) go under `kind=metric`.

## D4. `GET /api/tour`

Drives a guided first-run walkthrough in the UI.

```json
{
  "steps": [
    {
      "id": "welcome",
      "order": 1,
      "view": "overview",
      "target": "[data-tour='stat-tiles']",
      "title": "Start here",
      "body": "These six numbers summarise everything happening on your network right now. Total traffic is how much has moved; active flows is how many conversations are open.",
      "glossary_terms": ["flow", "bandwidth"],
      "action_hint": null
    }
  ]
}
```

`target` is a CSS selector the frontend attaches via `data-tour` attributes.
`action_hint` is `null` or a short instruction ("try clicking a row").
Minimum 12 steps covering all six views.

## D5. `GET /api/lessons` and `GET /api/lessons/{id}`

Short structured lessons that use the user's own live data as the example.

```json
{
  "lessons": [
    {
      "id": "spot-unencrypted-traffic",
      "title": "Find traffic that isn't encrypted",
      "summary": "Learn to tell encrypted from plaintext traffic, and why it matters.",
      "difficulty": "beginner",
      "estimated_minutes": 5,
      "prerequisites": [],
      "objectives": ["Read the encrypted/plaintext split", "Filter the traffic log to plaintext only", "Explain the risk of one real finding on this machine"],
      "steps": [
        {
          "order": 1,
          "instruction": "Open the Overview and find the 'Encrypted vs plaintext' panel.",
          "explanation": "Encrypted traffic can still be seen -- who you talked to, how much -- but not read. Plaintext can be read in full by anyone on the path.",
          "check": {"kind": "view_visited", "value": "overview"},
          "glossary_terms": ["encryption", "plaintext", "tls"]
        }
      ],
      "uses_live_data": true
    }
  ]
}
```

`check.kind` ∈ `view_visited` | `filter_applied` | `element_clicked` | `manual`.
The frontend tracks completion locally; there is no server-side progress state.
Minimum 6 lessons spanning beginner to advanced.

## D6. `GET /api/findings/prioritised`

The single most useful endpoint for a beginner: one merged, ranked list of
everything wrong, across posture checks, hygiene recommendations and threats,
answering "what should I fix first?".

```json
{
  "generated_at": "2026-07-31T14:03:11.482Z",
  "items": [
    {
      "id": "posture:smb_signing_required",
      "source": "posture",
      "title": "Require SMB signing",
      "observed": "SMB signing is not required on the client or the server",
      "severity": "high",
      "impact_score": 82,
      "effort": "low",
      "priority_rank": 1,
      "why_first": "High impact, low effort, and it closes a well-known attack path that needs no special access to exploit.",
      "one_line_fix": "Run one PowerShell command as administrator.",
      "deep_link": {"view": "posture", "id": "smb_signing_required"}
    }
  ]
}
```

`source` ∈ `posture` | `recommendation` | `threat`.
`impact_score` 0-100. `effort` ∈ `low` | `medium` | `high`.
Ranking must favour high impact + low effort, and must be deterministic and
explained in `why_first`.

`observed` (added after the freeze; optional and additive, so it does not
break a client written against the original shape) is what is actually true
right now, and may be absent when the source has nothing more specific to
say than the title. It exists because posture check titles state the
*desired* end state ("Require SMB signing", "Default inbound action is
Block"). That reads correctly beside a pass/fail badge and backwards in this
list, where every entry is by definition a failure: without `observed` a
student sees a headline asserting the thing is already fine, filed under
"fix this first". Clients should render it directly beneath the title.

---

# Part E — Professional workflows

## E1. PCAP export — `GET /api/capture/pcap`

Export captured traffic as a real `.pcap` file that opens in Wireshark.

Query params: `since`, `until` (ISO-8601), `protocol`, `peer`, `port`, `limit`
(default 100000, hard cap 1000000).

Returns `application/vnd.tcpdump.pcap` with
`Content-Disposition: attachment; filename="netaudit-<ts>.pcap"`.

Write a genuine libpcap file: 24-byte global header (magic `0xa1b2c3d4`, version
2.4, snaplen, linktype), then per-packet 16-byte records. On tiers where only
headers were captured, synthesise the frame from the stored header fields and
**say so** — see E3 `synthetic` flag. Never fabricate payload bytes: pad with
zeroes and set the pcap `orig_len` to the real observed length while `incl_len`
reflects what was actually stored.

## E2. PCAP import — `POST /api/capture/pcap/import`

Multipart upload of a `.pcap`/`.pcapng` file for offline analysis. The file is
parsed, stored into a **separate, named analysis session** (never merged into
live capture), and made available to the stats/log/threat endpoints via a
`session` query parameter.

```json
{
  "session_id": "imported-2026-07-31-a91f",
  "filename": "suspicious.pcap",
  "packets": 48221,
  "bytes": 31884412,
  "first_packet": "2026-07-20T09:11:02Z",
  "last_packet": "2026-07-20T09:41:55Z",
  "linktype": "EN10MB",
  "truncated": false,
  "parse_errors": 0
}
```

Hard limits: 200 MB upload cap, streamed to disk not buffered in memory,
rejected with 413 beyond that. Malformed files return 400 with a useful message
and must never crash the server or hang. This is untrusted input parsed by our
own code — fuzz it.

## E3. `GET /api/sessions`

```json
{
  "sessions": [
    {"id": "live", "kind": "live", "label": "Live capture", "packets": 48221, "synthetic": true,
     "synthetic_reason": "polling tier stores flow-derived records, not real frames"},
    {"id": "imported-2026-07-31-a91f", "kind": "imported", "label": "suspicious.pcap",
     "packets": 48221, "synthetic": false, "imported_at": "2026-07-31T14:00:00Z"}
  ]
}
```

`DELETE /api/sessions/{id}` removes an imported session (never `live`).

## E4. Capture filters — `GET`/`PUT /api/capture/filter`

```json
{
  "expression": "tcp port 443 or udp port 53",
  "valid": true,
  "error": null,
  "applies_to_tier": ["npcap"],
  "active": true,
  "compiled_summary": "TCP dst/src port 443, UDP dst/src port 53"
}
```

Accept a **BPF-syntax subset** and validate it yourself: `tcp`/`udp`/`icmp`,
`port N`, `src`/`dst`, `host X`, `net X/Y`, `and`/`or`/`not`, parentheses.
A `PUT` with an invalid expression returns 400 with the parse error and position,
and must not change the active filter. On tiers that cannot filter at capture
time, apply the same predicate at ingest and report that in `applies_to_tier`.

**The expression must never be passed to a shell or eval'd.** Parse it into an
AST and evaluate structurally. This is the single highest-risk input in the tool.

## E5. Report generation — `POST /api/reports`

```json
{
  "format": "html",
  "sections": ["summary", "posture", "threats", "recommendations", "traffic", "devices"],
  "window": "24h",
  "title": "Weekly network audit"
}
```

Returns a self-contained report. `format` ∈ `html` | `markdown` | `json`.
HTML must be a single file with inlined CSS, no external requests, printable to
PDF by the browser. Include an executive summary with the security score, the
prioritised findings from D6, and evidence tables. Server-generated filename.

`GET /api/reports` lists previously generated reports; `GET /api/reports/{id}`
retrieves one; `DELETE /api/reports/{id}` removes it. Reports are stored under
`%LOCALAPPDATA%\NetAudit\reports\`, capped at 50 with oldest-pruned.

## E6. SIEM / log-pipeline export — `GET /api/export/events`

Streaming export in formats a SOC actually ingests.

Query params: `format` ∈ `jsonl` | `cef` | `syslog` (RFC 5424) | `ecs`,
plus `since`, `until`, `kinds` (comma list of `threat,recommendation,posture,traffic`).

`jsonl` — one JSON object per line. `ecs` — Elastic Common Schema field names
(`@timestamp`, `event.kind`, `event.category`, `source.ip`, `destination.ip`,
`network.protocol`, `process.name`, `threat.technique.id`). `cef` — ArcSight
CEF:0 header plus extension pairs. `syslog` — RFC 5424 with structured data.

Streamed, never fully materialised in memory. Escape/encode per format — a CEF
value containing `=` or `|` must be escaped, not emitted raw.

## E7. Active LAN scan — `POST /api/devices/scan`

Opt-in, explicitly user-triggered discovery of devices on the **local subnet only**.

```json
{"subnet": "192.168.1.0/24", "ports": [22, 80, 443, 445, 3389], "rate_limit_pps": 50}
```

Constraints, all enforced server-side and all testable:
- The target must be a private (RFC1918) subnet that this machine has an
  interface on. Anything else ⇒ 400. No scanning arbitrary internet ranges.
- Maximum /24 in one request. Maximum 20 ports. Rate limit capped at 100 pps.
- TCP connect scan only. No SYN/stealth scanning, no OS fingerprinting, no
  exploitation, no credential testing.
- Returns a job id; `GET /api/devices/scan/{job_id}` polls progress and results;
  `DELETE` cancels. One scan at a time.
- The response must carry a `consent_notice` string that the UI displays,
  stating plainly that this sends traffic to other devices and should only be
  run on a network the user is authorised to test.

## E8. Baseline snapshots — `POST /api/baselines` / `GET /api/baselines`

Capture a named snapshot of current posture + traffic profile, and diff two of
them, so a professional can answer "what changed since last month?".

`GET /api/baselines/{a}/diff/{b}`:

```json
{
  "from": {"id": "b1", "label": "Before hardening", "captured_at": "2026-07-01T10:00:00Z"},
  "to": {"id": "b2", "label": "After hardening", "captured_at": "2026-07-31T10:00:00Z"},
  "score_delta": {"posture": 22, "threats": -5, "overall": 11},
  "checks": {
    "fixed": [{"id": "smb_signing_required", "from": "fail", "to": "pass"}],
    "regressed": [{"id": "firewall_logging_enabled", "from": "pass", "to": "fail"}],
    "unchanged_count": 39
  },
  "new_peers": ["203.0.113.9"],
  "new_listeners": [{"port": 8080, "process": "node.exe"}],
  "removed_listeners": []
}
```

---

# Part F — Compliance and alerting

## F1. `GET /api/compliance/frameworks`

```json
{
  "frameworks": [
    {"id": "cis_win11", "label": "CIS Microsoft Windows 11 Benchmark v3.0.0",
     "controls_mapped": 31, "checks_mapped": 38, "coverage_note": "Covers only the network-facing subset of the benchmark."},
    {"id": "nist_800_53", "label": "NIST SP 800-53 Rev. 5", "controls_mapped": 18, "checks_mapped": 40,
     "coverage_note": "Indicative mapping for the SC and SI families only."},
    {"id": "essential_eight", "label": "ACSC Essential Eight", "controls_mapped": 5, "checks_mapped": 22,
     "coverage_note": "Partial: this tool cannot assess application control or backups."}
  ]
}
```

Every framework **must** carry an honest `coverage_note`. This tool audits one
Windows host's network posture; it cannot certify compliance with anything, and
the API and UI must not imply otherwise.

## F2. `GET /api/compliance/{framework_id}`

```json
{
  "framework": {"id": "cis_win11", "label": "..."},
  "generated_at": "2026-07-31T14:03:11.482Z",
  "summary": {"pass": 21, "fail": 8, "partial": 4, "not_assessed": 6, "coverage_percent": 68},
  "disclaimer": "Indicative only. NetAudit assesses network-facing configuration on this host and is not a certified compliance audit.",
  "controls": [
    {
      "control_id": "2.3.9.2",
      "title": "Microsoft network server: Digitally sign communications (always)",
      "status": "fail",
      "evidence_checks": [{"check_id": "smb_signing_required", "status": "fail"}],
      "rationale": "The mapped posture check found signing is not required on client or server."
    }
  ]
}
```

`status` ∈ `pass` | `fail` | `partial` | `not_assessed`.
`not_assessed` is required wherever the tool genuinely cannot see the control —
never guess a `pass`.

## F3. Alerting — `GET`/`PUT /api/alerts/config`

```json
{
  "enabled": false,
  "min_severity": "high",
  "channels": [
    {"id": "desktop", "kind": "desktop", "enabled": true},
    {"id": "webhook-1", "kind": "webhook", "enabled": false,
     "url": "https://hooks.example.com/xxx", "template": "json",
     "last_status": null, "last_attempt": null}
  ],
  "rate_limit_per_hour": 20,
  "quiet_hours": {"start": "23:00", "end": "07:00"}
}
```

Webhook rules: disabled by default, user must supply the URL, `https` only
(reject `http` and any non-public scheme with 400), no redirects followed, 5s
timeout, failures logged and surfaced in `last_status` but never retried in a
tight loop. **A webhook URL is the only outbound destination this tool will ever
contact, and only when the user has explicitly enabled it.**

`POST /api/alerts/test` sends one test alert to a named channel and reports the
result. `GET /api/alerts/history` lists what was sent.

## F4. `GET /api/alerts/history`

```json
{
  "alerts": [
    {"id": "a1", "ts": "2026-07-31T14:03:11.482Z", "severity": "high",
     "source": "threat", "source_id": "beacon-...", "title": "...",
     "channels": [{"id": "desktop", "status": "delivered"}]}
  ]
}
```
