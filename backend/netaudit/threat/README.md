# NetAudit threat detection engine

Behavioral and signature detection over locally captured traffic metadata.
Everything here runs against data already sitting in the store (packets,
flows, DNS events, ARP/DHCP events) — there are no live sockets, no packet
sniffing of its own, and no outbound network calls of any kind. See
`DEPENDENCIES.md` for the dependency list (there are no new ones) and
`intel/data/indicators.json` + the "Bundled indicator set" section below
for exactly what offline threat intel ships and doesn't.

## How it fits together

- `source.py` — the `TrafficSource` Protocol and the four record types
  (`PacketRecord`, `FlowRecord`, `DnsRecord`, `ArpRecord`) detectors read.
  The orchestrator adapts the real store onto this Protocol; `ListTrafficSource`
  is the in-memory implementation used by every test and by the demo
  scenario below.
- `detectors/` — the 22 detectors, one `Detector` subclass each, grouped
  into 11 files by theme (see the catalogue below for which file holds
  which detector).
- `engine.py` — runs detectors over a window, turns their `Finding`s into
  stable `Threat` rows (dedupe by id, `first_seen`/`last_seen`/`occurrences`,
  cooldown → `resolved`, ack persistence), and answers the read/admin API
  the router calls into.
- `store.py` — this package's own SQLite tables (`threats`, `threat_events`,
  `detector_settings`) in a caller-supplied db file. Parameterised SQL only;
  sort/filter columns go through a hardcoded allowlist.
- `router.py` — the Part B HTTP surface, a bare `APIRouter` with no prefix.
- `scoring.py` — the `threats` component of `/api/security/score`.
- `baseline.py` — rolling per-process/per-peer volume, active-hour, and
  known-peer baselines used by the volume/novelty detectors.
- `stats.py` — the shared math (coefficient of variation, Shannon entropy,
  EWMA, MAD-based outliers, inter-arrival analysis), unit-tested against
  hand-computed values in `tests/threat/test_stats.py`.
- `mitre.py` — a small bundled MITRE ATT&CK tactic/technique lookup table,
  covering only the ids this catalogue actually uses.
- `intel/` — the offline threat intel lookup (`lookup.py`) and its bundled
  local indicator file (`data/indicators.json`, loaded by `bundled.py`).

## Detector catalogue

Every detector below ships with a synthetic "fires" test and a synthetic
"near miss" test in `tests/threat/test_detector_*.py`. Tunables are listed
with their default, type, and range; all of them are adjustable at runtime
via `PATCH /api/threats/detectors/{id}`.

### `c2.py`

**`c2_beaconing`** (command_and_control, MITRE TA0011/T1071.001)
Finds peers contacted on a low-variance interval with uniform payload
sizes. Measures the coefficient of variation (CV) of inter-arrival times
between outbound packets to the same peer, and the CV of their payload
sizes, over a minimum contact count.
- Tunables: `min_contacts` (int, default 8, 4–100), `max_interval_cv`
  (float, default 0.15, 0.01–1.0), `max_payload_cv` (float, default 0.35,
  0.01–2.0), `ignore_ports` (str, default `"123"` — NTP, a known-regular
  noisy protocol excluded by design).
- False positives: software update checkers, telemetry/analytics agents,
  and keepalive-polling chat/mail clients all beacon on fixed intervals
  with similar-sized requests. Regularity alone is not proof of C2.

### `dns.py`

**`dns_tunneling`** (dns_abuse, TA0011/T1071.004)
High query volume, long labels, high-entropy subdomains, or a TXT/NULL-heavy
mix to one parent domain. Computes unique-subdomain ratio, average Shannon
entropy of the leftmost label, and TXT/NULL ratio per parent domain, using
a small bundled CDN/telemetry allowlist (`ALLOWLISTED_PARENTS` in this
file) to cut noise from legitimate high-volume services.
- Tunables: `min_queries` (int, 30, 10–500), `min_unique_ratio` (float,
  0.6, 0.1–1.0), `min_entropy` (float, 3.4, 2.0–5.0), `min_txt_null_ratio`
  (float, 0.5, 0.1–1.0).
- False positives: some legitimate update/telemetry/ad-SDK services
  legitimately generate many unique, high-entropy subdomains. Check the
  allowlist before treating a hit as confirmed tunneling.

**`dga_domains`** (dns_abuse, TA0011/T1568.002)
High-entropy, consonant-heavy, unpronounceable domain lookups, evaluated
per registrable domain (not subdomain) and requiring several qualifying
domains from one process before firing.
- Tunables: `min_label_length` (int, 10, 6–40), `min_entropy` (float, 3.3,
  2.5–5.0), `min_consonant_run` (int, 5, 3–10), `min_domains` (int, 3, 1–50).
- False positives: hashed asset URLs, CDN edge hostnames, and some
  randomly-generated tracking subdomains look similar entropy-wise. This
  only looks at registrable domains, not subdomains, and skips the
  allowlist, but novel legitimate high-entropy domains can still trip it.

### `exfil.py`

**`dns_exfil_volume`** (exfiltration, TA0010/T1048.003)
Outbound bytes over DNS far exceeding a normal ratio of a process's total
egress. Uses a **fixed expected-ratio heuristic**, not a learned baseline —
DNS is a low-bandwidth control-plane protocol, so a large fraction of
egress moving over it is abnormal regardless of history.
- Tunables: `max_normal_ratio` (float, 0.1, 0.01–1.0), `min_dns_bytes`
  (int, 50000, 1000–100000000), `min_queries` (int, 20, 5–5000).
- False positives: enterprise EDR/DNS-filtering agents can generate large
  DNS volumes; a process with almost no other network activity will show
  a high ratio on entirely normal DNS use — check the absolute byte count.

**`data_exfiltration`** (exfiltration, TA0010/T1048)
Egress volume to a single external peer far above the historical baseline
for that process/peer pair. **Compares against a learned baseline, not a
fixed threshold** — see `baseline.py` — and does not fire until the
baseline has `min_samples` historical flows for that pair.
- Tunables: `lookback_hours` (int, 168, 24–720), `min_samples` (int, 5,
  3–100), `min_zscore` (float, 4.0, 2.0–10.0), `min_ratio` (float, 5.0,
  2.0–50.0 — used when the baseline has ~zero variance), `min_bytes`
  (int, 5000000, 100000–1000000000 — absolute floor regardless of baseline).
- False positives: backup software, large one-off downloads/uploads the
  user initiated, cloud sync catch-up, and VM/container image pulls are
  all legitimate and can still be far above a process's typical baseline.

**`off_hours_transfer`** (exfiltration, TA0010/T1029)
Large transfer during an hour-of-day with historically no activity for
that process. Also baseline-gated (`min_samples`), and only evaluates
hours the process's history says it has *never* used.
- Tunables: `lookback_hours` (int, 336, 48–2160), `min_samples` (int, 10,
  3–200), `min_bytes` (int, 1000000, 10000–1000000000).
- False positives: scheduled backups, overnight updates, sync/replication
  jobs, and timezone-shifted remote work. A newly-installed backup tool
  looks identical to this on its first night, since it has no baseline yet
  to be "off-hours" *for*.

### `recon.py`

**`port_scan_outbound`** (reconnaissance, TA0007/T1046)
This host touching many ports on one peer in a short window.
- Tunables: `min_ports` (int, 15, 5–200), `max_span_seconds` (int, 300,
  10–3600).
- False positives: vulnerability scanners you run yourself, network
  monitoring tools, some P2P/game traffic hunting for an open port.

**`port_scan_inbound`** (reconnaissance, TA0043/T1595.001)
One peer touching many ports on this host.
- Tunables: same shape as outbound.
- False positives: mass internet scanners (research projects, security
  vendors, and less benign operators) constantly sweep the public IPv4
  space; check `/api/intel/lookup` before escalating.

**`host_sweep`** (reconnaissance, TA0043/T1595.001)
One peer contacting many hosts on the subnet.
- Tunables: `min_hosts` (int, 5, 3–100), `max_span_seconds` (int, 300,
  10–3600).
- False positives: network management tools, the router/DHCP server
  itself, backup software doing LAN discovery, asset-inventory scanners.

### `spoofing.py`

**`arp_spoofing`** (spoofing, TA0006/T1557.002, cooldown 600s)
One MAC claiming multiple IPs, or (separately, more severe) a gateway IP
changing MAC address.
- Tunables: `min_ips_per_mac` (int, 2, 2–20).
- False positives: hypervisors/VM hosts and routers doing NAT/failover can
  legitimately answer for several IPs from one MAC; a gateway MAC change
  is expected right after replacing/rebooting the router.

**`mac_flapping`** (spoofing, TA0006/T1557, cooldown 600s)
An IP rapidly alternating between MAC addresses.
- Tunables: `min_transitions` (int, 3, 2–50), `max_span_seconds` (int, 60,
  5–3600).
- False positives: fast-roaming Wi-Fi mobility features, NIC teaming/
  failover, some load balancers.

**`rogue_dhcp`** (spoofing, TA0006/T1557.003, cooldown 600s)
DHCP offers from an address that is not the known/majority server. If
`known_server_ip` isn't set, the detector infers "known" as whichever
server holds a clear majority (`min_dominance_ratio`) of offers in the
window, and only then flags the rest as rogue.
- Tunables: `known_server_ip` (str, default `""` — inferred if blank),
  `min_offers` (int, 3, 1–100), `min_dominance_ratio` (float, 0.6, 0.5–1.0).
- False positives: a second legitimate DHCP server (new router in bridge
  mode, misconfigured AP, a phone's mobile-hotspot ICS) is common and
  entirely non-malicious.

### `lateral.py`

**`lateral_smb_rdp`** (lateral_movement, TA0008/T1021)
SMB/RDP/WinRM connections to multiple internal hosts in a short window.
- Tunables: `min_hosts` (int, 3, 2–50), `max_span_seconds` (int, 1800,
  60–86400).
- False positives: IT/sysadmin tooling (deployment software, remote
  monitoring, backup agents, a domain controller doing Group Policy work)
  legitimately touches many internal hosts over these same ports.

### `credentials.py`

**`credentials_plaintext`** (credential_exposure, TA0006/T1040)
Auth-bearing protocols in the clear. FTP/Telnet/IMAP/POP3/LDAP-simple-bind
are flagged by port alone (the protocol itself is inherently cleartext);
HTTP Basic auth only fires when a payload snippet is actually available
and contains the header — it skips cleanly otherwise rather than guessing.
- Tunables: `min_events` (int, 1, 1–50).
- False positives: legacy internal devices (printers, NAS, building/
  industrial control systems) often only support these protocols and are
  used intentionally on trusted internal segments.

### `peers.py`

**`known_bad_peer`** (malicious_peer, TA0011 tactic-only)
Peer matches the bundled offline indicator set, any category. No single
technique fits a "matches a local list" detector, so this ships
tactic-only rather than inventing an id.
- Tunables: none.
- False positives: the bundled set intentionally contains no attributed
  malware infrastructure (see below) — a match reflects what category of
  address this is, not proof of compromise.

**`tor_or_proxy`** (malicious_peer, TA0011/T1090.003)
Traffic to known SOCKS/HTTP-proxy/Tor default ports from the bundled set.
- Tunables: none.
- False positives: corporate VPN clients, legitimate SOCKS proxies, and
  privacy tools the user runs intentionally (including Tor Browser itself)
  use exactly these ports. **No Tor exit/relay IP list is bundled** — see
  limitations below — so this is port-based only.

**`crypto_mining`** (malicious_peer, TA0040/T1496)
Stratum ports / known pool domains / mining-shaped traffic. Reuses
`c2_beaconing`'s regularity math on packets to a candidate mining peer:
periodic, uniform-size contacts (Stratum share submissions) boost
confidence beyond the port/domain match alone.
- Tunables: `min_contacts_for_shape` (int, 6, 3–100), `max_interval_cv`
  (float, 0.4, 0.05–2.0).
- False positives: a user intentionally running their own miner is common
  and legitimate. Low-numbered mining ports (3333/4444/5555/7777/8888) are
  also reused by unrelated software — see the per-entry confidence values.

### `tls.py`

**`suspicious_tls`** (anomaly, TA0005/T1573)
Self-signed/expired certs, TLS < 1.2, missing SNI, unusual ALPN, or a JA3
on a (empty-by-default) watchlist. Accumulates a 0–1 suspicion score
across whichever signals are actually present in the capture; **skips a
packet entirely if it carries no TLS handshake metadata at all**, rather
than guessing.
- Tunables: `min_score` (float, 0.3, 0.1–1.0), `ja3_watchlist` (str,
  default `""` — no JA3 hashes are bundled; supply your own).
- False positives: self-signed certs are routine for internal devices
  (routers, printers, home-lab services, IoT admin UIs) and local dev.

### `anomaly.py`

**`nonstandard_port_service`** (anomaly, TA0005/T1571)
A known protocol banner (SSH/HTTP/FTP signature strings in the packet
`summary`) seen on a port other than that protocol's expected set.
- Tunables: none.
- False positives: plenty of legitimate services deliberately run on
  alternate ports (dev servers, SSH moved off 22 to cut scanner noise).

**`new_external_peer`** (anomaly, TA0011 tactic-only, severity low)
First-ever contact with an external peer by a process with an otherwise
stable history (baseline-gated). Genuinely ambiguous — could be a user
visiting something new, or the first sign of anything from C2 to
exfiltration — so this ships tactic-only, low severity, low confidence
by design.
- Tunables: `lookback_hours` (int, 720, 24–4320), `min_samples` (int, 10,
  3–500).
- False positives: browsers, package managers, and anything talking to a
  large/changing set of servers (CDNs, load-balanced services) will trip
  this constantly — it's most useful for install-and-forget background
  agents that normally only ever talk to a small fixed set of peers.

**`protocol_anomaly`** (anomaly, TA0005 tactic-only)
Malformed/impossible TCP flag combinations (SYN+FIN together, Xmas-scan
FIN+PSH+URG without ACK, NULL-scan with no flags at all).
- Tunables: `min_events` (int, 2, 1–50).
- False positives: some old/buggy embedded TCP stacks occasionally produce
  unusual flags without scanning intent; a single stray packet isn't
  meaningful, which is why this gates on a minimum event count.

### `policy.py`

**`deprecated_protocol`** (policy_violation, TA0006 tactic-only)
SMBv1, Telnet, FTP, SSLv3, or NTLMv1 observed on the wire. Telnet/FTP fire
on port alone; SSLv3 needs `tls_version`; SMBv1/NTLMv1 need a textual
marker in `summary` — those skip cleanly when the capture layer doesn't
supply one.
- Tunables: `min_events` (int, 1, 1–50).
- False positives: legacy devices (old printers, NAS, industrial/building
  control systems) frequently only support these and can't be upgraded —
  segmentation is often the right answer, not an outright block.

## Bundled indicator set (`intel/data/indicators.json`)

**This is a small, honest starter set, not a threat feed.** Every entry
carries a `source` and a `note`. It contains exactly four kinds of fact,
all publicly documented and non-sensitive:

1. **Reserved/bogon ranges** (RFC 1918, 3927, 5737, 6598, 6890, 1112, 2544,
   791/1122) — private-use, link-local, documentation/TEST-NET,
   carrier-grade-NAT, and reserved-for-future-use blocks. These exist for
   the `classification` fields, not to accuse anyone of anything.
2. **Mining-pool ports** — common Stratum protocol default ports
   (3333/4444/5555/7777/8888/9999/14444/45700), each explicitly noted as
   weak evidence alone since several are reused by unrelated software.
3. **Mining-pool domains** — apex domains of long-running, publicly
   operated pools (minexmr.com, supportxmr.com, nanopool.org, ethermine.org,
   f2pool.com), each noted that presence doesn't imply compromise.
4. **Proxy/Tor ports** — SOCKS (1080), Squid-default HTTP proxy (3128),
   and Tor's default SOCKS ports (9050, 9150).

### What is deliberately **not** in it, and why

- **No malware C2 IPs or domains, and no threat-actor attribution.**
  Fabricating these would be worse than useless in a tool people rely on
  for their own network's security — a wrong or stale entry either creates
  false confidence or false alarms. If you have a real feed, that's a
  separate integration; this file is not it.
- **No Tor exit/relay or directory-authority IP list.** Exit-node lists
  rotate on the order of hours (the official list is
  `https://check.torproject.org/torbulkexitlist`); shipping a static copy
  would be stale before the release even ships. `tor_or_proxy` therefore
  only detects via port heuristics, which is a real, acknowledged
  limitation — not every proxy/Tor connection will be caught.
- **No scanner IP ranges for Shodan/Censys/Shadowserver.** These also
  rotate over time and are best fetched live from the vendor's own current
  published list; a stale hardcoded copy in a security tool is a liability,
  not a feature. `port_scan_inbound`/`host_sweep` still catch scanning
  *behavior* regardless of who's doing it — they just won't label the
  *source* as "known scanner" the way a live feed could.
- **No ASN/org/country enrichment.** `/api/intel/lookup`'s
  `classification.asn/org/country` are `null` unless a local GeoIP/ASN
  database is present, per the hard constraint that this tool makes no
  outbound lookups of its own.

Treat every `/api/intel/lookup` result as one input among several, not a
verdict — and re-derive this file periodically from primary sources if you
want it to stay useful; it is not automatically refreshed (and, per the
no-network-calls constraint, never could be from inside this process).

## Known gaps / things not fully verified

- `suspicious_tls` and `deprecated_protocol`'s SSLv3/SMBv1/NTLMv1 paths
  depend on the capture layer populating `PacketRecord.tls_version` or a
  recognizable substring in `PacketRecord.summary`. Whether the real
  capture layer (owned by the rest of `netaudit`, not this package)
  actually populates these fields for real traffic is outside this
  package's control — the detector code and its tests demonstrate correct
  behavior against the documented field contract, in both directions
  (fires when present, skips cleanly when absent).
- `registrable_domain()` in `dns.py` uses a simple last-two-labels
  heuristic and does not special-case multi-part public suffixes like
  `co.uk` — documented in the function's docstring as a known
  simplification, not fixed here to keep this package dependency-free
  (a correct implementation needs the Public Suffix List, which would mean
  bundling and periodically refreshing an external dataset).
- Engine scheduling (when `run_once` gets called, and on what window
  cadence in production) is the orchestrator's responsibility — this
  package only guarantees `run_once(now)` is deterministic and idempotent
  given the same store state, which is what the test suite exercises.
