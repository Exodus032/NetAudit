# `netaudit.pcap` -- PCAP read/write, BPF capture filter, import sessions

Implements API Contract v3 Part E, sections E1-E4. Hand-written libpcap and
pcapng parsing (no scapy/dpkt -- see `DEPENDENCIES.md`).

## Modules

- `format.py` -- the libpcap global header and per-packet record reader/
  writer, plus a pcapng reader (Section Header Block, Interface Description
  Block, Enhanced Packet Block). This is the only module that touches raw
  file bytes; every length field is bounds-checked before it's used to
  allocate or slice anything (`PcapError` on anything implausible).
- `synth.py` -- builds a synthetic Ethernet/IPv4/TCP|UDP|ICMP frame from a
  stored packet-log row, since the packet store never persists raw frame
  bytes on any tier (see `backend/SECURITY.md` Part C item 8). Payload is
  always zero, never fabricated.
- `dissect.py` -- the inverse of `synth.py`: pulls (protocol, addrs, ports,
  flags) out of *real* frame bytes from an imported pcap/pcapng file, for
  storing importable sessions in queryable form.
- `bpf.py` -- tokeniser, recursive-descent parser, AST, and a purely
  structural evaluator for the BPF-syntax subset in E4. Never touches a
  shell, `eval`, or `exec`; the tokeniser's regex pattern is a fixed
  literal, never built from user input (see `tests/pcap/test_bpf.py`'s
  AST-scan tests).
- `session_store.py` -- SQLite storage for imported sessions, in a
  database file separate from `netaudit/store/db.py` (imported sessions
  are never merged into live capture).
- `import_pipeline.py` -- the untrusted-input path for E2: streams an
  upload to disk under the 200 MB cap, then parses and dissects it.
- `live_query.py` -- reads `netaudit.store.db`/`packets` directly (read-
  only) for E1 export filters.
- `router.py` -- the `APIRouter` (E1-E4 routes). Bare, no side effects at
  import time beyond in-process state for the currently active capture
  filter.

## Known limitations (be honest about these)

- **pcapng byte order**: the parser assumes a little-endian pcapng file
  when reading the very first Section Header Block's own type/length
  fields (before it has parsed the BOM that would tell it otherwise). This
  is correct for the overwhelming majority of real captures (Wireshark/
  tshark on any common platform write little-endian pcapng), but a
  genuinely big-endian-written pcapng file's *first* SHB could be
  misread. Every block *after* a successfully-parsed SHB does honor
  whatever byte order that SHB declared.
- **pcapng multi-interface files**: if a file declares more than one
  Interface Description Block with different linktypes, the `FormatMeta`
  returned by `read_pcapng` reports only the *first* interface's linktype/
  snaplen. Individual packets are still dissected using their own
  declared `interface_id`, so per-packet dissection is correct; only the
  summary-level `linktype` field is a best-effort single value.
- **Synthesized frames**: MAC addresses, TCP sequence/ack numbers, IP
  identification, and TTL are fixed placeholders (never invented to look
  real) because none of those fields are in the packet store. IPv6
  addresses get an Ethernet-only frame (ethertype set, no fabricated IPv6
  header) since the store doesn't retain enough to build one honestly.
- **Imported-session enrichment**: dissected rows have no `process_name`,
  `pid`, `risk`, or `is_encrypted`-beyond-a-port-heuristic, since none of
  that is recoverable from raw frame bytes alone without the live OS
  process/socket table this tool has for live capture.
- **BPF grammar**: intentionally a subset (`tcp`/`udp`/`icmp`, `port`,
  `src`/`dst`, `host`, `net`, `and`/`or`/`not`, parentheses, with implicit
  AND by juxtaposition matching real tcpdump syntax) -- not the full BPF
  language (no `ether`, `vlan`, `greater`, byte-offset comparisons, etc).
- **Capture-time filter enforcement**: `router.py`'s `/api/capture/filter`
  validates, parses, and stores the active filter, and exposes
  `bpf.evaluate()` for structural matching. Actually wiring that
  evaluation into the live capture ingest path (or a real kernel/driver
  BPF program on the npcap tier) is `netaudit.capture`'s responsibility,
  owned elsewhere -- out of scope for this package per the task's file-
  ownership rules.

## What was verified vs. what wasn't

- Round-trip write/read, byte-exact header comparison against
  independently-hand-derived expected bytes, both endiannesses, the
  nanosecond magic variant, and a minimal SHB+IDB+EPB pcapng file are all
  covered by `tests/pcap/test_format.py` and pass.
- The truncate-at-every-offset and bit-flip fuzz tests
  (`tests/pcap/test_import_fuzz.py`) ran against a real multi-packet pcap
  fixture and confirm every mutation produces a clean parse or a clean
  `PcapImportError` -- never an unhandled exception.
- **Not verified**: actually opening a NetAudit-exported `.pcap` in real
  Wireshark. The Definition-of-Done step (generating a pcap from the live
  database and reading it back with this package's own reader) is
  self-consistent by construction -- it proves our writer and reader agree
  with each other and with the hand-derived byte-exact fixture in
  `test_format.py`, but does not prove a third-party tool like Wireshark
  accepts the file, decodes the synthesized headers as expected, or
  displays the checksums as valid. No Wireshark installation was available
  in this environment to check that independently.
