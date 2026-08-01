# `netaudit.export` -- reports and SIEM export

Implements API Contract v3 Part E, sections E5-E6.

## Modules

- `provider.py` -- the `ReportDataProvider` Protocol (`security_score()`,
  `posture_report()`, `threats()`, `recommendations()`, `traffic_summary()`,
  `devices()`, each returning plain dicts/lists in the shapes already
  defined by `API_CONTRACT.md`/`API_CONTRACT_V2_SECURITY.md`),
  `StaticReportDataProvider` for tests, and `get_report_provider`, a
  FastAPI dependency the orchestrator overrides with a real implementation.
  This is the seam that keeps this package from importing
  `netaudit.threat`/`netaudit.posture`/etc. directly.
- `report_data.py` -- assembles the plain-data structure shared by all
  three report formats, including a locally-computed "prioritised
  findings" ranking (posture + threats + recommendations, by impact/effort)
  for the executive summary -- an independent approximation of D6's
  ranking idea, not a call into D6 itself (out of scope to import).
- `report_html.py` / `report_markdown.py` -- the two human-readable report
  renderers. Every value that could contain live/user-influenced text
  (process names, hostnames, titles, summaries, ...) is escaped
  (`html.escape` for HTML; `<`/`>`/`|`/newline neutralisation for
  Markdown, since most Markdown renderers pass raw HTML through
  untouched).
- `reports_store.py` -- filesystem storage under
  `%LOCALAPPDATA%\NetAudit\reports\`, capped at 50 with oldest-pruned.
- `events.py` -- normalises threat/recommendation/posture (from the
  provider) and traffic (read directly from `netaudit.store.db`, same
  pattern as `netaudit/pcap/live_query.py`) into one canonical event shape
  for SIEM export.
- `siem.py` -- the four streaming formatters (`jsonl`, `ecs`, `cef`,
  `syslog`). Each is a generator over normalized events; nothing is
  materialised in memory beyond one event/line at a time.
- `router.py` -- the `APIRouter` (E5-E6 routes).

## Escaping, since that's the part that actually matters

- **HTML**: `report_html.py::_esc()` runs every interpolated value through
  `html.escape(..., quote=True)`. Tested with an XSS payload
  (`<script>alert('xss')</script>`) injected into a posture check title, a
  threat title/summary, a recommendation title/summary, and a device
  hostname -- confirmed the literal string `<script>` never appears in the
  rendered output.
- **CEF**: header fields escape `\`, `|`, and newlines; extension values
  escape `\`, `=`, `|`, and newlines (the task's contract is explicit that
  `|` must be escaped even in extension values, which is stricter than
  some real-world CEF consumers require but never wrong). Tested against a
  hostile record containing all of `=`, `|`, embedded `\n`/`\r\n`, `"` and
  `]` at once, with a test-side CEF parser confirming the record still
  parses into exactly 7 header fields + 1 extension, and that every value
  round-trips back to the original string (module CRLF/LF normalisation,
  documented in the test).
- **Syslog (RFC 5424)**: structured-data `PARAM-VALUE`s escape `\`, `"`,
  `]`, and (additionally, beyond the bare RFC requirement, since a raw
  newline would still split the line) embedded newlines. Tested the same
  hostile record; confirmed the structured-data block's `]` never
  terminates early and the whole line contains exactly one real newline
  (the trailing line terminator).

## What was verified vs. what wasn't

- Report determinism (same input -> same output modulo the generated-at
  timestamp), the 50-report cap pruning the *oldest* reports, and the
  prioritised-findings ranking being a deterministic function of the input
  are all covered by `tests/export/test_report.py` and pass.
- Router-level tests (`tests/export/test_router.py`) use a `TestClient`
  with `get_report_provider` overridden to a `StaticReportDataProvider`,
  matching the task's "Routers via TestClient with faked providers"
  requirement.
- **Not verified**: the real end-to-end shape once the orchestrator wires
  a live provider backed by the actual posture/threat/rules engines --
  only the documented contract shapes were used to build
  `StaticReportDataProvider`'s test fixtures, since this package cannot
  import those engines to check against their real output directly.
- **Not verified**: how a real SIEM product (Splunk, Elastic, ArcSight,
  a syslog collector) actually ingests these exports. The tests confirm
  each format is internally well-formed and round-trips through a
  test-side parser written against the relevant spec, not against a real
  third-party ingester.
