# NetAudit backend security notes

This covers the hardening work against `docs/API_CONTRACT_V2_SECURITY.md`
Part C (items 1-13). It does not cover Part A (posture) or Part B (threat
detection) -- those are separate packages (`netaudit/posture/`,
`netaudit/threat/`) owned and tested by other agents.

## Threat model

**What this defends against:**

- A malicious web page open in the same browser as the NetAudit dashboard,
  trying to read traffic/device/recommendation data or issue capture
  control commands by pointing requests at `127.0.0.1:8787` (CSRF-style
  and cross-origin reads). Defended by: the auth token, strict CORS, the
  WebSocket Origin check, and the bootstrap endpoint's same-origin gate.
- A local, non-privileged process or script that doesn't already have the
  token, trying to hit the API cold. Defended by: 401 on every `/api` and
  `/ws` path except `GET /api/bootstrap`.
- Malformed or hostile query parameters (SQL-injection-shaped strings,
  out-of-range limits, bad sort/filter values, formula-injection process
  names) reaching the store layer or an exported file. Defended by:
  parameterised SQL, allowlisted sort/filter fields, hard limit clamps,
  CSV cell escaping.
- Resource exhaustion from a hostile page hammering the API, an unbounded
  capture queue, an unbounded DNS cache, or a runaway query. Defended by:
  per-peer rate limiting, bounded queues/caches with eviction/drop
  counting, and a soft per-call SQLite query timeout.
- Accidental exposure beyond this machine (binding `0.0.0.0`, a wildcard
  CORS origin, an unsecured token file). Defended by: a hardcoded loopback
  default with no env override, an explicit `--unsafe-bind` escape hatch
  that warns loudly, a strict CORS allowlist, and fail-closed token-file
  ACL verification.
- Leaking internals through error responses (stack traces, filesystem
  paths). Defended by: a generic 500 body with full details only in the
  local log.

**What this does NOT defend against**, because it is out of scope for a
single-user local tool or is a fundamental property of the platform:

- **Any other local process that can read files as this Windows user, or
  reach loopback.** The token file is owner-only (see below), but any
  process running *as this same user* (or as SYSTEM/an administrator) can
  read it directly, or call `GET /api/bootstrap` itself, exactly like the
  dashboard does. This is the single largest residual risk and is
  inherent to a loopback-bound, locally-authenticated service on a
  single-user desktop OS: Windows has no equivalent of a per-process
  network namespace that would let us distinguish "the dashboard" from
  "any other program you're running." A compromised browser extension, a
  malicious locally-installed app, or malware already running as you can
  get the token. This is a documented, accepted risk for this class of
  tool (compare: any other localhost-bound dev server with a bearer
  token).
- **A local administrator or SYSTEM.** Either can read the token file
  regardless of its ACL (take ownership, reset the DACL, or just read
  physical disk), stop/replace the server binary, or reconfigure the
  firewall. No application-level control stops an admin from doing
  anything on their own machine.
- **Compromise of the machine itself** (keyloggers, screen scraping,
  memory inspection of the running process). Out of scope for an
  application-layer hardening pass.
- **DNS/ARP data integrity.** NetAudit trusts what the OS resolver and ARP
  cache tell it (reverse DNS hostnames, vendor lookups). A hostile LAN
  peer can already poison ARP/DNS at the network layer; NetAudit reports
  what it observes, it doesn't try to detect this class of attack against
  its own enrichment layer (that's Part B's job, for on-the-wire traffic,
  not for the OS's own resolver state).
- **A malicious frontend build.** If `frontend/dist` is swapped for a
  hostile bundle, it runs with the CSP this backend serves, but the CSP
  still allows `'self'` scripts, connecting back to this same API with
  whatever token it can obtain via bootstrap. We don't have (and can't
  practically have) a way to verify the frontend bundle's integrity from
  the backend.
- **Physical/local access in general** (someone sitting at the keyboard).
  Not a remote-attacker tool's problem to solve.

---

## Part C items

### 1. Bind loopback only

`netaudit/config.py`: `HOST = "127.0.0.1"` is a hardcoded literal, not read
from an environment variable (it used to read `NETAUDIT_HOST`; that
override was removed specifically so nothing short of the CLI flag below
can change it).

`netaudit/server.py`: `main()` parses `--unsafe-bind HOST`. If passed, it
overrides the bind host and logs a multi-line `WARNING`-level message
naming the exposure before `uvicorn.run()` is called. There is no other
way to bind anywhere but `127.0.0.1` -- confirmed by
`tests/test_hardening.py::TestLoopbackBind`.

**Verified**: started the real server with no flag, confirmed
`Uvicorn running on http://127.0.0.1:8788` in the log (see the pasted
transcript in the final report).

### 2. Local auth token

`netaudit/auth.py::ensure_token()`:

- Generates `secrets.token_urlsafe(32)` on first run, or reuses an
  existing token file if (and only if) it is present, non-empty, and its
  ACL can be verified as owner-only. If it exists but is missing/wrong,
  it's regenerated and re-secured (never trusted as-is).
- Location: **`%LOCALAPPDATA%\NetAudit\token`** (confirmed at
  `C:\Users\lukab\AppData\Local\NetAudit\token` on this machine).
  Overridable via `NETAUDIT_TOKEN_PATH` for tests only, so test runs never
  touch or race the real file.
- Windows ACL: `icacls <path> /inheritance:r /grant:r <domain>\<user>:F`,
  as a fixed argument list (see item 3). After granting, the ACL is
  re-read and parsed to confirm the only grantees are the current user,
  `NT AUTHORITY\SYSTEM`, `BUILTIN\Administrators`, and the synthetic
  `OWNER RIGHTS` pseudo-grantee (not a real third party -- see the code
  comment in `auth.py`). Anything else present (Everyone, BUILTIN\Users,
  Authenticated Users, a different account) fails verification.
- **Verified on the real machine**: `icacls` output after startup --
  ```
  C:\Users\lukab\AppData\Local\NetAudit\token NT AUTHORITY\SYSTEM:(F)
                                              BUILTIN\Administrators:(F)
                                              DESKTOP-NAIARIP\lukab:(F)
  ```

`netaudit/security.py::SecurityMiddleware` enforces the token on every
`/api` and `/ws` path via `X-NetAudit-Token` header or `?token=` query
param, compared with `secrets.compare_digest` (never `==`), except
`GET /api/bootstrap`.

`netaudit/api/bootstrap.py` serves the token only when: the TCP peer is
loopback, `Sec-Fetch-Site` (if sent) is `same-origin`/`same-site`/`none`,
and `Origin` (if sent) is in the CORS allowlist. All three checks are
independent -- any one failing is a 403.

**Residual risk, stated plainly**: any local process that can open a
socket to `127.0.0.1:8787` can call `GET /api/bootstrap` and get the token
exactly as the dashboard does, and any process running as this user can
read the token file directly regardless of the ACL (it's *this user's*
file). This is inherent to a loopback-bound, single-user-desktop tool and
is not something an application-layer check can close -- see Threat
model above.

### 3. No command execution from HTTP input

Audited every module this agent owns (`netaudit/` excluding `posture/` and
`threat/`, which are separately owned and tested) for `subprocess`,
`os.system`, `os.popen`, and `shell=True`. Found exactly one pre-existing
call (`netaudit/arpscan.py::read_arp_table`, `subprocess.run(["arp", "-a"],
...)`) -- already a fixed list with no shell, no request-derived
interpolation. Added one more in `netaudit/auth.py` (`icacls`, also a fixed
list; username/path come from the local OS environment, never HTTP input).

`tests/test_hardening.py::TestNoShellExecution` walks the AST of every
owned module and fails on:

- `shell=True` anywhere,
- `os.system`/`os.popen` anywhere,
- a `subprocess.run/call/check_call/check_output/Popen(...)` call whose
  first argument is a *string* (literal, f-string, concatenation, or
  `.format()`) -- the shape that implies shell parsing and that a
  request-derived value could get spliced into.

A `Name`/`Attribute` argument (e.g. `auth._run_icacls(args)` forwarding a
`list[str]` parameter) is accepted, since a list is safe from shell
injection regardless of how it was constructed or passed around -- the
list *shape* is the actual protection, not whether the token is a literal
at that exact call site. A companion test
(`test_run_icacls_helper_itself_only_ever_called_with_list_literals`)
confirms every call site of that one small wrapper does pass a literal
list, closing the gap the general rule intentionally leaves open.

**Scoping note**: `netaudit/posture/probes/runner.py` (owned by another
agent, already complete and committed with its own 192 tests) also runs
`subprocess` against a hardcoded, parameterless, read-only command
allowlist, with no HTTP input anywhere near it. This agent's AST scan does
not walk `posture/` or `threat/` at all -- confirmed by
`TestOwnedModuleScan::test_scan_excludes_posture_and_threat` -- so it makes
no claim about that file either way. From a read-only review (not an
edit), `runner.py`'s pattern looked consistent with this item's intent,
but it wasn't in scope to verify exhaustively or fix.

### 4. Parameterised SQL + allowlists

Audited `netaudit/store/*.py`. All values are already bound via named
SQLite parameters (`:name`), never interpolated into SQL text. The only
f-string-built SQL fragments are `where_sql` (joining a list of *fixed*
clause templates like `"protocol = :protocol"`, never a raw value) and
`sort_col`/`order_sql` (two-way ternaries over a hardcoded pair of
literals) in `store/packets.py::query_log`. No client-supplied string ever
reaches SQL text directly.

Added allowlist validation that was missing at the API layer
(`netaudit/api/traffic.py`): `protocol` and `direction` now validate
against hardcoded sets and return 400 on anything else, matching the
pattern already used for `sort`/`order`/`window`/`by` elsewhere. This
doesn't close a SQL-injection hole (those values were always parameter-
bound) -- it stops nonsense values from silently matching zero rows and
makes the "reject, don't interpolate" contract explicit everywhere filters
exist.

`tests/test_hardening.py::TestSqlSafety` covers: invalid sort/protocol/
direction return 400 before reaching SQL; three different SQL-injection-
shaped `q` payloads all return 200 and leave the `packets` table's row
count unchanged; an AST check that no raw filter-value name is
interpolated directly into the string passed to `.execute(...)` (as
opposed to a parameter *value*, which is the safe, standard pattern used
throughout).

### 5. CSV injection defence

`netaudit/security.py::csv_safe_cell()`: any cell whose string form starts
with `=`, `+`, `-`, `@`, tab, or CR gets a leading `'`. Applied to every
field in `netaudit/api/traffic.py`'s CSV export. Tested with a hostile
`process_name` of `=cmd|' /C calc'!A1` end-to-end through the real export
endpoint, plus a parametrised unit test over all six dangerous prefixes.

### 6. Bounded everything

- **`limit`**: hard-capped at `config.MAX_LIMIT = 1000` in both
  `/api/traffic/log` (+ export) and `/api/stats/top`. Changed from
  "reject anything over 1000 with 400" to "clamp to 1000" per this item's
  explicit wording and the done-criteria (`limit=999999` must return
  *entries*, not an error). Verified against the real running server: DB
  had 2592 rows, `?limit=999999` returned exactly 1000.
- **SQLite query timeouts**: `netaudit/store/db.py` installs a
  `progress_handler` that aborts the running statement
  (`sqlite3.OperationalError`) once a thread-local deadline
  (`config.SQL_QUERY_TIMEOUT_SECONDS`, default 5s) has passed. The
  deadline is re-armed on every `get_conn()` call, so each batch of
  queries a store function makes gets up to that budget. This is a soft,
  per-call-batch bound, not a hard per-statement one (SQLite has no native
  per-statement CPU timeout) -- tested by deliberately running a
  recursive CTE against a 50ms budget and confirming it raises.
  `busy_timeout` (lock-wait, a different thing) is also set to the same
  value.
- **Capture queue**: already bounded (`queue.Queue(maxsize=...)` in
  `capture/base.py`) with a drop counter that already existed
  (`self._dropped`) but wasn't surfaced anywhere. Added a `.dropped`
  property and wired it into `Pipeline.capture_status()` as
  `capture.dropped_packets`, additive on both `/api/health` and
  `/api/capture/status` -- confirmed not to remove/rename any v1 field
  (existing tests updated from exact-set to superset assertions, since
  that's the correct fix for an *additive* field breaking a
  too-strict test, not a reason to skip adding the field).
- **DNS cache**: `capture/enrich.py::ReverseDnsCache` was already
  concurrency-bounded (`ThreadPoolExecutor(max_workers=4)`) but the cache
  dict itself was unbounded. Converted to an `OrderedDict` with
  LRU-eviction at `config.DNS_CACHE_MAX_ENTRIES` (5000).
- **Rate limiter**: bounded to `config.RATE_LIMIT_... ` max distinct peers
  (see item 9) so it can't grow without bound either.

### 7. Path safety

No endpoint in this backend accepts a filesystem path from the client --
confirmed by inspection of every router under `netaudit/api/`. Export
filenames are server-generated from a timestamp
(`netaudit-log-<ts>.<format>`) in `api/traffic.py`; the client only
chooses `format` (validated against `{csv, json}`).

### 8. No payload persistence

Confirmed by schema inspection: the `packets` table
(`netaudit/store/db.py`) has no payload/raw/body/data column -- headers
and metadata only (protocol, addrs, ports, length, flags, process,
summary, risk). Test asserts this structurally
(`TestPayloadRedaction::test_no_payload_bytes_column_in_packets_table`).

Added `netaudit/security.py::redact_payload_snippet()` as a general-
purpose helper (truncates to `config.PAYLOAD_SNIPPET_MAX_BYTES = 64`
bytes, and returns a redaction placeholder instead of the content if it
matches credential-shaped patterns: `Authorization:`/`Basic `/`Bearer `/
`password=`/`api_key=`/etc.) even though nothing in this agent's code
currently captures payload snippets, so the guarantee is in place if it
ever does.

**Coordination note, not fixed here**: `netaudit/threat/source.py` (owned
by the threat-detection agent, not touched) defines a
`payload_snippet: Optional[str]` field, used by at least the credentials
detector to look for `authorization: basic` in captured text. That package
is out of scope for this agent to edit or verify, but if it persists raw
snippets without truncation/redaction, it would be worth checking against
this same item -- flagging this for the orchestrator rather than guessing
at code in a package I was told not to touch.

### 9. Rate limiting

`netaudit/ratelimit.py::RateLimiter`: per-peer token bucket,
`config.RATE_LIMIT_CAPACITY = 120` tokens refilling over
`config.RATE_LIMIT_WINDOW_SECONDS = 10`s -- generous enough for the
dashboard's 2s polling across several endpoints (roughly 12 req/s
sustained headroom), tight enough to stop a hostile page from looping
requests. Enforced in `SecurityMiddleware` for every `/api` request
(including `/api/bootstrap`) and every `/ws` connection attempt. Returns
429 with a `Retry-After` header computed from the bucket's actual refill
rate. Bounded to `max_peers=4096` distinct buckets to avoid unbounded
growth (item 6).

### 10. Strict CORS

`config.CORS_ORIGINS` was already exactly `["http://localhost:5173",
"http://127.0.0.1:5173"]` with no wildcard -- verified, not changed.
`CORSMiddleware` with an explicit origin list (not `"*"`) never reflects
an arbitrary `Origin`; confirmed against the real running server that a
preflight `OPTIONS` from `http://evil.example` gets `400 Bad Request` /
`Disallowed CORS origin`, and that a simple `GET` with that Origin never
gets `Access-Control-Allow-Origin` echoing it back.

### 11. WebSocket origin check

`SecurityMiddleware._handle_websocket` intercepts every `/ws*` scope
*before* the ASGI app (and therefore before `websocket.accept()`) ever
runs. Checks, in order: rate limit, `Origin` (if present) against the
CORS allowlist, then the token (header or `?token=`). Any failure sends
`{"type": "websocket.close", "code": 1008}` directly at the ASGI level --
confirmed this rejects the handshake rather than accepting-then-closing
(Starlette's `TestClient.websocket_connect` raises `WebSocketDisconnect`
with `code=1008` on `__enter__`, meaning the connection was never
accepted).

An absent `Origin` header is allowed through (subject to the token check
still applying) -- a deliberate choice for non-browser local clients that
don't set one; browsers always send `Origin` on a WebSocket handshake, so
this doesn't weaken the browser-facing protection.

### 12. Dependency hygiene

`backend/pyproject.toml` pins every dependency with `==`, and `uv.lock`
locks the full dependency graph to exact resolved versions. Pinned
versions:

| Package | Version |
|---|---|
| fastapi | 0.141.1 |
| uvicorn[standard] | 0.52.0 |
| pydantic | 2.13.4 |
| psutil | 7.2.2 |
| scapy | 2.7.0 (Windows only) |
| pytest | 9.1.1 |
| httpx | 0.28.1 |

None of these phone home (no telemetry/analytics/update-checkers in any of
them); `httpx` is test-only (FastAPI's `TestClient`), not imported by the
running service.

### 13. Fail closed

`netaudit/server.py`'s lifespan handler calls `auth.ensure_token()` before
starting capture or serving anything; a `TokenSecurityError` (file
unsecurable) propagates out of `lifespan`, which aborts FastAPI/uvicorn
startup entirely -- there is no fallback path that serves unauthenticated.
`dbmod.get_conn()` similarly raises on an unopenable DB, with the same
effect. Both are exercised in `tests/test_hardening.py::TestFailClosed`,
including a genuine (not weakened) failure-injection test and a real,
unmocked run of the full `icacls` flow against a fresh temp path so a
regression here is caught by CI, not just by hand-testing.

**The bug this surfaced and how it was actually fixed** (worth recording
plainly, since it took the service down entirely the first time): the
initial ACL verification parsed `icacls <path>` output by substring-
matching each line against a blocklist that included the literal text
`"\users"`. Every Windows user profile path contains `\Users\` (e.g.
`C:\Users\lukab\...`), and `icacls`' first output line is
`"<path> <grantee>:(perms)"` -- path and grantee on the same line. The
blocklist matched the *file's own path*, not an actual `BUILTIN\Users`
grant, so verification failed on every single run, on every machine,
100% of the time -- which is exactly the fail-closed behavior working as
designed against a bug in the check itself, not against a real
insecure file. The fix was a real parser rewrite
(`auth._parse_icacls_grantees`), not a threshold tweak: it strips the
known path string from the first line using the exact path (not a
keyword heuristic), extracts just the grantee identity per ACE via
regex, and compares grantee identities *exactly* (lowercased) against an
explicit allowlist (`{current user, NT AUTHORITY\SYSTEM,
BUILTIN\Administrators, OWNER RIGHTS}`) rather than blocklisting
substrings. A second, related issue in the same vein: this machine's
`%TEMP%` (and therefore pytest's `tmp_path`) grants an inherited `OWNER
RIGHTS` ACE (SID `S-1-3-4`, "whatever rights the current owner has" --
not a third-party grantee) alongside the explicit user grant, which the
original code would also have flagged. Both are covered by regression
tests: `TestFailClosed::test_acl_parser_rejects_a_broad_grant` asserts the
parser correctly ignores the path-collision case *and* still rejects a
genuine `BUILTIN\Users` grant in the same input shape, and
`test_ensure_token_real_machine_path_succeeds` runs the entire flow for
real (no mocking) against a fresh nested temp path every test run.

---

## A second, unrelated bug this work surfaced and fixed

While verifying that routers mounted after `create_app()` returns (the
orchestrator's plan for `posture` and `threat`) actually inherit
protections automatically, testing found they wouldn't have been
*reachable at all* once a frontend build exists: `server.py` mounted the
built SPA via `app.mount("/", StaticFiles(...))`. A `Mount` at `"/"` is
itself a route, and Starlette commits to the first *full* route match in
registration order -- since that mount was registered inside
`create_app()`, it would silently shadow every route added afterward
(`app.include_router(...)` called by the orchestrator later), returning
whatever the static-file app does (typically 404) instead of ever
reaching posture's or threat's handlers. This wasn't about auth at all;
it would have broken those routers even unauthenticated.

Fixed by assigning the static-file app to `app.router.default` instead of
routing it via `Mount("/")`. `Router.default` is Starlette's actual
last-resort fallback: it's only invoked after the *complete* current
route table is checked and nothing matched, which correctly includes
routes added to the router at any point before the request arrives --
regardless of when they were registered relative to this line. Verified
with a throwaway dummy router mounted after `create_app()` returns
(`tests/test_hardening.py::TestMiddlewareCoversRoutersAddedLater`): it's
401 without a token, 200 with one, carries the security headers, and gets
CORS-checked -- all with zero code in the dummy route itself, and
confirmed the SPA (`GET /`) still serves correctly afterward.

---

## Security response headers

Applied by `SecurityMiddleware` to every response (API and static alike,
where sensible): `X-Content-Type-Options: nosniff`, `X-Frame-Options:
DENY`, `Referrer-Policy: no-referrer`, and a `Content-Security-Policy`
scoped to `'self'` (plus `'unsafe-inline'` for styles, which is common for
built Vite/React CSS-in-JS output; no `unsafe-inline`/`unsafe-eval` for
scripts). `Cache-Control: no-store` is added specifically to `/api/*`
responses (including `/api/bootstrap`, which must never be cached) but not
to static frontend assets, so the SPA itself can still cache normally.

Error responses (`StarletteHTTPException`, `RequestValidationError`, and
the catch-all `Exception` handler in `server.py`) never include a stack
trace or filesystem path in the client-facing body; the catch-all handler
logs the full exception via `logger.exception(...)` locally and returns a
fixed generic message.

## Fixed testing baseline

`.\.venv\Scripts\python.exe -m pytest tests -q` (full suite, including
`posture` and `threat`): **495 passed** (424 prior + 71 new hardening
tests, both added by this pass and covering every numbered Part C item).

`.\.venv\Scripts\python.exe -m pytest tests -q --ignore=tests/posture
--ignore=tests/threat` (this agent's scope only): **143 passed** (72
original + 71 hardening).

## Token file location and permissions (for reference)

- **Path**: `%LOCALAPPDATA%\NetAudit\token` --
  `C:\Users\<you>\AppData\Local\NetAudit\token` on a normal install.
- **Permissions**: owner-only via `icacls /inheritance:r /grant:r
  <you>:F`. In practice the file also lists `NT AUTHORITY\SYSTEM` and
  `BUILTIN\Administrators` (Windows doesn't let you meaningfully exclude
  either, and any local admin can rewrite the ACL anyway) plus the
  synthetic `OWNER RIGHTS` entry. No other account, group, or "Everyone"/
  "Users"/"Authenticated Users" grant is present; the server verifies this
  on every startup and refuses to start if it can't confirm it.
- **Override for testing only**: `NETAUDIT_TOKEN_PATH` env var (mirrors
  the existing `NETAUDIT_DB_PATH` pattern) -- never used by the shipped
  entrypoint, only by `create_app(token_path=...)` in tests, so test runs
  never touch or race the real file.
