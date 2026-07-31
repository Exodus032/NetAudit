# Alerting

Implements Part F3/F4 of `docs/API_CONTRACT_V3.md`: alert config/channels,
a desktop toast channel, a webhook channel, `POST /api/alerts/test`, and
`GET /api/alerts/history`. Persisted to this package's own tables
(`alerts_config`, `alert_channels`, `alerts_history`) in the shared SQLite
file.

## The webhook is the only outbound path, and it is defended in depth

`webhook.py` is deliberately the only file in this package that opens a
real socket (`RealTransport.send()`), and every request goes through
`validate_and_resolve()` first:

1. **`https` only.** Any other scheme (`http`, `file`, `ftp`, no scheme at
   all) is rejected with `WebhookRejected("invalid_scheme", ...)`.
2. **Resolve, then check every resolved address.** `socket.getaddrinfo()`
   is called on the hostname, and *every* returned address (not just the
   first) is checked against `ipaddress`'s `is_private`, `is_loopback`,
   `is_link_local`, `is_reserved`, `is_multicast`, `is_unspecified`, and
   `is_site_local` (legacy IPv6). One private/reserved answer among several
   public ones is enough to reject the whole URL.
3. **No caching across time.** The IP is never cached from config-save
   time to send time. `validate_and_resolve()` runs again, fresh, on every
   single send -- so a hostname that resolved to a public IP when the user
   saved the config, then got repointed at `169.254.x.x` or `127.0.0.1` by
   the time an alert actually fires (DNS rebinding), is still caught.
4. **Connect to the resolved IP directly**, not back through DNS a second
   time inside the HTTP client -- this closes the classic TOCTOU gap where
   a library re-resolves the hostname at connect time and gets a different
   (attacker-controlled) answer than the one that was validated.
5. **No redirects.** The response status is read and reported as-is; a 3xx
   is just a non-2xx result. There is no code path that reads `Location`
   and issues a second request.
6. **5s timeout**, hard default, on both the TCP connect and the read.
7. **Exactly one attempt per call, never a retry loop.** Failures are
   returned as a `WebhookResult(ok=False, ...)` and recorded in
   `last_status` / alert history; nothing in this package calls
   `send_webhook` in a loop on failure.
8. **Bounded response read** (4096 bytes) -- a malicious or broken webhook
   endpoint can't make this hang or balloon memory by streaming an
   unbounded response body.

Both `PUT /api/alerts/config` (before persisting a webhook channel) and
`AlertService.dispatch()`/`test_channel()` (before every send) call
`validate_and_resolve()` -- rejecting bad config at save time is a UX nicety,
not the actual security boundary; the boundary is re-checked at send time.

## F3 rules and where they're enforced

| Rule | Where |
|---|---|
| Disabled by default, user supplies URL | `AlertsConfig.enabled: bool = False`; `_validate_channels()` requires a non-empty `url` on any *enabled* webhook channel |
| https-only, SSRF rejection | `webhook.validate_and_resolve()`, called from both config save and every send |
| No redirects | `RealTransport.send()` never reads `Location` |
| 5s timeout | `webhook.DEFAULT_TIMEOUT_SECONDS = 5.0`, passed through every call |
| Failures in `last_status`, never retried in a tight loop | `AlertService.test_channel()`/`dispatch()` call `send_webhook` exactly once and write the result to `alert_channels.last_status` |
| `min_severity` | `AlertService.dispatch()`, using `SEVERITY_ORDER` |
| `rate_limit_per_hour` | `AlertService.dispatch()`, counting `alerts_history` rows in the trailing hour |
| `quiet_hours` | `AlertService.dispatch()` / `_is_quiet_now()`, handling a window that wraps past midnight (e.g. `23:00`-`07:00`) |

`POST /api/alerts/test` deliberately **bypasses** `enabled`/`min_severity`/
`quiet_hours`/`rate_limit_per_hour` -- it is an explicit, one-off user
action to check a channel actually works (including checking a channel
that isn't turned on yet), not part of the automatic dispatch pipeline
those filters govern. It still goes through the full webhook validation
path.

## Desktop notifications

`desktop.py` degrades gracefully: not on Windows, `powershell.exe`
missing, the call times out (5s default), or the toast API throws --
all become a recorded `DesktopResult(status=...)`, never an exception that
reaches the caller, never a block past the timeout. The title/message are
passed to the fixed PowerShell script via environment variables
(`$env:NETAUDIT_TOAST_TITLE`/`BODY`), never string-interpolated into the
script text, so a title or message containing PowerShell-special
characters can't be interpreted as code.

## Decoupling

This package has no visibility into posture or threat data (no import of
`netaudit.posture`/`netaudit.threat`/`netaudit.rules`). `AlertService.
dispatch(severity, source, source_id, title, ...)` is a plain method the
rest of the backend calls when it decides something is alert-worthy --
it is not itself an HTTP endpoint, since the frozen contract only defines
`GET`/`PUT /api/alerts/config`, `POST /api/alerts/test`, and `GET
/api/alerts/history`.

`providers.py` exposes `get_webhook_transport()` and `get_desktop_sender()`
as FastAPI dependencies (defaulting to the real implementations) so
`POST /api/alerts/test` can be exercised end-to-end in tests with a fake
transport and a fake desktop sender -- no real socket, no real
`powershell.exe` spawn, ever, in this package's test suite.

## Testing

```
.\.venv\Scripts\python.exe -m pytest tests/alerts -q
```

- `test_webhook_ssrf.py`: scheme rejection (`http`, `file`, no scheme);
  SSRF rejection for loopback (`127.0.0.1`, `localhost`), private
  (`10.x`, `172.16.x`, `192.168.x`), link-local (`169.254.x.x`), and
  reserved ranges, via a fake resolver so no real DNS lookup happens;
  a mixed-answer host (one public IP, one private IP) is still rejected;
  a genuinely public IP is accepted; no redirect is ever followed (a fake
  transport returns a 302 and the result is reported as a failed, non-2xx
  delivery, never re-requested); a 5s timeout is passed through to the
  transport; two consecutive calls after a failure never trigger more than
  the one attempt per call (no tight retry loop).
- `test_no_stray_network_calls.py`: greps this package's own source and
  asserts `socket.create_connection`, `ssl.`, and `http.client` appear only
  in `webhook.py`'s `RealTransport`, proving the webhook sender is the only
  call site that can reach the network.
- `test_config_rules.py`: min_severity filtering, rate_limit_per_hour
  (measured against real inserted history rows), quiet_hours (including a
  window that wraps past midnight), disabled-by-default, and rejection of
  an enabled webhook channel with no URL.
- `test_desktop.py`: graceful degradation to `unavailable`/`failed` via a
  fake sender simulating "not Windows", a timeout, and a non-zero exit,
  and confirms the argv passed to `subprocess.run` is a list (never a
  shell string) with the title/message going through `env`, not the
  command text.
- `test_router.py`: `GET`/`PUT /api/alerts/config`, `POST /api/alerts/test`,
  `GET /api/alerts/history` via `TestClient` against faked providers,
  including a 400 for a rejected webhook URL.
