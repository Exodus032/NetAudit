# Dependencies

None beyond what the backend already installs (`fastapi`, `pydantic`).
Everything else is standard library:

- `socket`, `ssl`, `http.client`, `ipaddress`, `urllib.parse` -- the
  SSRF-safe webhook sender (`webhook.py`). Deliberately not `requests` or
  `httpx`: this needed to connect to a pre-validated IP address rather than
  letting a client library re-resolve DNS at connect time (see the
  DNS-rebinding note in `webhook.py`'s docstring), which is easiest to get
  right by driving the socket/TLS handshake directly.
- `subprocess`, `platform`, `os` -- the desktop toast (`desktop.py`), via a
  fixed PowerShell script and `Windows.UI.Notifications`. No third-party
  toast library (`win10toast`, `winotify`, `plyer`, ...) was added; the
  task instructions prefer the standard library, and a toast is simple
  enough to drive directly without one.
- `sqlite3`, `json`, `secrets`, `dataclasses` -- persistence (`store.py`),
  reusing the shared SQLite file via `netaudit.store.db.get_conn()`.

Nothing in this package makes an outbound network call except
`webhook.RealTransport.send()`, and only when the user has explicitly
enabled a webhook channel with a URL that passed `validate_and_resolve()`.
