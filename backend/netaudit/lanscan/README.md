# Active LAN scan

Implements Part E7 of `docs/API_CONTRACT_V3.md`. This is the only feature
in NetAudit that sends traffic to other machines, so every constraint in
the contract is load-bearing and has a test that fails if it's removed.

| Constraint | Enforced in | Tested by |
|---|---|---|
| Target must be RFC1918 | `validation._is_rfc1918()` | `test_validation.py::test_non_rfc1918_rejected` (includes the `8.8.8.0/24` case from the done-criteria) |
| Target must be on an interface this machine actually has | `validation._matches_local_interface()`, via the `InterfaceProvider` Protocol | `test_validation.py::test_subnet_not_on_any_local_interface_rejected` |
| Maximum /24 per request | `validation.MIN_PREFIXLEN = 24` | `test_validation.py::test_subnet_larger_than_slash24_rejected` (includes the `/16` case from the done-criteria) |
| Maximum 20 ports | `validation.MAX_PORTS = 20` | `test_validation.py::test_more_than_20_ports_rejected` |
| Rate limit capped at 100 pps, actually enforced | `validation.MAX_RATE_LIMIT_PPS = 100` (cap) + `service.LanScanService._run()`'s pacing wait (enforcement) | `test_service.py::test_rate_limit_is_actually_enforced_with_measured_pacing` -- measures real wall-clock time across a real (fake-connector) scan and asserts it's not faster than the requested rate allows |
| TCP connect scan only | `providers.RealPortConnector` -- plain `socket.socket(...).connect_ex(...)`, nothing else | `test_providers.py::test_real_connector_is_plain_tcp_connect` (AST-level: no `scapy`, no `SOCK_RAW`, no raw-socket imports anywhere in the package) |
| No SYN/stealth/fingerprinting/exploitation/credential testing | same -- there is no code path that does any of these | same AST test, plus the package has no dependency capable of it (see DEPENDENCIES.md) |
| Job model: `POST` returns a job id, `GET` polls, `DELETE` cancels | `service.LanScanService` + `router.py` | `test_router.py` |
| Cancel actually stops the work promptly | `_JobState.cancel_event`, checked before every single host and every single port, and used as the pacing wait itself (`cancel_event.wait(timeout=interval)` wakes immediately on cancel instead of sleeping the full interval) | `test_service.py::test_cancel_stops_promptly_mid_scan` -- synchronizes with a blocking fake connector, cancels mid-attempt, and asserts the scan thread exits well before it would have finished naturally |
| One scan at a time; second concurrent request gets 409 | `LanScanService._manager_lock` + a status check (`status == "running"`, not just "does a job exist") | `test_service.py::test_second_concurrent_scan_rejected_with_409` (via `ScanAlreadyRunning`, mapped to 409 in `router.py`) |
| Response carries `consent_notice` | `service.CONSENT_NOTICE`, included in every `ScanJob` (`POST` response and every `GET` poll) | `test_router.py::test_consent_notice_present` |

## Why the interface check is a Protocol, not a real NIC lookup

`providers.InterfaceProvider.interfaces() -> Iterable[dict]` (each dict:
`{"address": "192.168.1.42", "prefixlen": 24}`) is the only way this
package learns what interfaces the machine has. Production code never
enumerates real NICs itself (that would need `psutil` or platform-specific
calls this package doesn't own); the orchestrator wires in the real
implementation. The default (`get_interface_provider()` with nothing
overridden) reports zero interfaces, so an un-wired deployment fails safe:
every scan request is rejected as not matching a local interface, never
silently allowed through.

## Why the scan is single-threaded and sequential

One worker thread makes exactly one connect attempt at a time, waiting
`1 / rate_limit_pps` seconds between attempts. This is what makes the rate
cap a real, structural guarantee rather than a stored number nothing
checks: there's no concurrency that could let the actual attempt rate
exceed what the pacing wait allows, so "assert the pacing in a test" is
literally measuring wall-clock time across a real (fake-connector) scan
loop, not just asserting a config value round-trips.

## Testing

```
.\.venv\Scripts\python.exe -m pytest tests/lanscan -q
```

Every test uses a fake `PortConnector` (`tests/lanscan/conftest.py`) --
the suite never opens a real socket or touches a real network. Covers all
ten rows of the table above, plus: `/31` and `/32` subnets (no
network/broadcast address to exclude), duplicate ports rejected, an
invalid CIDR string rejected with `400`, and the full happy path (`POST`
-> poll via `GET` until `completed` -> results shape) via `TestClient`.
