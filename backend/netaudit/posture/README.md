# Host security posture

Read-only audit of how this machine is configured for network exposure, per
`docs/API_CONTRACT_V2_SECURITY.md` Part A. Never changes system state.

## Read-only guarantee

- `probes/runner.py` is the only place in this package that spawns a
  subprocess. It runs a fixed argument list (`Sequence[str]`) with
  `shell=False` -- never a concatenated string, never anything containing
  HTTP request data.
- `probes/powershell.py`'s `ALLOWLIST` is a hardcoded `dict[str, list[str]]`.
  Every command is a `Get-*`/`Test-*` PowerShell cmdlet or a `netsh ... show`
  -- no `Set-`, `New-`, `Remove-`, `Disable-`, `Enable-`, `Add-`, `Clear-`,
  `Start-`, `Stop-`, `Restart-`, `Rename-`, `Copy-`, `Move-`, `Install-`,
  `Uninstall-`, `netsh ... set`, `reg add`, or `reg delete` appears anywhere
  in it.
- `probes/registry_probe.py` only ever calls `winreg.OpenKey` (read access)
  and `winreg.QueryValueEx`/`EnumValue`. No write API is used.
- `probes/netprobe.py` only enumerates (`psutil.net_connections`,
  `psutil.Process.name`).
- `checks/*.py` never imports `subprocess` or `winreg` directly -- they only
  reach the OS through `base.ProbeContext`.
- Every `Remediation.commands[].command` string is advisory text the user
  copies and runs themselves. It is never executed by this package. Some of
  these strings do contain write-verb cmdlets (e.g.
  `Set-SmbClientConfiguration`) -- that is the intended fix text, and is
  covered by a different, deliberately-scoped test than the "no write verb"
  checks on the execution path (see `backend/tests/posture/test_no_writes.py`).

All of this is enforced by tests, not just by convention:
`test_allowlist_safety.py` walks the PowerShell allowlist and fails on a
write-verb cmdlet, a `netsh ... set`, a `reg add`/`delete`, a Python format
placeholder, or evidence of runtime string-building; `test_no_writes.py`
greps the whole package for a `winreg` write call and confirms
`subprocess`/`os.system` appears only in `runner.py`.

## Safety properties

- Every probe has a default 5s timeout (a couple of specifically slow probes
  -- the firewall rule/filter join, and `Get-BitLockerVolume` -- get a longer
  budget, since they're legitimately slower than a single `Get-*` call, not
  broken). A probe timeout, missing cmdlet, or access-denied error becomes
  `status: "error"` with the reason in `observed` -- never a guessed `pass`.
- A single check's exception (in `gather()` or `evaluate()`) is caught by
  `Check.run()` and reported as that one check's `error` status; it never
  fails the whole scan.
- The whole scan is bounded to 30s wall time by default
  (`PostureService(scan_timeout_seconds=...)`); checks run concurrently in a
  `ThreadPoolExecutor`. A check still running when the deadline hits is
  reported as `error` ("did not complete within the Ns scan budget"), not
  silently dropped.
- `probes.runner.is_admin()` (`ctypes.windll.shell32.IsUserAnAdmin()`) is
  used by checks whose data source is unreliable without elevation
  (BitLocker, Defender, SMB shares) to make the error message specific
  ("...this check likely requires running NetAudit as Administrator")
  instead of just failing silently or guessing a status.

## The catalogue

43 checks across the 10 required categories. "Reads" is the underlying data
source; "Admin?" is whether elevation is typically required for it to return
useful data on a standard (non-elevated) run.

| Check id | Category | Reads | Admin? |
|---|---|---|---|
| `firewall_profiles_enabled` | firewall | `Get-NetFirewallProfile` | No |
| `firewall_inbound_default_block` | firewall | `Get-NetFirewallProfile` | No |
| `firewall_allow_rules_broad` | firewall | `Get-NetFirewallRule` + port/address filters (bulk-joined by `InstanceID`) | No |
| `firewall_logging_enabled` | firewall | `Get-NetFirewallProfile` | No |
| `smb1_disabled` | smb | `Get-SmbServerConfiguration` | No |
| `smb_signing_required` | smb | `Get-SmbClientConfiguration` + `Get-SmbServerConfiguration` | No |
| `smb_guest_auth_disabled` | smb | registry: `LanmanWorkstation\Parameters\AllowInsecureGuestAuth` | No |
| `smb_shares_exposed` | smb | `Get-SmbShare` + `Get-SmbShareAccess` | Sometimes |
| `rdp_disabled_or_nla` | remote_access | registry: `Terminal Server\fDenyTSConnections`, `...\WinStations\RDP-Tcp\UserAuthentication` | No |
| `winrm_exposure` | remote_access | `Get-Service WinRM`, `WSMan:\localhost\Service\AllowUnencrypted`, listeners | No |
| `remote_registry_disabled` | remote_access | `Get-Service RemoteRegistry` | No |
| `psremoting_scope` | remote_access | `Get-Service WinRM`, `WSMan:\localhost\Client\TrustedHosts` | No |
| `llmnr_disabled` | name_resolution | registry: `Policies\...\DNSClient\EnableMulticast` | No |
| `netbios_disabled` | name_resolution | `Get-CimInstance Win32_NetworkAdapterConfiguration` | No |
| `mdns_exposure` | name_resolution | registry: `Dnscache\Parameters\EnableMDNS` | No |
| `wpad_disabled` | name_resolution | registry: `Internet Settings\Connections\DefaultConnectionSettings` (binary flag) | No |
| `dns_over_https` | name_resolution | `Get-DnsClientDohServerAddress` | No |
| `dns_servers_trusted` | name_resolution | `Get-DnsClientServerAddress` | No |
| `ipv6_state` | network_config | registry: `Tcpip6\Parameters\DisabledComponents` | No |
| `ip_forwarding_disabled` | network_config | registry: `Tcpip\Parameters\IPEnableRouter` | No |
| `promiscuous_adapters` | network_config | `Get-NetAdapterBinding` (heuristic -- see check docstring) | No |
| `unused_adapters_enabled` | network_config | `Get-NetAdapter` | No |
| `network_profile_public` | network_config | `Get-NetConnectionProfile` | No |
| `wifi_encryption_strength` | wifi | `netsh wlan show interfaces` | No |
| `wifi_open_networks_saved` | wifi | `netsh wlan show profiles` + per-profile security type (no keys) | No |
| `wifi_autoconnect_open` | wifi | same as above | No |
| `tls10_11_disabled` | tls | registry: SCHANNEL `Protocols\TLS 1.0\1.1\{Client,Server}` | No |
| `ssl3_disabled` | tls | registry: SCHANNEL `Protocols\SSL 3.0\{Client,Server}` | No |
| `weak_ciphers_disabled` | tls | `Get-TlsCipherSuite` | No |
| `certificate_store_anomalies` | tls | `Get-ChildItem Cert:\LocalMachine\Root` | No |
| `listening_on_all_interfaces` | listening_services | `psutil.net_connections()` | Sometimes |
| `high_risk_ports_open` | listening_services | `psutil.net_connections()` | Sometimes |
| `unexpected_listeners` | listening_services | `psutil.net_connections()` + process name | Sometimes |
| `upnp_disabled` | listening_services | `Get-Service SSDPSRV,upnphost` | No |
| `defender_realtime_enabled` | updates_and_defense | `Get-MpComputerStatus` | Sometimes |
| `defender_signatures_current` | updates_and_defense | `Get-MpComputerStatus` | Sometimes |
| `windows_update_current` | updates_and_defense | registry: `WindowsUpdate\Auto Update\Results\Install\LastSuccessTime` | No |
| `uac_enabled` | updates_and_defense | registry: `Policies\System\EnableLUA` | No |
| `bitlocker_status` | updates_and_defense | `Get-BitLockerVolume` | **Yes** |
| `guest_account_disabled` | accounts | `Get-LocalUser` | No |
| `local_admin_count` | accounts | `Get-LocalGroupMember -Group Administrators` | No |
| `blank_passwords` | accounts | `Get-LocalUser` (`PasswordRequired`) | No |
| `autologon_disabled` | accounts | registry: `Winlogon\AutoAdminLogon`, `DefaultPassword` | No |

Checks marked "Sometimes" return good data unelevated on most machines but
can degrade to `error` on some configurations; `bitlocker_status` is the one
check that reliably needs elevation to return real data -- observed on this
machine's own scan (see below).

### A note on `fail` vs `warn`

Twelve checks (`mdns_exposure`, `dns_over_https`, `dns_servers_trusted`,
`ipv6_state`, `promiscuous_adapters`, `unused_adapters_enabled`,
`network_profile_public`, `certificate_store_anomalies`,
`listening_on_all_interfaces`, `unexpected_listeners`, `upnp_disabled`,
`local_admin_count`) never return `fail` -- their negative finding is `warn`,
by design. Each of these is either genuinely informational (`ipv6_state`),
a heuristic rather than a direct measurement (`promiscuous_adapters`), or a
soft threshold rather than a binary misconfiguration (`local_admin_count`).
Scoring them as a hard `fail` would overstate the risk. The other 31 checks
are binary controls and do reach `fail`.

## Scoring

```
score = round(100 * (sum(score_weight for pass) + 0.5 * sum(score_weight for warn))
                   / sum(score_weight for pass | warn | fail))
```

`error` and `skipped` checks are excluded from both sides of the fraction.
If nothing is scorable (every check errored or was skipped), the score is
**0**, not divided-by-zero and not a passing default -- no verifiable data
means no assurance can be claimed. See `scoring.py`.

Grade bands (not given numerically in the contract beyond one worked example
-- `score: 68` -> `grade: "C"` -- so these are chosen to satisfy that example
with an otherwise standard-shaped curve):

| Score | Grade |
|---|---|
| 90-100 | A |
| 80-89 | B |
| 65-79 | C |
| 50-64 | D |
| 0-49 | F |

`GET /api/security/score` composites `posture` (this package), `threats`,
and `hygiene` with base weights 0.4 / 0.35 / 0.25. `threats`/`hygiene` are
supplied as optional `ScoreContributor`s (see `service.ScoreContributor`,
a `Protocol` with `id`, `label`, `compute_score() -> Optional[int]`) --
when none are supplied, or a contributor returns `None`, that component is
omitted from `components` entirely and the remaining weights are
renormalized to sum to 1 (e.g. posture-only becomes weight 1.0; posture +
threats becomes 0.4/0.75 and 0.35/0.75).

## Category label reference

| id | label |
|---|---|
| `firewall` | Firewall |
| `smb` | SMB |
| `remote_access` | Remote Access |
| `name_resolution` | Name Resolution |
| `network_config` | Network Configuration |
| `wifi` | Wi-Fi |
| `tls` | TLS |
| `listening_services` | Listening Services |
| `updates_and_defense` | Updates & Defense |
| `accounts` | Accounts |

## Running it

```
python -m netaudit.posture.service
```

runs a real scan against the current machine (uses real probes, not fakes)
and prints a summary -- not part of the test suite, which uses fake probes
exclusively so it's deterministic on any machine, elevated or not.

## Testing

```
python -m pytest backend/tests/posture -q
```

192 tests: every check's pass/fail-or-warn/error path via fabricated
`ProbeResult`s, the scoring formula (including the zero-division and grade
boundary cases), the allowlist safety properties, a whole-package grep for
write APIs, model JSON round-trips with `Z`-suffixed timestamps, registry
catalogue completeness, `PostureService` behavior (wall-clock bounding,
partial rescan, score renormalization, history ring buffer), and router
shape tests against a faked service.
