"""Typed wrappers around a fixed allowlist of read-only PowerShell / netsh
invocations.

Every entry in `ALLOWLIST` is a hardcoded `list[str]` -- the full argv passed
to `subprocess.run` via `runner.run_command`. Nothing in this module ever
builds a command with an f-string, `.format()`, `%` formatting, or string
concatenation of a runtime value. Where a script needs to iterate over
system-discovered data (e.g. the list of saved Wi-Fi profiles), that looping
happens *inside* the single hardcoded PowerShell script string -- Python
never assembles a new argv per iteration. See
`backend/tests/posture/test_allowlist_safety.py` for the automated check.

Every command here is read-only: `Get-*`, `Test-*`, or a `netsh ... show`.
No `Set-`, `New-`, `Remove-`, `Disable-`, `Enable-`, `Add-`, `Clear-`,
`Start-`, `Stop-`, `Restart-`, `Rename-`, `Copy-`, `Move-`, `Install-`,
`Uninstall-`, `netsh ... set`, `reg add`, or `reg delete` appears anywhere
in this file.
"""
from __future__ import annotations

import json

from .runner import CommandResult, DEFAULT_TIMEOUT_SECONDS, ProbeResult, run_command

PS_EXE = "powershell.exe"
_PS_PREFIX = [PS_EXE, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command"]


def _ps(script: str) -> list[str]:
    """Build a hardcoded argv entry for a fixed PowerShell script literal.
    `script` must always be a literal passed in at the ALLOWLIST call site
    below -- never a value built from a variable at call time."""
    return [*_PS_PREFIX, script]


# ---------------------------------------------------------------------------
# The allowlist. Keys are the only strings a Check may pass to `run_ps()`.
# ---------------------------------------------------------------------------

ALLOWLIST: dict[str, list[str]] = {
    "firewall_profiles": _ps(
        "$ProgressPreference='SilentlyContinue'; "
        "Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,"
        "DefaultOutboundAction,LogAllowed,LogBlocked,LogFileName,LogMaxSizeKilobytes "
        "| ConvertTo-Json -Compress -Depth 4"
    ),
    "firewall_rules_inbound_allow": _ps(
        "$ProgressPreference='SilentlyContinue'; "
        "$rules = Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True; "
        "$out = foreach ($r in $rules) { "
        "  $pf = $r | Get-NetFirewallPortFilter; "
        "  $af = $r | Get-NetFirewallAddressFilter; "
        "  [pscustomobject]@{ "
        "    name = $r.DisplayName; profile = [string]$r.Profile; "
        "    protocol = $pf.Protocol; local_port = $pf.LocalPort; "
        "    remote_address = $af.RemoteAddress "
        "  } "
        "}; $out | ConvertTo-Json -Compress -Depth 4"
    ),
    "smb_server_config": _ps(
        "$ProgressPreference='SilentlyContinue'; "
        "Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol,RequireSecuritySignature,"
        "EncryptData,RejectUnencryptedAccess | ConvertTo-Json -Compress -Depth 3"
    ),
    "smb_client_config": _ps(
        "$ProgressPreference='SilentlyContinue'; "
        "Get-SmbClientConfiguration | Select-Object RequireSecuritySignature,EnableSecuritySignature "
        "| ConvertTo-Json -Compress -Depth 3"
    ),
    "smb_shares": _ps(
        "$ProgressPreference='SilentlyContinue'; "
        "$shares = Get-SmbShare | Where-Object { $_.Name -notmatch '\\$$' -and $_.Name -ne 'IPC$' }; "
        "$out = foreach ($s in $shares) { "
        "  $acc = Get-SmbShareAccess -Name $s.Name | Select-Object AccountName,AccessControlType,AccessRight; "
        "  [pscustomobject]@{ name = $s.Name; path = $s.Path; access = $acc } "
        "}; $out | ConvertTo-Json -Compress -Depth 5"
    ),
    "winrm_status": _ps(
        "$ProgressPreference='SilentlyContinue'; "
        "$svc = Get-Service -Name WinRM | Select-Object Status,StartType; "
        "$unenc = $null; $listeners = $null; "
        "try { $unenc = (Get-Item WSMan:\\localhost\\Service\\AllowUnencrypted).Value } catch {} "
        "try { $listeners = Get-ChildItem WSMan:\\localhost\\Listener | ForEach-Object { "
        "  $addr = ($_ | Get-ChildItem | Where-Object Name -eq 'Address').Value; "
        "  $transport = ($_ | Get-ChildItem | Where-Object Name -eq 'Transport').Value; "
        "  [pscustomobject]@{ address = $addr; transport = $transport } "
        "} } catch {} "
        "[pscustomobject]@{ service = $svc; allow_unencrypted = $unenc; listeners = $listeners } "
        "| ConvertTo-Json -Compress -Depth 5"
    ),
    "remote_registry_service": _ps(
        "$ProgressPreference='SilentlyContinue'; "
        "Get-Service -Name RemoteRegistry | Select-Object Status,StartType | ConvertTo-Json -Compress -Depth 3"
    ),
    "psremoting_status": _ps(
        "$ProgressPreference='SilentlyContinue'; "
        "$svc = Get-Service -Name WinRM | Select-Object Status,StartType; "
        "$trusted = $null; "
        "try { $trusted = (Get-Item WSMan:\\localhost\\Client\\TrustedHosts).Value } catch {} "
        "$listeners = $null; "
        "try { $listeners = Get-ChildItem WSMan:\\localhost\\Listener | ForEach-Object { "
        "  ($_ | Get-ChildItem | Where-Object Name -eq 'Address').Value "
        "} } catch {} "
        "[pscustomobject]@{ service = $svc; trusted_hosts = $trusted; listener_addresses = $listeners } "
        "| ConvertTo-Json -Compress -Depth 5"
    ),
    "dns_doh": _ps(
        "$ProgressPreference='SilentlyContinue'; "
        "try { Get-DnsClientDohServerAddress | Select-Object ServerAddress,DohTemplate,AllowFallbackToUdp,AutoUpgrade "
        "| ConvertTo-Json -Compress -Depth 4 } catch { Write-Error $_.Exception.Message; exit 1 }"
    ),
    "dns_servers": _ps(
        "$ProgressPreference='SilentlyContinue'; "
        "Get-DnsClientServerAddress | Where-Object { $_.ServerAddresses.Count -gt 0 } "
        "| Select-Object InterfaceAlias,AddressFamily,ServerAddresses | ConvertTo-Json -Compress -Depth 4"
    ),
    "netbios_options": _ps(
        "$ProgressPreference='SilentlyContinue'; "
        "Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' "
        "| Select-Object Description,TcpipNetbiosOptions | ConvertTo-Json -Compress -Depth 3"
    ),
    "net_adapters": _ps(
        "$ProgressPreference='SilentlyContinue'; "
        "Get-NetAdapter | Select-Object Name,InterfaceDescription,Status,AdminStatus,MacAddress,ifIndex,Virtual "
        "| ConvertTo-Json -Compress -Depth 3"
    ),
    "net_adapter_bindings": _ps(
        "$ProgressPreference='SilentlyContinue'; "
        "Get-NetAdapterBinding | Select-Object Name,ComponentID,DisplayName,Enabled | ConvertTo-Json -Compress -Depth 3"
    ),
    "connection_profiles": _ps(
        "$ProgressPreference='SilentlyContinue'; "
        "Get-NetConnectionProfile | Select-Object Name,InterfaceAlias,NetworkCategory,IPv4Connectivity "
        "| ConvertTo-Json -Compress -Depth 3"
    ),
    "wifi_interfaces": ["netsh.exe", "wlan", "show", "interfaces"],
    "wifi_profiles": _ps(
        "$ProgressPreference='SilentlyContinue'; "
        "try { "
        "  $raw = netsh wlan show profiles; "
        "  $names = $raw | Select-String 'All User Profile\\s*:\\s*(.+)$' "
        "    | ForEach-Object { $_.Matches[0].Groups[1].Value.Trim() }; "
        "  $results = foreach ($n in $names) { "
        "    $detail = netsh wlan show profile name=\"$n\"; "
        "    $auth = $detail | Select-String 'Authentication\\s*:\\s*(.+)$' | Select-Object -First 1; "
        "    $cipher = $detail | Select-String 'Cipher\\s*:\\s*(.+)$' | Select-Object -First 1; "
        "    $mode = $detail | Select-String 'Connection mode\\s*:\\s*(.+)$' | Select-Object -First 1; "
        "    [pscustomobject]@{ "
        "      name = $n; "
        "      authentication = $(if ($auth) { $auth.Matches[0].Groups[1].Value.Trim() } else { $null }); "
        "      cipher = $(if ($cipher) { $cipher.Matches[0].Groups[1].Value.Trim() } else { $null }); "
        "      connection_mode = $(if ($mode) { $mode.Matches[0].Groups[1].Value.Trim() } else { $null }) "
        "    } "
        "  } "
        "  , @($results) | ConvertTo-Json -Compress -Depth 4 "
        "} catch { Write-Error $_.Exception.Message; exit 1 }"
    ),
    "upnp_services": _ps(
        "$ProgressPreference='SilentlyContinue'; "
        "Get-Service -Name SSDPSRV,upnphost -ErrorAction SilentlyContinue "
        "| Select-Object Name,Status,StartType | ConvertTo-Json -Compress -Depth 3"
    ),
    "tls_cipher_suites": _ps(
        "$ProgressPreference='SilentlyContinue'; "
        "try { Get-TlsCipherSuite | Select-Object Name | ConvertTo-Json -Compress -Depth 3 } "
        "catch { Write-Error $_.Exception.Message; exit 1 }"
    ),
    "cert_store_root": _ps(
        "$ProgressPreference='SilentlyContinue'; "
        "Get-ChildItem Cert:\\LocalMachine\\Root | Select-Object Subject,NotAfter,Thumbprint "
        "| ConvertTo-Json -Compress -Depth 3"
    ),
    "defender_status": _ps(
        "$ProgressPreference='SilentlyContinue'; "
        "try { Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled,AntivirusEnabled,"
        "AntivirusSignatureAge,AntispywareSignatureAge,AntivirusSignatureLastUpdated,IsTamperProtected "
        "| ConvertTo-Json -Compress -Depth 3 } catch { Write-Error $_.Exception.Message; exit 1 }"
    ),
    "bitlocker_status": _ps(
        "$ProgressPreference='SilentlyContinue'; "
        "try { Get-BitLockerVolume | Select-Object MountPoint,VolumeType,ProtectionStatus,EncryptionPercentage "
        "| ConvertTo-Json -Compress -Depth 3 } catch { Write-Error $_.Exception.Message; exit 1 }"
    ),
    "local_users": _ps(
        "$ProgressPreference='SilentlyContinue'; "
        "try { Get-LocalUser | Select-Object Name,Enabled,PasswordRequired,PasswordLastSet "
        "| ConvertTo-Json -Compress -Depth 3 } catch { Write-Error $_.Exception.Message; exit 1 }"
    ),
    "local_admins": _ps(
        "$ProgressPreference='SilentlyContinue'; "
        "try { Get-LocalGroupMember -Group 'Administrators' | Select-Object Name,ObjectClass,PrincipalSource "
        "| ConvertTo-Json -Compress -Depth 3 } catch { Write-Error $_.Exception.Message; exit 1 }"
    ),
    "hotfix_latest": _ps(
        "$ProgressPreference='SilentlyContinue'; "
        "try { Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending "
        "| Select-Object -First 1 HotFixID,InstalledOn | ConvertTo-Json -Compress -Depth 3 } "
        "catch { Write-Error $_.Exception.Message; exit 1 }"
    ),
}


def run_ps(key: str, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> ProbeResult:
    """Run an allowlisted probe by key and parse its stdout as JSON (except
    for `wifi_interfaces`, which is plain netsh text and returned raw)."""
    if key not in ALLOWLIST:
        return ProbeResult(ok=False, error=f"unknown probe key: {key!r} is not in the allowlist")

    argv = ALLOWLIST[key]
    result: CommandResult = run_command(argv, timeout=timeout)
    if not result.ok:
        return ProbeResult(ok=False, error=result.error or "command failed", raw_stdout=result.stdout)

    if key == "wifi_interfaces":
        return ProbeResult(ok=True, data=result.stdout, raw_stdout=result.stdout)

    text = result.stdout.strip()
    if not text:
        # Empty stdout from a successful (exit 0) Get-* pipeline means "no
        # objects" -- treat as an empty list, not an error.
        return ProbeResult(ok=True, data=[], raw_stdout=result.stdout)
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        return ProbeResult(ok=False, error=f"could not parse PowerShell JSON output: {exc}", raw_stdout=result.stdout)

    return ProbeResult(ok=True, data=parsed, raw_stdout=result.stdout)
