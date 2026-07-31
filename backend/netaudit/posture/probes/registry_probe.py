"""Read-only Windows registry reads via `winreg`.

Every lookup goes through `read(key)`, dispatching on a hardcoded map of
(hive, subkey, value_name) tuples -- REGISTRY_MAP below. No hive/subkey/value
is ever built from a variable; every path is a literal in this file. Only
`winreg.OpenKey` (with default `KEY_READ` access) and `winreg.QueryValueEx`
are used -- `SetValueEx`, `CreateKey`, `DeleteKey`, and `DeleteValue` do not
appear anywhere in this module (see test_no_writes.py, which greps the whole
package for them).

Safe to import on non-Windows: `winreg` doesn't exist there, so every read
degrades to `ProbeResult(ok=False, error=...)` instead of raising at import
time. That keeps the test suite collectible on any CI platform.
"""
from __future__ import annotations

import sys
from typing import NamedTuple, Optional

from .runner import ProbeResult

try:
    import winreg
except ImportError:  # pragma: no cover - exercised on non-Windows CI only
    winreg = None  # type: ignore[assignment]


class _RegTarget(NamedTuple):
    hive: str  # attribute name on winreg, e.g. "HKEY_LOCAL_MACHINE"
    subkey: str
    value_name: Optional[str]  # None = read the whole key's values as a dict


# Hardcoded map of probe key -> registry location. Every subkey string below
# is a literal; nothing here is assembled from a variable.
REGISTRY_MAP: dict[str, _RegTarget] = {
    "rdp_deny_connections": _RegTarget(
        "HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections"
    ),
    "rdp_nla": _RegTarget(
        "HKEY_LOCAL_MACHINE",
        r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
        "UserAuthentication",
    ),
    "llmnr_enable_multicast": _RegTarget(
        "HKEY_LOCAL_MACHINE", r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "EnableMulticast"
    ),
    "mdns_enabled": _RegTarget(
        "HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters", "EnableMDNS"
    ),
    "wpad_autodetect": _RegTarget(
        "HKEY_CURRENT_USER",
        r"Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections",
        "DefaultConnectionSettings",
    ),
    "ipv6_disabled_components": _RegTarget(
        "HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters", "DisabledComponents"
    ),
    "ip_forwarding": _RegTarget(
        "HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "IPEnableRouter"
    ),
    "schannel_tls10_client": _RegTarget(
        "HKEY_LOCAL_MACHINE",
        r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client",
        None,
    ),
    "schannel_tls10_server": _RegTarget(
        "HKEY_LOCAL_MACHINE",
        r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server",
        None,
    ),
    "schannel_tls11_client": _RegTarget(
        "HKEY_LOCAL_MACHINE",
        r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client",
        None,
    ),
    "schannel_tls11_server": _RegTarget(
        "HKEY_LOCAL_MACHINE",
        r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server",
        None,
    ),
    "schannel_ssl3_client": _RegTarget(
        "HKEY_LOCAL_MACHINE",
        r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client",
        None,
    ),
    "schannel_ssl3_server": _RegTarget(
        "HKEY_LOCAL_MACHINE",
        r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server",
        None,
    ),
    "uac_settings": _RegTarget(
        "HKEY_LOCAL_MACHINE", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", None
    ),
    "autologon_settings": _RegTarget(
        "HKEY_LOCAL_MACHINE", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", None
    ),
    "smb_guest_auth": _RegTarget(
        "HKEY_LOCAL_MACHINE",
        r"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters",
        "AllowInsecureGuestAuth",
    ),
    "windows_update_last_success": _RegTarget(
        "HKEY_LOCAL_MACHINE",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install",
        "LastSuccessTime",
    ),
}


def read(key: str) -> ProbeResult:
    """Read one registry value (or, if `value_name` is None, every value
    under that subkey as a dict) by allowlisted key name."""
    if key not in REGISTRY_MAP:
        return ProbeResult(ok=False, error=f"unknown registry probe key: {key!r}")
    if winreg is None or sys.platform != "win32":
        return ProbeResult(ok=False, error="registry access is only available on Windows")

    target = REGISTRY_MAP[key]
    try:
        hive = getattr(winreg, target.hive)
    except AttributeError:
        return ProbeResult(ok=False, error=f"invalid registry hive: {target.hive!r}")

    try:
        with winreg.OpenKey(hive, target.subkey, 0, winreg.KEY_READ) as hkey:
            if target.value_name is not None:
                value, _vtype = winreg.QueryValueEx(hkey, target.value_name)
                return ProbeResult(ok=True, data=value)
            values: dict[str, object] = {}
            index = 0
            while True:
                try:
                    name, value, _vtype = winreg.EnumValue(hkey, index)
                except OSError:
                    break
                values[name] = value
                index += 1
            return ProbeResult(ok=True, data=values)
    except FileNotFoundError:
        # Key/value not present. For most of these that means "not
        # explicitly configured" -- callers decide what the OS default is.
        return ProbeResult(ok=False, error=f"registry value not found: {target.hive}\\{target.subkey}\\{target.value_name}")
    except PermissionError:
        return ProbeResult(ok=False, error="access denied reading registry (try running as administrator)")
    except OSError as exc:
        return ProbeResult(ok=False, error=f"registry read failed: {exc}")
