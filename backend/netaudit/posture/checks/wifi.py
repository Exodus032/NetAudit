"""wifi: wifi_encryption_strength, wifi_open_networks_saved, wifi_autoconnect_open.

All three checks are `skipped` on a machine with no wireless interface --
`netsh wlan show interfaces` says so in plain text when there isn't one.
"""
from __future__ import annotations

from ..base import Check, CheckOutcome, ProbeContext, as_list, require_ok
from ..models import Remediation, RemediationCommand
from ..registry import register

_NO_INTERFACE_MARKERS = ("no wireless interface", "wireless autoconfig service", "wlan autoconfig service is not running")

_WEAK_AUTH = {"open", "shared", "wep"}


def _parse_netsh_kv(text: str) -> dict[str, str]:
    """netsh's `show interfaces` output is `Key                 : Value` lines
    for a single connected interface block. Best-effort line parse."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        value = value.strip()
        if key:
            out[key] = value
    return out


def _no_adapter(raw_text: str) -> bool:
    lowered = raw_text.lower()
    return any(marker in lowered for marker in _NO_INTERFACE_MARKERS)


@register
class WifiEncryptionStrength(Check):
    id = "wifi_encryption_strength"
    category = "wifi"
    title = "Currently connected Wi-Fi uses strong encryption"
    severity = "high"
    score_weight = 6
    why_it_matters = (
        "WEP is broken and crackable in minutes; WPA/TKIP is deprecated and vulnerable to known "
        "keystream attacks. Anyone in radio range of a weakly-encrypted network can potentially decrypt "
        "or inject into this machine's Wi-Fi traffic."
    )
    remediation = Remediation(
        summary="Reconfigure the access point for WPA2-AES or WPA3, and forget/reconnect from this machine.",
        commands=[
            RemediationCommand(
                shell="powershell",
                command="netsh wlan show interfaces",
                requires_admin=False,
                reversible=True,
                risk_note="Read-only; the actual fix is on the access point/router, not this machine.",
            )
        ],
        docs_url="https://learn.microsoft.com/windows/win32/nativewifi/wlan-security-settings",
    )

    def gather(self, probes: ProbeContext) -> dict:
        return {"interfaces": require_ok(probes.ps("wifi_interfaces"), "Wi-Fi interface status")}

    def evaluate(self, raw: dict) -> CheckOutcome:
        text = raw["interfaces"] or ""
        if _no_adapter(text):
            return CheckOutcome(status="skipped", observed="No wireless interface present on this machine", expected="N/A")
        info = _parse_netsh_kv(text)
        state = info.get("State", "").lower()
        if state != "connected":
            return CheckOutcome(status="skipped", observed=f"Wi-Fi adapter present but not connected (State: {info.get('State', 'unknown')})", expected="N/A")
        auth = info.get("Authentication", "unknown")
        cipher = info.get("Cipher", "unknown")
        evidence = [{"label": "Authentication", "value": auth}, {"label": "Cipher", "value": cipher}]
        if auth.lower() in _WEAK_AUTH or "wep" in cipher.lower():
            return CheckOutcome(status="fail", observed=f"Connected network uses {auth}/{cipher}", expected="WPA2-Personal/Enterprise (AES) or WPA3", evidence=evidence)
        if "tkip" in cipher.lower() or auth.upper() == "WPA":
            return CheckOutcome(status="warn", observed=f"Connected network uses {auth}/{cipher} (deprecated)", expected="WPA2-Personal/Enterprise (AES) or WPA3", evidence=evidence)
        return CheckOutcome(status="pass", observed=f"Connected network uses {auth}/{cipher}", expected="WPA2-Personal/Enterprise (AES) or WPA3", evidence=evidence)


@register
class WifiOpenNetworksSaved(Check):
    id = "wifi_open_networks_saved"
    category = "wifi"
    title = "No saved Wi-Fi profiles are open (unencrypted) networks"
    severity = "medium"
    score_weight = 4
    why_it_matters = (
        "Every saved profile is a network this machine will automatically consider joining. A saved "
        "open network is an easy impersonation target: an attacker just has to broadcast the same SSID "
        "nearby and this machine may connect to it with zero encryption."
    )
    remediation = Remediation(
        summary="Remove saved profiles for open networks you no longer need.",
        commands=[
            RemediationCommand(
                shell="powershell",
                command="netsh wlan delete profile name=\"<profile name>\"",
                requires_admin=False,
                reversible=False,
                risk_note="You will need to re-enter credentials to rejoin that network later; there's no encrypted equivalent to fall back to since the network itself is open.",
            )
        ],
        docs_url="https://learn.microsoft.com/windows-server/networking/technologies/netsh/netsh-wlan",
    )

    def gather(self, probes: ProbeContext) -> dict:
        return {
            "interfaces": require_ok(probes.ps("wifi_interfaces"), "Wi-Fi interface status"),
            "profiles": probes.ps("wifi_profiles"),
        }

    def evaluate(self, raw: dict) -> CheckOutcome:
        if _no_adapter(raw["interfaces"] or ""):
            return CheckOutcome(status="skipped", observed="No wireless interface present on this machine", expected="N/A")
        profiles_result = raw["profiles"]
        if not profiles_result.ok:
            return CheckOutcome(status="error", observed=f"could not enumerate saved Wi-Fi profiles: {profiles_result.error}")
        profiles = as_list(profiles_result.data)
        open_profiles = [p for p in profiles if str(p.get("authentication", "")).lower() in _WEAK_AUTH]
        evidence = [{"label": p.get("name", "?"), "value": f"authentication: {p.get('authentication')}"} for p in open_profiles]
        if open_profiles:
            return CheckOutcome(status="fail", observed=f"{len(open_profiles)} saved profile(s) are open/unencrypted: {', '.join(str(p.get('name')) for p in open_profiles)}", expected="No saved profile uses Open/Shared/WEP authentication", evidence=evidence)
        return CheckOutcome(status="pass", observed=f"No open networks among {len(profiles)} saved Wi-Fi profile(s)", expected="No saved profile uses Open/Shared/WEP authentication", evidence=evidence)


@register
class WifiAutoconnectOpen(Check):
    id = "wifi_autoconnect_open"
    category = "wifi"
    title = "No open network is set to auto-connect"
    severity = "medium"
    score_weight = 4
    why_it_matters = (
        "A saved open network with auto-connect enabled means this machine will silently join any "
        "matching SSID in range without asking -- exactly the setup a Wi-Fi Pineapple / evil-twin attack "
        "relies on to get a victim onto an attacker-controlled network unattended."
    )
    remediation = Remediation(
        summary="Disable auto-connect for saved open networks, or remove the profile entirely.",
        commands=[
            RemediationCommand(
                shell="powershell",
                command="netsh wlan set profileparameter name=\"<profile name>\" connectionmode=manual",
                requires_admin=True,
                reversible=True,
                risk_note="You'll need to manually select and connect to that network going forward instead of it joining automatically.",
            )
        ],
        docs_url="https://learn.microsoft.com/windows-server/networking/technologies/netsh/netsh-wlan",
    )

    def gather(self, probes: ProbeContext) -> dict:
        return {
            "interfaces": require_ok(probes.ps("wifi_interfaces"), "Wi-Fi interface status"),
            "profiles": probes.ps("wifi_profiles"),
        }

    def evaluate(self, raw: dict) -> CheckOutcome:
        if _no_adapter(raw["interfaces"] or ""):
            return CheckOutcome(status="skipped", observed="No wireless interface present on this machine", expected="N/A")
        profiles_result = raw["profiles"]
        if not profiles_result.ok:
            return CheckOutcome(status="error", observed=f"could not enumerate saved Wi-Fi profiles: {profiles_result.error}")
        profiles = as_list(profiles_result.data)
        risky = [
            p for p in profiles
            if str(p.get("authentication", "")).lower() in _WEAK_AUTH
            and "auto" in str(p.get("connection_mode", "")).lower()
        ]
        evidence = [{"label": p.get("name", "?"), "value": f"authentication: {p.get('authentication')}, mode: {p.get('connection_mode')}"} for p in risky]
        if risky:
            return CheckOutcome(status="fail", observed=f"{len(risky)} open network(s) set to auto-connect: {', '.join(str(p.get('name')) for p in risky)}", expected="No open network profile has connection_mode = auto", evidence=evidence)
        return CheckOutcome(status="pass", observed=f"No auto-connecting open networks among {len(profiles)} saved Wi-Fi profile(s)", expected="No open network profile has connection_mode = auto", evidence=evidence)
