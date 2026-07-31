"""name_resolution: llmnr_disabled, netbios_disabled, mdns_exposure,
wpad_disabled, dns_over_https, dns_servers_trusted."""
from __future__ import annotations

from ..base import Check, CheckOutcome, ProbeContext, as_list, require_ok
from ..models import Remediation, RemediationCommand
from ..registry import register

# Small, documented allowlist of well-known public resolvers used only to
# soften the dns_servers_trusted verdict from "unrecognized" to "known
# provider" -- never used to make a network call.
_KNOWN_PUBLIC_RESOLVERS = {
    "1.1.1.1": "Cloudflare", "1.0.0.1": "Cloudflare",
    "8.8.8.8": "Google", "8.8.4.4": "Google",
    "9.9.9.9": "Quad9", "149.112.112.112": "Quad9",
    "208.67.222.222": "OpenDNS", "208.67.220.220": "OpenDNS",
}


def _is_private_or_link_local(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        octets = [int(p) for p in parts]
        if octets[0] == 10:
            return True
        if octets[0] == 172 and 16 <= octets[1] <= 31:
            return True
        if octets[0] == 192 and octets[1] == 168:
            return True
        if octets[0] == 169 and octets[1] == 254:
            return True
        if octets[0] == 127:
            return True
        return False
    # IPv6: treat link-local/ULA/loopback as private-ish
    lowered = ip.lower()
    return lowered.startswith(("fe80", "fc", "fd", "::1"))


@register
class LlmnrDisabled(Check):
    id = "llmnr_disabled"
    category = "name_resolution"
    title = "LLMNR is disabled"
    severity = "high"
    score_weight = 7
    why_it_matters = (
        "LLMNR broadcasts name lookup requests to the whole local segment when DNS fails to resolve a "
        "name. Any peer on the network can answer, which is the basis of the Responder/LLMNR "
        "poisoning attack that captures NTLM credential hashes."
    )
    remediation = Remediation(
        summary="Disable multicast name resolution (LLMNR) via policy.",
        commands=[
            RemediationCommand(
                shell="powershell",
                command="New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -Force | Out-Null; Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -Name EnableMulticast -Value 0",
                requires_admin=True,
                reversible=True,
                risk_note="Name resolution on small/flat networks without a working DNS server (e.g. some home printer discovery) can stop working.",
            )
        ],
        docs_url="https://learn.microsoft.com/windows-server/networking/dns/dns-top",
    )

    def gather(self, probes: ProbeContext) -> dict:
        return {"enable_multicast": probes.registry("llmnr_enable_multicast")}

    def evaluate(self, raw: dict) -> CheckOutcome:
        result = raw["enable_multicast"]
        if not result.ok:
            return CheckOutcome(
                status="warn",
                observed="EnableMulticast policy is not configured; LLMNR is enabled by Windows default",
                expected="EnableMulticast = 0",
                evidence=[{"label": "EnableMulticast", "value": "not configured (default: enabled)"}],
            )
        value = result.data
        evidence = [{"label": "EnableMulticast", "value": str(value)}]
        if value == 0:
            return CheckOutcome(status="pass", observed="EnableMulticast = 0 (LLMNR disabled)", expected="EnableMulticast = 0", evidence=evidence)
        return CheckOutcome(status="fail", observed=f"EnableMulticast = {value} (LLMNR enabled)", expected="EnableMulticast = 0", evidence=evidence)


@register
class NetbiosDisabled(Check):
    id = "netbios_disabled"
    category = "name_resolution"
    title = "NetBIOS over TCP/IP is disabled"
    severity = "medium"
    score_weight = 5
    why_it_matters = (
        "NetBIOS name service, like LLMNR, answers broadcast name lookups on the local segment and is "
        "commonly abused alongside LLMNR poisoning to harvest authentication attempts."
    )
    remediation = Remediation(
        summary="Disable NetBIOS over TCP/IP on every adapter.",
        commands=[
            RemediationCommand(
                shell="powershell",
                command="Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | Invoke-CimMethod -MethodName SetTcpipNetbios -Arguments @{TcpipNetbiosOptions=2}",
                requires_admin=True,
                reversible=True,
                risk_note="Breaks NetBIOS-name-based discovery of very old devices/shares that don't support DNS.",
            )
        ],
        docs_url="https://learn.microsoft.com/troubleshoot/windows-server/networking/direct-hosted-netbios-traffic-windows",
    )

    def gather(self, probes: ProbeContext) -> dict:
        return {"adapters": require_ok(probes.ps("netbios_options"), "NetBIOS adapter configuration")}

    def evaluate(self, raw: dict) -> CheckOutcome:
        adapters = as_list(raw["adapters"])
        if not adapters:
            return CheckOutcome(status="skipped", observed="No IP-enabled network adapters found", expected="TcpipNetbiosOptions = 2 (disabled) on every adapter")
        # TcpipNetbiosOptions: 0=default(DHCP-controlled, usually enabled), 1=enabled, 2=disabled
        not_disabled = [a for a in adapters if a.get("TcpipNetbiosOptions") != 2]
        evidence = [{"label": a.get("Description", "adapter"), "value": f"TcpipNetbiosOptions: {a.get('TcpipNetbiosOptions')}"} for a in adapters]
        if not_disabled:
            return CheckOutcome(status="fail", observed=f"NetBIOS is not explicitly disabled on {len(not_disabled)} of {len(adapters)} adapter(s)", expected="TcpipNetbiosOptions = 2 (disabled) on every adapter", evidence=evidence)
        return CheckOutcome(status="pass", observed="NetBIOS over TCP/IP is disabled on all adapters", expected="TcpipNetbiosOptions = 2 (disabled) on every adapter", evidence=evidence)


@register
class MdnsExposure(Check):
    id = "mdns_exposure"
    category = "name_resolution"
    title = "mDNS responder is not unnecessarily exposed"
    severity = "low"
    score_weight = 3
    why_it_matters = (
        "The Windows mDNS responder (and third-party stacks like Bonjour) answers multicast queries on "
        "UDP/5353 from anyone on the local segment, which can leak the hostname and, on some networks, "
        "let a peer enumerate services this machine advertises."
    )
    remediation = Remediation(
        summary="Disable the built-in mDNS responder if you don't rely on service discovery (AirPlay/Chromecast/etc.) on this machine.",
        commands=[
            RemediationCommand(
                shell="powershell",
                command="New-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters' -Name EnableMDNS -PropertyType DWord -Value 0 -Force",
                requires_admin=True,
                reversible=True,
                risk_note="Breaks discovery of mDNS-advertised devices/services on the local network (some printers, smart-home and casting devices).",
            )
        ],
        docs_url="https://learn.microsoft.com/windows-server/administration/windows-commands/dns",
    )

    def gather(self, probes: ProbeContext) -> dict:
        return {"enabled": probes.registry("mdns_enabled")}

    def evaluate(self, raw: dict) -> CheckOutcome:
        result = raw["enabled"]
        if not result.ok:
            return CheckOutcome(
                status="warn",
                observed="EnableMDNS is not explicitly configured; current Windows default is enabled",
                expected="EnableMDNS = 0",
                evidence=[{"label": "EnableMDNS", "value": "not configured (default: enabled)"}],
            )
        value = result.data
        evidence = [{"label": "EnableMDNS", "value": str(value)}]
        if value == 0:
            return CheckOutcome(status="pass", observed="EnableMDNS = 0", expected="EnableMDNS = 0", evidence=evidence)
        return CheckOutcome(status="warn", observed=f"EnableMDNS = {value} (mDNS responder active on UDP/5353)", expected="EnableMDNS = 0", evidence=evidence)


@register
class WpadDisabled(Check):
    id = "wpad_disabled"
    category = "name_resolution"
    title = "WPAD proxy auto-detection is disabled"
    severity = "medium"
    score_weight = 5
    why_it_matters = (
        "WPAD auto-detection asks the network 'who is my proxy?' via DHCP/DNS/NetBIOS broadcasts. An "
        "attacker who answers first can hand this machine a malicious proxy and transparently intercept "
        "and modify unencrypted web traffic."
    )
    remediation = Remediation(
        summary="Turn off automatic proxy detection in Internet Settings.",
        commands=[
            RemediationCommand(
                shell="powershell",
                command="netsh winhttp reset proxy",
                requires_admin=True,
                reversible=True,
                risk_note="If this network legitimately relies on WPAD to configure a corporate proxy, web access may need a manually configured proxy afterward.",
            )
        ],
        docs_url="https://learn.microsoft.com/troubleshoot/browsers/internet-explorer-does-not-detect-proxy-server-settings",
    )

    def gather(self, probes: ProbeContext) -> dict:
        return {"settings": probes.registry("wpad_autodetect")}

    def evaluate(self, raw: dict) -> CheckOutcome:
        result = raw["settings"]
        if not result.ok:
            return CheckOutcome(status="error", observed=f"could not read proxy auto-detect setting: {result.error}")
        raw_bytes = result.data
        evidence = [{"label": "DefaultConnectionSettings", "value": f"{len(raw_bytes) if hasattr(raw_bytes, '__len__') else '?'} bytes"}]
        try:
            # Byte 8 of this binary blob is a bitmask; bit 0x08 = "Automatically detect settings".
            auto_detect = bool(raw_bytes[8] & 0x08)
        except (TypeError, IndexError):
            return CheckOutcome(status="error", observed="could not parse DefaultConnectionSettings binary value", evidence=evidence)
        evidence.append({"label": "Automatically detect settings", "value": str(auto_detect)})
        if auto_detect:
            return CheckOutcome(status="fail", observed="'Automatically detect settings' (WPAD) is enabled", expected="Automatic proxy detection disabled", evidence=evidence)
        return CheckOutcome(status="pass", observed="'Automatically detect settings' (WPAD) is disabled", expected="Automatic proxy detection disabled", evidence=evidence)


@register
class DnsOverHttps(Check):
    id = "dns_over_https"
    category = "name_resolution"
    title = "DNS over HTTPS is configured"
    severity = "low"
    score_weight = 3
    why_it_matters = (
        "Plain DNS queries are visible and modifiable by anyone on the path between this machine and its "
        "resolver, including the local network operator -- DoH encrypts those lookups so they can't be "
        "read or tampered with in transit."
    )
    remediation = Remediation(
        summary="Configure your DNS servers to use DNS over HTTPS (Windows 11 supports it natively for compatible resolvers such as Cloudflare, Google, and Quad9).",
        commands=[
            RemediationCommand(
                shell="powershell",
                command="Add-DnsClientDohServerAddress -ServerAddress 1.1.1.1 -DohTemplate 'https://cloudflare-dns.com/dns-query' -AllowFallbackToUdp $false -AutoUpgrade $true",
                requires_admin=True,
                reversible=True,
                risk_note="If the DoH endpoint is unreachable and fallback is disabled, DNS resolution can fail entirely; test before disabling fallback on a network you depend on.",
            )
        ],
        docs_url="https://learn.microsoft.com/windows-server/networking/dns/doh-client-support",
    )

    def gather(self, probes: ProbeContext) -> dict:
        return {"doh": probes.ps("dns_doh")}

    def evaluate(self, raw: dict) -> CheckOutcome:
        result = raw["doh"]
        if not result.ok:
            return CheckOutcome(status="error", observed=f"could not query DoH configuration (requires Windows 11 21H2+): {result.error}")
        entries = as_list(result.data)
        configured = [e for e in entries if e.get("DohTemplate")]
        evidence = [{"label": e.get("ServerAddress", "?"), "value": f"DohTemplate: {e.get('DohTemplate')}, AutoUpgrade: {e.get('AutoUpgrade')}"} for e in entries[:10]]
        if configured:
            return CheckOutcome(status="pass", observed=f"{len(configured)} DNS server(s) have a DoH template configured", expected="At least the primary DNS server has a DoH template configured", evidence=evidence)
        return CheckOutcome(status="warn", observed="No DNS servers have a DNS-over-HTTPS template configured; lookups are sent in the clear", expected="At least the primary DNS server has a DoH template configured", evidence=evidence)


@register
class DnsServersTrusted(Check):
    id = "dns_servers_trusted"
    category = "name_resolution"
    title = "Configured DNS servers are on the local network or a recognized provider"
    severity = "medium"
    score_weight = 4
    why_it_matters = (
        "The DNS resolver sees (and can lie about) every domain name this machine looks up. A DNS "
        "server that is neither on your local network nor a well-known public resolver could have been "
        "pushed by a compromised router, a rogue DHCP server, or malware."
    )
    remediation = Remediation(
        summary="Set DNS servers to your router/known-good resolver, or a recognized public provider (e.g. 1.1.1.1, 9.9.9.9).",
        commands=[
            RemediationCommand(
                shell="powershell",
                command="Get-NetAdapter | Get-DnsClientServerAddress",
                requires_admin=False,
                reversible=True,
                risk_note="Listing only; use Set-DnsClientServerAddress on the specific interface once you've picked a trusted resolver.",
            )
        ],
        docs_url="https://learn.microsoft.com/powershell/module/dnsclient/set-dnsclientserveraddress",
    )

    def gather(self, probes: ProbeContext) -> dict:
        return {"servers": require_ok(probes.ps("dns_servers"), "configured DNS servers")}

    def evaluate(self, raw: dict) -> CheckOutcome:
        entries = as_list(raw["servers"])
        addresses: list[str] = []
        for entry in entries:
            addresses.extend(as_list(entry.get("ServerAddresses")))
        addresses = [a for a in addresses if a]
        if not addresses:
            return CheckOutcome(status="skipped", observed="No DNS servers configured on any adapter", expected="DNS servers are on the local network or a recognized public provider")
        untrusted = []
        evidence = []
        for addr in addresses:
            if _is_private_or_link_local(addr):
                evidence.append({"label": addr, "value": "private/local network"})
            elif addr in _KNOWN_PUBLIC_RESOLVERS:
                evidence.append({"label": addr, "value": f"known provider: {_KNOWN_PUBLIC_RESOLVERS[addr]}"})
            else:
                evidence.append({"label": addr, "value": "unrecognized public address"})
                untrusted.append(addr)
        if untrusted:
            return CheckOutcome(status="warn", observed=f"Unrecognized public DNS server(s) configured: {', '.join(untrusted)}", expected="DNS servers are on the local network or a recognized public provider", evidence=evidence)
        return CheckOutcome(status="pass", observed=f"All configured DNS servers ({', '.join(addresses)}) are local or a recognized provider", expected="DNS servers are on the local network or a recognized public provider", evidence=evidence)
