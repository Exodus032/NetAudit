"""network_config: ipv6_state, ip_forwarding_disabled, promiscuous_adapters,
unused_adapters_enabled, network_profile_public."""
from __future__ import annotations

from ..base import Check, CheckOutcome, ProbeContext, as_list, require_ok
from ..models import Remediation, RemediationCommand
from ..registry import register

# Adapter binding ComponentIDs associated with packet-capture drivers. Used
# as a best-effort heuristic for promiscuous_adapters -- see that check's
# why_it_matters for the caveat.
_CAPTURE_DRIVER_COMPONENT_IDS = {"insi_pacer", "npcap", "npf", "npf_ndis6", "winpcap", "vbox_npcap"}


@register
class Ipv6State(Check):
    id = "ipv6_state"
    category = "network_config"
    title = "IPv6 configuration is intentional, not a silent default"
    severity = "low"
    score_weight = 3
    why_it_matters = (
        "IPv6 is on by default and, unlike IPv4, often has no NAT boundary -- a globally routable "
        "address can make services bound to all interfaces directly reachable from the internet if the "
        "firewall doesn't also cover the IPv6 stack. This check is informational: it reports the current "
        "state so you can decide, not because IPv6 itself is a vulnerability."
    )
    remediation = Remediation(
        summary="If you don't need IPv6, disable it only on the components that don't need it (rarely a full disable) -- or ensure the firewall's IPv6 rules mirror the IPv4 rules.",
        commands=[
            RemediationCommand(
                shell="powershell",
                command="Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters' -Name DisabledComponents -Value 0xFF",
                requires_admin=True,
                reversible=True,
                risk_note="Fully disabling IPv6 can break modern network features (some VPNs, Direct Access, newer Wi-Fi/Bluetooth sharing, and any IPv6-only service you connect to) and is explicitly discouraged by Microsoft except as a last resort.",
            )
        ],
        docs_url="https://learn.microsoft.com/troubleshoot/windows-server/networking/disable-ipv6-or-its-components-in-windows",
    )

    def gather(self, probes: ProbeContext) -> dict:
        return {"disabled_components": probes.registry("ipv6_disabled_components")}

    def evaluate(self, raw: dict) -> CheckOutcome:
        result = raw["disabled_components"]
        if not result.ok:
            return CheckOutcome(
                status="pass",
                observed="DisabledComponents is not configured; IPv6 is enabled on all components (Windows default)",
                expected="Informational -- confirm this matches your intended configuration",
                evidence=[{"label": "DisabledComponents", "value": "not configured (default: fully enabled)"}],
            )
        value = result.data
        evidence = [{"label": "DisabledComponents", "value": hex(value) if isinstance(value, int) else str(value)}]
        return CheckOutcome(status="pass", observed=f"DisabledComponents = {evidence[0]['value']}", expected="Informational -- confirm this matches your intended configuration", evidence=evidence)


@register
class IpForwardingDisabled(Check):
    id = "ip_forwarding_disabled"
    category = "network_config"
    title = "IP forwarding (routing) is disabled"
    severity = "high"
    score_weight = 6
    why_it_matters = (
        "IP forwarding turns this workstation into a router, relaying packets between the networks it's "
        "attached to (e.g. Wi-Fi and a USB-tethered phone, or a VPN and the LAN). Unless you're "
        "deliberately bridging two networks, this silently defeats network segmentation."
    )
    remediation = Remediation(
        summary="Disable IP routing.",
        commands=[
            RemediationCommand(
                shell="powershell",
                command="Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters' -Name IPEnableRouter -Value 0",
                requires_admin=True,
                reversible=True,
                risk_note="Breaks any deliberate internet-connection-sharing or routing setup you have running on this machine.",
            )
        ],
        docs_url="https://learn.microsoft.com/troubleshoot/windows-server/networking/configure-ip-routing",
    )

    def gather(self, probes: ProbeContext) -> dict:
        return {"ip_forwarding": probes.registry("ip_forwarding")}

    def evaluate(self, raw: dict) -> CheckOutcome:
        result = raw["ip_forwarding"]
        if not result.ok:
            return CheckOutcome(status="pass", observed="IPEnableRouter is not configured; IP forwarding is disabled (Windows default)", expected="IPEnableRouter = 0", evidence=[{"label": "IPEnableRouter", "value": "not configured (default: 0)"}])
        value = result.data
        evidence = [{"label": "IPEnableRouter", "value": str(value)}]
        if value:
            return CheckOutcome(status="fail", observed=f"IPEnableRouter = {value} (this machine forwards IP packets between interfaces)", expected="IPEnableRouter = 0", evidence=evidence)
        return CheckOutcome(status="pass", observed=f"IPEnableRouter = {value}", expected="IPEnableRouter = 0", evidence=evidence)


@register
class PromiscuousAdapters(Check):
    id = "promiscuous_adapters"
    category = "network_config"
    title = "No adapters are bound to a packet-capture driver"
    severity = "medium"
    score_weight = 4
    why_it_matters = (
        "Windows does not expose a true 'promiscuous mode' flag through any public API, so this is a "
        "heuristic, not a direct measurement: it looks for adapter bindings to known packet-capture "
        "drivers (Npcap/WinPcap and similar). A capture driver bound to an adapter means *something* on "
        "this machine can sniff traffic on that link -- confirm it's a tool you installed on purpose "
        "(NetAudit itself may use one)."
    )
    remediation = Remediation(
        summary="Remove capture-driver bindings from adapters where packet capture isn't intentionally in use.",
        commands=[
            RemediationCommand(
                shell="powershell",
                command="Get-NetAdapterBinding | Where-Object ComponentID -match 'npcap|npf|winpcap'",
                requires_admin=False,
                reversible=True,
                risk_note="Listing only; disabling the binding on a specific adapter with Disable-NetAdapterBinding will stop that capture tool from seeing traffic on that adapter.",
            )
        ],
        docs_url="https://learn.microsoft.com/powershell/module/netadapter/disable-netadapterbinding",
    )

    def gather(self, probes: ProbeContext) -> dict:
        return {"bindings": require_ok(probes.ps("net_adapter_bindings"), "network adapter bindings")}

    def evaluate(self, raw: dict) -> CheckOutcome:
        bindings = as_list(raw["bindings"])
        capture_bound = [b for b in bindings if str(b.get("ComponentID", "")).lower() in _CAPTURE_DRIVER_COMPONENT_IDS and b.get("Enabled")]
        evidence = [{"label": b.get("Name", "adapter"), "value": f"{b.get('ComponentID')} enabled={b.get('Enabled')}"} for b in capture_bound]
        if capture_bound:
            names = ", ".join(f"{b.get('Name')} ({b.get('ComponentID')})" for b in capture_bound)
            return CheckOutcome(status="warn", observed=f"Packet-capture driver bound and enabled on: {names}", expected="No capture-driver binding enabled unless intentionally installed", evidence=evidence)
        return CheckOutcome(status="pass", observed=f"No packet-capture driver bindings found across {len(bindings)} adapter binding(s)", expected="No capture-driver binding enabled unless intentionally installed", evidence=evidence)


@register
class UnusedAdaptersEnabled(Check):
    id = "unused_adapters_enabled"
    category = "network_config"
    title = "No enabled-but-disconnected adapters add unused attack surface"
    severity = "low"
    score_weight = 3
    why_it_matters = (
        "An adapter that's enabled but never connected (an old VPN virtual adapter, an unused Bluetooth "
        "PAN, a leftover virtual switch) still runs its network stack and can be a soft target -- "
        "disabling what you don't use shrinks what needs to be secured."
    )
    remediation = Remediation(
        summary="Disable network adapters that are enabled but not in active use.",
        commands=[
            RemediationCommand(
                shell="powershell",
                command="Get-NetAdapter | Where-Object { $_.AdminStatus -eq 'Up' -and $_.Status -ne 'Up' }",
                requires_admin=False,
                reversible=True,
                risk_note="Listing only; use Disable-NetAdapter on a specific adapter once you've confirmed it's genuinely unused.",
            )
        ],
        docs_url="https://learn.microsoft.com/powershell/module/netadapter/disable-netadapter",
    )

    def gather(self, probes: ProbeContext) -> dict:
        return {"adapters": require_ok(probes.ps("net_adapters"), "network adapter list")}

    def evaluate(self, raw: dict) -> CheckOutcome:
        adapters = as_list(raw["adapters"])
        physical = [a for a in adapters if not a.get("Virtual")]
        unused = [a for a in physical if a.get("AdminStatus") == "Up" and a.get("Status") not in ("Up",)]
        evidence = [{"label": a.get("Name", "?"), "value": f"Status={a.get('Status')}, InterfaceDescription={a.get('InterfaceDescription')}"} for a in unused]
        if unused:
            return CheckOutcome(status="warn", observed=f"{len(unused)} enabled adapter(s) are not connected: {', '.join(a.get('Name', '?') for a in unused)}", expected="No enabled adapter sits idle/disconnected long-term", evidence=evidence)
        return CheckOutcome(status="pass", observed=f"All {len(physical)} physical adapter(s) that are enabled are also connected", expected="No enabled adapter sits idle/disconnected long-term", evidence=evidence)


@register
class NetworkProfilePublic(Check):
    id = "network_profile_public"
    category = "network_config"
    title = "Active network connections are categorized correctly"
    severity = "medium"
    score_weight = 4
    why_it_matters = (
        "Windows relaxes firewall defaults and enables discovery/sharing features on Private/Domain "
        "networks that stay locked down on Public. A trusted home or office network mis-categorized as "
        "Public is mildly inconvenient; an untrusted network (coffee shop Wi-Fi) mis-categorized as "
        "Private exposes file sharing and other services you didn't mean to expose."
    )
    remediation = Remediation(
        summary="Set each network connection's category to match how trusted that network actually is.",
        commands=[
            RemediationCommand(
                shell="powershell",
                command="Set-NetConnectionProfile -InterfaceAlias '<adapter name>' -NetworkCategory Public",
                requires_admin=True,
                reversible=True,
                risk_note="Switching a network to Public will hide this machine from discovery and can break file/printer sharing on that network if you actually trust it.",
            )
        ],
        docs_url="https://learn.microsoft.com/powershell/module/netconnection/set-netconnectionprofile",
    )

    def gather(self, probes: ProbeContext) -> dict:
        return {"profiles": require_ok(probes.ps("connection_profiles"), "active network connection profiles")}

    def evaluate(self, raw: dict) -> CheckOutcome:
        profiles = as_list(raw["profiles"])
        if not profiles:
            return CheckOutcome(status="skipped", observed="No active network connections found", expected="Informational -- network category matches actual trust level")
        evidence = [{"label": p.get("Name", "?"), "value": f"Category: {p.get('NetworkCategory')}, Connectivity: {p.get('IPv4Connectivity')}"} for p in profiles]
        public = [p for p in profiles if p.get("NetworkCategory") == "Public"]
        if public:
            return CheckOutcome(status="pass", observed=f"{len(public)} of {len(profiles)} active connection(s) categorized Public (most restrictive firewall profile)", expected="Informational -- network category matches actual trust level", evidence=evidence)
        return CheckOutcome(status="warn", observed=f"No active connection is categorized Public; all {len(profiles)} are Private/Domain -- confirm every one of these networks is actually trusted", expected="Informational -- network category matches actual trust level", evidence=evidence)
