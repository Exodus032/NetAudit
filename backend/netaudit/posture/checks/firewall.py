"""firewall: firewall_profiles_enabled, firewall_inbound_default_block,
firewall_allow_rules_broad, firewall_logging_enabled."""
from __future__ import annotations

from ..base import Check, CheckOutcome, ProbeContext, as_list, require_ok
from ..models import Remediation, RemediationCommand
from ..registry import register


@register
class FirewallProfilesEnabled(Check):
    id = "firewall_profiles_enabled"
    category = "firewall"
    title = "Windows Firewall enabled on all profiles"
    severity = "critical"
    score_weight = 10
    why_it_matters = (
        "A disabled firewall profile removes Windows' only built-in packet filter for that network "
        "context -- every listening service becomes reachable from any host that can route to this "
        "machine, including other devices on an untrusted public network or a compromised LAN peer."
    )
    remediation = Remediation(
        summary="Enable the firewall on every profile (Domain, Private, Public).",
        commands=[
            RemediationCommand(
                shell="powershell",
                command="Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True",
                requires_admin=True,
                reversible=True,
                risk_note="None expected; re-enabling the firewall only blocks traffic that isn't already explicitly allowed.",
            )
        ],
        docs_url="https://learn.microsoft.com/windows/security/operating-system-security/network-security/windows-firewall/",
    )

    def gather(self, probes: ProbeContext) -> dict:
        return {"profiles": require_ok(probes.ps("firewall_profiles"), "firewall profile state")}

    def evaluate(self, raw: dict) -> CheckOutcome:
        profiles = as_list(raw["profiles"])
        if not profiles:
            return CheckOutcome(status="error", observed="Get-NetFirewallProfile returned no profiles")
        disabled = [p["Name"] for p in profiles if not p.get("Enabled")]
        evidence = [{"label": p["Name"], "value": f"Enabled: {bool(p.get('Enabled'))}"} for p in profiles]
        if disabled:
            return CheckOutcome(
                status="fail",
                observed=f"Firewall disabled on profile(s): {', '.join(disabled)}",
                expected="Enabled = True on Domain, Private, and Public profiles",
                evidence=evidence,
            )
        return CheckOutcome(
            status="pass",
            observed="Firewall is enabled on all profiles (Domain, Private, Public)",
            expected="Enabled = True on Domain, Private, and Public profiles",
            evidence=evidence,
        )


@register
class FirewallInboundDefaultBlock(Check):
    id = "firewall_inbound_default_block"
    category = "firewall"
    title = "Default inbound action is Block"
    severity = "high"
    score_weight = 8
    why_it_matters = (
        "If the default inbound action is Allow, any inbound connection not explicitly matched by a "
        "block rule gets through -- the firewall only protects you from things you remembered to block, "
        "instead of only exposing what you explicitly allowed."
    )
    remediation = Remediation(
        summary="Set the default inbound action to Block on every profile.",
        commands=[
            RemediationCommand(
                shell="powershell",
                command="Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block",
                requires_admin=True,
                reversible=True,
                risk_note="Any inbound-initiated traffic not already covered by an explicit allow rule will stop working (e.g. unconfigured file sharing, remote management tools).",
            )
        ],
        docs_url="https://learn.microsoft.com/windows/security/operating-system-security/network-security/windows-firewall/",
    )

    def gather(self, probes: ProbeContext) -> dict:
        return {"profiles": require_ok(probes.ps("firewall_profiles"), "firewall profile state")}

    def evaluate(self, raw: dict) -> CheckOutcome:
        profiles = as_list(raw["profiles"])
        if not profiles:
            return CheckOutcome(status="error", observed="Get-NetFirewallProfile returned no profiles")
        non_blocking = [p["Name"] for p in profiles if p.get("DefaultInboundAction") != "Block"]
        evidence = [{"label": p["Name"], "value": f"DefaultInboundAction: {p.get('DefaultInboundAction')}"} for p in profiles]
        if non_blocking:
            return CheckOutcome(
                status="fail",
                observed=f"Default inbound action is not Block on: {', '.join(non_blocking)}",
                expected="DefaultInboundAction = Block on every profile",
                evidence=evidence,
            )
        return CheckOutcome(
            status="pass",
            observed="Default inbound action is Block on all profiles",
            expected="DefaultInboundAction = Block on every profile",
            evidence=evidence,
        )


@register
class FirewallAllowRulesBroad(Check):
    id = "firewall_allow_rules_broad"
    category = "firewall"
    title = "No overly broad inbound allow rules"
    severity = "high"
    score_weight = 6
    why_it_matters = (
        "An enabled inbound allow rule scoped to RemoteAddress=Any and LocalPort=Any punches a hole "
        "through the firewall for every port from every reachable host -- it is functionally the same "
        "as having no firewall for whatever the rule targets, and is a common leftover from software "
        "installers that over-request access."
    )
    remediation = Remediation(
        summary="Scope broad inbound allow rules to the specific remote addresses and ports they actually need, or remove them.",
        commands=[
            RemediationCommand(
                shell="powershell",
                command="Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True | Get-NetFirewallPortFilter",
                requires_admin=False,
                reversible=True,
                risk_note="This command only lists rules; review each one before narrowing or removing it, since a legitimate app may need broad access on a trusted network.",
            )
        ],
        docs_url="https://learn.microsoft.com/powershell/module/netsecurity/set-netfirewallrule",
    )

    def gather(self, probes: ProbeContext) -> dict:
        return {"rules": require_ok(probes.ps("firewall_rules_inbound_allow"), "inbound firewall allow rules")}

    def evaluate(self, raw: dict) -> CheckOutcome:
        rules = as_list(raw["rules"])
        broad = []
        for rule in rules:
            remote = as_list(rule.get("remote_address"))
            ports = as_list(rule.get("local_port"))
            remote_is_any = (not remote) or any(str(r).lower() == "any" for r in remote)
            port_is_any = (not ports) or any(str(p).lower() == "any" for p in ports)
            if remote_is_any and port_is_any:
                broad.append(rule)
        evidence = [
            {"label": r.get("name", "unknown"), "value": f"profile={r.get('profile')}, remote=Any, port=Any"}
            for r in broad[:10]
        ]
        if not broad:
            return CheckOutcome(
                status="pass",
                observed=f"No overly broad inbound allow rules found among {len(rules)} enabled inbound allow rule(s)",
                expected="No enabled inbound allow rule with RemoteAddress=Any and LocalPort=Any",
                evidence=evidence,
            )
        public_exposed = any("Public" in str(r.get("profile", "")) for r in broad)
        status = "fail" if public_exposed else "warn"
        return CheckOutcome(
            status=status,
            observed=f"{len(broad)} inbound allow rule(s) permit any remote address on any port: {', '.join(str(r.get('name')) for r in broad[:5])}",
            expected="No enabled inbound allow rule with RemoteAddress=Any and LocalPort=Any",
            evidence=evidence,
        )


@register
class FirewallLoggingEnabled(Check):
    id = "firewall_logging_enabled"
    category = "firewall"
    title = "Firewall blocked-packet logging is enabled"
    severity = "medium"
    score_weight = 5
    why_it_matters = (
        "Without blocked-packet logging, the firewall silently drops scan and probe attempts with no "
        "record -- there is no way to notice reconnaissance or a failed intrusion attempt after the fact."
    )
    remediation = Remediation(
        summary="Turn on logging for blocked packets on every profile.",
        commands=[
            RemediationCommand(
                shell="powershell",
                command="Set-NetFirewallProfile -Profile Domain,Private,Public -LogBlocked True -LogFileName '%SystemRoot%\\System32\\LogFiles\\Firewall\\pfirewall.log' -LogMaxSizeKilobytes 16384",
                requires_admin=True,
                reversible=True,
                risk_note="Minor disk I/O and log growth; the log is capped at the configured size and old entries roll off.",
            )
        ],
        docs_url="https://learn.microsoft.com/windows/security/operating-system-security/network-security/windows-firewall/",
    )

    def gather(self, probes: ProbeContext) -> dict:
        return {"profiles": require_ok(probes.ps("firewall_profiles"), "firewall profile state")}

    def evaluate(self, raw: dict) -> CheckOutcome:
        profiles = as_list(raw["profiles"])
        if not profiles:
            return CheckOutcome(status="error", observed="Get-NetFirewallProfile returned no profiles")
        not_logging = [p["Name"] for p in profiles if not p.get("LogBlocked")]
        evidence = [{"label": p["Name"], "value": f"LogBlocked: {bool(p.get('LogBlocked'))}, LogFileName: {p.get('LogFileName')}"} for p in profiles]
        if len(not_logging) == len(profiles):
            return CheckOutcome(
                status="fail",
                observed="Blocked-packet logging is off on every profile",
                expected="LogBlocked = True on every profile",
                evidence=evidence,
            )
        if not_logging:
            return CheckOutcome(
                status="warn",
                observed=f"Blocked-packet logging is off on: {', '.join(not_logging)}",
                expected="LogBlocked = True on every profile",
                evidence=evidence,
            )
        return CheckOutcome(
            status="pass",
            observed="Blocked-packet logging is enabled on all profiles",
            expected="LogBlocked = True on every profile",
            evidence=evidence,
        )
