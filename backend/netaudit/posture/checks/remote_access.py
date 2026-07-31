"""remote_access: rdp_disabled_or_nla, winrm_exposure, remote_registry_disabled,
psremoting_scope."""
from __future__ import annotations

from ..base import Check, CheckOutcome, ProbeContext, as_list, require_ok
from ..models import Remediation, RemediationCommand
from ..registry import register


@register
class RdpDisabledOrNla(Check):
    id = "rdp_disabled_or_nla"
    category = "remote_access"
    title = "RDP is disabled, or requires Network Level Authentication"
    severity = "high"
    score_weight = 8
    why_it_matters = (
        "RDP without Network Level Authentication completes the graphical logon before the peer proves "
        "any credentials, expanding the attack surface to the full pre-auth logon stack. RDP enabled at "
        "all on a laptop that roams onto untrusted networks is itself a routinely scanned-for target."
    )
    remediation = Remediation(
        summary="Disable RDP if unused, or require NLA if you need it.",
        commands=[
            RemediationCommand(
                shell="powershell",
                command="Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -Value 1",
                requires_admin=True,
                reversible=True,
                risk_note="Disables all incoming Remote Desktop access, including any legitimate remote administration you rely on.",
            ),
            RemediationCommand(
                shell="powershell",
                command="Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name UserAuthentication -Value 1",
                requires_admin=True,
                reversible=True,
                risk_note="Clients older than Windows Vista / without CredSSP support will no longer be able to connect.",
            ),
        ],
        docs_url="https://learn.microsoft.com/windows-server/remote/remote-desktop-services/clients/network-level-authentication",
    )

    def gather(self, probes: ProbeContext) -> dict:
        return {"deny": probes.registry("rdp_deny_connections"), "nla": probes.registry("rdp_nla")}

    def evaluate(self, raw: dict) -> CheckOutcome:
        deny_result = raw["deny"]
        nla_result = raw["nla"]
        if not deny_result.ok:
            return CheckOutcome(status="error", observed=f"could not read fDenyTSConnections: {deny_result.error}")
        deny = bool(deny_result.data)
        evidence = [{"label": "fDenyTSConnections", "value": str(deny_result.data)}]
        if deny:
            return CheckOutcome(status="pass", observed="Remote Desktop is disabled (fDenyTSConnections = 1)", expected="fDenyTSConnections = 1, or UserAuthentication = 1 if RDP is needed", evidence=evidence)
        if not nla_result.ok:
            evidence.append({"label": "UserAuthentication", "value": f"unreadable: {nla_result.error}"})
            return CheckOutcome(status="warn", observed="RDP is enabled and NLA requirement could not be determined", expected="fDenyTSConnections = 1, or UserAuthentication = 1 if RDP is needed", evidence=evidence)
        nla = bool(nla_result.data)
        evidence.append({"label": "UserAuthentication (NLA)", "value": str(nla_result.data)})
        if nla:
            return CheckOutcome(status="warn", observed="RDP is enabled with NLA required -- exposure is reduced but RDP is still reachable", expected="fDenyTSConnections = 1, or UserAuthentication = 1 if RDP is needed", evidence=evidence)
        return CheckOutcome(status="fail", observed="RDP is enabled without Network Level Authentication", expected="fDenyTSConnections = 1, or UserAuthentication = 1 if RDP is needed", evidence=evidence)


@register
class WinrmExposure(Check):
    id = "winrm_exposure"
    category = "remote_access"
    title = "WinRM is not exposed unencrypted or unnecessarily"
    severity = "high"
    score_weight = 7
    why_it_matters = (
        "WinRM gives remote command execution on this machine. Running with AllowUnencrypted or a "
        "listener bound to a routable address instead of the loopback/management interface widens the "
        "path an attacker on the network needs to get a shell."
    )
    remediation = Remediation(
        summary="Disable the WinRM service if unused, or ensure AllowUnencrypted is off and listeners are scoped to a trusted interface.",
        commands=[
            RemediationCommand(
                shell="powershell",
                command="Disable-PSRemoting -Force",
                requires_admin=True,
                reversible=True,
                risk_note="Stops all PowerShell remoting to this machine, including any automation or management tooling that depends on it.",
            )
        ],
        docs_url="https://learn.microsoft.com/powershell/scripting/learn/remoting/winrmsecurity",
    )

    def gather(self, probes: ProbeContext) -> dict:
        return {"status": require_ok(probes.ps("winrm_status"), "WinRM service status")}

    def evaluate(self, raw: dict) -> CheckOutcome:
        status = raw["status"] or {}
        service = status.get("service") or {}
        svc_status = service.get("Status")
        evidence = [{"label": "WinRM service", "value": f"Status: {svc_status}, StartType: {service.get('StartType')}"}]
        if svc_status != "Running":
            return CheckOutcome(status="pass", observed=f"WinRM service is not running (Status: {svc_status})", expected="WinRM stopped, or running with AllowUnencrypted = False", evidence=evidence)
        unencrypted = status.get("allow_unencrypted")
        evidence.append({"label": "AllowUnencrypted", "value": str(unencrypted)})
        if unencrypted:
            return CheckOutcome(status="fail", observed="WinRM is running with AllowUnencrypted = true", expected="WinRM stopped, or running with AllowUnencrypted = False", evidence=evidence)
        return CheckOutcome(status="warn", observed="WinRM is running (encrypted); confirm this is intentional and firewalled to trusted sources", expected="WinRM stopped, or running with AllowUnencrypted = False", evidence=evidence)


@register
class RemoteRegistryDisabled(Check):
    id = "remote_registry_disabled"
    category = "remote_access"
    title = "Remote Registry service is disabled"
    severity = "medium"
    score_weight = 5
    why_it_matters = (
        "The Remote Registry service lets an authenticated remote user read and modify this machine's "
        "registry over the network. It has almost no legitimate use on a workstation and is a favorite "
        "post-exploitation persistence/reconnaissance target."
    )
    remediation = Remediation(
        summary="Stop and disable the Remote Registry service.",
        commands=[
            RemediationCommand(
                shell="powershell",
                command="Stop-Service RemoteRegistry -Force; Set-Service RemoteRegistry -StartupType Disabled",
                requires_admin=True,
                reversible=True,
                risk_note="Breaks any remote registry-based management tooling that depends on it (uncommon on a personal workstation).",
            )
        ],
        docs_url="https://learn.microsoft.com/windows/win32/services/service-control-manager",
    )

    def gather(self, probes: ProbeContext) -> dict:
        return {"service": require_ok(probes.ps("remote_registry_service"), "Remote Registry service status")}

    def evaluate(self, raw: dict) -> CheckOutcome:
        service = raw["service"] or {}
        status = service.get("Status")
        start_type = service.get("StartType")
        evidence = [{"label": "RemoteRegistry", "value": f"Status: {status}, StartType: {start_type}"}]
        if status == "Running" or start_type not in ("Disabled",):
            return CheckOutcome(status="fail" if status == "Running" else "warn", observed=f"Remote Registry service: Status={status}, StartType={start_type}", expected="StartType = Disabled (and Status = Stopped)", evidence=evidence)
        return CheckOutcome(status="pass", observed=f"Remote Registry service: Status={status}, StartType={start_type}", expected="StartType = Disabled (and Status = Stopped)", evidence=evidence)


@register
class PsRemotingScope(Check):
    id = "psremoting_scope"
    category = "remote_access"
    title = "PowerShell remoting trusted hosts / listeners are scoped"
    severity = "medium"
    score_weight = 5
    why_it_matters = (
        "A wildcard TrustedHosts entry (`*`) tells this machine's WinRM client to accept any remote host "
        "identity without verifying it against Kerberos or a certificate, opening the door to "
        "man-in-the-middle credential theft if PowerShell remoting is ever used from this machine."
    )
    remediation = Remediation(
        summary="Scope TrustedHosts to specific known hosts instead of a wildcard, or clear it if remoting isn't used.",
        commands=[
            RemediationCommand(
                shell="powershell",
                command="Set-Item WSMan:\\localhost\\Client\\TrustedHosts -Value '' -Force",
                requires_admin=True,
                reversible=True,
                risk_note="Breaks any script that relies on connecting outbound to remote hosts via PowerShell remoting without Kerberos.",
            )
        ],
        docs_url="https://learn.microsoft.com/powershell/scripting/learn/remoting/winrmsecurity",
    )

    def gather(self, probes: ProbeContext) -> dict:
        return {"status": require_ok(probes.ps("psremoting_status"), "PSRemoting/WinRM client status")}

    def evaluate(self, raw: dict) -> CheckOutcome:
        status = raw["status"] or {}
        trusted = status.get("trusted_hosts")
        evidence = [{"label": "TrustedHosts", "value": str(trusted)}]
        if trusted and str(trusted).strip() == "*":
            return CheckOutcome(status="fail", observed="WSMan TrustedHosts is set to '*' (any remote host is trusted)", expected="TrustedHosts is empty or lists specific hostnames only", evidence=evidence)
        if trusted and trusted.strip():
            return CheckOutcome(status="warn", observed=f"WSMan TrustedHosts is set to: {trusted}", expected="TrustedHosts is empty or lists specific hostnames only", evidence=evidence)
        return CheckOutcome(status="pass", observed="WSMan TrustedHosts is empty", expected="TrustedHosts is empty or lists specific hostnames only", evidence=evidence)
