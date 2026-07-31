"""listening_services: listening_on_all_interfaces, high_risk_ports_open,
unexpected_listeners, upnp_disabled."""
from __future__ import annotations

from ..base import Check, CheckOutcome, ProbeContext, as_list, require_ok
from ..models import Remediation, RemediationCommand
from ..registry import register

_ANY_ADDR = {"0.0.0.0", "::"}

_HIGH_RISK_PORTS = {
    21: "FTP", 23: "Telnet", 135: "RPC endpoint mapper", 139: "NetBIOS Session",
    445: "SMB", 1433: "MSSQL", 1434: "MSSQL Monitor", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 27017: "MongoDB",
}

# Processes it's normal to see listening on a fresh Windows install. Anything
# else is flagged for the user's own review -- not a verdict of "bad".
_EXPECTED_LISTENERS = {
    "system", "svchost.exe", "lsass.exe", "services.exe", "wininit.exe",
    "spoolsv.exe", "mmc.exe", "sqlservr.exe",
}


@register
class ListeningOnAllInterfaces(Check):
    id = "listening_on_all_interfaces"
    category = "listening_services"
    title = "Few services bind to all interfaces (0.0.0.0/::) rather than loopback"
    severity = "medium"
    score_weight = 5
    why_it_matters = (
        "A service bound to 0.0.0.0 or :: accepts connections on every network this machine is attached "
        "to -- including an untrusted public Wi-Fi network -- rather than only from this machine itself. "
        "Binding to 127.0.0.1 when only local access is needed removes that exposure entirely."
    )
    remediation = Remediation(
        summary="Reconfigure services that don't need LAN/remote access to bind to 127.0.0.1 instead of 0.0.0.0, or firewall them off from untrusted networks.",
        commands=[
            RemediationCommand(
                shell="powershell",
                command="Get-NetTCPConnection -State Listen | Where-Object { $_.LocalAddress -in '0.0.0.0','::' } | Select-Object LocalPort,OwningProcess",
                requires_admin=False,
                reversible=True,
                risk_note="Listing only; the actual bind address is a per-application setting, not something NetAudit or a single command can change generically.",
            )
        ],
        docs_url="https://learn.microsoft.com/powershell/module/nettcpip/get-nettcpconnection",
    )

    def gather(self, probes: ProbeContext) -> dict:
        return {"sockets": require_ok(probes.net("listening_sockets"), "listening sockets", admin_hint=True)}

    def evaluate(self, raw: dict) -> CheckOutcome:
        sockets = as_list(raw["sockets"])
        broad = [s for s in sockets if s.get("ip") in _ANY_ADDR]
        evidence = [{"label": f"{s.get('process_name') or 'unknown'} (pid {s.get('pid')})", "value": f"{s.get('ip')}:{s.get('port')}/{s.get('protocol')}"} for s in broad[:15]]
        if not broad:
            return CheckOutcome(status="pass", observed=f"No listeners bound to 0.0.0.0/:: among {len(sockets)} listening socket(s)", expected="Services that don't need remote access bind to 127.0.0.1, not 0.0.0.0/::", evidence=evidence)
        return CheckOutcome(status="warn", observed=f"{len(broad)} listener(s) bound to all interfaces", expected="Services that don't need remote access bind to 127.0.0.1, not 0.0.0.0/::", evidence=evidence)


@register
class HighRiskPortsOpen(Check):
    id = "high_risk_ports_open"
    category = "listening_services"
    title = "No high-risk legacy service ports are reachable"
    severity = "critical"
    score_weight = 8
    why_it_matters = (
        "Ports like FTP (21), Telnet (23), SMB (445), and RDP (3389) are the most commonly scanned-for "
        "and exploited services on the internet and LANs alike. One reachable on a non-loopback address "
        "is a standing target for automated exploitation tools, not just a theoretical risk."
    )
    remediation = Remediation(
        summary="Stop the service if unneeded, or bind it to loopback only / firewall it from untrusted networks.",
        commands=[
            RemediationCommand(
                shell="powershell",
                command="Get-NetTCPConnection -State Listen | Where-Object LocalPort -in 21,23,135,139,445,1433,1434,3306,3389,5432,5900,6379,27017",
                requires_admin=False,
                reversible=True,
                risk_note="Listing only; stopping the owning service can break whatever legitimately depends on it (e.g. RDP for remote admin, SMB for file sharing).",
            )
        ],
        docs_url="https://learn.microsoft.com/powershell/module/nettcpip/get-nettcpconnection",
    )

    def gather(self, probes: ProbeContext) -> dict:
        return {"sockets": require_ok(probes.net("listening_sockets"), "listening sockets", admin_hint=True)}

    def evaluate(self, raw: dict) -> CheckOutcome:
        sockets = as_list(raw["sockets"])
        reachable = [s for s in sockets if s.get("ip") not in ("127.0.0.1", "::1") and s.get("port") in _HIGH_RISK_PORTS]
        evidence = [{"label": f"{_HIGH_RISK_PORTS.get(s.get('port'))} ({s.get('port')})", "value": f"{s.get('ip')}:{s.get('port')} - {s.get('process_name') or 'unknown'}"} for s in reachable]
        if reachable:
            names = ", ".join(f"{_HIGH_RISK_PORTS.get(s.get('port'))}/{s.get('port')}" for s in reachable)
            return CheckOutcome(status="fail", observed=f"High-risk port(s) reachable on a non-loopback address: {names}", expected="No high-risk legacy service port bound to a non-loopback address", evidence=evidence)
        return CheckOutcome(status="pass", observed=f"No high-risk ports reachable among {len(sockets)} listening socket(s)", expected="No high-risk legacy service port bound to a non-loopback address", evidence=evidence)


@register
class UnexpectedListeners(Check):
    id = "unexpected_listeners"
    category = "listening_services"
    title = "No unexpected processes are listening for inbound connections"
    severity = "medium"
    score_weight = 4
    why_it_matters = (
        "Most user-installed software has no business accepting inbound network connections. A process "
        "you don't recognize with an open listening socket is one of the more reliable signals of "
        "malware, a forgotten dev server, or bundled remote-access software you didn't intend to run."
    )
    remediation = Remediation(
        summary="Review each unexpected listener and stop or uninstall it if it isn't something you intend to run.",
        commands=[
            RemediationCommand(
                shell="powershell",
                command="Get-Process -Id <pid> | Select-Object Id,ProcessName,Path,StartTime",
                requires_admin=False,
                reversible=True,
                risk_note="Identification only; confirm what the process is before stopping it.",
            )
        ],
        docs_url="https://learn.microsoft.com/powershell/module/microsoft.powershell.management/get-process",
    )

    def gather(self, probes: ProbeContext) -> dict:
        return {"sockets": require_ok(probes.net("listening_sockets"), "listening sockets", admin_hint=True)}

    def evaluate(self, raw: dict) -> CheckOutcome:
        sockets = as_list(raw["sockets"])
        unexpected = [s for s in sockets if (s.get("process_name") or "").lower() not in _EXPECTED_LISTENERS]
        evidence = [{"label": f"{s.get('process_name') or 'unknown'} (pid {s.get('pid')})", "value": f"{s.get('ip')}:{s.get('port')}/{s.get('protocol')}"} for s in unexpected[:15]]
        if unexpected:
            names = ", ".join(sorted({s.get("process_name") or "unknown" for s in unexpected}))
            return CheckOutcome(status="warn", observed=f"{len(unexpected)} listening socket(s) belong to processes outside the common system baseline: {names}", expected="Review listed processes; this is informational, not a verdict", evidence=evidence)
        return CheckOutcome(status="pass", observed=f"All {len(sockets)} listening socket(s) belong to common system processes", expected="Review listed processes; this is informational, not a verdict", evidence=evidence)


@register
class UpnpDisabled(Check):
    id = "upnp_disabled"
    category = "listening_services"
    title = "UPnP device discovery/port-mapping services are disabled"
    severity = "medium"
    score_weight = 4
    why_it_matters = (
        "UPnP lets any device or piece of software on the LAN ask this machine (or the router) to open "
        "inbound ports automatically, with no authentication. It's a convenience feature that's also a "
        "standing invitation for malware or a compromised IoT device on the same network to punch a "
        "hole outward."
    )
    remediation = Remediation(
        summary="Disable the SSDP Discovery and UPnP Device Host services.",
        commands=[
            RemediationCommand(
                shell="powershell",
                command="Stop-Service SSDPSRV,upnphost -Force; Set-Service SSDPSRV,upnphost -StartupType Disabled",
                requires_admin=True,
                reversible=True,
                risk_note="Breaks device discovery features that rely on UPnP/SSDP (some media players, smart-home apps, game console connectivity, printer discovery).",
            )
        ],
        docs_url="https://learn.microsoft.com/windows-server/networking/technologies/networking",
    )

    def gather(self, probes: ProbeContext) -> dict:
        return {"services": require_ok(probes.ps("upnp_services"), "SSDP/UPnP service status")}

    def evaluate(self, raw: dict) -> CheckOutcome:
        services = as_list(raw["services"])
        running = [s for s in services if s.get("Status") == "Running"]
        evidence = [{"label": s.get("Name", "?"), "value": f"Status: {s.get('Status')}, StartType: {s.get('StartType')}"} for s in services]
        if running:
            names = ", ".join(s.get("Name", "?") for s in running)
            return CheckOutcome(status="warn", observed=f"UPnP-related service(s) running: {names}", expected="SSDPSRV and upnphost are stopped/disabled", evidence=evidence)
        return CheckOutcome(status="pass", observed="SSDP/UPnP services are not running", expected="SSDPSRV and upnphost are stopped/disabled", evidence=evidence)
