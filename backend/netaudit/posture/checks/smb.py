"""smb: smb1_disabled, smb_signing_required, smb_guest_auth_disabled,
smb_shares_exposed."""
from __future__ import annotations

from ..base import Check, CheckOutcome, ProbeContext, as_list, require_ok
from ..models import Remediation, RemediationCommand
from ..registry import register


@register
class Smb1Disabled(Check):
    id = "smb1_disabled"
    category = "smb"
    title = "SMBv1 is disabled"
    severity = "critical"
    score_weight = 10
    why_it_matters = (
        "SMBv1 has no protection against relay attacks and was the protocol exploited by WannaCry and "
        "NotPetya via EternalBlue. It has no legitimate use on a modern network unless you have "
        "decades-old NAS or printer hardware that only speaks it."
    )
    remediation = Remediation(
        summary="Disable the SMBv1 server (and uninstall the optional feature if not already removed).",
        commands=[
            RemediationCommand(
                shell="powershell",
                command="Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force",
                requires_admin=True,
                reversible=True,
                risk_note="Breaks connectivity to any device that only speaks SMBv1 (very old NAS boxes, some networked scanners/printers).",
            )
        ],
        docs_url="https://learn.microsoft.com/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3",
    )

    def gather(self, probes: ProbeContext) -> dict:
        return {"server": require_ok(probes.ps("smb_server_config"), "SMB server configuration")}

    def evaluate(self, raw: dict) -> CheckOutcome:
        server = raw["server"] or {}
        enabled = bool(server.get("EnableSMB1Protocol"))
        evidence = [{"label": "Server", "value": f"EnableSMB1Protocol: {enabled}"}]
        if enabled:
            return CheckOutcome(status="fail", observed="SMBv1 server protocol is enabled", expected="EnableSMB1Protocol = False", evidence=evidence)
        return CheckOutcome(status="pass", observed="SMBv1 server protocol is disabled", expected="EnableSMB1Protocol = False", evidence=evidence)


@register
class SmbSigningRequired(Check):
    id = "smb_signing_required"
    category = "smb"
    title = "SMB signing is required"
    severity = "high"
    score_weight = 8
    why_it_matters = (
        "Without required signing, an attacker on the same network can relay or tamper with SMB sessions."
    )
    remediation = Remediation(
        summary="Require SMB signing on both the client and the server.",
        commands=[
            RemediationCommand(
                shell="powershell",
                command="Set-SmbClientConfiguration -RequireSecuritySignature $true -Force; Set-SmbServerConfiguration -RequireSecuritySignature $true -Force",
                requires_admin=True,
                reversible=True,
                risk_note="May reduce throughput slightly and can break very old SMBv1 devices.",
            )
        ],
        docs_url="https://learn.microsoft.com/windows-server/storage/file-server/smb-signing",
    )
    references = ["CIS Microsoft Windows 11 v3.0.0 2.3.9.2"]

    def gather(self, probes: ProbeContext) -> dict:
        return {
            "client": require_ok(probes.ps("smb_client_config"), "SMB client configuration"),
            "server": require_ok(probes.ps("smb_server_config"), "SMB server configuration"),
        }

    def evaluate(self, raw: dict) -> CheckOutcome:
        client = raw["client"] or {}
        server = raw["server"] or {}
        client_ok = bool(client.get("RequireSecuritySignature"))
        server_ok = bool(server.get("RequireSecuritySignature"))
        evidence = [
            {"label": "Client", "value": f"RequireSecuritySignature: {client_ok}"},
            {"label": "Server", "value": f"RequireSecuritySignature: {server_ok}"},
        ]
        if client_ok and server_ok:
            return CheckOutcome(status="pass", observed="RequireSecuritySignature = True on the SMB client and server", expected="RequireSecuritySignature = True", evidence=evidence)
        return CheckOutcome(
            status="fail",
            observed=f"RequireSecuritySignature = {client_ok} on the SMB client, {server_ok} on the SMB server",
            expected="RequireSecuritySignature = True",
            evidence=evidence,
        )


@register
class SmbGuestAuthDisabled(Check):
    id = "smb_guest_auth_disabled"
    category = "smb"
    title = "Insecure SMB guest authentication is disabled"
    severity = "high"
    score_weight = 7
    why_it_matters = (
        "Allowing insecure guest fallback lets the SMB client silently downgrade to an unauthenticated, "
        "unsigned session against a rogue or misconfigured server -- exactly the scenario the "
        "CVE-2019-1166 guest-auth hardening was built to close."
    )
    remediation = Remediation(
        summary="Disable insecure guest authentication for the SMB client.",
        commands=[
            RemediationCommand(
                shell="powershell",
                command="New-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters' -Name AllowInsecureGuestAuth -PropertyType DWord -Value 0 -Force",
                requires_admin=True,
                reversible=True,
                risk_note="Breaks connections to old NAS/router shares that only offer unauthenticated guest access.",
            )
        ],
        docs_url="https://learn.microsoft.com/troubleshoot/windows-client/networking/guest-access-in-smb2-disabled-by-default",
    )

    def gather(self, probes: ProbeContext) -> dict:
        return {"guest_auth": probes.registry("smb_guest_auth")}

    def evaluate(self, raw: dict) -> CheckOutcome:
        result = raw["guest_auth"]
        if not result.ok:
            # Missing value = not explicitly configured. Windows 10 1709+/11 default is disabled (0).
            evidence = [{"label": "AllowInsecureGuestAuth", "value": "not configured (registry value absent)"}]
            return CheckOutcome(
                status="pass",
                observed="AllowInsecureGuestAuth is not explicitly configured; current Windows default is disabled",
                expected="AllowInsecureGuestAuth = 0",
                evidence=evidence,
            )
        value = result.data
        evidence = [{"label": "AllowInsecureGuestAuth", "value": str(value)}]
        if value:
            return CheckOutcome(status="fail", observed=f"AllowInsecureGuestAuth = {value} (insecure guest fallback is permitted)", expected="AllowInsecureGuestAuth = 0", evidence=evidence)
        return CheckOutcome(status="pass", observed=f"AllowInsecureGuestAuth = {value}", expected="AllowInsecureGuestAuth = 0", evidence=evidence)


@register
class SmbSharesExposed(Check):
    id = "smb_shares_exposed"
    category = "smb"
    title = "No SMB shares grant Everyone/Guest broad access"
    severity = "high"
    score_weight = 7
    why_it_matters = (
        "A share that grants Everyone or Guest read or write access is reachable by any device on the "
        "network without credentials, including malware on a peer machine looking for a place to plant "
        "or exfiltrate files."
    )
    remediation = Remediation(
        summary="Remove Everyone/Guest access from shares and grant named accounts only the access they need.",
        commands=[
            RemediationCommand(
                shell="powershell",
                command="Get-SmbShare | Get-SmbShareAccess",
                requires_admin=False,
                reversible=True,
                risk_note="Listing only; use Revoke-SmbShareAccess / Grant-SmbShareAccess per share after reviewing which access is actually needed.",
            )
        ],
        docs_url="https://learn.microsoft.com/powershell/module/smbshare/revoke-smbshareaccess",
    )

    def gather(self, probes: ProbeContext) -> dict:
        return {"shares": require_ok(probes.ps("smb_shares"), "SMB share list", admin_hint=True)}

    def evaluate(self, raw: dict) -> CheckOutcome:
        shares = as_list(raw["shares"])
        flagged = []
        for share in shares:
            for acc in as_list(share.get("access")):
                account = str(acc.get("AccountName", "")).lower()
                right = acc.get("AccessRight")
                if account in ("everyone", "builtin\\guests", "guest", "guests") and str(right).lower() != "no access":
                    flagged.append(f"{share.get('name')} -> {acc.get('AccountName')} ({right})")
        evidence = [{"label": s.get("name", "?"), "value": s.get("path", "")} for s in shares[:10]]
        if flagged:
            return CheckOutcome(
                status="fail",
                observed=f"{len(flagged)} share ACE(s) grant Everyone/Guest access: {'; '.join(flagged[:5])}",
                expected="No non-default share grants Everyone or Guest read/write access",
                evidence=evidence,
            )
        return CheckOutcome(
            status="pass",
            observed=f"No Everyone/Guest access found across {len(shares)} non-default share(s)",
            expected="No non-default share grants Everyone or Guest read/write access",
            evidence=evidence,
        )
