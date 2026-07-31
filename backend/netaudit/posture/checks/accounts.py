"""accounts: guest_account_disabled, local_admin_count, blank_passwords,
autologon_disabled."""
from __future__ import annotations

from ..base import Check, CheckOutcome, ProbeContext, as_list, require_ok
from ..models import Remediation, RemediationCommand
from ..registry import register

_MAX_EXPECTED_ADMINS = 2


@register
class GuestAccountDisabled(Check):
    id = "guest_account_disabled"
    category = "accounts"
    title = "The built-in Guest account is disabled"
    severity = "high"
    score_weight = 6
    why_it_matters = (
        "The Guest account is a well-known, unauthenticated (or trivially-authenticated) local account "
        "name that attackers try first. Left enabled, it's a free foothold for anything on the network "
        "that can reach an SMB or logon surface on this machine."
    )
    remediation = Remediation(
        summary="Disable the Guest account.",
        commands=[
            RemediationCommand(
                shell="powershell",
                command="Disable-LocalUser -Name Guest",
                requires_admin=True,
                reversible=True,
                risk_note="None expected; the Guest account has no legitimate use on a personally administered machine.",
            )
        ],
        docs_url="https://learn.microsoft.com/powershell/module/microsoft.powershell.localaccounts/disable-localuser",
    )

    def gather(self, probes: ProbeContext) -> dict:
        return {"users": require_ok(probes.ps("local_users"), "local user accounts")}

    def evaluate(self, raw: dict) -> CheckOutcome:
        users = as_list(raw["users"])
        guest = next((u for u in users if str(u.get("Name", "")).lower() == "guest"), None)
        if guest is None:
            return CheckOutcome(status="skipped", observed="No account named 'Guest' was found", expected="Guest account is Enabled = False, or absent")
        enabled = bool(guest.get("Enabled"))
        evidence = [{"label": "Guest", "value": f"Enabled: {enabled}"}]
        if enabled:
            return CheckOutcome(status="fail", observed="Guest account is enabled", expected="Enabled = False", evidence=evidence)
        return CheckOutcome(status="pass", observed="Guest account is disabled", expected="Enabled = False", evidence=evidence)


@register
class LocalAdminCount(Check):
    id = "local_admin_count"
    category = "accounts"
    title = "The local Administrators group has a small, expected membership"
    severity = "medium"
    score_weight = 4
    why_it_matters = (
        "Every account in the Administrators group is a full compromise of this machine if that "
        "account's credentials leak -- each additional admin (forgotten service account, an old "
        "installer-created account) is another way in that gets easier to lose track of over time."
    )
    remediation = Remediation(
        summary="Remove accounts from Administrators that don't need standing admin rights.",
        commands=[
            RemediationCommand(
                shell="powershell",
                command="Get-LocalGroupMember -Group Administrators",
                requires_admin=False,
                reversible=True,
                risk_note="Listing only; use Remove-LocalGroupMember per account after confirming it doesn't need admin rights.",
            )
        ],
        docs_url="https://learn.microsoft.com/powershell/module/microsoft.powershell.localaccounts/remove-localgroupmember",
    )

    def gather(self, probes: ProbeContext) -> dict:
        return {"admins": require_ok(probes.ps("local_admins"), "local Administrators group membership")}

    def evaluate(self, raw: dict) -> CheckOutcome:
        admins = as_list(raw["admins"])
        evidence = [{"label": a.get("Name", "?"), "value": str(a.get("ObjectClass"))} for a in admins]
        if len(admins) > _MAX_EXPECTED_ADMINS:
            names = ", ".join(a.get("Name", "?") for a in admins)
            return CheckOutcome(status="warn", observed=f"{len(admins)} accounts are in Administrators: {names}", expected=f"<= {_MAX_EXPECTED_ADMINS} accounts in Administrators", evidence=evidence)
        return CheckOutcome(status="pass", observed=f"{len(admins)} account(s) in Administrators", expected=f"<= {_MAX_EXPECTED_ADMINS} accounts in Administrators", evidence=evidence)


@register
class BlankPasswords(Check):
    id = "blank_passwords"
    category = "accounts"
    title = "No local account allows a blank password"
    severity = "critical"
    score_weight = 9
    why_it_matters = (
        "An account with PasswordRequired = False can be logged into (locally, over RDP if enabled, or "
        "via SMB) with no password at all -- it's the same exposure as a leaked credential, except "
        "nothing needed to leak."
    )
    remediation = Remediation(
        summary="Require a password for every enabled local account.",
        commands=[
            RemediationCommand(
                shell="powershell",
                command="Get-LocalUser | Where-Object { -not $_.PasswordRequired } | Set-LocalUser -PasswordNeverExpires $false",
                requires_admin=True,
                reversible=True,
                risk_note="Setting PasswordRequired needs `net user <name> *` or the Local Users and Groups console to actually set a password interactively; a locked-out account with no password set could become unusable until a password is assigned.",
            )
        ],
        docs_url="https://learn.microsoft.com/powershell/module/microsoft.powershell.localaccounts/set-localuser",
    )

    def gather(self, probes: ProbeContext) -> dict:
        return {"users": require_ok(probes.ps("local_users"), "local user accounts")}

    def evaluate(self, raw: dict) -> CheckOutcome:
        users = as_list(raw["users"])
        enabled_users = [u for u in users if u.get("Enabled")]
        blank_allowed = [u for u in enabled_users if u.get("PasswordRequired") is False]
        evidence = [{"label": u.get("Name", "?"), "value": "PasswordRequired: False"} for u in blank_allowed]
        if blank_allowed:
            names = ", ".join(u.get("Name", "?") for u in blank_allowed)
            return CheckOutcome(status="fail", observed=f"{len(blank_allowed)} enabled account(s) allow a blank password: {names}", expected="PasswordRequired = True for every enabled account", evidence=evidence)
        return CheckOutcome(status="pass", observed=f"All {len(enabled_users)} enabled account(s) require a password", expected="PasswordRequired = True for every enabled account", evidence=evidence)


@register
class AutologonDisabled(Check):
    id = "autologon_disabled"
    category = "accounts"
    title = "Automatic logon is disabled"
    severity = "critical"
    score_weight = 8
    why_it_matters = (
        "Automatic logon skips the login prompt entirely -- anyone who can power on or restart this "
        "machine gets a fully logged-in session with no credentials. If it's configured with a stored "
        "password (DefaultPassword), that password sits in the registry in plaintext, readable by any "
        "process or account that can read HKLM."
    )
    remediation = Remediation(
        summary="Disable automatic logon and clear any stored plaintext password.",
        commands=[
            RemediationCommand(
                shell="powershell",
                command="Remove-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -Name DefaultPassword -ErrorAction SilentlyContinue; Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -Name AutoAdminLogon -Value '0'",
                requires_admin=True,
                reversible=True,
                risk_note="You will need to enter your password at every boot going forward -- that is the point, but it's a workflow change if you were relying on unattended reboots.",
            )
        ],
        docs_url="https://learn.microsoft.com/troubleshoot/windows-server/user-profiles-and-logon/turn-on-automatic-logon",
    )

    def gather(self, probes: ProbeContext) -> dict:
        return {"settings": require_ok(probes.registry("autologon_settings"), "Winlogon settings")}

    def evaluate(self, raw: dict) -> CheckOutcome:
        settings = raw["settings"] or {}
        auto_admin_logon = str(settings.get("AutoAdminLogon", "0"))
        has_default_password = bool(settings.get("DefaultPassword"))
        evidence = [
            {"label": "AutoAdminLogon", "value": auto_admin_logon},
            {"label": "DefaultPassword stored", "value": str(has_default_password)},
        ]
        if auto_admin_logon == "1" and has_default_password:
            return CheckOutcome(status="fail", observed="Automatic logon is enabled with a plaintext password stored in the registry", expected="AutoAdminLogon = 0, no DefaultPassword value", evidence=evidence)
        if auto_admin_logon == "1":
            return CheckOutcome(status="fail", observed="Automatic logon is enabled", expected="AutoAdminLogon = 0, no DefaultPassword value", evidence=evidence)
        return CheckOutcome(status="pass", observed="Automatic logon is disabled", expected="AutoAdminLogon = 0, no DefaultPassword value", evidence=evidence)
