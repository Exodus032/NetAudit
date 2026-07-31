"""updates_and_defense: defender_realtime_enabled, defender_signatures_current,
windows_update_current, uac_enabled, bitlocker_status."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from ..base import Check, CheckOutcome, ProbeContext, as_list, require_ok
from ..models import Remediation, RemediationCommand
from ..registry import register

_SIGNATURE_MAX_AGE_DAYS = 7
_UPDATE_MAX_AGE_DAYS = 45


@register
class DefenderRealtimeEnabled(Check):
    id = "defender_realtime_enabled"
    category = "updates_and_defense"
    title = "Microsoft Defender real-time protection is enabled"
    severity = "critical"
    score_weight = 10
    why_it_matters = (
        "Real-time protection is what catches malware at write/execute time, before it can act. With it "
        "off, this machine only gets scanned on whatever schedule you remember to run manually -- most "
        "malware infections would be caught in the seconds it's off, not found later."
    )
    remediation = Remediation(
        summary="Turn Microsoft Defender real-time protection back on.",
        commands=[
            RemediationCommand(
                shell="powershell",
                command="Set-MpPreference -DisableRealtimeMonitoring $false",
                requires_admin=True,
                reversible=True,
                risk_note="If another antivirus product is installed and active, Windows may keep Defender's real-time engine off by design to avoid conflicts -- check for a third-party AV before assuming this is a misconfiguration.",
            )
        ],
        docs_url="https://learn.microsoft.com/microsoft-365/security/defender-endpoint/configure-real-time-protection-microsoft-defender-antivirus",
    )

    def gather(self, probes: ProbeContext) -> dict:
        return {"status": require_ok(probes.ps("defender_status"), "Microsoft Defender status", admin_hint=True)}

    def evaluate(self, raw: dict) -> CheckOutcome:
        status = raw["status"] or {}
        enabled = status.get("RealTimeProtectionEnabled")
        evidence = [{"label": "RealTimeProtectionEnabled", "value": str(enabled)}, {"label": "AntivirusEnabled", "value": str(status.get("AntivirusEnabled"))}]
        if enabled is True:
            return CheckOutcome(status="pass", observed="RealTimeProtectionEnabled = True", expected="RealTimeProtectionEnabled = True", evidence=evidence)
        return CheckOutcome(status="fail", observed=f"RealTimeProtectionEnabled = {enabled}", expected="RealTimeProtectionEnabled = True", evidence=evidence)


@register
class DefenderSignaturesCurrent(Check):
    id = "defender_signatures_current"
    category = "updates_and_defense"
    title = "Defender signatures are current"
    severity = "high"
    score_weight = 6
    why_it_matters = (
        "Signature-based detection is only as good as its last update. Signatures more than a week old "
        "miss every threat catalogued since then -- an antivirus running on stale signatures gives a "
        "false sense of protection."
    )
    remediation = Remediation(
        summary="Update Defender's signatures.",
        commands=[
            RemediationCommand(
                shell="powershell",
                command="Update-MpSignature",
                requires_admin=True,
                reversible=True,
                risk_note="Requires outbound internet access to Microsoft's update servers; none otherwise.",
            )
        ],
        docs_url="https://learn.microsoft.com/powershell/module/defender/update-mpsignature",
    )

    def gather(self, probes: ProbeContext) -> dict:
        return {"status": require_ok(probes.ps("defender_status"), "Microsoft Defender status", admin_hint=True)}

    def evaluate(self, raw: dict) -> CheckOutcome:
        status = raw["status"] or {}
        av_age = status.get("AntivirusSignatureAge")
        as_age = status.get("AntispywareSignatureAge")
        evidence = [{"label": "AntivirusSignatureAge (days)", "value": str(av_age)}, {"label": "AntispywareSignatureAge (days)", "value": str(as_age)}]
        ages = [a for a in (av_age, as_age) if isinstance(a, (int, float))]
        if not ages:
            return CheckOutcome(status="error", observed="Defender did not report a signature age", evidence=evidence)
        if max(ages) > _SIGNATURE_MAX_AGE_DAYS:
            return CheckOutcome(status="fail", observed=f"Signatures are {max(ages)} day(s) old", expected=f"Signature age <= {_SIGNATURE_MAX_AGE_DAYS} days", evidence=evidence)
        return CheckOutcome(status="pass", observed=f"Signatures are {max(ages)} day(s) old", expected=f"Signature age <= {_SIGNATURE_MAX_AGE_DAYS} days", evidence=evidence)


@register
class WindowsUpdateCurrent(Check):
    id = "windows_update_current"
    category = "updates_and_defense"
    title = "Windows Update has installed updates recently"
    severity = "high"
    score_weight = 6
    why_it_matters = (
        "Patch age is a direct measure of exposure to every publicly disclosed vulnerability fixed since "
        "the last successful update -- attackers routinely weaponize patched CVEs within days of the "
        "patch Tuesday disclosure, targeting exactly the machines that haven't updated yet."
    )
    remediation = Remediation(
        summary="Install pending Windows updates.",
        commands=[
            RemediationCommand(
                shell="powershell",
                command="Get-WindowsUpdate -Install -AcceptAll -AutoReboot",
                requires_admin=True,
                reversible=False,
                risk_note="Requires the PSWindowsUpdate module; installing updates can require a reboot and, rarely, can introduce a regression that needs to be rolled back.",
            )
        ],
        docs_url="https://learn.microsoft.com/windows/deployment/update/",
    )

    def gather(self, probes: ProbeContext) -> dict:
        return {"last_success": probes.registry("windows_update_last_success")}

    def evaluate(self, raw: dict) -> CheckOutcome:
        result = raw["last_success"]
        if not result.ok:
            return CheckOutcome(status="error", observed=f"could not determine last successful Windows Update install time: {result.error}")
        raw_value = result.data
        parsed = _parse_update_timestamp(raw_value)
        evidence = [{"label": "LastSuccessTime", "value": str(raw_value)}]
        if parsed is None:
            return CheckOutcome(status="error", observed=f"could not parse last update timestamp: {raw_value!r}", evidence=evidence)
        age_days = (datetime.now(timezone.utc) - parsed).days
        evidence.append({"label": "Age (days)", "value": str(age_days)})
        if age_days > _UPDATE_MAX_AGE_DAYS:
            return CheckOutcome(status="fail", observed=f"Last successful update was {age_days} day(s) ago ({raw_value})", expected=f"Last update <= {_UPDATE_MAX_AGE_DAYS} days ago", evidence=evidence)
        return CheckOutcome(status="pass", observed=f"Last successful update was {age_days} day(s) ago ({raw_value})", expected=f"Last update <= {_UPDATE_MAX_AGE_DAYS} days ago", evidence=evidence)


def _parse_update_timestamp(value):
    if not isinstance(value, str) or not value.strip():
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%m/%d/%Y %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(value.strip(), fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


@register
class UacEnabled(Check):
    id = "uac_enabled"
    category = "updates_and_defense"
    title = "User Account Control is enabled"
    severity = "critical"
    score_weight = 8
    why_it_matters = (
        "UAC is the boundary between a standard user token and an elevated administrator token. With it "
        "off, every process a logged-in administrator runs -- including malware that tricks the user "
        "into launching it -- runs fully elevated with no prompt."
    )
    remediation = Remediation(
        summary="Re-enable UAC.",
        commands=[
            RemediationCommand(
                shell="powershell",
                command="Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableLUA -Value 1",
                requires_admin=True,
                reversible=True,
                risk_note="Requires a reboot to take effect; some legacy applications written before UAC existed may start prompting or misbehaving once it's back on.",
            )
        ],
        docs_url="https://learn.microsoft.com/windows/security/application-security/application-control/user-account-control/",
    )

    def gather(self, probes: ProbeContext) -> dict:
        return {"settings": require_ok(probes.registry("uac_settings"), "UAC policy settings")}

    def evaluate(self, raw: dict) -> CheckOutcome:
        settings = raw["settings"] or {}
        enable_lua = settings.get("EnableLUA")
        consent_prompt = settings.get("ConsentPromptBehaviorAdmin")
        evidence = [{"label": "EnableLUA", "value": str(enable_lua)}, {"label": "ConsentPromptBehaviorAdmin", "value": str(consent_prompt)}]
        if enable_lua == 1:
            return CheckOutcome(status="pass", observed="EnableLUA = 1 (UAC is enabled)", expected="EnableLUA = 1", evidence=evidence)
        return CheckOutcome(status="fail", observed=f"EnableLUA = {enable_lua} (UAC is disabled)", expected="EnableLUA = 1", evidence=evidence)


@register
class BitlockerStatus(Check):
    id = "bitlocker_status"
    category = "updates_and_defense"
    title = "The system drive is BitLocker-protected"
    severity = "high"
    score_weight = 7
    why_it_matters = (
        "Without disk encryption, anyone with physical access to this machine can remove the drive, "
        "mount it on another computer, and read every file on it -- including cached credentials and "
        "browser data -- with no need to log in at all."
    )
    remediation = Remediation(
        summary="Enable BitLocker on the system drive.",
        commands=[
            RemediationCommand(
                shell="powershell",
                command="Enable-BitLocker -MountPoint C: -EncryptionMethod XtsAes256 -UsedSpaceOnly -RecoveryPasswordProtector",
                requires_admin=True,
                reversible=True,
                risk_note="Save the recovery key somewhere safe before enabling -- losing both the unlock method and the recovery key makes the drive's data permanently unrecoverable. Requires a TPM or a USB key on some editions, and Windows 11 Home does not include BitLocker (only Device Encryption, which has narrower hardware requirements).",
            )
        ],
        docs_url="https://learn.microsoft.com/windows/security/operating-system-security/data-protection/bitlocker/",
    )

    def gather(self, probes: ProbeContext) -> dict:
        # The BitLocker WMI provider is measurably slower than a plain
        # Get-* cmdlet; give it more room than the 5s default before
        # concluding it's actually inaccessible rather than just slow.
        return {
            "volumes": require_ok(probes.ps("bitlocker_status", timeout=15.0), "BitLocker volume status", admin_hint=True),
            "is_admin": probes.is_admin(),
        }

    def evaluate(self, raw: dict) -> CheckOutcome:
        volumes = as_list(raw["volumes"])
        system_volumes = [v for v in volumes if v.get("VolumeType") == "OperatingSystem"] or volumes[:1]
        if not system_volumes:
            if not raw.get("is_admin"):
                return CheckOutcome(
                    status="error",
                    observed="Get-BitLockerVolume returned no volumes while not running elevated -- this cmdlet is unreliable without administrator rights on some Windows editions; re-run NetAudit as Administrator to confirm",
                )
            return CheckOutcome(status="error", observed="Get-BitLockerVolume returned no volumes (this edition of Windows may not support BitLocker)")
        evidence = [{"label": v.get("MountPoint", "?"), "value": f"ProtectionStatus: {v.get('ProtectionStatus')}, Encryption: {v.get('EncryptionPercentage')}%"} for v in system_volumes]
        unprotected = [v for v in system_volumes if v.get("ProtectionStatus") != "On"]
        if unprotected:
            return CheckOutcome(status="fail", observed=f"System volume protection status: {unprotected[0].get('ProtectionStatus')}", expected="ProtectionStatus = On for the system volume", evidence=evidence)
        return CheckOutcome(status="pass", observed="System volume ProtectionStatus = On", expected="ProtectionStatus = On for the system volume", evidence=evidence)
