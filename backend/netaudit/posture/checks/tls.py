"""tls: tls10_11_disabled, ssl3_disabled, weak_ciphers_disabled,
certificate_store_anomalies."""
from __future__ import annotations

from datetime import datetime, timezone

from ..base import Check, CheckOutcome, ProbeContext, as_list, require_ok
from ..models import Remediation, RemediationCommand
from ..registry import register

_WEAK_CIPHER_MARKERS = ("RC4", "DES", "NULL", "MD5", "EXPORT")


def _schannel_protocol_state(client, server) -> tuple[bool, bool]:
    """Returns (client_disabled, server_disabled). A missing key means "not
    explicitly configured" -- Windows 11's OS default for TLS 1.0/1.1/SSL3
    is disabled at the negotiation level for most callers, but that default
    isn't visible in the registry, so we report it as unconfigured rather
    than assuming either way."""
    def _disabled(result) -> "bool | None":
        if not result.ok or not isinstance(result.data, dict) or not result.data:
            return None
        values = {k.lower(): v for k, v in result.data.items()}
        if values.get("disabledbydefault") == 1 and values.get("enabled", 1) == 0:
            return True
        if values.get("enabled") == 0:
            return True
        if values.get("enabled") == 1:
            return False
        return None

    return _disabled(client), _disabled(server)


@register
class Tls1011Disabled(Check):
    id = "tls10_11_disabled"
    category = "tls"
    title = "TLS 1.0 and 1.1 are disabled"
    severity = "high"
    score_weight = 7
    why_it_matters = (
        "TLS 1.0/1.1 lack modern AEAD ciphers and have known weaknesses (BEAST, POODLE-adjacent padding "
        "issues); PCI-DSS has required disabling them for years. Leaving them enabled lets a "
        "man-in-the-middle force a downgrade on outbound connections this machine makes as a client, or "
        "lets an old client negotiate a weaker session against anything this machine serves."
    )
    remediation = Remediation(
        summary="Explicitly disable TLS 1.0 and 1.1 for both the client and server SCHANNEL roles.",
        commands=[
            RemediationCommand(
                shell="powershell",
                command="foreach ($p in 'TLS 1.0','TLS 1.1') { foreach ($r in 'Client','Server') { $k = \"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\$p\\$r\"; New-Item -Path $k -Force | Out-Null; Set-ItemProperty -Path $k -Name Enabled -Value 0 -Type DWord; Set-ItemProperty -Path $k -Name DisabledByDefault -Value 1 -Type DWord } }",
                requires_admin=True,
                reversible=True,
                risk_note="Breaks TLS to any legacy server or client that cannot negotiate TLS 1.2+ (rare in 2026, but some embedded/IoT management interfaces still only speak TLS 1.0).",
            )
        ],
        docs_url="https://learn.microsoft.com/windows-server/security/tls/tls-registry-settings",
    )

    def gather(self, probes: ProbeContext) -> dict:
        return {
            "client10": probes.registry("schannel_tls10_client"),
            "server10": probes.registry("schannel_tls10_server"),
            "client11": probes.registry("schannel_tls11_client"),
            "server11": probes.registry("schannel_tls11_server"),
        }

    def evaluate(self, raw: dict) -> CheckOutcome:
        c10, s10 = _schannel_protocol_state(raw["client10"], raw["server10"])
        c11, s11 = _schannel_protocol_state(raw["client11"], raw["server11"])
        evidence = [
            {"label": "TLS 1.0 Client", "value": "not configured" if c10 is None else str(c10)},
            {"label": "TLS 1.0 Server", "value": "not configured" if s10 is None else str(s10)},
            {"label": "TLS 1.1 Client", "value": "not configured" if c11 is None else str(c11)},
            {"label": "TLS 1.1 Server", "value": "not configured" if s11 is None else str(s11)},
        ]
        states = [c10, s10, c11, s11]
        if all(s is True for s in states):
            return CheckOutcome(status="pass", observed="TLS 1.0 and 1.1 are explicitly disabled for client and server", expected="Enabled=0, DisabledByDefault=1 for TLS 1.0 and 1.1, client and server", evidence=evidence)
        if any(s is False for s in states):
            return CheckOutcome(status="fail", observed="TLS 1.0 and/or 1.1 is explicitly enabled", expected="Enabled=0, DisabledByDefault=1 for TLS 1.0 and 1.1, client and server", evidence=evidence)
        return CheckOutcome(status="warn", observed="TLS 1.0/1.1 are not explicitly configured (relying on OS default, not verifiable from the registry)", expected="Enabled=0, DisabledByDefault=1 for TLS 1.0 and 1.1, client and server", evidence=evidence)


@register
class Ssl3Disabled(Check):
    id = "ssl3_disabled"
    category = "tls"
    title = "SSL 3.0 is disabled"
    severity = "critical"
    score_weight = 8
    why_it_matters = (
        "SSL 3.0 is broken by the POODLE padding-oracle attack, which lets an attacker who can intercept "
        "traffic decrypt it byte-by-byte. There is no legitimate reason to keep it negotiable in 2026."
    )
    remediation = Remediation(
        summary="Explicitly disable SSL 3.0 for both client and server SCHANNEL roles.",
        commands=[
            RemediationCommand(
                shell="powershell",
                command="foreach ($r in 'Client','Server') { $k = \"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\SSL 3.0\\$r\"; New-Item -Path $k -Force | Out-Null; Set-ItemProperty -Path $k -Name Enabled -Value 0 -Type DWord; Set-ItemProperty -Path $k -Name DisabledByDefault -Value 1 -Type DWord }",
                requires_admin=True,
                reversible=True,
                risk_note="None expected; nothing legitimate should still require SSL 3.0.",
            )
        ],
        docs_url="https://learn.microsoft.com/windows-server/security/tls/tls-registry-settings",
    )

    def gather(self, probes: ProbeContext) -> dict:
        return {"client": probes.registry("schannel_ssl3_client"), "server": probes.registry("schannel_ssl3_server")}

    def evaluate(self, raw: dict) -> CheckOutcome:
        client_disabled, server_disabled = _schannel_protocol_state(raw["client"], raw["server"])
        evidence = [
            {"label": "SSL 3.0 Client", "value": "not configured" if client_disabled is None else str(client_disabled)},
            {"label": "SSL 3.0 Server", "value": "not configured" if server_disabled is None else str(server_disabled)},
        ]
        if client_disabled is True and server_disabled is True:
            return CheckOutcome(status="pass", observed="SSL 3.0 is explicitly disabled for client and server", expected="Enabled=0, DisabledByDefault=1 for SSL 3.0, client and server", evidence=evidence)
        if client_disabled is False or server_disabled is False:
            return CheckOutcome(status="fail", observed="SSL 3.0 is explicitly enabled", expected="Enabled=0, DisabledByDefault=1 for SSL 3.0, client and server", evidence=evidence)
        return CheckOutcome(status="warn", observed="SSL 3.0 is not explicitly configured (relying on OS default, not verifiable from the registry)", expected="Enabled=0, DisabledByDefault=1 for SSL 3.0, client and server", evidence=evidence)


@register
class WeakCiphersDisabled(Check):
    id = "weak_ciphers_disabled"
    category = "tls"
    title = "No weak cipher suites are enabled"
    severity = "high"
    score_weight = 6
    why_it_matters = (
        "RC4 has known keystream biases, DES/3DES are trivially brute-forced or fall to Sweet32, and "
        "NULL ciphers provide no encryption at all. If any of these remain in the enabled cipher suite "
        "list, a downgrade attack can force a connection to use one of them."
    )
    remediation = Remediation(
        summary="Remove weak cipher suites from the enabled list.",
        commands=[
            RemediationCommand(
                shell="powershell",
                command="Get-TlsCipherSuite | Where-Object Name -match 'RC4|DES|NULL|MD5' | ForEach-Object { Disable-TlsCipherSuite -Name $_.Name }",
                requires_admin=True,
                reversible=True,
                risk_note="Any legacy peer that only supports these ciphers will fail to connect afterward.",
            )
        ],
        docs_url="https://learn.microsoft.com/powershell/module/tls/disable-tlsciphersuite",
    )

    def gather(self, probes: ProbeContext) -> dict:
        return {"ciphers": require_ok(probes.ps("tls_cipher_suites"), "enabled TLS cipher suites")}

    def evaluate(self, raw: dict) -> CheckOutcome:
        ciphers = as_list(raw["ciphers"])
        # `Name` can be present with a JSON null, not just absent -- `or ""`
        # covers both, where `.get("Name", "")` alone only covers the latter.
        names = [c.get("Name") or "" for c in ciphers]
        weak = [n for n in names if n and any(marker in n.upper() for marker in _WEAK_CIPHER_MARKERS)]
        evidence = [{"label": "Weak suite", "value": n} for n in weak[:10]]
        if weak:
            return CheckOutcome(status="fail", observed=f"{len(weak)} weak cipher suite(s) enabled: {', '.join(weak[:5])}", expected="No enabled cipher suite contains RC4, DES, NULL, MD5, or EXPORT", evidence=evidence)
        return CheckOutcome(status="pass", observed=f"No weak cipher suites found among {len(names)} enabled suite(s)", expected="No enabled cipher suite contains RC4, DES, NULL, MD5, or EXPORT", evidence=evidence)


@register
class CertificateStoreAnomalies(Check):
    id = "certificate_store_anomalies"
    category = "tls"
    title = "No expired certificates remain trusted as roots"
    severity = "medium"
    score_weight = 4
    why_it_matters = (
        "A trusted root certificate past its expiry date is a sign the store hasn't been maintained -- "
        "and any certificate chain still validating against it (some validators don't strictly enforce "
        "root expiry) is trust that should have lapsed but hasn't."
    )
    remediation = Remediation(
        summary="Remove expired root certificates that are no longer needed from the Trusted Root store.",
        commands=[
            RemediationCommand(
                shell="powershell",
                command="Get-ChildItem Cert:\\LocalMachine\\Root | Where-Object { $_.NotAfter -lt (Get-Date) }",
                requires_admin=False,
                reversible=True,
                risk_note="Listing only; removing a root certificate that something still depends on (an old internal CA, an offline device's management console) can break trust for that specific use.",
            )
        ],
        docs_url="https://learn.microsoft.com/powershell/module/pkiclient/remove-item",
    )

    def gather(self, probes: ProbeContext) -> dict:
        return {"certs": require_ok(probes.ps("cert_store_root"), "Local Machine Trusted Root certificate store")}

    def evaluate(self, raw: dict) -> CheckOutcome:
        certs = as_list(raw["certs"])
        now = datetime.now(timezone.utc)
        expired = []
        for cert in certs:
            not_after = cert.get("NotAfter")
            if not not_after:
                continue
            parsed = _parse_dotnet_date(not_after)
            if parsed and parsed < now:
                expired.append(cert)
        evidence = [{"label": c.get("Subject", "?")[:60], "value": f"NotAfter: {c.get('NotAfter')}"} for c in expired[:10]]
        if expired:
            return CheckOutcome(status="warn", observed=f"{len(expired)} of {len(certs)} trusted root certificate(s) are expired", expected="No expired certificate remains in the Trusted Root store", evidence=evidence)
        return CheckOutcome(status="pass", observed=f"No expired certificates among {len(certs)} trusted root certificate(s)", expected="No expired certificate remains in the Trusted Root store", evidence=evidence)


def _parse_dotnet_date(value: str):
    """`ConvertTo-Json` renders [datetime] as either an ISO string or the
    legacy `/Date(ms)/` form depending on PowerShell version. Handle both,
    returning None on anything unparseable rather than raising."""
    if not isinstance(value, str):
        return None
    value = value.strip()
    if value.startswith("/Date(") and value.endswith(")/"):
        try:
            millis = int(value[6:-2].split("+")[0].split("-")[0])
            return datetime.fromtimestamp(millis / 1000, tz=timezone.utc)
        except (ValueError, IndexError):
            return None
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S"):
        try:
            parsed = datetime.strptime(value, fmt)
            return parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None
