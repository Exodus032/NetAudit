"""suspicious_tls: works from handshake metadata that may not always be
present (self-signed/expired cert flags, TLS version, SNI, ALPN, JA3).
Per the detection-quality spec, this must skip cleanly rather than crash
or guess when the capture layer didn't parse a handshake -- a packet with
every tls_* field None is simply not evaluated."""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime

from ..mitre import mitre_ref
from ..models import Action, Evidence, Indicator, TunableSpec
from ..source import PacketRecord, TrafficSource
from .base import Detector, Finding

WEAK_VERSIONS = {"SSLv3", "TLSv1.0", "TLSv1.1"}
COMMON_ALPN = {"h2", "http/1.1", "http/1.0", "spdy/3.1", ""}


def _has_tls_metadata(p: PacketRecord) -> bool:
    return p.tls_version is not None or p.tls_cert_self_signed is not None or p.tls_cert_expired is not None


class SuspiciousTlsDetector(Detector):
    id = "suspicious_tls"
    label = "Suspicious TLS"
    category = "anomaly"
    description = "Self-signed or expired certs, TLS < 1.2, unusual SNI/ALPN, or a JA3 on the watchlist."
    default_severity = "medium"
    mitre = [mitre_ref("TA0005", "T1573")]
    tunables = [
        TunableSpec(key="min_score", value=0.3, type="float", min=0.1, max=1.0,
                    description="Minimum accumulated suspicion score (weak version/self-signed/expired/missing SNI/unusual ALPN/watchlisted JA3) to fire."),
        TunableSpec(key="ja3_watchlist", value="", type="str", min=None, max=None,
                    description="Comma-separated JA3 hashes to treat as watchlisted. Empty by default -- no JA3 hashes are bundled (see README); supply your own."),
    ]

    def run(self, source: TrafficSource, since: datetime, until: datetime, tunables: dict) -> list[Finding]:
        min_score = float(tunables["min_score"])
        watchlist = {h.strip() for h in str(tunables.get("ja3_watchlist", "")).split(",") if h.strip()}

        by_peer: dict[tuple, list[PacketRecord]] = defaultdict(list)
        for p in source.packets(since, until):
            if p.direction != "outbound" or p.dst_port is None or not _has_tls_metadata(p):
                continue
            by_peer[(p.dst_addr, p.dst_port)].append(p)

        findings: list[Finding] = []
        for (peer, port), pkts in by_peer.items():
            reasons: list[str] = []
            score = 0.0

            versions = {p.tls_version for p in pkts if p.tls_version}
            weak = versions & WEAK_VERSIONS
            if weak:
                score += 0.4
                reasons.append(f"weak TLS version(s) negotiated: {', '.join(sorted(weak))}")

            if any(p.tls_cert_self_signed for p in pkts):
                score += 0.3
                reasons.append("self-signed certificate")

            if any(p.tls_cert_expired for p in pkts):
                score += 0.3
                reasons.append("expired certificate")

            sni_present = [p.tls_sni for p in pkts if p.tls_sni is not None]
            if sni_present and all(not s for s in sni_present):
                score += 0.15
                reasons.append("SNI omitted despite TLS in use")

            alpn_values = {p.tls_alpn for p in pkts if p.tls_alpn}
            unusual_alpn = alpn_values - COMMON_ALPN
            if unusual_alpn:
                score += 0.15
                reasons.append(f"unusual ALPN value(s): {', '.join(sorted(unusual_alpn))}")

            watchlisted_ja3 = {p.tls_ja3 for p in pkts if p.tls_ja3 and p.tls_ja3 in watchlist}
            if watchlisted_ja3:
                score += 0.4
                reasons.append(f"JA3 on watchlist: {', '.join(sorted(watchlisted_ja3))}")

            if score < min_score:
                continue

            severity = "high" if score >= 0.7 else ("medium" if score >= 0.4 else "low")
            confidence = round(min(0.95, 0.4 + score * 0.5), 2)
            process = next((p.process_name for p in pkts if p.process_name), "unknown")

            findings.append(Finding(
                key=f"tls|{peer}:{port}",
                title=f"Suspicious TLS to {peer}:{port}",
                severity=severity,
                confidence=confidence,
                summary=f"TLS to {peer}:{port} showed: {'; '.join(reasons)}.",
                detail=(
                    f"{len(pkts)} TLS packet(s) between {process} and {peer}:{port} showed: {'; '.join(reasons)}. "
                    f"Each of these individually has legitimate explanations, but together they add up to a "
                    f"suspicion score of {score:.2f}. Weak protocol versions and bad certificates both remove "
                    f"the guarantees TLS is supposed to provide (confidentiality/integrity, and confirming who "
                    f"you're actually talking to), which is why they matter even on traffic that is nominally "
                    f"'encrypted'."
                ),
                observed_at=max(p.ts for p in pkts),
                evidence=[Evidence(label="Peer", value=f"{peer}:{port}"), Evidence(label="Process", value=process)] +
                         [Evidence(label="Finding", value=r) for r in reasons],
                indicators=[Indicator(type="ip", value=peer, context="suspicious TLS peer")] +
                           ([Indicator(type="ja3", value=j, context="watchlisted JA3") for j in watchlisted_ja3]),
                metrics={"score": round(score, 3), "packets": len(pkts)},
                related_log_ids=[p.id for p in pkts],
                occurrence_count=len(pkts),
                false_positive_notes=(
                    "Self-signed certs are routine for internal devices (routers, printers, home lab services, "
                    "IoT admin UIs) and for local development. Old TLS versions sometimes remain in use for "
                    "legacy device compatibility. This detector reports what it can measure from handshake "
                    "metadata; it never guesses when that metadata is absent from the capture."
                ),
                recommended_actions=[
                    Action(label="Check what this certificate actually is", kind="manual",
                           detail=f"Open https://{peer}:{port} in a browser or use openssl s_client to inspect the certificate chain directly."),
                    Action(label="Identify the process", kind="command", shell="powershell",
                           command=f"Get-Process | Where-Object {{ $_.ProcessName -eq '{process.replace('.exe', '')}' }} | Select-Object Id,ProcessName,Path",
                           requires_admin=False, detail="Confirm what this process is before blocking anything."),
                ],
            ))
        return findings
