"""dns_tunneling and dga_domains: both work off the DNS query stream and
share a small bundled allowlist of common CDN/telemetry parent domains that
legitimately produce high-volume, high-entropy-looking subdomains (content
hashes, cache-buster tokens, per-session ids) so they don't get flagged."""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime

from ..mitre import mitre_ref
from ..models import Action, Evidence, Indicator, TunableSpec
from ..source import DnsRecord, TrafficSource
from ..stats import digit_ratio, longest_consonant_run, mean, shannon_entropy
from .base import Detector, Finding

# Parent domains that legitimately generate high query volume with
# unusual-looking subdomains (CDN edge nodes, telemetry beacons, cache
# busting). Kept short and reviewed periodically -- see threat/README.md.
ALLOWLISTED_PARENTS = frozenset({
    "akamaiedge.net", "akamaitechnologies.com", "edgesuite.net", "edgekey.net",
    "cloudfront.net", "amazonaws.com", "fastly.net", "cloudflare.com", "cloudflare.net",
    "googleusercontent.com", "gstatic.com", "googlevideo.com", "google.com",
    "windowsupdate.com", "microsoft.com", "office.com", "live.com", "msftconnecttest.com",
    "apple.com", "icloud.com", "doubleclick.net", "1e100.net",
})


def registrable_domain(query: str) -> str:
    """Best-effort registrable (parent) domain: last two labels. Doesn't
    special-case multi-part TLDs like co.uk -- documented simplification."""
    labels = query.strip(".").lower().split(".")
    if len(labels) < 2:
        return query.strip(".").lower()
    return ".".join(labels[-2:])


def leftmost_label(query: str) -> str:
    labels = query.strip(".").lower().split(".")
    return labels[0] if labels else query


class DnsTunnelingDetector(Detector):
    id = "dns_tunneling"
    label = "DNS tunneling"
    category = "dns_abuse"
    description = "High query volume, long labels, high-entropy subdomains, or TXT/NULL-heavy traffic to one domain."
    default_severity = "high"
    mitre = [mitre_ref("TA0011", "T1071.004")]
    tunables = [
        TunableSpec(key="min_queries", value=30, type="int", min=10, max=500,
                    description="Minimum queries to one parent domain before the detector fires."),
        TunableSpec(key="min_unique_ratio", value=0.6, type="float", min=0.1, max=1.0,
                    description="Minimum fraction of queries that must be unique subdomains."),
        TunableSpec(key="min_entropy", value=3.4, type="float", min=2.0, max=5.0,
                    description="Minimum average Shannon entropy (bits/char) of the subdomain label."),
        TunableSpec(key="min_txt_null_ratio", value=0.5, type="float", min=0.1, max=1.0,
                    description="Minimum fraction of queries of type TXT or NULL to count as tunneling-shaped on their own."),
    ]

    def run(self, source: TrafficSource, since: datetime, until: datetime, tunables: dict) -> list[Finding]:
        min_queries = int(tunables["min_queries"])
        min_unique_ratio = float(tunables["min_unique_ratio"])
        min_entropy = float(tunables["min_entropy"])
        min_txt_null_ratio = float(tunables["min_txt_null_ratio"])

        groups: dict[str, list[DnsRecord]] = defaultdict(list)
        for d in source.dns_events(since, until):
            parent = registrable_domain(d.query)
            if parent in ALLOWLISTED_PARENTS:
                continue
            groups[parent].append(d)

        findings: list[Finding] = []
        for parent, records in groups.items():
            if len(records) < min_queries:
                continue
            unique_subdomains = len({r.query.lower() for r in records})
            unique_ratio = unique_subdomains / len(records)
            if unique_ratio < min_unique_ratio:
                continue
            labels = [leftmost_label(r.query) for r in records]
            avg_entropy = mean([shannon_entropy(lbl) for lbl in labels])
            avg_len = mean([float(len(lbl)) for lbl in labels])
            txt_null = sum(1 for r in records if r.qtype in ("TXT", "NULL"))
            txt_null_ratio = txt_null / len(records)

            if avg_entropy < min_entropy and txt_null_ratio < min_txt_null_ratio:
                continue

            process_names = {r.process_name for r in records if r.process_name}
            process = next(iter(process_names), "unknown") if len(process_names) == 1 else "multiple processes"
            confidence = round(min(0.95, 0.4 + unique_ratio * 0.25 + min(avg_entropy / 4.5, 1.0) * 0.2 + txt_null_ratio * 0.15), 2)

            findings.append(Finding(
                key=f"dns-tunnel|{parent}",
                title=f"Possible DNS tunneling to {parent}",
                severity=self.default_severity,
                confidence=confidence,
                summary=f"{len(records)} DNS queries to {parent} with {unique_subdomains} unique subdomains and average entropy {avg_entropy:.2f} bits/char.",
                detail=(
                    f"{len(records)} queries were made to {parent} in this window, {unique_ratio:.0%} of them "
                    f"unique subdomains (baseline expectation for normal browsing is a small, repeated set of "
                    f"names). Subdomain labels averaged {avg_len:.0f} characters with {avg_entropy:.2f} bits/char "
                    f"of entropy, and {txt_null_ratio:.0%} of queries were TXT/NULL record types. High unique-"
                    f"subdomain counts with high-entropy labels or a TXT/NULL-heavy query mix are the signature "
                    f"of data being encoded into DNS queries (tunneling), rather than resolving a fixed set of "
                    f"hostnames."
                ),
                observed_at=max(r.ts for r in records),
                evidence=[
                    Evidence(label="Parent domain", value=parent),
                    Evidence(label="Queries", value=str(len(records))),
                    Evidence(label="Unique subdomains", value=f"{unique_subdomains} ({unique_ratio:.0%})"),
                    Evidence(label="Avg label entropy", value=f"{avg_entropy:.2f} bits/char"),
                    Evidence(label="TXT/NULL ratio", value=f"{txt_null_ratio:.0%}"),
                ],
                indicators=[Indicator(type="domain", value=parent, context="possible tunneling parent domain")],
                metrics={
                    "queries": len(records), "unique_subdomains": unique_subdomains,
                    "unique_ratio": round(unique_ratio, 3), "avg_entropy": round(avg_entropy, 3),
                    "avg_label_length": round(avg_len, 1), "txt_null_ratio": round(txt_null_ratio, 3),
                },
                occurrence_count=len(records),
                false_positive_notes=(
                    "Some legitimate services (software update channels, security telemetry, some ad/analytics "
                    "SDKs) generate many unique, high-entropy subdomains by design. Check the allowlist in "
                    "threat/detectors/dns.py before treating this as confirmed tunneling."
                ),
                recommended_actions=[
                    Action(label="List recent queries to this domain", kind="manual",
                           detail=f"Filter the traffic log for dst domain {parent} and review the actual subdomain strings."),
                    Action(label="Identify the querying process", kind="command", shell="powershell",
                           command="Get-DnsClientCache | Where-Object { $_.Name -like '*" + parent + "*' }",
                           requires_admin=False, detail="See what's currently cached for this domain."),
                    Action(label="Block the domain at the resolver", kind="command", shell="powershell",
                           command=f"Add-DnsClientNrptRule -Namespace '.{parent}' -NameServers '0.0.0.0'",
                           requires_admin=True, reversible=True, detail="Redirects lookups for this domain to a dead address."),
                ],
            ))
        return findings


class DgaDomainsDetector(Detector):
    id = "dga_domains"
    label = "DGA-like domains"
    category = "dns_abuse"
    description = "High-entropy, consonant-heavy, unpronounceable domain lookups typical of domain generation algorithms."
    default_severity = "medium"
    mitre = [mitre_ref("TA0011", "T1568.002")]
    tunables = [
        TunableSpec(key="min_label_length", value=10, type="int", min=6, max=40,
                    description="Minimum registrable-name length to evaluate (short domains are too noisy)."),
        TunableSpec(key="min_entropy", value=3.3, type="float", min=2.5, max=5.0,
                    description="Minimum Shannon entropy (bits/char) of the registrable name."),
        TunableSpec(key="min_consonant_run", value=5, type="int", min=3, max=10,
                    description="Minimum run of consecutive consonants to count as unpronounceable."),
        TunableSpec(key="min_domains", value=3, type="int", min=1, max=50,
                    description="Minimum number of distinct DGA-looking domains from one process before firing."),
    ]

    def run(self, source: TrafficSource, since: datetime, until: datetime, tunables: dict) -> list[Finding]:
        min_label_length = int(tunables["min_label_length"])
        min_entropy = float(tunables["min_entropy"])
        min_consonant_run = int(tunables["min_consonant_run"])
        min_domains = int(tunables["min_domains"])

        by_process: dict[str, list[DnsRecord]] = defaultdict(list)
        for d in source.dns_events(since, until):
            by_process[d.process_name or "unknown"].append(d)

        findings: list[Finding] = []
        for process, records in by_process.items():
            seen: dict[str, DnsRecord] = {}
            for r in records:
                parent = registrable_domain(r.query)
                if parent in ALLOWLISTED_PARENTS or parent in seen:
                    continue
                seen[parent] = r

            suspicious: list[tuple[str, DnsRecord, float, int]] = []
            for parent, r in seen.items():
                name = parent.split(".")[0]
                if len(name) < min_label_length:
                    continue
                entropy = shannon_entropy(name)
                run = longest_consonant_run(name)
                dr = digit_ratio(name)
                if entropy >= min_entropy and run >= min_consonant_run and dr < 0.5:
                    suspicious.append((parent, r, entropy, run))

            if len(suspicious) < min_domains:
                continue

            avg_entropy = mean([e for _, _, e, _ in suspicious])
            max_run = max(run for _, _, _, run in suspicious)
            confidence = round(min(0.9, 0.4 + min(avg_entropy / 4.5, 1.0) * 0.3 + min(len(suspicious) / 10, 1.0) * 0.2), 2)
            domains_list = ", ".join(p for p, _, _, _ in suspicious[:8])

            findings.append(Finding(
                key=f"dga|{process}",
                title=f"{process} looked up {len(suspicious)} DGA-like domains",
                severity=self.default_severity,
                confidence=confidence,
                summary=f"{process} queried {len(suspicious)} high-entropy, unpronounceable domain names in this window.",
                detail=(
                    f"{process} made {len(suspicious)} DNS queries to distinct registrable domains whose names "
                    f"average {avg_entropy:.2f} bits/char of entropy and include a run of up to {max_run} "
                    f"consecutive consonants (e.g. {domains_list}). Domain generation algorithms produce exactly "
                    f"this shape: long, random-looking, low-vowel names, generated so malware can find a live C2 "
                    f"host even after domains get taken down."
                ),
                observed_at=max(r.ts for _, r, _, _ in suspicious),
                evidence=[
                    Evidence(label="Process", value=process),
                    Evidence(label="Suspicious domains", value=str(len(suspicious))),
                    Evidence(label="Avg entropy", value=f"{avg_entropy:.2f} bits/char"),
                    Evidence(label="Longest consonant run", value=str(max_run)),
                    Evidence(label="Examples", value=domains_list),
                ],
                indicators=[Indicator(type="domain", value=p, context="DGA-like lookup") for p, _, _, _ in suspicious[:10]],
                metrics={
                    "suspicious_domains": len(suspicious), "avg_entropy": round(avg_entropy, 3),
                    "max_consonant_run": max_run,
                },
                occurrence_count=len(suspicious),
                false_positive_notes=(
                    "Some CDN edge hostnames, hashed asset URLs, and randomly-generated tracking subdomains "
                    "look entropy-wise similar to DGA output. This detector only looks at registrable domains, "
                    "not subdomains, and skips the bundled CDN/telemetry allowlist, but novel legitimate "
                    "high-entropy domains can still trip it -- check what the process actually is."
                ),
                recommended_actions=[
                    Action(label="Identify the process", kind="command", shell="powershell",
                           command=f"Get-Process | Where-Object {{ $_.ProcessName -eq '{process.replace('.exe', '')}' }} | Select-Object Id,ProcessName,Path",
                           requires_admin=False, detail="Confirm what this process is before blocking anything."),
                    Action(label="Check the resolution results", kind="manual",
                           detail="Most DGA domains fail to resolve (NXDOMAIN); a handful that do resolve are the live C2 host for that period."),
                    Action(label="Block the process's outbound DNS", kind="command", shell="powershell",
                           command=f"New-NetFirewallRule -DisplayName 'NetAudit block DNS for {process}' -Direction Outbound -Program '{process}' -RemotePort 53 -Protocol UDP -Action Block",
                           requires_admin=True, reversible=True, detail="Stops this process from resolving any domain until you allow it again."),
                ],
            ))
        return findings
