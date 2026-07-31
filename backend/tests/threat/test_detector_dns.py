"""dns_tunneling: fires on high-volume, high-unique-ratio, high-entropy
subdomains to one parent domain; must not fire on ordinary repeated-name
browsing traffic.

dga_domains: fires on multiple high-entropy, consonant-heavy registrable
domain names from one process; must not fire on ordinary English-like
domain names.
"""
from __future__ import annotations

import random
import string
from datetime import datetime, timedelta, timezone

from netaudit.threat.detectors.dns import DgaDomainsDetector, DnsTunnelingDetector
from netaudit.threat.source import DnsRecord, ListTrafficSource

NOW = datetime(2026, 7, 31, 14, 0, 0, tzinfo=timezone.utc)


def _random_label(rng, length=28):
    # High entropy, mixed alnum -- shaped like base32-encoded exfil data.
    alphabet = string.ascii_lowercase + string.digits
    return "".join(rng.choice(alphabet) for _ in range(length))


def test_dns_tunneling_fires_on_high_entropy_unique_subdomains():
    detector = DnsTunnelingDetector()
    rng = random.Random(7)
    records = []
    for i in range(60):
        label = _random_label(rng)
        records.append(DnsRecord(
            ts=NOW - timedelta(seconds=(60 - i) * 5), query=f"{label}.evil-tunnel.example",
            qtype="TXT", process_name="suspicious.exe",
        ))
    source = ListTrafficSource(dns_events=records)
    since = NOW - timedelta(hours=1)

    findings = detector.run(source, since, NOW, detector.default_tunable_values())

    assert len(findings) == 1
    f = findings[0]
    assert f.metrics["queries"] == 60
    assert f.metrics["unique_subdomains"] == 60
    assert f.metrics["avg_entropy"] > 3.4


def test_dns_tunneling_does_not_fire_on_ordinary_browsing():
    detector = DnsTunnelingDetector()
    names = ["www", "api", "cdn", "static", "mail"]
    records = []
    for i in range(60):
        records.append(DnsRecord(
            ts=NOW - timedelta(seconds=(60 - i) * 5),
            query=f"{names[i % len(names)]}.example.com",
            qtype="A", process_name="chrome.exe",
        ))
    source = ListTrafficSource(dns_events=records)
    since = NOW - timedelta(hours=1)

    findings = detector.run(source, since, NOW, detector.default_tunable_values())

    assert findings == []


def test_dga_domains_fires_on_multiple_high_entropy_domains():
    detector = DgaDomainsDetector()
    rng = random.Random(11)
    consonants = "bcdfghjklmnpqrstvwxyz"
    records = []
    for i in range(5):
        # Long, consonant-heavy, no vowels, no repeats -- classic DGA shape
        # with entropy comfortably above the detector's threshold.
        name = "".join(rng.sample(consonants, 14))
        records.append(DnsRecord(
            ts=NOW - timedelta(minutes=i), query=f"{name}.com", qtype="A",
            process_name="malware.exe", response_code="NXDOMAIN",
        ))
    source = ListTrafficSource(dns_events=records)
    since = NOW - timedelta(hours=1)

    findings = detector.run(source, since, NOW, detector.default_tunable_values())

    assert len(findings) == 1
    f = findings[0]
    assert f.metrics["suspicious_domains"] == 5
    assert f.metrics["max_consonant_run"] >= 5


def test_dga_domains_does_not_fire_on_normal_domains():
    detector = DgaDomainsDetector()
    domains = ["google.com", "microsoft.com", "wikipedia.org", "github.com", "stackoverflow.com"]
    records = [
        DnsRecord(ts=NOW - timedelta(minutes=i), query=d, qtype="A", process_name="chrome.exe")
        for i, d in enumerate(domains)
    ]
    source = ListTrafficSource(dns_events=records)
    since = NOW - timedelta(hours=1)

    findings = detector.run(source, since, NOW, detector.default_tunable_values())

    assert findings == []
