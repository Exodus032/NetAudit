"""intel/bundled.py + intel/lookup.py: classification helpers and the
local indicator index, using a fixture file rather than the real shipped
`data/indicators.json` so these tests are stable regardless of what's in
the real bundled set."""
from __future__ import annotations

import json

import pytest

from netaudit.threat.intel import bundled, lookup


@pytest.fixture
def fixture_index(tmp_path):
    data = [
        {"value": "203.0.113.0/24", "type": "cidr", "category": "reserved_range", "confidence": 0.15,
         "source": "RFC 5737", "note": "TEST-NET-3", "first_added": "2026-01-01"},
        {"value": "198.51.100.77", "type": "ip", "category": "scanner", "confidence": 0.9,
         "source": "test-fixture", "note": "Test-only marker.", "first_added": "2026-01-01"},
        {"value": "evil-tunnel.example", "type": "domain", "category": "test_bad_domain", "confidence": 0.8,
         "source": "test-fixture", "note": "Test-only marker.", "first_added": "2026-01-01"},
        {"value": "9999", "type": "port", "category": "mining_pool_port", "confidence": 0.4,
         "source": "test-fixture", "note": "Test-only marker.", "first_added": "2026-01-01"},
    ]
    path = tmp_path / "indicators.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return bundled.load(path)


class TestIndicatorIndex:
    def test_cidr_match(self, fixture_index):
        matches = fixture_index.match_ip("203.0.113.55")
        assert len(matches) == 1
        assert matches[0].category == "reserved_range"

    def test_exact_ip_match(self, fixture_index):
        matches = fixture_index.match_ip("198.51.100.77")
        assert len(matches) == 1
        assert matches[0].category == "scanner"

    def test_ip_no_match(self, fixture_index):
        assert fixture_index.match_ip("93.184.216.34") == []

    def test_domain_subdomain_match(self, fixture_index):
        matches = fixture_index.match_domain("a1b2c3.evil-tunnel.example")
        assert len(matches) == 1

    def test_domain_no_match(self, fixture_index):
        assert fixture_index.match_domain("example.com") == []

    def test_port_match(self, fixture_index):
        matches = fixture_index.match_port(9999)
        assert len(matches) == 1

    def test_port_no_match(self, fixture_index):
        assert fixture_index.match_port(443) == []


class TestClassifyIp:
    def test_private_ip(self):
        c = lookup.classify_ip("192.168.1.1")
        assert c.is_private is True
        assert c.is_multicast is False

    def test_loopback_is_not_private(self):
        # is_private excludes loopback deliberately (loopback isn't "a LAN address").
        c = lookup.classify_ip("127.0.0.1")
        assert c.is_private is False

    def test_multicast(self):
        c = lookup.classify_ip("224.0.0.1")
        assert c.is_multicast is True

    def test_public_ip(self):
        c = lookup.classify_ip("93.184.216.34")
        assert c.is_private is False
        assert c.is_bogon is False

    def test_invalid_ip_returns_default(self):
        c = lookup.classify_ip("not-an-ip")
        assert c.is_private is False
        assert c.is_bogon is False


class TestLookup:
    def test_private_ip_is_clean_even_with_bundled_match(self, fixture_index):
        result = lookup.lookup("203.0.113.55", "ip", index=fixture_index)
        # Not actually private, so this one *should* reflect the bundled match.
        assert result.found is True
        assert result.reputation in ("suspicious", "malicious")

    def test_high_confidence_match_is_malicious(self, fixture_index):
        result = lookup.lookup("198.51.100.77", "ip", index=fixture_index)
        assert result.reputation == "malicious"
        assert result.matches[0].source == "test-fixture"

    def test_no_match_is_unknown(self, fixture_index):
        result = lookup.lookup("8.8.8.8", "ip", index=fixture_index)
        assert result.found is False
        assert result.reputation == "unknown"

    def test_private_lan_ip_is_clean(self, fixture_index):
        result = lookup.lookup("192.168.1.1", "ip", index=fixture_index)
        assert result.reputation == "clean"
        assert result.classification.is_private is True

    def test_domain_lookup(self, fixture_index):
        result = lookup.lookup("sub.evil-tunnel.example", "domain", index=fixture_index)
        assert result.found is True
        assert result.matches[0].category == "test_bad_domain"


class TestBundledDataIsWellFormed:
    """The real shipped starter set must load and every entry must carry
    the source/note fields the README promises."""

    def test_default_index_loads(self):
        idx = bundled.default_index()
        assert len(idx.entries) > 0

    def test_every_entry_has_source_and_note(self):
        idx = bundled.load()
        for entry in idx.entries:
            assert entry.source.strip() != ""
            assert entry.note.strip() != ""

    def test_no_entry_claims_high_malicious_confidence(self):
        """Honesty check: the bundled starter set should not fabricate
        high-confidence malicious attribution (see README limitations)."""
        idx = bundled.load()
        assert all(e.confidence < 0.85 for e in idx.entries)
