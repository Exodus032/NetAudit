"""Every firewall check: a probe result that must produce pass, one that
must produce fail, and one that raises (via a failed probe), which must
produce error."""
from __future__ import annotations

from netaudit.posture.checks.firewall import (
    FirewallAllowRulesBroad,
    FirewallInboundDefaultBlock,
    FirewallLoggingEnabled,
    FirewallProfilesEnabled,
)

from .conftest import err, ok

_PROFILES_OK = [
    {"Name": "Domain", "Enabled": True, "DefaultInboundAction": "Block", "DefaultOutboundAction": "Allow", "LogAllowed": False, "LogBlocked": True, "LogFileName": "x"},
    {"Name": "Private", "Enabled": True, "DefaultInboundAction": "Block", "DefaultOutboundAction": "Allow", "LogAllowed": False, "LogBlocked": True, "LogFileName": "x"},
    {"Name": "Public", "Enabled": True, "DefaultInboundAction": "Block", "DefaultOutboundAction": "Allow", "LogAllowed": False, "LogBlocked": True, "LogFileName": "x"},
]


def _profiles(**overrides_by_name):
    profiles = [dict(p) for p in _PROFILES_OK]
    for p in profiles:
        if p["Name"] in overrides_by_name:
            p.update(overrides_by_name[p["Name"]])
    return profiles


def test_firewall_profiles_enabled_pass(fake_probes):
    probes = fake_probes(ps={"firewall_profiles": ok(_profiles())})
    result = FirewallProfilesEnabled().run(probes)
    assert result.status == "pass"


def test_firewall_profiles_enabled_fail(fake_probes):
    probes = fake_probes(ps={"firewall_profiles": ok(_profiles(Public={"Enabled": False}))})
    result = FirewallProfilesEnabled().run(probes)
    assert result.status == "fail"
    assert "Public" in result.observed


def test_firewall_profiles_enabled_error(fake_probes):
    probes = fake_probes(ps={"firewall_profiles": err("access denied")})
    result = FirewallProfilesEnabled().run(probes)
    assert result.status == "error"
    assert "access denied" in result.observed


def test_firewall_inbound_default_block_pass(fake_probes):
    probes = fake_probes(ps={"firewall_profiles": ok(_profiles())})
    result = FirewallInboundDefaultBlock().run(probes)
    assert result.status == "pass"


def test_firewall_inbound_default_block_fail(fake_probes):
    probes = fake_probes(ps={"firewall_profiles": ok(_profiles(Domain={"DefaultInboundAction": "Allow"}))})
    result = FirewallInboundDefaultBlock().run(probes)
    assert result.status == "fail"
    assert "Domain" in result.observed


def test_firewall_inbound_default_block_error(fake_probes):
    probes = fake_probes(ps={"firewall_profiles": err("timed out")})
    result = FirewallInboundDefaultBlock().run(probes)
    assert result.status == "error"


def test_firewall_logging_enabled_pass(fake_probes):
    probes = fake_probes(ps={"firewall_profiles": ok(_profiles())})
    result = FirewallLoggingEnabled().run(probes)
    assert result.status == "pass"


def test_firewall_logging_enabled_fail(fake_probes):
    probes = fake_probes(ps={"firewall_profiles": ok(_profiles(
        Domain={"LogBlocked": False}, Private={"LogBlocked": False}, Public={"LogBlocked": False}
    ))})
    result = FirewallLoggingEnabled().run(probes)
    assert result.status == "fail"


def test_firewall_logging_enabled_error(fake_probes):
    probes = fake_probes(ps={"firewall_profiles": err("cmdlet not found")})
    result = FirewallLoggingEnabled().run(probes)
    assert result.status == "error"
    assert "cmdlet not found" in result.observed


def test_firewall_allow_rules_broad_pass(fake_probes):
    rules = [{"name": "scoped", "profile": "Private", "protocol": "TCP", "local_port": "8080", "remote_address": "192.168.1.0/24"}]
    probes = fake_probes(ps={"firewall_rules_inbound_allow": ok(rules)})
    result = FirewallAllowRulesBroad().run(probes)
    assert result.status == "pass"


def test_firewall_allow_rules_broad_fail(fake_probes):
    rules = [{"name": "wide open", "profile": "Public", "protocol": "Any", "local_port": "Any", "remote_address": "Any"}]
    probes = fake_probes(ps={"firewall_rules_inbound_allow": ok(rules)})
    result = FirewallAllowRulesBroad().run(probes)
    assert result.status == "fail"
    assert "wide open" in result.observed


def test_firewall_allow_rules_broad_error(fake_probes):
    probes = fake_probes(ps={"firewall_rules_inbound_allow": err("timed out after 10s")})
    result = FirewallAllowRulesBroad().run(probes)
    assert result.status == "error"
