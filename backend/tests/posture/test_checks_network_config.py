"""Every network_config check: pass / negative-finding / error via fake probe
results.

Several of these checks (ipv6_state, promiscuous_adapters,
unused_adapters_enabled, network_profile_public) are deliberately low
severity and report their negative finding as `warn`, never `fail` -- they
are heuristic or informational-only ("here's the state, decide for
yourself"), not a hard pass/fail control, so a `fail` verdict would
overstate the risk and unfairly tank the score. Those tests assert `warn`
(or, for ipv6_state, that the informational finding still surfaces cleanly)
instead of `fail`. `ip_forwarding_disabled` is a real binary control and does
reach `fail`.
"""
from __future__ import annotations

from netaudit.posture.checks.network_config import (
    IpForwardingDisabled,
    Ipv6State,
    NetworkProfilePublic,
    PromiscuousAdapters,
    UnusedAdaptersEnabled,
)

from .conftest import err, ok


def test_ipv6_state_pass_when_not_configured(fake_probes):
    probes = fake_probes(registry={"ipv6_disabled_components": err("not found")})
    result = Ipv6State().run(probes)
    assert result.status == "pass"


def test_ipv6_state_pass_when_configured(fake_probes):
    # Informational: any readable value is reported as "pass" with the
    # actual value in `observed` -- there's no wrong answer to flag.
    probes = fake_probes(registry={"ipv6_disabled_components": ok(0xFF)})
    result = Ipv6State().run(probes)
    assert result.status == "pass"
    assert "0xff" in result.observed.lower()


def test_ipv6_state_error(fake_probes):
    class ExplodingProbes:
        def registry(self, key):
            raise RuntimeError("boom")

    result = Ipv6State().run(ExplodingProbes())
    assert result.status == "error"


def test_ip_forwarding_disabled_pass(fake_probes):
    probes = fake_probes(registry={"ip_forwarding": ok(0)})
    result = IpForwardingDisabled().run(probes)
    assert result.status == "pass"


def test_ip_forwarding_disabled_fail(fake_probes):
    probes = fake_probes(registry={"ip_forwarding": ok(1)})
    result = IpForwardingDisabled().run(probes)
    assert result.status == "fail"


def test_ip_forwarding_disabled_error(fake_probes):
    class ExplodingProbes:
        def registry(self, key):
            raise RuntimeError("boom")

    result = IpForwardingDisabled().run(ExplodingProbes())
    assert result.status == "error"


def test_promiscuous_adapters_pass(fake_probes):
    probes = fake_probes(ps={"net_adapter_bindings": ok([{"Name": "Ethernet", "ComponentID": "ms_tcpip", "Enabled": True}])})
    result = PromiscuousAdapters().run(probes)
    assert result.status == "pass"


def test_promiscuous_adapters_warn(fake_probes):
    probes = fake_probes(ps={"net_adapter_bindings": ok([{"Name": "Ethernet", "ComponentID": "npcap", "Enabled": True}])})
    result = PromiscuousAdapters().run(probes)
    assert result.status == "warn"


def test_promiscuous_adapters_error(fake_probes):
    probes = fake_probes(ps={"net_adapter_bindings": err("Get-NetAdapterBinding failed")})
    result = PromiscuousAdapters().run(probes)
    assert result.status == "error"


def test_unused_adapters_enabled_pass(fake_probes):
    probes = fake_probes(ps={"net_adapters": ok([{"Name": "Ethernet", "AdminStatus": "Up", "Status": "Up", "Virtual": False}])})
    result = UnusedAdaptersEnabled().run(probes)
    assert result.status == "pass"


def test_unused_adapters_enabled_warn(fake_probes):
    probes = fake_probes(ps={"net_adapters": ok([{"Name": "Old VPN", "AdminStatus": "Up", "Status": "Disconnected", "Virtual": False}])})
    result = UnusedAdaptersEnabled().run(probes)
    assert result.status == "warn"
    assert "Old VPN" in result.observed


def test_unused_adapters_enabled_error(fake_probes):
    probes = fake_probes(ps={"net_adapters": err("access denied")})
    result = UnusedAdaptersEnabled().run(probes)
    assert result.status == "error"


def test_network_profile_public_pass(fake_probes):
    probes = fake_probes(ps={"connection_profiles": ok([{"Name": "Coffee Shop", "NetworkCategory": "Public", "IPv4Connectivity": "Internet"}])})
    result = NetworkProfilePublic().run(probes)
    assert result.status == "pass"


def test_network_profile_public_warn(fake_probes):
    probes = fake_probes(ps={"connection_profiles": ok([{"Name": "Home", "NetworkCategory": "Private", "IPv4Connectivity": "Internet"}])})
    result = NetworkProfilePublic().run(probes)
    assert result.status == "warn"


def test_network_profile_public_error(fake_probes):
    probes = fake_probes(ps={"connection_profiles": err("Get-NetConnectionProfile failed")})
    result = NetworkProfilePublic().run(probes)
    assert result.status == "error"
