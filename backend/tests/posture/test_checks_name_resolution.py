"""Every name_resolution check: pass / fail / error via fake probe results."""
from __future__ import annotations

from netaudit.posture.checks.name_resolution import (
    DnsOverHttps,
    DnsServersTrusted,
    LlmnrDisabled,
    MdnsExposure,
    NetbiosDisabled,
    WpadDisabled,
)

from .conftest import err, ok


def test_llmnr_disabled_pass(fake_probes):
    probes = fake_probes(registry={"llmnr_enable_multicast": ok(0)})
    result = LlmnrDisabled().run(probes)
    assert result.status == "pass"


def test_llmnr_disabled_fail(fake_probes):
    probes = fake_probes(registry={"llmnr_enable_multicast": ok(1)})
    result = LlmnrDisabled().run(probes)
    assert result.status == "fail"


def test_llmnr_disabled_error(fake_probes):
    class ExplodingProbes:
        def registry(self, key):
            raise RuntimeError("boom")

    result = LlmnrDisabled().run(ExplodingProbes())
    assert result.status == "error"


def test_netbios_disabled_pass(fake_probes):
    probes = fake_probes(ps={"netbios_options": ok([{"Description": "Ethernet", "TcpipNetbiosOptions": 2}])})
    result = NetbiosDisabled().run(probes)
    assert result.status == "pass"


def test_netbios_disabled_fail(fake_probes):
    probes = fake_probes(ps={"netbios_options": ok([{"Description": "Ethernet", "TcpipNetbiosOptions": 0}])})
    result = NetbiosDisabled().run(probes)
    assert result.status == "fail"


def test_netbios_disabled_error(fake_probes):
    probes = fake_probes(ps={"netbios_options": err("CIM query failed")})
    result = NetbiosDisabled().run(probes)
    assert result.status == "error"


def test_mdns_exposure_pass(fake_probes):
    probes = fake_probes(registry={"mdns_enabled": ok(0)})
    result = MdnsExposure().run(probes)
    assert result.status == "pass"


def test_mdns_exposure_fail_ish_warn(fake_probes):
    # mDNS enabled is a warn (low-severity, informational), not a hard fail --
    # confirm it's flagged rather than silently passed.
    probes = fake_probes(registry={"mdns_enabled": ok(1)})
    result = MdnsExposure().run(probes)
    assert result.status == "warn"


def test_mdns_exposure_error(fake_probes):
    class ExplodingProbes:
        def registry(self, key):
            raise RuntimeError("boom")

    result = MdnsExposure().run(ExplodingProbes())
    assert result.status == "error"


def test_wpad_disabled_pass(fake_probes):
    data = bytes([0] * 8 + [0x00] + [0] * 30)  # bit 0x08 clear at byte 8
    probes = fake_probes(registry={"wpad_autodetect": ok(data)})
    result = WpadDisabled().run(probes)
    assert result.status == "pass"


def test_wpad_disabled_fail(fake_probes):
    data = bytes([0] * 8 + [0x08] + [0] * 30)  # bit 0x08 set at byte 8
    probes = fake_probes(registry={"wpad_autodetect": ok(data)})
    result = WpadDisabled().run(probes)
    assert result.status == "fail"


def test_wpad_disabled_error(fake_probes):
    probes = fake_probes(registry={"wpad_autodetect": err("value not found")})
    result = WpadDisabled().run(probes)
    assert result.status == "error"


def test_dns_over_https_pass(fake_probes):
    probes = fake_probes(ps={"dns_doh": ok([{"ServerAddress": "1.1.1.1", "DohTemplate": "https://cloudflare-dns.com/dns-query", "AutoUpgrade": True}])})
    result = DnsOverHttps().run(probes)
    assert result.status == "pass"


def test_dns_over_https_fail_ish_warn(fake_probes):
    probes = fake_probes(ps={"dns_doh": ok([{"ServerAddress": "1.1.1.1", "DohTemplate": None}])})
    result = DnsOverHttps().run(probes)
    assert result.status == "warn"


def test_dns_over_https_error(fake_probes):
    probes = fake_probes(ps={"dns_doh": err("cmdlet not available on this Windows build")})
    result = DnsOverHttps().run(probes)
    assert result.status == "error"


def test_dns_servers_trusted_pass(fake_probes):
    probes = fake_probes(ps={"dns_servers": ok([{"InterfaceAlias": "Ethernet", "ServerAddresses": ["192.168.1.1"]}])})
    result = DnsServersTrusted().run(probes)
    assert result.status == "pass"


def test_dns_servers_trusted_fail_ish_warn(fake_probes):
    probes = fake_probes(ps={"dns_servers": ok([{"InterfaceAlias": "Ethernet", "ServerAddresses": ["203.0.113.5"]}])})
    result = DnsServersTrusted().run(probes)
    assert result.status == "warn"
    assert "203.0.113.5" in result.observed


def test_dns_servers_trusted_error(fake_probes):
    probes = fake_probes(ps={"dns_servers": err("Get-DnsClientServerAddress failed")})
    result = DnsServersTrusted().run(probes)
    assert result.status == "error"
