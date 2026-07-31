"""Every listening_services check: pass / negative-finding / error via fake
probe results.

`listening_on_all_interfaces`, `unexpected_listeners`, and `upnp_disabled`
are informational/heuristic and report their negative finding as `warn`
rather than `fail` (see the network_config test module for the same
rationale). `high_risk_ports_open` is a hard control and reaches `fail`.
"""
from __future__ import annotations

from netaudit.posture.checks.listening_services import (
    HighRiskPortsOpen,
    ListeningOnAllInterfaces,
    UnexpectedListeners,
    UpnpDisabled,
)

from .conftest import err, ok


def test_listening_on_all_interfaces_pass(fake_probes):
    probes = fake_probes(net={"listening_sockets": ok([{"ip": "127.0.0.1", "port": 8787, "pid": 100, "process_name": "svchost.exe", "protocol": "tcp"}])})
    result = ListeningOnAllInterfaces().run(probes)
    assert result.status == "pass"


def test_listening_on_all_interfaces_warn(fake_probes):
    probes = fake_probes(net={"listening_sockets": ok([{"ip": "0.0.0.0", "port": 445, "pid": 4, "process_name": "System", "protocol": "tcp"}])})
    result = ListeningOnAllInterfaces().run(probes)
    assert result.status == "warn"


def test_listening_on_all_interfaces_error(fake_probes):
    probes = fake_probes(net={"listening_sockets": err("access denied enumerating network connections")})
    result = ListeningOnAllInterfaces().run(probes)
    assert result.status == "error"


def test_high_risk_ports_open_pass(fake_probes):
    probes = fake_probes(net={"listening_sockets": ok([{"ip": "127.0.0.1", "port": 8787, "pid": 100, "process_name": "netaudit.exe", "protocol": "tcp"}])})
    result = HighRiskPortsOpen().run(probes)
    assert result.status == "pass"


def test_high_risk_ports_open_fail(fake_probes):
    probes = fake_probes(net={"listening_sockets": ok([{"ip": "0.0.0.0", "port": 3389, "pid": 500, "process_name": "svchost.exe", "protocol": "tcp"}])})
    result = HighRiskPortsOpen().run(probes)
    assert result.status == "fail"
    assert "3389" in result.observed


def test_high_risk_ports_open_error(fake_probes):
    probes = fake_probes(net={"listening_sockets": err("timed out")})
    result = HighRiskPortsOpen().run(probes)
    assert result.status == "error"


def test_unexpected_listeners_pass(fake_probes):
    probes = fake_probes(net={"listening_sockets": ok([{"ip": "127.0.0.1", "port": 135, "pid": 4, "process_name": "svchost.exe", "protocol": "tcp"}])})
    result = UnexpectedListeners().run(probes)
    assert result.status == "pass"


def test_unexpected_listeners_warn(fake_probes):
    probes = fake_probes(net={"listening_sockets": ok([{"ip": "127.0.0.1", "port": 9999, "pid": 4242, "process_name": "sketchy-tool.exe", "protocol": "tcp"}])})
    result = UnexpectedListeners().run(probes)
    assert result.status == "warn"
    assert "sketchy-tool.exe" in result.observed


def test_unexpected_listeners_error(fake_probes):
    probes = fake_probes(net={"listening_sockets": err("access denied")})
    result = UnexpectedListeners().run(probes)
    assert result.status == "error"


def test_upnp_disabled_pass(fake_probes):
    probes = fake_probes(ps={"upnp_services": ok([{"Name": "SSDPSRV", "Status": "Stopped", "StartType": "Disabled"}, {"Name": "upnphost", "Status": "Stopped", "StartType": "Disabled"}])})
    result = UpnpDisabled().run(probes)
    assert result.status == "pass"


def test_upnp_disabled_warn(fake_probes):
    probes = fake_probes(ps={"upnp_services": ok([{"Name": "SSDPSRV", "Status": "Running", "StartType": "Automatic"}])})
    result = UpnpDisabled().run(probes)
    assert result.status == "warn"


def test_upnp_disabled_error(fake_probes):
    probes = fake_probes(ps={"upnp_services": err("Get-Service failed")})
    result = UpnpDisabled().run(probes)
    assert result.status == "error"
