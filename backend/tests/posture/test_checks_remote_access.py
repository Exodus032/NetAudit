"""Every remote_access check: pass / fail / error via fake probe results."""
from __future__ import annotations

from netaudit.posture.checks.remote_access import (
    PsRemotingScope,
    RdpDisabledOrNla,
    RemoteRegistryDisabled,
    WinrmExposure,
)

from .conftest import err, ok


def test_rdp_disabled_or_nla_pass_when_disabled(fake_probes):
    probes = fake_probes(registry={"rdp_deny_connections": ok(1), "rdp_nla": ok(1)})
    result = RdpDisabledOrNla().run(probes)
    assert result.status == "pass"


def test_rdp_disabled_or_nla_fail_when_enabled_without_nla(fake_probes):
    probes = fake_probes(registry={"rdp_deny_connections": ok(0), "rdp_nla": ok(0)})
    result = RdpDisabledOrNla().run(probes)
    assert result.status == "fail"


def test_rdp_disabled_or_nla_error(fake_probes):
    probes = fake_probes(registry={"rdp_deny_connections": err("access denied"), "rdp_nla": ok(1)})
    result = RdpDisabledOrNla().run(probes)
    assert result.status == "error"


def test_winrm_exposure_pass_when_stopped(fake_probes):
    probes = fake_probes(ps={"winrm_status": ok({"service": {"Status": "Stopped", "StartType": "Manual"}, "allow_unencrypted": False})})
    result = WinrmExposure().run(probes)
    assert result.status == "pass"


def test_winrm_exposure_fail_when_unencrypted(fake_probes):
    probes = fake_probes(ps={"winrm_status": ok({"service": {"Status": "Running", "StartType": "Auto"}, "allow_unencrypted": True})})
    result = WinrmExposure().run(probes)
    assert result.status == "fail"


def test_winrm_exposure_error(fake_probes):
    probes = fake_probes(ps={"winrm_status": err("timed out")})
    result = WinrmExposure().run(probes)
    assert result.status == "error"


def test_remote_registry_disabled_pass(fake_probes):
    probes = fake_probes(ps={"remote_registry_service": ok({"Status": "Stopped", "StartType": "Disabled"})})
    result = RemoteRegistryDisabled().run(probes)
    assert result.status == "pass"


def test_remote_registry_disabled_fail(fake_probes):
    probes = fake_probes(ps={"remote_registry_service": ok({"Status": "Running", "StartType": "Automatic"})})
    result = RemoteRegistryDisabled().run(probes)
    assert result.status == "fail"


def test_remote_registry_disabled_error(fake_probes):
    probes = fake_probes(ps={"remote_registry_service": err("service not found")})
    result = RemoteRegistryDisabled().run(probes)
    assert result.status == "error"


def test_psremoting_scope_pass(fake_probes):
    probes = fake_probes(ps={"psremoting_status": ok({"service": {"Status": "Stopped"}, "trusted_hosts": "", "listener_addresses": []})})
    result = PsRemotingScope().run(probes)
    assert result.status == "pass"


def test_psremoting_scope_fail(fake_probes):
    probes = fake_probes(ps={"psremoting_status": ok({"service": {"Status": "Running"}, "trusted_hosts": "*", "listener_addresses": ["*"]})})
    result = PsRemotingScope().run(probes)
    assert result.status == "fail"


def test_psremoting_scope_error(fake_probes):
    probes = fake_probes(ps={"psremoting_status": err("WSMan provider unavailable")})
    result = PsRemotingScope().run(probes)
    assert result.status == "error"
