"""Every smb check: pass / fail / error via fake probe results."""
from __future__ import annotations

from netaudit.posture.checks.smb import (
    Smb1Disabled,
    SmbGuestAuthDisabled,
    SmbSharesExposed,
    SmbSigningRequired,
)

from .conftest import err, ok


def test_smb1_disabled_pass(fake_probes):
    probes = fake_probes(ps={"smb_server_config": ok({"EnableSMB1Protocol": False})})
    result = Smb1Disabled().run(probes)
    assert result.status == "pass"


def test_smb1_disabled_fail(fake_probes):
    probes = fake_probes(ps={"smb_server_config": ok({"EnableSMB1Protocol": True})})
    result = Smb1Disabled().run(probes)
    assert result.status == "fail"


def test_smb1_disabled_error(fake_probes):
    probes = fake_probes(ps={"smb_server_config": err("SmbShare module not found")})
    result = Smb1Disabled().run(probes)
    assert result.status == "error"
    assert "SmbShare module not found" in result.observed


def test_smb_signing_required_pass(fake_probes):
    probes = fake_probes(ps={
        "smb_client_config": ok({"RequireSecuritySignature": True}),
        "smb_server_config": ok({"RequireSecuritySignature": True}),
    })
    result = SmbSigningRequired().run(probes)
    assert result.status == "pass"


def test_smb_signing_required_fail(fake_probes):
    probes = fake_probes(ps={
        "smb_client_config": ok({"RequireSecuritySignature": False}),
        "smb_server_config": ok({"RequireSecuritySignature": False}),
    })
    result = SmbSigningRequired().run(probes)
    assert result.status == "fail"


def test_smb_signing_required_error(fake_probes):
    probes = fake_probes(ps={
        "smb_client_config": err("access denied"),
        "smb_server_config": ok({"RequireSecuritySignature": True}),
    })
    result = SmbSigningRequired().run(probes)
    assert result.status == "error"


def test_smb_guest_auth_disabled_pass(fake_probes):
    probes = fake_probes(registry={"smb_guest_auth": ok(0)})
    result = SmbGuestAuthDisabled().run(probes)
    assert result.status == "pass"


def test_smb_guest_auth_disabled_fail(fake_probes):
    probes = fake_probes(registry={"smb_guest_auth": ok(1)})
    result = SmbGuestAuthDisabled().run(probes)
    assert result.status == "fail"


def test_smb_guest_auth_disabled_error(fake_probes):
    # evaluate() treats a missing registry value as "not configured" (pass,
    # matching the modern OS default) rather than an error -- to reach the
    # error path here we need `evaluate()` itself to blow up, which happens
    # if the probe layer hands back something evaluate() can't use. Simplest
    # reliable trigger: make gather() raise by having .registry() itself
    # raise (simulating an unexpected probe-layer exception).
    class ExplodingProbes:
        def registry(self, key):
            raise RuntimeError("winreg exploded")

    result = SmbGuestAuthDisabled().run(ExplodingProbes())
    assert result.status == "error"
    assert "winreg exploded" in result.observed


def test_smb_shares_exposed_pass(fake_probes):
    shares = [{"name": "Data", "path": "C:\\Data", "access": [{"AccountName": "Everyone", "AccessRight": "No Access"}]}]
    probes = fake_probes(ps={"smb_shares": ok(shares)})
    result = SmbSharesExposed().run(probes)
    assert result.status == "pass"


def test_smb_shares_exposed_fail(fake_probes):
    shares = [{"name": "Data", "path": "C:\\Data", "access": [{"AccountName": "Everyone", "AccessRight": "Full"}]}]
    probes = fake_probes(ps={"smb_shares": ok(shares)})
    result = SmbSharesExposed().run(probes)
    assert result.status == "fail"
    assert "Data" in result.observed


def test_smb_shares_exposed_error(fake_probes):
    probes = fake_probes(ps={"smb_shares": err("access denied")})
    result = SmbSharesExposed().run(probes)
    assert result.status == "error"
