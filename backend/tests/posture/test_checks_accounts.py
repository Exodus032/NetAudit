"""Every accounts check: pass / negative-finding / error via fake probe
results.

`local_admin_count` is a soft heuristic (a threshold on group size, not a
binary misconfiguration) and reports its negative finding as `warn`; the
other three are binary controls and reach `fail`.
"""
from __future__ import annotations

from netaudit.posture.checks.accounts import (
    AutologonDisabled,
    BlankPasswords,
    GuestAccountDisabled,
    LocalAdminCount,
)

from .conftest import err, ok


def test_guest_account_disabled_pass(fake_probes):
    probes = fake_probes(ps={"local_users": ok([{"Name": "Guest", "Enabled": False, "PasswordRequired": True}])})
    result = GuestAccountDisabled().run(probes)
    assert result.status == "pass"


def test_guest_account_disabled_fail(fake_probes):
    probes = fake_probes(ps={"local_users": ok([{"Name": "Guest", "Enabled": True, "PasswordRequired": False}])})
    result = GuestAccountDisabled().run(probes)
    assert result.status == "fail"


def test_guest_account_disabled_error(fake_probes):
    probes = fake_probes(ps={"local_users": err("Get-LocalUser failed")})
    result = GuestAccountDisabled().run(probes)
    assert result.status == "error"


def test_local_admin_count_pass(fake_probes):
    probes = fake_probes(ps={"local_admins": ok([{"Name": "Administrator", "ObjectClass": "User"}])})
    result = LocalAdminCount().run(probes)
    assert result.status == "pass"


def test_local_admin_count_warn(fake_probes):
    admins = [{"Name": f"user{i}", "ObjectClass": "User"} for i in range(5)]
    probes = fake_probes(ps={"local_admins": ok(admins)})
    result = LocalAdminCount().run(probes)
    assert result.status == "warn"


def test_local_admin_count_error(fake_probes):
    probes = fake_probes(ps={"local_admins": err("Get-LocalGroupMember failed")})
    result = LocalAdminCount().run(probes)
    assert result.status == "error"


def test_blank_passwords_pass(fake_probes):
    probes = fake_probes(ps={"local_users": ok([{"Name": "lukab", "Enabled": True, "PasswordRequired": True}])})
    result = BlankPasswords().run(probes)
    assert result.status == "pass"


def test_blank_passwords_fail(fake_probes):
    probes = fake_probes(ps={"local_users": ok([{"Name": "lukab", "Enabled": True, "PasswordRequired": False}])})
    result = BlankPasswords().run(probes)
    assert result.status == "fail"
    assert "lukab" in result.observed


def test_blank_passwords_error(fake_probes):
    probes = fake_probes(ps={"local_users": err("Get-LocalUser failed")})
    result = BlankPasswords().run(probes)
    assert result.status == "error"


def test_autologon_disabled_pass(fake_probes):
    probes = fake_probes(registry={"autologon_settings": ok({"AutoAdminLogon": "0"})})
    result = AutologonDisabled().run(probes)
    assert result.status == "pass"


def test_autologon_disabled_fail(fake_probes):
    probes = fake_probes(registry={"autologon_settings": ok({"AutoAdminLogon": "1", "DefaultPassword": "hunter2"})})
    result = AutologonDisabled().run(probes)
    assert result.status == "fail"
    assert "plaintext" in result.observed.lower()


def test_autologon_disabled_error(fake_probes):
    probes = fake_probes(registry={"autologon_settings": err("access denied")})
    result = AutologonDisabled().run(probes)
    assert result.status == "error"
