"""Every updates_and_defense check: pass / fail / error via fake probe
results."""
from __future__ import annotations

from netaudit.posture.checks.updates_and_defense import (
    BitlockerStatus,
    DefenderRealtimeEnabled,
    DefenderSignaturesCurrent,
    UacEnabled,
    WindowsUpdateCurrent,
)

from .conftest import err, ok


def test_defender_realtime_enabled_pass(fake_probes):
    probes = fake_probes(ps={"defender_status": ok({"RealTimeProtectionEnabled": True, "AntivirusEnabled": True})})
    result = DefenderRealtimeEnabled().run(probes)
    assert result.status == "pass"


def test_defender_realtime_enabled_fail(fake_probes):
    probes = fake_probes(ps={"defender_status": ok({"RealTimeProtectionEnabled": False, "AntivirusEnabled": True})})
    result = DefenderRealtimeEnabled().run(probes)
    assert result.status == "fail"


def test_defender_realtime_enabled_error(fake_probes):
    probes = fake_probes(ps={"defender_status": err("Get-MpComputerStatus is not available")})
    result = DefenderRealtimeEnabled().run(probes)
    assert result.status == "error"


def test_defender_signatures_current_pass(fake_probes):
    probes = fake_probes(ps={"defender_status": ok({"AntivirusSignatureAge": 0, "AntispywareSignatureAge": 0})})
    result = DefenderSignaturesCurrent().run(probes)
    assert result.status == "pass"


def test_defender_signatures_current_fail(fake_probes):
    probes = fake_probes(ps={"defender_status": ok({"AntivirusSignatureAge": 30, "AntispywareSignatureAge": 30})})
    result = DefenderSignaturesCurrent().run(probes)
    assert result.status == "fail"


def test_defender_signatures_current_error(fake_probes):
    probes = fake_probes(ps={"defender_status": err("Defender module not loaded")})
    result = DefenderSignaturesCurrent().run(probes)
    assert result.status == "error"


def test_windows_update_current_pass(fake_probes):
    probes = fake_probes(registry={"windows_update_last_success": ok("2026-07-25 10:00:00")})
    result = WindowsUpdateCurrent().run(probes)
    assert result.status == "pass"


def test_windows_update_current_fail(fake_probes):
    probes = fake_probes(registry={"windows_update_last_success": ok("2020-01-01 10:00:00")})
    result = WindowsUpdateCurrent().run(probes)
    assert result.status == "fail"


def test_windows_update_current_error(fake_probes):
    probes = fake_probes(registry={"windows_update_last_success": err("registry value not found")})
    result = WindowsUpdateCurrent().run(probes)
    assert result.status == "error"


def test_uac_enabled_pass(fake_probes):
    probes = fake_probes(registry={"uac_settings": ok({"EnableLUA": 1, "ConsentPromptBehaviorAdmin": 5})})
    result = UacEnabled().run(probes)
    assert result.status == "pass"


def test_uac_enabled_fail(fake_probes):
    probes = fake_probes(registry={"uac_settings": ok({"EnableLUA": 0})})
    result = UacEnabled().run(probes)
    assert result.status == "fail"


def test_uac_enabled_error(fake_probes):
    probes = fake_probes(registry={"uac_settings": err("access denied")})
    result = UacEnabled().run(probes)
    assert result.status == "error"


def test_bitlocker_status_pass(fake_probes):
    probes = fake_probes(
        ps={"bitlocker_status": ok([{"MountPoint": "C:", "VolumeType": "OperatingSystem", "ProtectionStatus": "On", "EncryptionPercentage": 100}])},
        admin=True,
    )
    result = BitlockerStatus().run(probes)
    assert result.status == "pass"


def test_bitlocker_status_fail(fake_probes):
    probes = fake_probes(
        ps={"bitlocker_status": ok([{"MountPoint": "C:", "VolumeType": "OperatingSystem", "ProtectionStatus": "Off", "EncryptionPercentage": 0}])},
        admin=True,
    )
    result = BitlockerStatus().run(probes)
    assert result.status == "fail"


def test_bitlocker_status_error(fake_probes):
    probes = fake_probes(ps={"bitlocker_status": err("Get-BitLockerVolume timed out")}, admin=False)
    result = BitlockerStatus().run(probes)
    assert result.status == "error"


def test_bitlocker_status_error_empty_without_admin(fake_probes):
    """Real-world case seen on this machine: the cmdlet succeeds but returns
    zero volumes when not elevated -- must be `error`, not a false `pass`."""
    probes = fake_probes(ps={"bitlocker_status": ok([])}, admin=False)
    result = BitlockerStatus().run(probes)
    assert result.status == "error"
    assert "administrator" in result.observed.lower()
