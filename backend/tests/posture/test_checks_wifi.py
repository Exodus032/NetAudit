"""Every wifi check: pass / fail / error via fake probe results, plus the
`skipped` path when there's no wireless interface (a real, common case this
package must handle without erroring)."""
from __future__ import annotations

from netaudit.posture.checks.wifi import (
    WifiAutoconnectOpen,
    WifiEncryptionStrength,
    WifiOpenNetworksSaved,
)

from .conftest import err, ok

_CONNECTED_WPA2 = "Name : Wi-Fi\nState : connected\nAuthentication : WPA2-Personal\nCipher : CCMP\n"
_CONNECTED_OPEN = "Name : Wi-Fi\nState : connected\nAuthentication : Open\nCipher : None\n"
_NO_ADAPTER = "There is no wireless interface on the system.\n"


def test_wifi_encryption_strength_pass(fake_probes):
    probes = fake_probes(ps={"wifi_interfaces": ok(_CONNECTED_WPA2)})
    result = WifiEncryptionStrength().run(probes)
    assert result.status == "pass"


def test_wifi_encryption_strength_fail(fake_probes):
    probes = fake_probes(ps={"wifi_interfaces": ok(_CONNECTED_OPEN)})
    result = WifiEncryptionStrength().run(probes)
    assert result.status == "fail"


def test_wifi_encryption_strength_skipped_when_no_adapter(fake_probes):
    probes = fake_probes(ps={"wifi_interfaces": ok(_NO_ADAPTER)})
    result = WifiEncryptionStrength().run(probes)
    assert result.status == "skipped"


def test_wifi_encryption_strength_error(fake_probes):
    probes = fake_probes(ps={"wifi_interfaces": err("netsh not found")})
    result = WifiEncryptionStrength().run(probes)
    assert result.status == "error"


def test_wifi_open_networks_saved_pass(fake_probes):
    probes = fake_probes(ps={
        "wifi_interfaces": ok(_CONNECTED_WPA2),
        "wifi_profiles": ok([{"name": "Home", "authentication": "WPA2-Personal", "cipher": "CCMP", "connection_mode": "Auto Connect"}]),
    })
    result = WifiOpenNetworksSaved().run(probes)
    assert result.status == "pass"


def test_wifi_open_networks_saved_fail(fake_probes):
    probes = fake_probes(ps={
        "wifi_interfaces": ok(_CONNECTED_WPA2),
        "wifi_profiles": ok([{"name": "Cafe", "authentication": "Open", "cipher": "None", "connection_mode": "Manual Connect"}]),
    })
    result = WifiOpenNetworksSaved().run(probes)
    assert result.status == "fail"
    assert "Cafe" in result.observed


def test_wifi_open_networks_saved_error(fake_probes):
    probes = fake_probes(ps={"wifi_interfaces": ok(_CONNECTED_WPA2), "wifi_profiles": err("netsh wlan show profiles failed")})
    result = WifiOpenNetworksSaved().run(probes)
    assert result.status == "error"


def test_wifi_open_networks_saved_skipped(fake_probes):
    probes = fake_probes(ps={"wifi_interfaces": ok(_NO_ADAPTER), "wifi_profiles": ok([])})
    result = WifiOpenNetworksSaved().run(probes)
    assert result.status == "skipped"


def test_wifi_autoconnect_open_pass(fake_probes):
    probes = fake_probes(ps={
        "wifi_interfaces": ok(_CONNECTED_WPA2),
        "wifi_profiles": ok([{"name": "Cafe", "authentication": "Open", "cipher": "None", "connection_mode": "Manual Connect"}]),
    })
    result = WifiAutoconnectOpen().run(probes)
    assert result.status == "pass"


def test_wifi_autoconnect_open_fail(fake_probes):
    probes = fake_probes(ps={
        "wifi_interfaces": ok(_CONNECTED_WPA2),
        "wifi_profiles": ok([{"name": "Cafe", "authentication": "Open", "cipher": "None", "connection_mode": "Auto Connect"}]),
    })
    result = WifiAutoconnectOpen().run(probes)
    assert result.status == "fail"
    assert "Cafe" in result.observed


def test_wifi_autoconnect_open_error(fake_probes):
    probes = fake_probes(ps={"wifi_interfaces": ok(_CONNECTED_WPA2), "wifi_profiles": err("netsh wlan show profiles failed")})
    result = WifiAutoconnectOpen().run(probes)
    assert result.status == "error"
