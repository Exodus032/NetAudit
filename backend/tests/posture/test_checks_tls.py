"""Every tls check: pass / fail / error via fake probe results."""
from __future__ import annotations

from netaudit.posture.checks.tls import (
    CertificateStoreAnomalies,
    Ssl3Disabled,
    Tls1011Disabled,
    WeakCiphersDisabled,
)

from .conftest import err, ok

_DISABLED = ok({"Enabled": 0, "DisabledByDefault": 1})
_ENABLED = ok({"Enabled": 1})


class _ExplodingProbes:
    """`Tls1011Disabled`/`Ssl3Disabled` read every registry value directly
    (no `require_ok`) since a missing/unreadable value is legitimately
    "not configured", not an error. To reach the error path we need the
    probe layer itself to blow up, not just report ok=False."""

    def registry(self, key):
        raise RuntimeError("winreg exploded")


def test_tls1011_disabled_pass(fake_probes):
    probes = fake_probes(registry={
        "schannel_tls10_client": _DISABLED, "schannel_tls10_server": _DISABLED,
        "schannel_tls11_client": _DISABLED, "schannel_tls11_server": _DISABLED,
    })
    result = Tls1011Disabled().run(probes)
    assert result.status == "pass"


def test_tls1011_disabled_fail(fake_probes):
    probes = fake_probes(registry={
        "schannel_tls10_client": _ENABLED, "schannel_tls10_server": _DISABLED,
        "schannel_tls11_client": _DISABLED, "schannel_tls11_server": _DISABLED,
    })
    result = Tls1011Disabled().run(probes)
    assert result.status == "fail"


def test_tls1011_disabled_error():
    result = Tls1011Disabled().run(_ExplodingProbes())
    assert result.status == "error"


def test_ssl3_disabled_pass(fake_probes):
    probes = fake_probes(registry={"schannel_ssl3_client": _DISABLED, "schannel_ssl3_server": _DISABLED})
    result = Ssl3Disabled().run(probes)
    assert result.status == "pass"


def test_ssl3_disabled_fail(fake_probes):
    probes = fake_probes(registry={"schannel_ssl3_client": _ENABLED, "schannel_ssl3_server": _DISABLED})
    result = Ssl3Disabled().run(probes)
    assert result.status == "fail"


def test_ssl3_disabled_error():
    result = Ssl3Disabled().run(_ExplodingProbes())
    assert result.status == "error"


def test_weak_ciphers_disabled_pass(fake_probes):
    probes = fake_probes(ps={"tls_cipher_suites": ok([{"Name": "TLS_AES_256_GCM_SHA384"}, {"Name": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"}])})
    result = WeakCiphersDisabled().run(probes)
    assert result.status == "pass"


def test_weak_ciphers_disabled_fail(fake_probes):
    probes = fake_probes(ps={"tls_cipher_suites": ok([{"Name": "TLS_RSA_WITH_RC4_128_SHA"}])})
    result = WeakCiphersDisabled().run(probes)
    assert result.status == "fail"
    assert "RC4" in result.observed


def test_weak_ciphers_disabled_error(fake_probes):
    probes = fake_probes(ps={"tls_cipher_suites": err("Get-TlsCipherSuite is not available on this Windows build")})
    result = WeakCiphersDisabled().run(probes)
    assert result.status == "error"


def test_weak_ciphers_disabled_handles_null_name(fake_probes):
    """Regression test: a cipher entry with a JSON null Name must not crash
    the check (found on a real scan -- `'NoneType' object has no attribute
    'upper'`)."""
    probes = fake_probes(ps={"tls_cipher_suites": ok([{"Name": None}, {"Name": "TLS_AES_256_GCM_SHA384"}])})
    result = WeakCiphersDisabled().run(probes)
    assert result.status == "pass"


def test_certificate_store_anomalies_pass(fake_probes):
    probes = fake_probes(ps={"cert_store_root": ok([{"Subject": "CN=Good CA", "NotAfter": "2099-01-01T00:00:00Z", "Thumbprint": "AAAA"}])})
    result = CertificateStoreAnomalies().run(probes)
    assert result.status == "pass"


def test_certificate_store_anomalies_fail_ish_warn(fake_probes):
    # Expired-but-trusted roots are surfaced as `warn` (medium severity,
    # maintenance hygiene) rather than a hard `fail`.
    probes = fake_probes(ps={"cert_store_root": ok([{"Subject": "CN=Old CA", "NotAfter": "2001-01-01T00:00:00Z", "Thumbprint": "BBBB"}])})
    result = CertificateStoreAnomalies().run(probes)
    assert result.status == "warn"
    assert any("Old CA" in item.label for item in result.evidence)


def test_certificate_store_anomalies_error(fake_probes):
    probes = fake_probes(ps={"cert_store_root": err("access denied")})
    result = CertificateStoreAnomalies().run(probes)
    assert result.status == "error"
