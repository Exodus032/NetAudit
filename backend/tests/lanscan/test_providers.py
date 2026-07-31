"""Proves, structurally, that the real connector can only ever do a plain
TCP connect scan -- no raw sockets, no scapy, no SYN-only construction, no
banner reading. A regression here (someone adding `socket.SOCK_RAW` or a
`scapy` import to "improve" the scanner) should fail this test on its own,
independent of anything a behavioral test could catch.
"""
from __future__ import annotations

from pathlib import Path

import netaudit.lanscan as lanscan_pkg

PACKAGE_DIR = Path(lanscan_pkg.__file__).resolve().parent

_FORBIDDEN_MARKERS = (
    "SOCK_RAW",
    "scapy",
    "IPPROTO_RAW",
    "AF_PACKET",
    ".recv(",  # a connect-scan closes immediately; it must never read a banner
    "sendto(",
)


def test_no_raw_socket_or_banner_reading_anywhere_in_package():
    offenders = []
    for path in PACKAGE_DIR.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        for marker in _FORBIDDEN_MARKERS:
            if marker in text:
                offenders.append(f"{path.relative_to(PACKAGE_DIR)}: found {marker!r}")
    assert not offenders, "raw-socket/banner-reading marker found in lanscan package:\n" + "\n".join(offenders)


def test_real_connector_uses_plain_stream_socket_connect(monkeypatch):
    from netaudit.lanscan.providers import RealPortConnector

    calls = {}

    class FakeSocket:
        def __init__(self, family, type_):
            calls["family"] = family
            calls["type"] = type_

        def settimeout(self, t):
            calls["timeout"] = t

        def connect_ex(self, addr):
            calls["addr"] = addr
            return 0

        def close(self):
            calls["closed"] = True

    import socket as socket_module

    monkeypatch.setattr(socket_module, "socket", FakeSocket)
    connector = RealPortConnector()
    result = connector.try_connect("192.168.1.5", 22, 1.0)

    assert result is True
    assert calls["family"] == socket_module.AF_INET
    assert calls["type"] == socket_module.SOCK_STREAM  # never SOCK_RAW
    assert calls["addr"] == ("192.168.1.5", 22)
    assert calls["closed"] is True


def test_real_connector_returns_false_on_refused_or_timeout(monkeypatch):
    from netaudit.lanscan.providers import RealPortConnector

    class RefusingSocket:
        def __init__(self, *a):
            pass

        def settimeout(self, t):
            pass

        def connect_ex(self, addr):
            return 111  # ECONNREFUSED

        def close(self):
            pass

    import socket as socket_module

    monkeypatch.setattr(socket_module, "socket", RefusingSocket)
    connector = RealPortConnector()
    assert connector.try_connect("192.168.1.5", 12345, 1.0) is False


def test_real_connector_never_raises_on_oserror(monkeypatch):
    from netaudit.lanscan.providers import RealPortConnector

    class ExplodingSocket:
        def __init__(self, *a):
            pass

        def settimeout(self, t):
            raise OSError("network unreachable")

        def connect_ex(self, addr):
            raise AssertionError("should not be reached")

        def close(self):
            pass

    import socket as socket_module

    monkeypatch.setattr(socket_module, "socket", ExplodingSocket)
    connector = RealPortConnector()
    assert connector.try_connect("192.168.1.5", 22, 1.0) is False
