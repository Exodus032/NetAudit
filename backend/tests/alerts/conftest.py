from __future__ import annotations

import socket

import pytest

from netaudit.alerts.webhook import WebhookResult
from netaudit.store import db as dbmod


@pytest.fixture
def db_path(tmp_path):
    path = tmp_path / "test.db"
    yield path
    dbmod.reset_for_tests(path)


class FakeTransport:
    """Records every call; never opens a socket. `responses` is a list of
    WebhookResult consumed in order (repeats the last one once exhausted)."""

    def __init__(self, responses=None):
        self.calls = []
        self._responses = list(responses) if responses else [WebhookResult(ok=True, status_code=200, detail="HTTP 200")]

    def send(self, *, ip, port, host, path, body, headers, timeout):
        self.calls.append({"ip": ip, "port": port, "host": host, "path": path, "body": body, "headers": headers, "timeout": timeout})
        if len(self._responses) > 1:
            return self._responses.pop(0)
        return self._responses[0]


@pytest.fixture
def fake_transport():
    return FakeTransport()


def fake_getaddrinfo(answers: dict[str, list[str]]):
    """Builds a drop-in replacement for socket.getaddrinfo backed by a
    fixed host->[ip,...] table, so SSRF tests never touch real DNS."""

    def _fake(host, port, *args, **kwargs):
        if host not in answers:
            raise socket.gaierror(f"no fake answer configured for host {host!r}")
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port)) for ip in answers[host]]

    return _fake
