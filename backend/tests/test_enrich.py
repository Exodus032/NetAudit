from __future__ import annotations

import psutil
import pytest

from netaudit.capture.enrich import resolve_process


class _FakeProcess:
    def __init__(self, pid, name="chrome.exe", path=r"C:\chrome.exe", raises=None):
        self.pid = pid
        self._name = name
        self._path = path
        self._raises = raises

    def name(self):
        if self._raises:
            raise self._raises
        return self._name

    def exe(self):
        if self._raises:
            raise self._raises
        return self._path


class TestResolveProcess:
    """Attribution has to be honest. A wrong process name on a network
    connection is worse than no process name: it sends someone hunting the
    wrong binary, and once they notice it was nonsense they stop trusting
    the rest of the screen too."""

    def test_pid_zero_is_not_attributed_to_the_idle_process(self, monkeypatch):
        """Windows reports PID 0 for sockets it will not attribute. Asking
        psutil for its name returns "System Idle Process", which cannot
        possibly have opened a socket to the internet."""
        called = []

        def _spy(pid):
            called.append(pid)
            return _FakeProcess(pid, name="System Idle Process")

        monkeypatch.setattr(psutil, "Process", _spy)
        assert resolve_process(0) == (None, None, None)
        assert called == [], "PID 0 must not even be looked up"

    def test_none_pid_is_unattributed(self):
        assert resolve_process(None) == (None, None, None)

    def test_pid_four_is_left_alone_because_the_kernel_really_does_own_traffic(self, monkeypatch):
        monkeypatch.setattr(psutil, "Process", lambda pid: _FakeProcess(pid, name="System", path=None))
        assert resolve_process(4) == (4, "System", None)

    def test_a_normal_process_resolves_to_name_and_path(self, monkeypatch):
        monkeypatch.setattr(psutil, "Process", lambda pid: _FakeProcess(pid))
        assert resolve_process(8842) == (8842, "chrome.exe", r"C:\chrome.exe")

    @pytest.mark.parametrize("exc", [
        psutil.NoSuchProcess(1),
        psutil.AccessDenied(1),
        OSError("handle closed"),
        RuntimeError("something else entirely"),
    ])
    def test_the_pid_survives_when_the_name_cannot_be_read(self, monkeypatch, exc):
        """A process that exited between enumeration and lookup, or one this
        token cannot open, still had a real PID worth reporting."""
        monkeypatch.setattr(psutil, "Process", lambda pid: _FakeProcess(pid, raises=exc))
        assert resolve_process(8842) == (8842, None, None)
