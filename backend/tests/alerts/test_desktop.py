from __future__ import annotations

import subprocess

from netaudit.alerts.desktop import DesktopResult, send_desktop_notification


class RaisingSender:
    def __init__(self, exc):
        self._exc = exc

    def send(self, title, message, timeout=5.0):
        raise self._exc


class ScriptedSender:
    def __init__(self, result: DesktopResult):
        self._result = result

    def send(self, title, message, timeout=5.0):
        return self._result


def test_unavailable_status_never_raises():
    sender = ScriptedSender(DesktopResult(status="unavailable", detail="not running on Windows"))
    result = send_desktop_notification("t", "m", sender=sender)
    assert result.status == "unavailable"


def test_timeout_becomes_failed_status_not_an_exception():
    sender = RaisingSender(subprocess.TimeoutExpired(cmd="powershell.exe", timeout=5))
    result = send_desktop_notification("t", "m", sender=sender)
    assert result.status == "failed"
    assert "unexpected error" in result.detail


def test_unexpected_exception_never_propagates():
    sender = RaisingSender(RuntimeError("boom"))
    result = send_desktop_notification("t", "m", sender=sender)
    assert result.status == "failed"


def test_nonzero_exit_is_failed():
    sender = ScriptedSender(DesktopResult(status="failed", detail="toast script exited non-zero"))
    result = send_desktop_notification("t", "m", sender=sender)
    assert result.status == "failed"


def test_real_sender_argv_is_a_list_not_a_shell_string(monkeypatch):
    """Confirms the real sender never builds a shell command string, and
    that the title/message are passed via env, not embedded in argv or the
    script text -- so a title containing PowerShell-special characters
    (quotes, `$(...)`, backticks) can never be interpreted as code."""
    from netaudit.alerts.desktop import RealDesktopSender

    captured = {}

    class FakeCompletedProcess:
        returncode = 0
        stderr = ""

    def fake_run(argv, input=None, capture_output=None, text=None, timeout=None, env=None, shell=None):
        captured["argv"] = argv
        captured["input"] = input
        captured["env"] = env
        captured["shell"] = shell
        return FakeCompletedProcess()

    monkeypatch.setattr("netaudit.alerts.desktop.platform.system", lambda: "Windows")
    monkeypatch.setattr("netaudit.alerts.desktop.subprocess.run", fake_run)

    hostile_title = '$(Remove-Item C:\\ -Recurse -Force); "quote"; `backtick`'
    result = RealDesktopSender().send(hostile_title, "body text")

    assert result.status == "delivered"
    assert isinstance(captured["argv"], list)
    assert captured["shell"] is False
    # the hostile string must appear only in the env var, never in argv or the script text
    assert hostile_title not in captured["argv"]
    assert hostile_title not in captured["input"]
    assert captured["env"]["NETAUDIT_TOAST_TITLE"] == hostile_title


def test_real_sender_not_windows_is_unavailable(monkeypatch):
    from netaudit.alerts.desktop import RealDesktopSender

    monkeypatch.setattr("netaudit.alerts.desktop.platform.system", lambda: "Linux")
    result = RealDesktopSender().send("t", "m")
    assert result.status == "unavailable"
