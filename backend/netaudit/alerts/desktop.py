"""Desktop toast notifications. Degrades gracefully to a no-op with a
recorded status when unavailable (not on Windows, `powershell.exe` missing,
the call times out, or the toast APIs throw) -- this function must never
raise and never block past its own timeout.

No third-party dependency (win10toast / winotify / plyer, etc.) is added
for this -- see DEPENDENCIES.md. Instead, a short, fixed PowerShell script
(same string every time, never built from request data) drives the WinRT
`Windows.UI.Notifications` toast API. The title/message are passed through
environment variables, not string-interpolated into the script text, so
there is no way for a title or message value to break out of its `$env:`
reference and be interpreted as PowerShell code -- the same discipline
`posture/probes/powershell.py` uses for its allowlisted commands, applied
here even though this package isn't in that agent's audited scope.
"""
from __future__ import annotations

import os
import platform
import subprocess
from dataclasses import dataclass
from typing import Optional, Protocol, runtime_checkable

DEFAULT_TIMEOUT_SECONDS = 5.0

# Fixed, parameterless (beyond env-var reads) PowerShell script. Never
# built from a template or f-string with request-derived content.
_TOAST_SCRIPT = r"""
$ErrorActionPreference = "Stop"
try {
    [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType=WindowsRuntime] | Out-Null
    [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType=WindowsRuntime] | Out-Null
    $title = $env:NETAUDIT_TOAST_TITLE
    $body = $env:NETAUDIT_TOAST_BODY
    $template = @"
<toast>
  <visual>
    <binding template="ToastGeneric">
      <text></text>
      <text></text>
    </binding>
  </visual>
</toast>
"@
    $xml = New-Object Windows.Data.Xml.Dom.XmlDocument
    $xml.LoadXml($template)
    $textNodes = $xml.GetElementsByTagName("text")
    $textNodes.Item(0).AppendChild($xml.CreateTextNode($title)) | Out-Null
    $textNodes.Item(1).AppendChild($xml.CreateTextNode($body)) | Out-Null
    $toast = New-Object Windows.UI.Notifications.ToastNotification $xml
    $notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("NetAudit")
    $notifier.Show($toast)
    exit 0
} catch {
    Write-Error $_.Exception.Message
    exit 1
}
"""


@dataclass(frozen=True)
class DesktopResult:
    status: str  # "delivered" | "failed" | "unavailable"
    detail: Optional[str] = None


@runtime_checkable
class DesktopSender(Protocol):
    def send(self, title: str, message: str, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> DesktopResult: ...


class RealDesktopSender:
    """The real sender -- spawns `powershell.exe` with a fixed argv list
    (`shell=False`) and the title/message passed only via environment
    variables, never concatenated into the script text."""

    def send(self, title: str, message: str, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> DesktopResult:
        if platform.system() != "Windows":
            return DesktopResult(status="unavailable", detail="not running on Windows")

        env = dict(os.environ)
        env["NETAUDIT_TOAST_TITLE"] = title
        env["NETAUDIT_TOAST_BODY"] = message

        argv = [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-WindowStyle",
            "Hidden",
            "-Command",
            "-",  # read the script from stdin, not the command line, to avoid any argv length/escaping surprises
        ]
        try:
            proc = subprocess.run(
                argv,
                input=_TOAST_SCRIPT,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env,
                shell=False,
            )
        except subprocess.TimeoutExpired:
            return DesktopResult(status="failed", detail=f"toast timed out after {timeout:g}s")
        except FileNotFoundError:
            return DesktopResult(status="unavailable", detail="powershell.exe not found")
        except OSError as exc:
            return DesktopResult(status="failed", detail=f"could not launch powershell.exe: {exc}")

        if proc.returncode == 0:
            return DesktopResult(status="delivered")
        return DesktopResult(status="failed", detail=(proc.stderr or "toast script exited non-zero").strip()[:300])


_REAL_SENDER = RealDesktopSender()


def send_desktop_notification(title: str, message: str, timeout: float = DEFAULT_TIMEOUT_SECONDS, sender: Optional[DesktopSender] = None) -> DesktopResult:
    sender = sender or _REAL_SENDER
    try:
        return sender.send(title, message, timeout)
    except Exception as exc:  # belt and suspenders: this must never raise or crash a dispatch
        return DesktopResult(status="failed", detail=f"unexpected error: {exc}")
