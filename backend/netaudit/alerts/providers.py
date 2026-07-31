"""FastAPI dependency wiring for the two pluggable senders. Both default to
the real implementation; tests override with a fake so the suite never
touches a real socket or spawns a real `powershell.exe`.
"""
from __future__ import annotations

from typing import Optional

from .desktop import DesktopSender, RealDesktopSender
from .webhook import RealTransport, Transport

_default_transport: Optional[Transport] = None
_default_desktop_sender: Optional[DesktopSender] = None


def get_webhook_transport() -> Transport:
    global _default_transport
    if _default_transport is None:
        _default_transport = RealTransport()
    return _default_transport


def get_desktop_sender() -> DesktopSender:
    global _default_desktop_sender
    if _default_desktop_sender is None:
        _default_desktop_sender = RealDesktopSender()
    return _default_desktop_sender
