"""Probes capability tiers in order (npcap > rawsocket > polling) and
returns a ready-to-start backend instance plus health metadata. Never
raises -- always falls back to polling, which requires zero privileges."""
from __future__ import annotations

import ctypes
from dataclasses import dataclass

from .base import CaptureBackend
from .polling import PollingBackend


def is_elevated() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:
        return False


@dataclass
class TierSelection:
    backend: CaptureBackend
    mode: str
    elevated: bool
    degraded_reason: str | None


def select_tier(prefer_npcap_probe=None, prefer_rawsocket_probe=None) -> TierSelection:
    """`prefer_*_probe` let tests inject fake probes; production callers
    leave them None and get the real npcap/rawsock probes."""
    elevated = is_elevated()

    if not elevated:
        return TierSelection(
            backend=PollingBackend(),
            mode="polling",
            elevated=False,
            # Names the two consequences a user will actually notice, rather
            # than only the tier name. The blank process column is the one
            # that gets read as a bug: without elevation Windows will not
            # name the owner of a socket belonging to another account, so
            # most rows are honestly unattributed rather than wrong.
            degraded_reason=(
                "Not running as Administrator; using connection-table polling. "
                "Traffic is sampled from the connection table rather than read "
                "per packet, and most connections cannot be attributed to a "
                "process. Restart as Administrator for full capture."
            ),
        )

    npcap_probe = prefer_npcap_probe
    if npcap_probe is None:
        from . import npcap as npcap_mod
        npcap_probe = npcap_mod.probe

    try:
        npcap_probe()
        from .npcap import NpcapBackend
        return TierSelection(backend=NpcapBackend(), mode="npcap", elevated=True, degraded_reason=None)
    except Exception as npcap_err:
        npcap_reason = str(npcap_err) or "unavailable"

    rawsock_probe = prefer_rawsocket_probe
    if rawsock_probe is None:
        from . import rawsock as rawsock_mod
        rawsock_probe = rawsock_mod.probe

    try:
        rawsock_probe()
        from .rawsock import RawSocketBackend
        return TierSelection(
            backend=RawSocketBackend(),
            mode="rawsocket",
            elevated=True,
            degraded_reason=f"Npcap not installed or unavailable ({npcap_reason}); using raw sockets instead.",
        )
    except Exception as rawsock_err:
        return TierSelection(
            backend=PollingBackend(),
            mode="polling",
            elevated=True,
            degraded_reason=(
                f"Npcap unavailable ({npcap_reason}) and raw sockets unavailable "
                f"({rawsock_err or 'unavailable'}); falling back to connection-table polling."
            ),
        )
