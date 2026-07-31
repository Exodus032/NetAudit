"""Decoupling: this package never imports anything outside itself. It
needs two things from the rest of the backend -- what interfaces this
machine actually has, and a way to attempt a TCP connect -- both defined
here as Protocols, resolved through FastAPI dependencies the orchestrator
overrides with real implementations.
"""
from __future__ import annotations

from typing import Iterable, Optional, Protocol, runtime_checkable


@runtime_checkable
class InterfaceProvider(Protocol):
    """What this package needs to know about the machine's own network
    interfaces to verify a scan target is actually local. Each dict needs
    `address` (str, e.g. "192.168.1.42") and `prefixlen` (int, e.g. 24).
    """

    def interfaces(self) -> Iterable[dict]: ...


@runtime_checkable
class PortConnector(Protocol):
    """A single TCP connect attempt. Returns True if the port accepted a
    connection within `timeout` seconds, False otherwise (refused,
    filtered, or timed out) -- never raises for an ordinary closed/filtered
    port."""

    def try_connect(self, ip: str, port: int, timeout: float) -> bool: ...


class RealPortConnector:
    """TCP **connect** scan only -- opens a normal `socket.connect()`
    (SOCK_STREAM) and closes it immediately. No raw sockets, no crafted
    packets, no SYN-only/stealth scanning, no OS fingerprinting, no banner
    grabbing/reading, no credential testing. This is the only place in the
    package that touches a socket."""

    def try_connect(self, ip: str, port: int, timeout: float) -> bool:
        import socket

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            return result == 0
        except OSError:
            return False
        finally:
            sock.close()


class StaticInterfaceProvider:
    def __init__(self, interfaces: Optional[list[dict]] = None) -> None:
        self._interfaces = list(interfaces or [])

    def interfaces(self) -> list[dict]:
        return list(self._interfaces)


_default_interface_provider: Optional[InterfaceProvider] = None
_default_connector: Optional[PortConnector] = None


def get_interface_provider() -> InterfaceProvider:
    """Defaults to reporting no interfaces at all (so, absent an override,
    every scan request is correctly rejected as not matching a real
    interface, rather than defaulting open)."""
    global _default_interface_provider
    if _default_interface_provider is None:
        _default_interface_provider = StaticInterfaceProvider([])
    return _default_interface_provider


def get_port_connector() -> PortConnector:
    global _default_connector
    if _default_connector is None:
        _default_connector = RealPortConnector()
    return _default_connector
