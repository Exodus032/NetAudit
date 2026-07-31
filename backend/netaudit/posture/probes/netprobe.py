"""psutil/socket-based probes: listening sockets and adapter inspection.

Read-only: every call here is an enumeration (`psutil.net_connections`,
`psutil.Process.name`) -- nothing here can change system state. Each probe
runs in a worker thread with an explicit timeout so a hang (e.g. a huge
connection table on a loaded box) can't stall a scan.
"""
from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as _FutureTimeoutError
from typing import Callable

import psutil

from .runner import DEFAULT_TIMEOUT_SECONDS, ProbeResult


def _run_with_timeout(fn: Callable[[], object], timeout: float):
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(fn)
        try:
            return future.result(timeout=timeout)
        except _FutureTimeoutError as exc:
            raise TimeoutError(f"timed out after {timeout:g}s") from exc


def _collect_listening_sockets() -> list[dict]:
    out: list[dict] = []
    for conn in psutil.net_connections(kind="inet"):
        if conn.status != psutil.CONN_LISTEN:
            continue
        process_name = None
        if conn.pid:
            try:
                process_name = psutil.Process(conn.pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                process_name = None
        out.append(
            {
                "ip": conn.laddr.ip if conn.laddr else None,
                "port": conn.laddr.port if conn.laddr else None,
                "pid": conn.pid,
                "process_name": process_name,
                "protocol": "tcp" if conn.type == socket.SOCK_STREAM else "udp",
            }
        )
    return out


def listening_sockets(timeout: float = DEFAULT_TIMEOUT_SECONDS) -> ProbeResult:
    try:
        data = _run_with_timeout(_collect_listening_sockets, timeout)
        return ProbeResult(ok=True, data=data)
    except TimeoutError as exc:
        return ProbeResult(ok=False, error=str(exc))
    except psutil.AccessDenied:
        return ProbeResult(ok=False, error="access denied enumerating network connections (try running as administrator)")
    except Exception as exc:  # defensive: one broken probe must not crash a scan
        return ProbeResult(ok=False, error=f"failed to enumerate listening sockets: {exc}")


# Allowlisted net-probe entry points, mirroring powershell.ALLOWLIST's shape.
ALLOWLIST: dict[str, Callable[..., ProbeResult]] = {
    "listening_sockets": listening_sockets,
}


def run(key: str, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> ProbeResult:
    if key not in ALLOWLIST:
        return ProbeResult(ok=False, error=f"unknown net probe key: {key!r}")
    return ALLOWLIST[key](timeout=timeout)
