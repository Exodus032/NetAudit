"""Raw-socket capture tier: SIO_RCVALL promiscuous IPv4 capture. Requires
admin, does not require Npcap. Windows-only (uses socket.SIO_RCVALL /
socket.RCVALL_ON, which only exist on the Windows socket module)."""
from __future__ import annotations

import socket
import threading
import time

from .. import config
from .base import CaptureBackend, PacketEvent
from .enrich import ProcessTable
from .parse import parse_ipv4_packet


class RawSocketBackend(CaptureBackend):
    tier = "rawsocket"

    def __init__(self, queue_max: int = config.CAPTURE_QUEUE_MAX) -> None:
        super().__init__(queue_max=queue_max)
        self._thread: threading.Thread | None = None
        self._sock: socket.socket | None = None
        self._stop_event = threading.Event()
        self._proc_table = ProcessTable()

    def start(self, interface_id: str | None = None) -> None:
        if self._running:
            return
        self.interface_id = interface_id
        bind_ip = _resolve_bind_ip(interface_id)
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        sock.bind((bind_ip, 0))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        sock.settimeout(1.0)
        self._sock = sock
        self._stop_event.clear()
        self._running = True
        self._thread = threading.Thread(target=self._run, name="netaudit-rawsock", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        self._stop_event.set()
        if self._sock is not None:
            try:
                self._sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except OSError:
                pass
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None

    def _run(self) -> None:
        last_proc_refresh = 0.0
        while not self._stop_event.is_set() and self._sock is not None:
            now = time.time()
            if now - last_proc_refresh > 1.0:
                self._proc_table.refresh()
                last_proc_refresh = now
            try:
                data, _addr = self._sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            parsed = parse_ipv4_packet(data)
            if parsed is None:
                continue
            pid = name = path = None
            local_port = None
            if parsed.src_addr == self.interface_id or True:
                # We don't know direction for sure without comparing to the
                # bound interface IP; try both ports against the process
                # table since only one will match a local socket.
                for port in (parsed.src_port, parsed.dst_port):
                    pid, name, path = self._proc_table.lookup(parsed.protocol, port)
                    if pid is not None:
                        local_port = port
                        break
            event = PacketEvent(
                ts=now,
                protocol=parsed.protocol,
                src_addr=parsed.src_addr,
                src_port=parsed.src_port,
                dst_addr=parsed.dst_addr,
                dst_port=parsed.dst_port,
                length=parsed.length,
                flags=parsed.flags,
                pid=pid,
                process_name=name,
                process_path=path,
            )
            self._emit(event)


def _resolve_bind_ip(interface_id: str | None) -> str:
    if interface_id:
        try:
            import psutil

            addrs = psutil.net_if_addrs().get(interface_id, [])
            for a in addrs:
                if a.family == socket.AF_INET:
                    return a.address
        except Exception:
            pass
    return socket.gethostbyname(socket.gethostname())


def probe() -> None:
    """Raise if raw-socket capture isn't usable on this host (used by the
    tier selector -- never call start() just to test capability)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    try:
        sock.bind((_resolve_bind_ip(None), 0))
        sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
    finally:
        sock.close()
