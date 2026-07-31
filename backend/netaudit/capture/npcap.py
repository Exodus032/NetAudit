"""Npcap capture tier via scapy. Full L2 headers, both directions, all
protocols. Requires scapy importable, admin, and Npcap installed (scapy's
L2 socket will fail to open otherwise)."""
from __future__ import annotations

import threading
import time

from .. import config
from .base import CaptureBackend, PacketEvent
from .enrich import ProcessTable

try:
    from scapy.all import AsyncSniffer, IP, TCP, UDP, ICMP  # type: ignore
    SCAPY_AVAILABLE = True
except Exception:  # pragma: no cover - environment dependent
    SCAPY_AVAILABLE = False


class NpcapBackend(CaptureBackend):
    tier = "npcap"

    def __init__(self, queue_max: int = config.CAPTURE_QUEUE_MAX) -> None:
        super().__init__(queue_max=queue_max)
        self._sniffer = None
        self._proc_table = ProcessTable()
        self._refresh_thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    def start(self, interface_id: str | None = None) -> None:
        if not SCAPY_AVAILABLE:
            raise RuntimeError("scapy is not available")
        if self._running:
            return
        self.interface_id = interface_id
        self._stop_event.clear()
        self._running = True

        self._refresh_thread = threading.Thread(target=self._refresh_loop, daemon=True, name="netaudit-npcap-proc")
        self._refresh_thread.start()

        kwargs = {"prn": self._on_packet, "store": False}
        if interface_id:
            kwargs["iface"] = interface_id
        self._sniffer = AsyncSniffer(**kwargs)
        self._sniffer.start()

    def stop(self) -> None:
        self._running = False
        self._stop_event.set()
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:
                pass
            self._sniffer = None
        if self._refresh_thread is not None:
            self._refresh_thread.join(timeout=2.0)
            self._refresh_thread = None

    def _refresh_loop(self) -> None:
        while not self._stop_event.is_set():
            self._proc_table.refresh()
            self._stop_event.wait(1.0)

    def _on_packet(self, pkt) -> None:
        try:
            if IP not in pkt:
                return
            ip = pkt[IP]
            now = time.time()
            length = int(ip.len) if ip.len else len(bytes(pkt))
            if TCP in pkt:
                tcp = pkt[TCP]
                protocol = "tcp"
                src_port, dst_port = int(tcp.sport), int(tcp.dport)
                flag_names = []
                for ch, name in (("F", "FIN"), ("S", "SYN"), ("R", "RST"), ("P", "PSH"), ("A", "ACK"), ("U", "URG")):
                    if ch in str(tcp.flags):
                        flag_names.append(name)
                flags = ",".join(flag_names)
            elif UDP in pkt:
                udp = pkt[UDP]
                protocol = "udp"
                src_port, dst_port = int(udp.sport), int(udp.dport)
                flags = ""
            elif ICMP in pkt:
                protocol = "icmp"
                src_port = dst_port = None
                flags = ""
            else:
                protocol = "other"
                src_port = dst_port = None
                flags = ""

            pid = name = path = None
            for port in (src_port, dst_port):
                pid, name, path = self._proc_table.lookup(protocol, port)
                if pid is not None:
                    break

            self._emit(PacketEvent(
                ts=now,
                protocol=protocol,
                src_addr=str(ip.src),
                dst_addr=str(ip.dst),
                src_port=src_port,
                dst_port=dst_port,
                length=length,
                flags=flags,
                pid=pid,
                process_name=name,
                process_path=path,
            ))
        except Exception:
            # Never let a malformed/unusual packet kill the sniffer thread.
            return


def probe() -> None:
    """Raise if the npcap tier isn't usable (scapy missing, or no working
    L2 socket -- e.g. Npcap not installed). Cheap: opens and immediately
    closes a short-lived sniffer."""
    if not SCAPY_AVAILABLE:
        raise RuntimeError("scapy is not importable")
    sniffer = AsyncSniffer(store=False, prn=lambda p: None)
    sniffer.start()
    time.sleep(0.05)
    sniffer.stop()
