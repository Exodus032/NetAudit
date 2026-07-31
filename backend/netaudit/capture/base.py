"""Common interface every capture tier implements."""
from __future__ import annotations

import queue
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class PacketEvent:
    """A single observed packet or (for the polling tier) a synthesized
    flow sample. This is the only shape the rest of the pipeline needs to
    understand -- each capture tier is responsible for producing it."""

    ts: float  # epoch seconds
    protocol: str  # "tcp" | "udp" | "icmp" | "other"
    src_addr: str
    dst_addr: str
    src_port: int | None = None
    dst_port: int | None = None
    length: int = 0
    flags: str = ""
    pid: int | None = None
    process_name: str | None = None
    process_path: str | None = None
    state: str | None = None  # e.g. ESTABLISHED, for connection-oriented tiers
    bytes_in: int = 0
    bytes_out: int = 0
    synthetic: bool = False  # True for the polling tier's estimated samples


class CaptureBackend(ABC):
    """Base class for a capture tier. Subclasses run their own background
    thread in start() and push PacketEvents into self._queue. Consumers
    call drain() from the asyncio ingest loop; nothing here touches asyncio
    directly so the tiers stay trivially testable."""

    tier: str = "off"

    def __init__(self, queue_max: int = 20000) -> None:
        self._queue: "queue.Queue[PacketEvent]" = queue.Queue(maxsize=queue_max)
        self._running = False
        self._lock = threading.Lock()
        self._dropped = 0
        self.degraded_reason: str | None = None
        self.interface_id: str | None = None

    @property
    def running(self) -> bool:
        return self._running

    @abstractmethod
    def start(self, interface_id: str | None = None) -> None:
        ...

    @abstractmethod
    def stop(self) -> None:
        ...

    def _emit(self, event: PacketEvent) -> None:
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            # Backpressure: drop rather than block the capture thread.
            self._dropped += 1
            try:
                self._queue.get_nowait()
                self._queue.put_nowait(event)
            except queue.Empty:
                pass

    def drain(self, max_items: int = 1000) -> list[PacketEvent]:
        items: list[PacketEvent] = []
        while len(items) < max_items:
            try:
                items.append(self._queue.get_nowait())
            except queue.Empty:
                break
        return items
