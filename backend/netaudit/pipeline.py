"""Owns the running capture backend and the background asyncio tasks that
drain it: ingest (capture -> enrich -> SQLite), retention sweeps, the
rules engine tick, and ARP-based device discovery. This is the piece that
turns a queue of PacketEvents into everything the API layer reads."""
from __future__ import annotations

import asyncio
import json
import time

from . import arpscan, config, netinfo
from .capture.base import PacketEvent
from .capture.enrich import ReverseDnsCache, classify_external, is_encrypted_port, mac_vendor
from .capture.selector import select_tier
from .risk import classify_risk
from .rules import engine as rules_engine
from .store import db as dbmod
from .store import devices as devices_store
from .store import flows as flows_store
from .store import packets as packets_store
from .store import retention as retention_store
from .store import stats as stats_store

RULES_WINDOW_SECONDS = 3600.0  # rules look at the last hour of flows/packets


class Pipeline:
    def __init__(self, db_path=None) -> None:
        self.db_path = db_path
        self.backend = None
        self.mode = "off"
        self.elevated = False
        self.degraded_reason: str | None = None
        self.interface_id: str | None = None
        self.start_time = time.time()
        self.dns_cache = ReverseDnsCache()
        self._running = False
        self._self_ips: set[str] = set()
        self._tasks: list[asyncio.Task] = []
        self.ws_clients: set = set()

    # --- capture control -----------------------------------------------

    def start(self, interface_id: str | None = None) -> None:
        selection = select_tier()
        self.backend = selection.backend
        self.mode = selection.mode
        self.elevated = selection.elevated
        self.degraded_reason = selection.degraded_reason

        chosen = interface_id or config.DEFAULT_INTERFACE_ID or netinfo.default_interface_id()
        self.interface_id = chosen
        self._refresh_self_ips()
        try:
            self.backend.start(chosen)
            self._running = True
        except Exception as exc:
            # Even the chosen backend can fail at start() time (e.g. a race
            # where npcap probed OK but the real sniffer can't open) --
            # degrade to polling rather than leaving capture off.
            from .capture.polling import PollingBackend
            self.backend = PollingBackend()
            self.mode = "polling"
            self.degraded_reason = f"{selection.mode} capture failed to start ({exc}); using polling."
            self.backend.start(chosen)
            self._running = True

    def stop(self) -> None:
        if self.backend is not None:
            self.backend.stop()
        self._running = False

    def restart(self, interface_id: str | None = None) -> None:
        self.stop()
        self.start(interface_id or self.interface_id)

    def capture_status(self) -> dict:
        return {
            "mode": self.mode,
            "elevated": self.elevated,
            "interface": self.interface_id,
            "running": bool(self._running and self.backend and self.backend.running),
            "degraded_reason": self.degraded_reason,
        }

    def _refresh_self_ips(self) -> None:
        ips = {"127.0.0.1", "::1"}
        for iface in netinfo.list_interfaces():
            if self.interface_id is None or iface["id"] == self.interface_id:
                if iface["ipv4"]:
                    ips.add(iface["ipv4"])
                if iface["ipv6"]:
                    ips.add(iface["ipv6"])
        self._self_ips = ips

    # --- background tasks -----------------------------------------------

    def spawn_background_tasks(self) -> None:
        self._tasks = [
            asyncio.create_task(self._ingest_loop(), name="netaudit-ingest"),
            asyncio.create_task(self._retention_loop(), name="netaudit-retention"),
            asyncio.create_task(self._rules_loop(), name="netaudit-rules"),
            asyncio.create_task(self._arp_loop(), name="netaudit-arp"),
        ]

    async def shutdown(self) -> None:
        for t in self._tasks:
            t.cancel()
        for t in self._tasks:
            try:
                await t
            except (asyncio.CancelledError, Exception):
                pass
        self.stop()
        self.dns_cache.shutdown()

    async def _ingest_loop(self) -> None:
        while True:
            await asyncio.sleep(config.INGEST_BATCH_INTERVAL_SECONDS)
            if self.backend is None:
                continue
            events = self.backend.drain(max_items=config.INGEST_BATCH_MAX)
            if not events:
                continue
            try:
                await asyncio.to_thread(self._process_events, events)
            except Exception:
                continue

    async def _retention_loop(self) -> None:
        while True:
            await asyncio.sleep(config.RETENTION_SWEEP_SECONDS)
            try:
                await asyncio.to_thread(retention_store.prune, self.db_path)
            except Exception:
                continue

    async def _rules_loop(self) -> None:
        while True:
            await asyncio.sleep(config.RULES_INTERVAL_SECONDS)
            try:
                await asyncio.to_thread(self._run_rules)
            except Exception:
                continue

    async def _arp_loop(self) -> None:
        while True:
            try:
                await asyncio.to_thread(self._refresh_devices)
            except Exception:
                pass
            await asyncio.sleep(15.0)

    def _run_rules(self) -> None:
        ctx = rules_engine.build_context(
            self.db_path, RULES_WINDOW_SECONDS, self.mode, self.elevated,
        )
        rules_engine.run_once(ctx, self.db_path)

    def _refresh_devices(self) -> None:
        now = time.time()
        for entry in arpscan.read_arp_table():
            ip = entry["ip"]
            if ip.startswith("224.") or ip.endswith(".255"):
                continue
            is_self = ip in self._self_ips
            hostname = self.dns_cache.lookup(ip)
            devices_store.upsert_device({
                "ip": ip,
                "mac": entry["mac"],
                "vendor": mac_vendor(entry["mac"]),
                "hostname": hostname,
                "ts_epoch": now,
                "bytes_total": 0,
                "is_gateway": 1 if ip.endswith(".1") and not is_self else 0,
                "is_self": 1 if is_self else 0,
                "open_ports": "[]",
                "risk": "low",
            }, self.db_path)

    # --- ingest core ------------------------------------------------------

    def _process_events(self, events: list[PacketEvent]) -> None:
        now = time.time()
        packet_rows = []
        stats_events = []
        device_bytes: dict[str, int] = {}
        flow_touches: list[dict] = []

        for e in events:
            direction, local_addr, local_port, remote_addr, remote_port, bytes_in, bytes_out = \
                self._classify_direction(e)

            is_external = classify_external(remote_addr)
            is_encrypted = is_encrypted_port(remote_port)
            remote_host = self.dns_cache.lookup(remote_addr) if remote_addr else None
            risk, risk_reasons = classify_risk(is_external, is_encrypted, remote_port)
            length = bytes_in + bytes_out
            summary = _summarize(e.protocol, remote_port, e.flags, is_encrypted)

            packet_rows.append({
                "ts_epoch": e.ts, "protocol": e.protocol,
                "src_addr": e.src_addr, "src_port": e.src_port,
                "dst_addr": e.dst_addr, "dst_port": e.dst_port,
                "direction": direction, "length": length, "flags": e.flags,
                "process_name": e.process_name, "pid": e.pid,
                "remote_addr": remote_addr, "remote_host": remote_host,
                "is_external": int(is_external), "is_encrypted": int(is_encrypted),
                "summary": summary, "risk": risk,
            })
            stats_events.append({"ts_epoch": e.ts, "length": length, "direction": direction, "protocol": e.protocol})

            if local_addr and remote_addr and local_port is not None and remote_port is not None:
                flow_id = f"{e.protocol}-{local_addr}:{local_port}-{remote_addr}:{remote_port}"
                flow_touches.append({
                    "id": flow_id, "protocol": e.protocol,
                    "state": e.state or ("ACTIVE" if e.protocol == "udp" else "ESTABLISHED"),
                    "local_addr": local_addr, "local_port": local_port,
                    "remote_addr": remote_addr, "remote_port": remote_port,
                    "remote_host": remote_host, "remote_org": None,
                    "direction": direction, "pid": e.pid,
                    "process_name": e.process_name, "process_path": e.process_path,
                    "bytes_in": bytes_in, "bytes_out": bytes_out,
                    "ts_epoch": e.ts, "is_external": int(is_external),
                    "is_encrypted": int(is_encrypted), "risk": risk,
                    "risk_reasons": json.dumps(risk_reasons),
                })
                if not is_external and remote_addr not in self._self_ips and direction == "outbound":
                    devices_store.merge_open_port(remote_addr, remote_port, self.db_path)

            if remote_addr and not is_external and remote_addr not in self._self_ips:
                device_bytes[remote_addr] = device_bytes.get(remote_addr, 0) + length

        packets_store.append_batch(packet_rows, self.db_path)
        stats_store.record_batch(stats_events, self.db_path)
        for f in flow_touches:
            flows_store.upsert_flow(f, self.db_path)
        for ip, total in device_bytes.items():
            devices_store.upsert_device({
                "ip": ip, "mac": None, "vendor": None, "hostname": None,
                "ts_epoch": now, "bytes_total": total, "is_gateway": 0,
                "is_self": 0, "open_ports": "[]", "risk": "low",
            }, self.db_path)

    def _classify_direction(self, e: PacketEvent):
        """Returns (direction, local_addr, local_port, remote_addr, remote_port, bytes_in, bytes_out)."""
        if e.synthetic:
            # Polling tier already tells us local/remote explicitly.
            direction = "outbound" if e.bytes_out >= e.bytes_in else "inbound"
            return direction, e.src_addr, e.src_port, e.dst_addr, e.dst_port, e.bytes_in, e.bytes_out

        src_is_self = e.src_addr in self._self_ips
        dst_is_self = e.dst_addr in self._self_ips
        if src_is_self and not dst_is_self:
            return "outbound", e.src_addr, e.src_port, e.dst_addr, e.dst_port, 0, e.length
        if dst_is_self and not src_is_self:
            return "inbound", e.dst_addr, e.dst_port, e.src_addr, e.src_port, e.length, 0
        # Both (or neither) match -- loopback traffic, or we don't
        # recognize either side (e.g. promiscuous capture saw a LAN
        # neighbor's packet). Treat the destination as "remote" for display
        # purposes and count it as local.
        return "local", e.src_addr, e.src_port, e.dst_addr, e.dst_port, 0, e.length


def _summarize(protocol: str, remote_port: int | None, flags: str, is_encrypted: bool) -> str:
    if protocol == "tcp":
        if remote_port == 443 or is_encrypted:
            return "TLS application data" if "PSH" in flags else "TCP segment"
        if remote_port == 80:
            return "HTTP traffic"
        if flags:
            return f"TCP [{flags}]"
        return "TCP segment"
    if protocol == "udp":
        if remote_port == 53:
            return "DNS query/response"
        return "UDP datagram"
    if protocol == "icmp":
        return "ICMP message"
    return "Other traffic"
