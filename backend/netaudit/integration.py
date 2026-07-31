"""Wiring between the v1 capture/store core and the two self-contained
security packages (`posture`, `threat`).

Both of those packages were deliberately written without importing anything
from the rest of `netaudit`: `posture` reaches the OS only through its own
probe allowlist, and `threat` only ever sees the `TrafficSource` Protocol in
`threat/source.py`. That keeps them independently testable, but it means
something has to translate the real SQLite store into the Protocol and hand
the routers their dependencies. That is this module, and it is the only
place those seams are joined.

What is genuinely available, and what is not
-------------------------------------------
`packets()` and `flows()` map onto real stored rows essentially 1:1.

`dns_events()` always returns empty. The capture layer records packet
headers only -- it never parses DNS payloads -- so there is no query name,
qtype or response code anywhere in the store to hand over. Synthesising
plausible-looking DnsRecords from port-53 traffic would let the DNS
detectors "run" while feeding them fabricated inputs, which is worse than
having them idle. The three DNS detectors (`dns_tunneling`, `dga_domains`,
`dns_exfil_volume`) therefore stay inert against live data until a DNS
payload parser exists. They remain fully covered by their own unit tests.

`arp_events()` is real but partial: `ArpObserver` polls the OS ARP cache and
emits an event whenever an IP's MAC changes, which is exactly what
`arp_spoofing` and `mac_flapping` need. It cannot see individual ARP frames
(so no request/reply/gratuitous distinction -- everything is reported as
"reply") and it cannot see DHCP at all, so `rogue_dhcp` stays inert too.

TLS handshake fields (`tls_version`, `tls_ja3`, cert flags) are likewise
never populated, because nothing parses ClientHello. `suspicious_tls` was
written to skip cleanly rather than guess when they are absent, which is
what happens here.

None of the above is hidden from the user: `/api/threats/detectors` reports
`fired_count`, and the reasons are documented in the threat package README.
"""
from __future__ import annotations

import logging
import threading
from collections import deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, Optional

from . import arpscan, config, netinfo
from .posture import PostureService
from .posture.router import router as posture_router
from .posture.service import get_posture_service
from .threat import ArpRecord, DnsRecord, FlowRecord, PacketRecord, ThreatEngine
from .threat.router import router as threat_router
from .threat.scoring import compute_threats_score
from .threat.store import ThreatStore
from .store import db as dbmod

logger = logging.getLogger("netaudit.integration")

# Upper bound on rows pulled into memory for a single detector pass. Part C
# item 6 (bounded everything) applies to internal paths too, not just HTTP.
MAX_PACKETS_PER_WINDOW = 200_000
MAX_FLOWS_PER_WINDOW = 50_000

# How many observed ARP transitions to retain. Small: only changes are
# recorded, not the whole table, so this covers a long history.
ARP_HISTORY_MAX = 5_000

# Detectors whose entire signal is the *timing* between contacts. The polling
# tier samples the connection table on a fixed cadence and synthesises one
# event per sample, so every long-lived connection comes out looking like a
# metronome-perfect beacon. Feeding that to these detectors manufactures
# high-severity false positives out of an artefact of our own sampling, so
# they are switched off while that tier is active and the reason is reported.
TIMING_DEPENDENT_DETECTORS = ("c2_beaconing",)

# Loopback is intra-machine IPC, not network traffic, and a desktop generates
# a great deal of it across many ports. Fed to the recon detectors it reads as
# a 113-port scan of yourself, by yourself. NetAudit audits what crosses the
# wire; exposure of local listeners is already covered by the v1
# `listening_exposed` rule and the posture `listening_services` checks, which
# are the right places for it. Filtered in SQL rather than after the fetch so
# the row limit applies to rows the detectors will actually see.
_NOT_LOOPBACK_SQL = (
    "({a} IS NULL OR ({a} NOT LIKE '127.%' AND {a} <> '::1')) "
    "AND ({b} IS NULL OR ({b} NOT LIKE '127.%' AND {b} <> '::1'))"
)


def _epoch(dt: datetime) -> float:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def _dt(epoch: float) -> datetime:
    return datetime.fromtimestamp(epoch, tz=timezone.utc)


def is_l2_broadcast_or_multicast(mac: str) -> bool:
    """True for the broadcast MAC and any multicast MAC.

    The OS ARP table legitimately contains entries mapping broadcast and
    multicast IPs (a subnet broadcast like 192.168.0.255, 255.255.255.255,
    the 224.0.0.0/4 range) onto FF:FF:FF:FF:FF:FF or 01:00:5E.../33:33...
    Those are not a host claiming an address, and handing them to
    `arp_spoofing` produces a critical "one MAC claims many IPs" finding for
    what is just how Ethernet works. Filtering belongs here, at the source,
    rather than in the detector, which is right to treat what it is given as
    genuine host claims.

    The multicast bit is the low bit of the first octet, so any odd first
    octet is multicast; FF:FF:FF:FF:FF:FF is odd and so is covered too.
    """
    try:
        first_octet = int(mac.split(":")[0], 16)
    except (ValueError, IndexError, AttributeError):
        return False
    return bool(first_octet & 0x01)


def _guess_gateway_ip() -> Optional[str]:
    """Same `.1`-suffix heuristic the device store already uses. Wrong on
    subnets whose router does not sit on .1; it only affects the
    `is_gateway` flag on ARP events, which raises `arp_spoofing` severity
    but is not required for it to fire."""
    try:
        interfaces = netinfo.list_interfaces()
        default_id = netinfo.default_interface_id(interfaces)
        for iface in interfaces:
            if iface.get("id") == default_id and iface.get("ipv4"):
                octets = str(iface["ipv4"]).split(".")
                if len(octets) == 4:
                    return ".".join(octets[:3] + ["1"])
    except Exception:  # pragma: no cover - best effort only
        logger.debug("gateway heuristic failed", exc_info=True)
    return None


class ArpObserver:
    """Polls the OS ARP cache and records IP->MAC *changes* as events.

    Only transitions are stored. A stable table produces no events, so a
    quiet network costs nothing and `mac_flapping` sees a clean signal.
    """

    def __init__(self, poll_seconds: float = 15.0) -> None:
        self.poll_seconds = poll_seconds
        self._known: dict[str, str] = {}
        self._events: deque[ArpRecord] = deque(maxlen=ARP_HISTORY_MAX)
        self._lock = threading.Lock()
        self._gateway_ip = _guess_gateway_ip()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def poll_once(self, now: Optional[datetime] = None) -> int:
        now = now or datetime.now(timezone.utc)
        try:
            table = arpscan.read_arp_table()
        except Exception:  # pragma: no cover - arp is best effort
            logger.debug("arp poll failed", exc_info=True)
            return 0

        new_events = 0
        with self._lock:
            for entry in table:
                ip, mac = entry.get("ip"), entry.get("mac")
                if not ip or not mac:
                    continue
                if is_l2_broadcast_or_multicast(mac):
                    continue
                previous = self._known.get(ip)
                if previous == mac:
                    continue
                self._known[ip] = mac
                # A first sighting is recorded too: the detectors need a
                # baseline observation before a later change means anything.
                self._events.append(
                    ArpRecord(
                        ts=now,
                        ip=ip,
                        mac=mac,
                        event="reply",
                        is_gateway=(ip == self._gateway_ip),
                    )
                )
                new_events += 1
        return new_events

    def events(self, since: datetime, until: datetime) -> list[ArpRecord]:
        with self._lock:
            return [e for e in self._events if since <= e.ts <= until]

    def start(self) -> None:
        if self._thread is not None:
            return

        def _loop() -> None:
            while not self._stop.wait(self.poll_seconds):
                self.poll_once()

        self.poll_once()
        self._thread = threading.Thread(target=_loop, name="netaudit-arp", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None


class ThreatScheduler:
    """Runs `ThreatEngine.run_once()` on a timer.

    Without this the engine is inert: the router only ever reads threats
    that a previous pass persisted, so nothing detects anything until
    something calls `run_once`. The first pass is delayed rather than
    immediate because several detectors compare against a baseline and have
    nothing useful to say about an empty database.
    """

    def __init__(
        self,
        engine: ThreatEngine,
        interval_seconds: float = 60.0,
        initial_delay_seconds: float = 20.0,
        capture_mode: Optional[callable] = None,
    ) -> None:
        self.engine = engine
        self.interval_seconds = interval_seconds
        self.initial_delay_seconds = initial_delay_seconds
        self.capture_mode = capture_mode
        self.last_run: Optional[datetime] = None
        self.last_error: Optional[str] = None
        self.run_count = 0
        self.suppressed_detectors: tuple[str, ...] = ()
        self._suppression_applied = False
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def apply_tier_suppression(self) -> tuple[str, ...]:
        """Disable timing-based detectors while the polling tier is active.

        Done once, lazily, because the capture tier is not settled until the
        pipeline has actually started. Uses the engine's own patch path so
        the change is persisted and visible in `/api/threats/detectors`
        rather than hidden -- the user can see exactly what is switched off
        and turn it back on if they disagree.
        """
        if self._suppression_applied or self.capture_mode is None:
            return self.suppressed_detectors
        try:
            mode = self.capture_mode()
        except Exception:
            return ()
        if mode != "polling":
            self._suppression_applied = True
            return ()

        suppressed = []
        for detector_id in TIMING_DEPENDENT_DETECTORS:
            _updated, error = self.engine.patch_detector(detector_id, {"enabled": False})
            if error is None:
                suppressed.append(detector_id)
        self._suppression_applied = True
        self.suppressed_detectors = tuple(suppressed)
        if suppressed:
            logger.info(
                "capture tier is 'polling'; disabled timing-based detector(s) %s "
                "because the tier's fixed sample interval would make every "
                "long-lived connection look like a perfect beacon",
                ", ".join(suppressed),
            )
        return self.suppressed_detectors

    def run_once(self) -> int:
        """Returns the number of threats touched by this pass. Never raises
        -- a detector blowing up must not kill the scheduler thread."""
        try:
            self.apply_tier_suppression()
            touched = self.engine.run_once()
            self.last_run = datetime.now(timezone.utc)
            self.last_error = None
            self.run_count += 1
            return len(touched)
        except Exception as exc:
            self.last_error = str(exc)
            logger.exception("threat detection pass failed")
            return 0

    def start(self) -> None:
        if self._thread is not None:
            return

        def _loop() -> None:
            if self._stop.wait(self.initial_delay_seconds):
                return
            while True:
                self.run_once()
                if self._stop.wait(self.interval_seconds):
                    return

        self._thread = threading.Thread(target=_loop, name="netaudit-threats", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None


class StoreTrafficSource:
    """Adapts the live SQLite store onto `threat.TrafficSource`.

    Queries go straight to the DB rather than through the HTTP-facing
    helpers in `store.packets`, because those clamp `limit` to 1000 for the
    API's benefit -- a bound that is correct for a web request and wrong for
    a detector pass over a window.
    """

    def __init__(self, db_path: Path, arp_observer: Optional[ArpObserver] = None) -> None:
        self.db_path = db_path
        self.arp_observer = arp_observer

    def packets(self, since: datetime, until: datetime) -> Iterable[PacketRecord]:
        conn = dbmod.get_conn(self.db_path)
        rows = conn.execute(
            """
            SELECT id, ts_epoch, protocol, src_addr, src_port, dst_addr, dst_port,
                   direction, length, flags, process_name, pid, remote_host,
                   is_external, is_encrypted, summary
            FROM packets
            WHERE ts_epoch >= ? AND ts_epoch <= ?
              AND """ + _NOT_LOOPBACK_SQL.format(a="src_addr", b="dst_addr") + """
            ORDER BY ts_epoch ASC
            LIMIT ?
            """,
            (_epoch(since), _epoch(until), MAX_PACKETS_PER_WINDOW),
        ).fetchall()

        return [
            PacketRecord(
                id=r["id"],
                ts=_dt(r["ts_epoch"]),
                protocol=r["protocol"],
                src_addr=r["src_addr"],
                src_port=r["src_port"],
                dst_addr=r["dst_addr"],
                dst_port=r["dst_port"],
                direction=r["direction"],
                length=r["length"],
                flags=r["flags"] or None,
                process_name=r["process_name"],
                pid=r["pid"],
                remote_host=r["remote_host"],
                is_external=bool(r["is_external"]),
                is_encrypted=bool(r["is_encrypted"]),
                summary=r["summary"] or None,
                # TLS handshake fields and payload snippets are never stored
                # (Part C item 8 -- headers and metadata only). Left None so
                # the detectors that need them skip rather than guess.
                payload_snippet=None,
            )
            for r in rows
        ]

    def flows(self, since: datetime, until: datetime) -> Iterable[FlowRecord]:
        conn = dbmod.get_conn(self.db_path)
        rows = conn.execute(
            """
            SELECT id, protocol, state, local_addr, local_port, remote_addr,
                   remote_port, remote_host, remote_org, direction, pid,
                   process_name, process_path, bytes_in, bytes_out, packets,
                   first_seen_epoch, last_seen_epoch, is_external, is_encrypted
            FROM flows
            WHERE first_seen_epoch <= ? AND last_seen_epoch >= ?
              AND """ + _NOT_LOOPBACK_SQL.format(a="local_addr", b="remote_addr") + """
            ORDER BY last_seen_epoch ASC
            LIMIT ?
            """,
            (_epoch(until), _epoch(since), MAX_FLOWS_PER_WINDOW),
        ).fetchall()

        return [
            FlowRecord(
                id=r["id"],
                protocol=r["protocol"],
                state=r["state"],
                local_addr=r["local_addr"],
                local_port=r["local_port"],
                remote_addr=r["remote_addr"],
                remote_port=r["remote_port"],
                remote_host=r["remote_host"],
                remote_org=r["remote_org"],
                direction=r["direction"],
                pid=r["pid"],
                process_name=r["process_name"],
                process_path=r["process_path"],
                bytes_in=r["bytes_in"],
                bytes_out=r["bytes_out"],
                packets=r["packets"],
                first_seen=_dt(r["first_seen_epoch"]),
                last_seen=_dt(r["last_seen_epoch"]),
                is_external=bool(r["is_external"]),
                is_encrypted=bool(r["is_encrypted"]),
            )
            for r in rows
        ]

    def dns_events(self, since: datetime, until: datetime) -> Iterable[DnsRecord]:
        """Always empty -- see the module docstring. Nothing in the capture
        layer parses DNS payloads, so there is no honest record to return."""
        return []

    def arp_events(self, since: datetime, until: datetime) -> Iterable[ArpRecord]:
        if self.arp_observer is None:
            return []
        return self.arp_observer.events(since, until)


class ThreatsScoreContributor:
    """`posture.ScoreContributor` backed by live threats, so
    `/api/security/score` reports a real `threats` component instead of
    silently renormalising it away."""

    id = "threats"
    label = "Active threats"

    def __init__(self, engine: ThreatEngine) -> None:
        self._engine = engine

    def compute_score(self) -> Optional[int]:
        try:
            _total, threats = self._engine.list_threats(
                include_acknowledged=False, limit=1000, offset=0,
            )
        except Exception:
            logger.debug("threat score contributor failed", exc_info=True)
            return None
        return compute_threats_score(threats)["score"]


class HygieneScoreContributor:
    """`hygiene` component: how clean the observed traffic looks, derived
    from the v1 recommendation rules that are currently firing."""

    id = "hygiene"
    label = "Traffic hygiene"

    _PENALTY = {"critical": 30, "high": 18, "medium": 8, "low": 3, "info": 0}

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path

    def compute_score(self) -> Optional[int]:
        try:
            from .rules import engine as rules_engine

            # include_dismissed defaults to False, so anything the user has
            # explicitly dismissed already stops counting against them.
            recs = rules_engine.list_recommendations(db_path=self.db_path)
        except Exception:
            logger.debug("hygiene score contributor failed", exc_info=True)
            return None

        score = 100
        for rec in recs:
            score -= self._PENALTY.get(str(rec.get("severity", "info")).lower(), 0)
        return max(0, min(100, score))


def wire_security(app, db_path: Optional[Path] = None, start_background: bool = True) -> None:
    """Mount the posture and threat routers and give them live dependencies.

    Called after `create_app()` has returned. `server.py` deliberately does
    not `app.mount("/", ...)` the SPA precisely so that routers added here
    still resolve -- see the comment there.
    """
    db_path = db_path or getattr(app.state, "db_path", None) or config.DB_PATH

    arp_observer = ArpObserver()
    source = StoreTrafficSource(db_path=db_path, arp_observer=arp_observer)
    threat_store = ThreatStore(db_path)
    engine = ThreatEngine(source=source, store=threat_store)

    posture_service = PostureService(
        contributors=[
            ThreatsScoreContributor(engine),
            HygieneScoreContributor(db_path),
        ]
    )

    def _capture_mode() -> Optional[str]:
        pipeline = getattr(app.state, "pipeline", None)
        status = pipeline.capture_status() if pipeline is not None else None
        return (status or {}).get("mode")

    scheduler = ThreatScheduler(engine, capture_mode=_capture_mode)

    app.state.arp_observer = arp_observer
    app.state.threat_source = source
    app.state.threat_engine = engine  # threat/router.py reads this
    app.state.threat_scheduler = scheduler
    app.state.posture_service = posture_service

    app.dependency_overrides[get_posture_service] = lambda: posture_service

    app.include_router(posture_router)
    app.include_router(threat_router)

    if start_background:
        arp_observer.start()
        scheduler.start()

    logger.info(
        "security packages wired: %d threat detectors, score contributors=%s",
        len(engine.list_detectors()),
        [c.id for c in (ThreatsScoreContributor, HygieneScoreContributor)],
    )
