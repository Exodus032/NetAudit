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
from .learn.router import router as learn_router
from .posture import PostureService
from .posture.router import router as posture_router
from .posture.service import get_posture_service
from .threat import ArpRecord, DnsRecord, FlowRecord, PacketRecord, ThreatEngine
from .threat.router import router as threat_router
from .threat.scoring import compute_threats_score
from .threat.store import ThreatStore
from .store import db as dbmod
from .timeutil import now_iso

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
        # Attached by `wire_pro`, which is what creates the alert service.
        # Optional so the scheduler still runs in a v2-only install.
        self.alert_dispatcher: Optional[ThreatAlertDispatcher] = None
        self.last_run: Optional[datetime] = None
        self.last_error: Optional[str] = None
        self.alerts_sent = 0
        self.run_count = 0
        self.suppressed_detectors: tuple[str, ...] = ()
        self._last_capture_mode: Optional[str] = None
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def apply_tier_suppression(self) -> tuple[str, ...]:
        """Disable timing-based detectors while the polling tier is active,
        and re-enable them once a real capture tier is back.

        Runs at the top of every pass but only acts on a *transition*
        between capture modes, for two reasons. First, the capture tier is
        not settled until the pipeline has actually started: the mode
        callback returns None until then, and treating that unknown state
        as "not polling" would re-enable timing detectors and latch that
        decision just before the tier degrades to polling. Second, a run
        can genuinely change tier mid-flight (an npcap capture dying falls
        back to polling), and a once-per-process decision would leave
        `c2_beaconing` running against sampled data. Acting only on
        transitions also means a user who disables a detector by hand on a
        real capture tier is not fought every pass -- the restore fires
        once per polling -> real-tier transition, not continuously.

        Uses the engine's own patch path so the change is persisted and
        visible in `/api/threats/detectors` rather than hidden.
        """
        if self.capture_mode is None:
            return self.suppressed_detectors
        try:
            mode = self.capture_mode()
        except Exception:
            return self.suppressed_detectors
        if mode is None or mode == self._last_capture_mode:
            # Tier not settled yet, or no change since the last pass.
            return self.suppressed_detectors
        self._last_capture_mode = mode
        if mode != "polling":
            self._restore_timing_detectors()
            self.suppressed_detectors = ()
            return ()

        suppressed = []
        for detector_id in TIMING_DEPENDENT_DETECTORS:
            _updated, error = self.engine.patch_detector(detector_id, {"enabled": False})
            if error is None:
                suppressed.append(detector_id)
        self.suppressed_detectors = tuple(suppressed)
        if suppressed:
            logger.info(
                "capture tier is 'polling'; disabled timing-based detector(s) %s "
                "because the tier's fixed sample interval would make every "
                "long-lived connection look like a perfect beacon",
                ", ".join(suppressed),
            )
        return self.suppressed_detectors

    def _restore_timing_detectors(self) -> tuple[str, ...]:
        """Re-enable timing-based detectors a previous polling-tier run
        disabled, now that a real capture tier is active.

        The persisted detector state is a bare `enabled` flag
        (`detector_settings.enabled`) with no record of *who* disabled it,
        so a detector the user switched off by hand is indistinguishable
        from one `apply_tier_suppression` switched off on an earlier
        polling run. The README promises elevation gets the detector back,
        so on a non-polling tier any disabled timing detector is re-enabled
        unconditionally. A user who wants it off on a real capture tier can
        disable it again and it will stay off for the rest of the process.
        """
        try:
            currently_enabled = {d["id"]: d.get("enabled", True) for d in self.engine.list_detectors()}
        except Exception:
            logger.debug("could not list detectors to restore tier suppression", exc_info=True)
            return ()
        restored = []
        for detector_id in TIMING_DEPENDENT_DETECTORS:
            if currently_enabled.get(detector_id, True):
                continue
            _updated, error = self.engine.patch_detector(detector_id, {"enabled": True})
            if error is None:
                restored.append(detector_id)
        if restored:
            logger.info(
                "capture tier is not 'polling'; re-enabled timing-based detector(s) %s "
                "that a previous polling-tier run had disabled",
                ", ".join(restored),
            )
        return tuple(restored)

    def run_once(self) -> int:
        """Returns the number of threats touched by this pass. Never raises
        -- a detector blowing up must not kill the scheduler thread."""
        try:
            self.apply_tier_suppression()
            touched = self.engine.run_once()
            if self.alert_dispatcher is not None:
                self.alerts_sent += self.alert_dispatcher.dispatch_new(touched)
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


class LiveFindingsProvider:
    """Feeds `/api/findings/prioritised` from the three live sources.

    Only actual findings cross this boundary: a posture check that passed,
    errored or was skipped is not something to fix, and a resolved threat is
    not something to act on. Filtering here rather than in the learn package
    keeps that package free of any knowledge of the other three.
    """

    def __init__(self, posture_service, engine: ThreatEngine, db_path: Path) -> None:
        self._posture = posture_service
        self._engine = engine
        self._db_path = db_path

    def posture_checks(self) -> list[dict]:
        try:
            report = self._posture.get_report()
        except Exception:
            logger.debug("posture findings unavailable", exc_info=True)
            return []
        out = []
        for check in getattr(report, "checks", []):
            status = getattr(check.status, "value", check.status)
            if status not in ("fail", "warn"):
                continue
            remediation = getattr(check, "remediation", None)
            out.append({
                "id": check.id,
                "title": check.title,
                # Posture titles state the desired end state, so on their
                # own they read backwards in a list of things to fix.
                # `observed` is the check's own description of what is
                # actually true, which is what the student needs to see.
                "observed": getattr(check, "observed", None),
                "severity": getattr(check.severity, "value", check.severity),
                "status": status,
                "one_line_fix": getattr(remediation, "summary", None) or "See the check detail for remediation steps.",
            })
        return out

    def recommendations(self) -> list[dict]:
        try:
            from .rules import engine as rules_engine

            recs = rules_engine.list_recommendations(db_path=self._db_path)
        except Exception:
            logger.debug("recommendation findings unavailable", exc_info=True)
            return []
        return [
            {
                "id": rec["id"],
                "title": rec["title"],
                "severity": rec["severity"],
                "one_line_fix": (rec.get("actions") or [{}])[0].get("label")
                or "See the recommendation detail.",
            }
            for rec in recs
        ]

    def threats(self) -> list[dict]:
        try:
            _total, threats = self._engine.list_threats(include_acknowledged=False, limit=1000)
        except Exception:
            logger.debug("threat findings unavailable", exc_info=True)
            return []
        return [
            {
                "id": t["id"],
                "title": t["title"],
                "severity": t["severity"],
                "one_line_fix": (t.get("recommended_actions") or [{}])[0].get("label")
                or "Investigate before taking action.",
            }
            for t in threats
            if t.get("status") != "resolved"
        ]


class ThreatAlertDispatcher:
    """Turns a newly detected threat into an alert, exactly once.

    `alerts` was written with a `dispatch()` that documents itself as
    "called by whatever in the backend decided something is worth alerting
    on", and nothing was calling it -- so alerting could be configured and
    tested but would never fire on its own. This is that caller.

    `ThreatEngine.run_once()` returns every open threat, not just the new
    ones, so firing on its output directly would re-alert the same threat
    every 60 seconds. The already-alerted set is seeded from alert history
    rather than kept purely in memory, so a restart does not replay every
    existing threat at the user.
    """

    HISTORY_SEED_LIMIT = 500

    def __init__(self, alert_service) -> None:
        self._alerts = alert_service
        self._alerted: Optional[set[str]] = None

    def _seed(self) -> None:
        if self._alerted is not None:
            return
        alerted: set[str] = set()
        try:
            history = self._alerts.history(limit=self.HISTORY_SEED_LIMIT)
            for item in history.alerts:
                if item.source == "threat" and item.source_id:
                    alerted.add(item.source_id)
        except Exception:
            logger.debug("could not seed alerted-threat set from history", exc_info=True)
        self._alerted = alerted

    def dispatch_new(self, threats: Iterable[dict]) -> int:
        """Returns how many alerts were actually recorded."""
        try:
            if not self._alerts.get_config().enabled:
                # Nothing is marked as alerted while alerting is off, so
                # turning it on does not silently swallow what is already
                # on screen.
                return 0
        except Exception:
            logger.debug("alert config unavailable", exc_info=True)
            return 0

        self._seed()
        assert self._alerted is not None
        sent = 0
        for threat in threats:
            threat_id = threat.get("id")
            if not threat_id or threat_id in self._alerted:
                continue
            if threat.get("status") == "resolved":
                continue
            try:
                entry = self._alerts.dispatch(
                    severity=str(threat.get("severity", "info")),
                    source="threat",
                    source_id=threat_id,
                    title=str(threat.get("title", threat_id)),
                )
            except Exception:
                logger.exception("alert dispatch failed for threat %s", threat_id)
                continue
            if entry is None:
                # Below min_severity. Deliberately not marked as alerted:
                # lowering the threshold later should surface it.
                continue
            self._alerted.add(threat_id)
            sent += 1
        return sent


class PostureChecksAdapter:
    """Satisfies both `compliance.PostureProvider` and
    `baselines.PostureProvider`, which are the same shape declared twice on
    purpose so neither package imports the other.

    Emits plain dicts rather than posture's pydantic models: that is the
    whole point of those Protocols, and it means a check gaining a field
    never ripples into compliance or baselines.

    `fresh=True` forces a full posture rescan on every `checks()` call
    instead of serving the boot-time cache. The baseline monitor's
    scheduled captures use that mode: they exist to detect drift over
    hours and days, and diffing the same cached report against itself can
    never see any. Interactive API reads (compliance, on-demand baseline
    capture) keep the default cached mode so they stay fast.
    """

    def __init__(self, posture_service, fresh: bool = False) -> None:
        self._posture = posture_service
        self._fresh = fresh

    def checks(self) -> list[dict]:
        try:
            report = self._posture.rescan() if self._fresh else self._posture.get_report()
        except Exception:
            logger.debug("posture checks unavailable", exc_info=True)
            return []
        out = []
        for check in getattr(report, "checks", []):
            out.append({
                "id": check.id,
                "status": getattr(check.status, "value", check.status),
                "title": getattr(check, "title", None),
                "severity": getattr(check.severity, "value", getattr(check, "severity", None)),
                "category": getattr(check, "category", None),
            })
        return out


class MachineInterfaceProvider:
    """Satisfies `lanscan.InterfaceProvider`.

    Only interfaces that are up and not loopback are reported. The default
    provider reports none at all, which correctly rejects every scan, so
    anything this adds is directly widening what a user is allowed to scan
    and should stay as narrow as the truth allows: a down adapter's stale
    APIPA address is not a subnet this machine is on.
    """

    def interfaces(self) -> list[dict]:
        import ipaddress

        out: list[dict] = []
        try:
            candidates = netinfo.list_interfaces()
        except Exception:
            logger.debug("interface enumeration failed", exc_info=True)
            return []
        for iface in candidates:
            if not iface.get("is_up") or iface.get("is_loopback"):
                continue
            address, netmask = iface.get("ipv4"), iface.get("netmask")
            if not address or not netmask:
                continue
            try:
                prefixlen = ipaddress.IPv4Network(f"0.0.0.0/{netmask}").prefixlen
            except ValueError:
                continue
            out.append({"address": address, "prefixlen": prefixlen})
        return out


class StoreTrafficProvider:
    """Satisfies `baselines.TrafficProvider`.

    `peers()` is external remote endpoints only. A baseline whose peer list
    is dominated by loopback and LAN chatter diffs noisily against itself
    and buries the one new internet destination that actually matters.

    Deliberately *not* `store.flows.query_connections()`, which only returns
    flows touched in the last 120 seconds. That is the right window for a
    live connections table and the wrong one for a baseline: capture a
    snapshot on a quiet minute and you would record an empty peer set, then
    diff it later and see every normal destination reported as newly
    appeared. `PEER_WINDOW_SECONDS` is a day, so a snapshot describes a
    day's worth of who this machine talks to.
    """

    PEER_WINDOW_SECONDS = 24 * 60 * 60
    MAX_BASELINE_PEERS = 10_000

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path

    def peers(self) -> list[str]:
        try:
            import time

            rows = dbmod.get_conn(self.db_path).execute(
                """
                SELECT DISTINCT COALESCE(NULLIF(remote_host, ''), remote_addr) AS peer
                FROM flows
                WHERE last_seen_epoch >= ?
                  AND is_external != 0
                  AND COALESCE(NULLIF(remote_host, ''), remote_addr) IS NOT NULL
                  AND COALESCE(NULLIF(remote_host, ''), remote_addr) != ''
                ORDER BY peer
                LIMIT ?
                """,
                (time.time() - self.PEER_WINDOW_SECONDS, self.MAX_BASELINE_PEERS),
            ).fetchall()
        except Exception:
            logger.debug("baseline peers unavailable", exc_info=True)
            return []
        return [str(row["peer"]) for row in rows]

    def listeners(self) -> list[dict]:
        """Read live from psutil rather than the packet store: a listening
        socket that has never been talked to leaves no packets behind, and
        those are precisely the ones worth baselining."""
        try:
            import psutil
        except Exception:  # pragma: no cover - psutil is a hard dependency
            return []
        out: dict[int, dict] = {}
        try:
            for conn in psutil.net_connections(kind="inet"):
                if conn.status != psutil.CONN_LISTEN or not conn.laddr:
                    continue
                port = conn.laddr.port
                if port in out:
                    continue
                from .capture.enrich import resolve_process

                _pid, name, _path = resolve_process(conn.pid)
                out[port] = {
                    "port": port,
                    "process": name or "unknown",
                    "address": conn.laddr.ip,
                }
        except (psutil.AccessDenied, OSError):
            logger.debug("listener enumeration denied", exc_info=True)
            return []
        return [out[p] for p in sorted(out)]


class CompositeScoreProvider:
    """Satisfies `baselines.ScoreProvider` by flattening posture's
    `SecurityScoreResponse` into the three numbers baselines wants.

    `threats` stays None when no threats component is present, rather than
    becoming 0 -- "we did not measure it" and "we measured it and found
    nothing" are different things and a baseline diff should not confuse
    them.
    """

    def __init__(self, posture_service) -> None:
        self._posture = posture_service

    def security_score(self) -> dict:
        try:
            score = self._posture.get_security_score()
        except Exception:
            logger.debug("security score unavailable", exc_info=True)
            return {"posture": 0, "threats": None, "overall": 0}
        components = {c.id: c.score for c in getattr(score, "components", [])}
        return {
            "posture": int(components.get("posture") or 0),
            "threats": components.get("threats"),
            "overall": int(getattr(score, "overall", 0)),
        }


class LiveReportDataProvider:
    """Satisfies `export.ReportDataProvider`.

    Each method is deliberately a thin call onto the source of truth for
    that section, returning the same shape the corresponding HTTP endpoint
    returns, so a generated report and the live UI can never disagree about
    what was found. Every one degrades to empty rather than raising: a
    report with a missing section is far more useful than no report.
    """

    def __init__(self, posture_service, engine: ThreatEngine, db_path: Path) -> None:
        self._posture = posture_service
        self._engine = engine
        self._db_path = db_path

    def security_score(self) -> dict:
        try:
            return self._posture.get_security_score().model_dump()
        except Exception:
            logger.debug("report security score unavailable", exc_info=True)
            return {}

    def posture_report(self) -> dict:
        try:
            return self._posture.get_report().model_dump()
        except Exception:
            logger.debug("report posture unavailable", exc_info=True)
            return {}

    def threats(self) -> list[dict]:
        try:
            _total, threats = self._engine.list_threats(include_acknowledged=True, limit=1000)
            return list(threats)
        except Exception:
            logger.debug("report threats unavailable", exc_info=True)
            return []

    def recommendations(self) -> list[dict]:
        try:
            from .rules import engine as rules_engine

            return list(rules_engine.list_recommendations(db_path=self._db_path))
        except Exception:
            logger.debug("report recommendations unavailable", exc_info=True)
            return []

    def traffic_summary(self) -> dict:
        try:
            from .store import stats as statsmod

            return statsmod.get_summary("5m", db_path=self._db_path)
        except Exception:
            logger.debug("report traffic summary unavailable", exc_info=True)
            return {}

    def devices(self) -> list[dict]:
        try:
            from .store import devices as devicesmod

            return list(devicesmod.query_devices(db_path=self._db_path))
        except Exception:
            logger.debug("report devices unavailable", exc_info=True)
            return []


def wire_pro(app, db_path: Optional[Path] = None) -> None:
    """Mount the professional-workflow packages (Parts E and F) and give
    them live dependencies.

    Must run after `wire_security`, because compliance, baselines and
    reports all read from the posture service and threat engine that
    function creates. Called from `wire_security` itself rather than from
    `server.py` so the ordering cannot be got wrong from outside.

    `pcap` and `export`'s storage already resolves to the same
    `%LOCALAPPDATA%\\NetAudit\\` location the rest of the backend uses, so
    those two routers need nothing but mounting.
    """
    from .alerts.router import router as alerts_router
    from .alerts.service import AlertService, get_alert_service
    from .baselines import providers as baseline_providers
    from .baselines.monitor import BaselineMonitor
    from .baselines.router import get_baseline_monitor, router as baselines_router
    from .baselines.service import BaselineService, get_baseline_service
    from .compliance import providers as compliance_providers
    from .compliance.router import router as compliance_router
    from .export.provider import get_report_provider
    from .export.router import router as export_router
    from .lanscan import providers as lanscan_providers
    from .lanscan.router import router as lanscan_router
    from .pcap.router import router as pcap_router

    db_path = db_path or getattr(app.state, "db_path", None) or config.DB_PATH
    posture_service = app.state.posture_service
    engine = app.state.threat_engine

    posture_adapter = PostureChecksAdapter(posture_service)
    # The scheduled monitor gets its own adapter that forces a rescan per
    # capture: a drift detector fed the boot-time cached report would diff
    # the same data forever and never fire. The monitor already runs
    # `run_once` off the event loop (asyncio.to_thread) and the posture
    # service bounds each scan to its own wall-clock budget, so the extra
    # seconds per capture cost nothing but that thread's time.
    monitor_posture_adapter = PostureChecksAdapter(posture_service, fresh=True)
    interface_provider = MachineInterfaceProvider()
    traffic_provider = StoreTrafficProvider(db_path)
    score_provider = CompositeScoreProvider(posture_service)
    report_provider = LiveReportDataProvider(posture_service, engine, db_path)

    alert_service = AlertService(db_path=db_path)
    baseline_service = BaselineService(db_path=db_path)
    baseline_monitor = BaselineMonitor(
        baseline_service,
        monitor_posture_adapter,
        traffic_provider,
        score_provider,
        alert_service,
        clock=now_iso,
    )

    app.dependency_overrides[compliance_providers.get_posture_provider] = lambda: posture_adapter
    app.dependency_overrides[baseline_providers.get_posture_provider] = lambda: posture_adapter
    app.dependency_overrides[baseline_providers.get_traffic_provider] = lambda: traffic_provider
    app.dependency_overrides[baseline_providers.get_score_provider] = lambda: score_provider
    app.dependency_overrides[lanscan_providers.get_interface_provider] = lambda: interface_provider
    app.dependency_overrides[get_report_provider] = lambda: report_provider
    app.dependency_overrides[get_alert_service] = lambda: alert_service
    app.dependency_overrides[get_baseline_service] = lambda: baseline_service
    app.dependency_overrides[get_baseline_monitor] = lambda: baseline_monitor

    app.state.alert_service = alert_service
    app.state.baseline_service = baseline_service
    app.state.baseline_monitor = baseline_monitor
    app.state.report_provider = report_provider

    # Give the detection loop somewhere to send what it finds. Without this
    # the alerting feature is configurable, testable, and permanently silent.
    scheduler = getattr(app.state, "threat_scheduler", None)
    if scheduler is not None:
        scheduler.alert_dispatcher = ThreatAlertDispatcher(alert_service)

    app.include_router(pcap_router)
    app.include_router(export_router)
    app.include_router(compliance_router)
    app.include_router(alerts_router)
    app.include_router(lanscan_router)
    app.include_router(baselines_router)

    logger.info(
        "pro packages wired: pcap, export/reports, compliance, alerts, lanscan, baselines "
        "(scannable interfaces: %d)",
        len(interface_provider.interfaces()),
    )


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

    app.state.learn_findings_provider = LiveFindingsProvider(posture_service, engine, db_path)

    app.dependency_overrides[get_posture_service] = lambda: posture_service

    app.include_router(posture_router)
    app.include_router(threat_router)
    app.include_router(learn_router)

    wire_pro(app, db_path=db_path)

    if start_background:
        arp_observer.start()
        scheduler.start()

    logger.info(
        "security packages wired: %d threat detectors, score contributors=%s",
        len(engine.list_detectors()),
        [c.id for c in (ThreatsScoreContributor, HygieneScoreContributor)],
    )
