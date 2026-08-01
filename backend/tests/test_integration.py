"""Tests for the seam between the v1 store and the posture/threat packages.

Everything here is about the adapter itself -- that stored rows map onto the
`TrafficSource` Protocol correctly, that the scheduler actually drives the
engine, and that routers mounted after `create_app()` inherit the security
middleware. The packages either side of this seam have their own suites.
"""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from netaudit import integration
from netaudit.store import db as dbmod
from netaudit.store import flows as flowstore
from netaudit.store import packets as packetstore
from netaudit.threat import ArpRecord


def _epoch(dt):
    return dt.timestamp()


@pytest.fixture
def db(tmp_path):
    path = tmp_path / "netaudit.db"
    dbmod.get_conn(path)
    return path


def _packet_row(ts, **overrides):
    row = {
        "ts_epoch": _epoch(ts),
        "protocol": "tcp",
        "src_addr": "192.168.1.42",
        "src_port": 51422,
        "dst_addr": "93.184.216.34",
        "dst_port": 80,
        "direction": "outbound",
        "length": 1420,
        "flags": "PSH,ACK",
        "process_name": "chrome.exe",
        "pid": 8842,
        "remote_addr": "93.184.216.34",
        "remote_host": "example.com",
        "is_external": 1,
        "is_encrypted": 0,
        "summary": "HTTP request",
        "risk": "low",
    }
    row.update(overrides)
    return row


class TestStoreTrafficSource:
    def test_packets_map_onto_protocol_records(self, db):
        now = datetime.now(timezone.utc)
        packetstore.append_batch([_packet_row(now - timedelta(seconds=10))], db_path=db)

        source = integration.StoreTrafficSource(db_path=db)
        got = list(source.packets(now - timedelta(minutes=1), now))

        assert len(got) == 1
        p = got[0]
        assert p.protocol == "tcp"
        assert p.src_addr == "192.168.1.42"
        assert p.dst_port == 80
        assert p.direction == "outbound"
        assert p.length == 1420
        assert p.process_name == "chrome.exe"
        assert p.remote_host == "example.com"
        assert p.is_external is True
        assert p.is_encrypted is False
        # tz-aware, so comparisons inside detectors never raise
        assert p.ts.tzinfo is not None

    def test_packets_respect_the_time_window(self, db):
        now = datetime.now(timezone.utc)
        packetstore.append_batch(
            [
                _packet_row(now - timedelta(hours=2)),
                _packet_row(now - timedelta(seconds=5)),
            ],
            db_path=db,
        )
        source = integration.StoreTrafficSource(db_path=db)
        got = list(source.packets(now - timedelta(minutes=1), now))
        assert len(got) == 1

    def test_payload_snippet_is_never_populated(self, db):
        """Part C item 8: headers and metadata only. The store has no
        payload column, so the adapter must not invent one."""
        now = datetime.now(timezone.utc)
        packetstore.append_batch([_packet_row(now)], db_path=db)
        source = integration.StoreTrafficSource(db_path=db)
        assert all(p.payload_snippet is None for p in source.packets(now - timedelta(minutes=1), now))

    def test_tls_metadata_is_never_guessed(self, db):
        """Nothing parses ClientHello, so these stay None and
        `suspicious_tls` skips rather than fabricating a verdict."""
        now = datetime.now(timezone.utc)
        packetstore.append_batch([_packet_row(now, dst_port=443, is_encrypted=1)], db_path=db)
        source = integration.StoreTrafficSource(db_path=db)
        p = list(source.packets(now - timedelta(minutes=1), now))[0]
        assert p.tls_version is None
        assert p.tls_ja3 is None
        assert p.tls_cert_self_signed is None

    def test_flows_are_selected_by_interval_overlap(self, db):
        now = datetime.now(timezone.utc)

        def seen_at(ts):
            return {
                "id": "tcp-a", "protocol": "tcp", "state": "ESTABLISHED",
                "local_addr": "192.168.1.42", "local_port": 5000,
                "remote_addr": "1.2.3.4", "remote_port": 443,
                "remote_host": None, "remote_org": None, "direction": "outbound",
                "pid": 1, "process_name": "x.exe", "process_path": None,
                "bytes_in": 10, "bytes_out": 20,
                "ts_epoch": _epoch(ts),
                "is_external": 1, "is_encrypted": 1,
                "risk": "low", "risk_reasons": "[]",
            }

        # A flow only spans a range after being seen more than once, which is
        # how the pipeline actually accumulates it.
        flowstore.upsert_flow(seen_at(now - timedelta(minutes=10)), db_path=db)
        flowstore.upsert_flow(seen_at(now - timedelta(minutes=8)), db_path=db)

        source = integration.StoreTrafficSource(db_path=db)

        # Window overlapping the flow's span picks it up...
        assert len(list(source.flows(now - timedelta(minutes=9), now))) == 1
        # ...a window entirely after it does not.
        assert len(list(source.flows(now - timedelta(minutes=1), now))) == 0

    def test_dns_events_are_empty_and_that_is_deliberate(self, db):
        source = integration.StoreTrafficSource(db_path=db)
        now = datetime.now(timezone.utc)
        assert list(source.dns_events(now - timedelta(hours=1), now)) == []

    def test_arp_events_come_from_the_observer(self, db):
        now = datetime.now(timezone.utc)
        observer = integration.ArpObserver()
        observer._events.append(ArpRecord(ts=now, ip="192.168.1.1", mac="AA:BB:CC:DD:EE:FF", event="reply"))
        source = integration.StoreTrafficSource(db_path=db, arp_observer=observer)
        assert len(list(source.arp_events(now - timedelta(minutes=1), now))) == 1

    def test_arp_events_empty_without_an_observer(self, db):
        source = integration.StoreTrafficSource(db_path=db, arp_observer=None)
        now = datetime.now(timezone.utc)
        assert list(source.arp_events(now - timedelta(minutes=1), now)) == []


class TestArpObserver:
    def test_records_first_sighting_then_only_changes(self, monkeypatch):
        observer = integration.ArpObserver()
        # Both are genuine unicast MACs -- an even first octet. An odd first
        # octet would be multicast and correctly filtered out.
        original, replacement = "AA:BB:CC:DD:EE:01", "AC:BB:CC:DD:EE:02"
        table = [{"ip": "192.168.1.1", "mac": original, "is_dynamic": True}]
        monkeypatch.setattr(integration.arpscan, "read_arp_table", lambda: table)

        assert observer.poll_once() == 1   # first sighting recorded
        assert observer.poll_once() == 0   # unchanged, nothing emitted

        table[0]["mac"] = replacement
        assert observer.poll_once() == 1   # the change is what matters

        events = observer.events(datetime.now(timezone.utc) - timedelta(minutes=1),
                                 datetime.now(timezone.utc))
        assert [e.mac for e in events] == [original, replacement]

    def test_a_failing_arp_command_is_survivable(self, monkeypatch):
        observer = integration.ArpObserver()

        def boom():
            raise OSError("arp unavailable")

        monkeypatch.setattr(integration.arpscan, "read_arp_table", boom)
        assert observer.poll_once() == 0  # must not propagate


class TestLoopbackFiltering:
    """Regression: a desktop talks to itself across a great many ports, so
    feeding loopback traffic to the recon detectors produced a "127.0.0.1
    touched 113 ports on this host" scan finding -- the machine scanning
    itself. Only visible by running against real captured traffic."""

    def test_loopback_packets_are_excluded(self, db):
        now = datetime.now(timezone.utc)
        packetstore.append_batch(
            [
                _packet_row(now, src_addr="127.0.0.1", dst_addr="127.0.0.1"),
                _packet_row(now, src_addr="::1", dst_addr="::1"),
                _packet_row(now, src_addr="192.168.1.42", dst_addr="93.184.216.34"),
            ],
            db_path=db,
        )
        source = integration.StoreTrafficSource(db_path=db)
        got = list(source.packets(now - timedelta(minutes=1), now))
        assert [p.dst_addr for p in got] == ["93.184.216.34"]

    def test_real_traffic_is_not_over_filtered(self, db):
        """127.x is loopback but 128.x is not -- the LIKE pattern must not
        swallow neighbouring ranges."""
        now = datetime.now(timezone.utc)
        packetstore.append_batch(
            [
                _packet_row(now, dst_addr="128.0.0.1"),
                _packet_row(now, dst_addr="12.7.0.1"),
            ],
            db_path=db,
        )
        source = integration.StoreTrafficSource(db_path=db)
        got = {p.dst_addr for p in source.packets(now - timedelta(minutes=1), now)}
        assert got == {"128.0.0.1", "12.7.0.1"}

    def test_loopback_flows_are_excluded(self, db):
        now = datetime.now(timezone.utc)

        def flow(flow_id, local, remote):
            return {
                "id": flow_id, "protocol": "tcp", "state": "ESTABLISHED",
                "local_addr": local, "local_port": 5000,
                "remote_addr": remote, "remote_port": 443,
                "remote_host": None, "remote_org": None, "direction": "outbound",
                "pid": 1, "process_name": "x.exe", "process_path": None,
                "bytes_in": 10, "bytes_out": 20, "ts_epoch": _epoch(now),
                "is_external": 0, "is_encrypted": 1,
                "risk": "low", "risk_reasons": "[]",
            }

        flowstore.upsert_flow(flow("loop", "127.0.0.1", "127.0.0.1"), db_path=db)
        flowstore.upsert_flow(flow("real", "192.168.1.42", "93.184.216.34"), db_path=db)

        source = integration.StoreTrafficSource(db_path=db)
        got = list(source.flows(now - timedelta(minutes=1), now + timedelta(minutes=1)))
        assert [f.id for f in got] == ["real"]


class TestBroadcastFiltering:
    """Regression: the OS ARP table maps broadcast/multicast IPs onto
    broadcast/multicast MACs. Passing those through made `arp_spoofing`
    report a *critical* "one MAC claimed 2 IPs" finding for
    FF:FF:FF:FF:FF:FF owning 192.168.0.255 and 255.255.255.255 -- which is
    just Ethernet, not an attack. Caught only by running against the real
    ARP table."""

    @pytest.mark.parametrize("mac", [
        "FF:FF:FF:FF:FF:FF",   # broadcast
        "01:00:5E:00:00:FB",   # IPv4 multicast (mDNS)
        "33:33:00:00:00:01",   # IPv6 all-nodes multicast
    ])
    def test_broadcast_and_multicast_macs_are_recognised(self, mac):
        assert integration.is_l2_broadcast_or_multicast(mac) is True

    @pytest.mark.parametrize("mac", [
        "AA:BB:CC:DD:EE:FF",
        "00:1A:2B:3C:4D:5E",
        "F0:9F:C2:11:22:33",
    ])
    def test_real_unicast_macs_are_not_filtered(self, mac):
        assert integration.is_l2_broadcast_or_multicast(mac) is False

    def test_malformed_mac_does_not_raise(self):
        for bad in ["", "not-a-mac", None, "ZZ:ZZ"]:
            assert integration.is_l2_broadcast_or_multicast(bad) is False

    def test_observer_drops_broadcast_entries(self, monkeypatch):
        observer = integration.ArpObserver()
        monkeypatch.setattr(integration.arpscan, "read_arp_table", lambda: [
            {"ip": "192.168.0.255", "mac": "FF:FF:FF:FF:FF:FF", "is_dynamic": False},
            {"ip": "255.255.255.255", "mac": "FF:FF:FF:FF:FF:FF", "is_dynamic": False},
            {"ip": "224.0.0.251", "mac": "01:00:5E:00:00:FB", "is_dynamic": False},
            {"ip": "192.168.0.1", "mac": "AA:BB:CC:DD:EE:FF", "is_dynamic": True},
        ])
        # Only the one real host is recorded.
        assert observer.poll_once() == 1
        events = observer.events(datetime.now(timezone.utc) - timedelta(minutes=1),
                                 datetime.now(timezone.utc))
        assert [e.ip for e in events] == ["192.168.0.1"]


class TestPollingTierSuppression:
    """Regression: the polling tier samples the connection table on a fixed
    cadence, so every long-lived connection arrives as a perfectly regular
    series and `c2_beaconing` fires on our own sampling artefact."""

    class _RecordingEngine:
        def __init__(self):
            self.patched = []

        def patch_detector(self, detector_id, body):
            self.patched.append((detector_id, body))
            return {"id": detector_id}, None

        def run_once(self):
            return []

    def test_timing_detectors_disabled_on_polling_tier(self):
        engine = self._RecordingEngine()
        scheduler = integration.ThreatScheduler(engine, capture_mode=lambda: "polling")

        suppressed = scheduler.apply_tier_suppression()

        assert suppressed == ("c2_beaconing",)
        assert engine.patched == [("c2_beaconing", {"enabled": False})]

    @pytest.mark.parametrize("mode", ["npcap", "rawsocket"])
    def test_timing_detectors_left_alone_on_real_capture_tiers(self, mode):
        engine = self._RecordingEngine()
        scheduler = integration.ThreatScheduler(engine, capture_mode=lambda: mode)

        assert scheduler.apply_tier_suppression() == ()
        assert engine.patched == []

    def test_suppression_is_applied_only_once(self):
        engine = self._RecordingEngine()
        scheduler = integration.ThreatScheduler(engine, capture_mode=lambda: "polling")
        scheduler.apply_tier_suppression()
        scheduler.apply_tier_suppression()
        scheduler.apply_tier_suppression()
        assert len(engine.patched) == 1

    def test_unavailable_capture_mode_is_not_fatal(self):
        engine = self._RecordingEngine()

        def boom():
            raise RuntimeError("pipeline not started")

        scheduler = integration.ThreatScheduler(engine, capture_mode=boom)
        assert scheduler.apply_tier_suppression() == ()
        assert scheduler.run_once() == 0  # still runs, does not propagate


class TestThreatScheduler:
    def test_run_once_drives_the_engine(self):
        class FakeEngine:
            def __init__(self):
                self.calls = 0

            def run_once(self):
                self.calls += 1
                return ["threat-1", "threat-2"]

        engine = FakeEngine()
        scheduler = integration.ThreatScheduler(engine)
        assert scheduler.run_once() == 2
        assert engine.calls == 1
        assert scheduler.run_count == 1
        assert scheduler.last_error is None
        assert scheduler.last_run is not None

    def test_a_detector_blowing_up_does_not_kill_the_scheduler(self):
        class ExplodingEngine:
            def run_once(self):
                raise RuntimeError("detector exploded")

        scheduler = integration.ThreatScheduler(ExplodingEngine())
        assert scheduler.run_once() == 0          # swallowed
        assert "detector exploded" in scheduler.last_error
        assert scheduler.run_count == 0           # not counted as a success

    def test_start_and_stop_are_idempotent(self):
        class IdleEngine:
            def run_once(self):
                return []

        scheduler = integration.ThreatScheduler(IdleEngine(), interval_seconds=0.05,
                                                initial_delay_seconds=0.01)
        scheduler.start()
        scheduler.start()  # second call must be a no-op, not a second thread
        time.sleep(0.2)
        scheduler.stop()
        scheduler.stop()   # must not raise
        assert scheduler.run_count >= 1


class TestWiredApp:
    """The security packages must be reachable *and* protected once mounted."""

    @pytest.fixture
    def client(self, tmp_path, monkeypatch):
        from netaudit.server import create_app

        db_path = tmp_path / "netaudit.db"
        token_path = tmp_path / "token"
        app = create_app(db_path=db_path, token_path=token_path, autostart_capture=False)
        with TestClient(app) as c:
            c.headers.update({"X-NetAudit-Token": app.state.token})
            yield c

    @pytest.mark.parametrize("path", [
        "/api/posture",
        "/api/security/score",
        "/api/threats",
        "/api/threats/detectors",
        "/api/glossary",
        "/api/tour",
        "/api/lessons",
        "/api/findings/prioritised",
    ])
    def test_v2_routes_are_reachable_after_late_mounting(self, client, path):
        assert client.get(path).status_code == 200

    @pytest.mark.parametrize("path", ["/api/posture", "/api/threats", "/api/threats/detectors"])
    def test_v2_routes_inherit_auth_without_per_route_work(self, client, path):
        """The whole point of hooking at middleware level: nobody had to
        decorate these routes for them to require a token."""
        assert client.get(path, headers={"X-NetAudit-Token": ""}).status_code == 401

    def test_all_22_detectors_are_registered(self, client):
        body = client.get("/api/threats/detectors").json()
        assert len(body["detectors"]) == 22

    def test_security_score_reports_all_three_components(self, client):
        body = client.get("/api/security/score").json()
        ids = {c["id"] for c in body["components"]}
        assert ids == {"posture", "threats", "hygiene"}
        assert 0 <= body["overall"] <= 100

    def test_prioritised_findings_draw_from_the_live_sources(self, client):
        """The provider must return real findings, not the package's static
        fallback -- and must exclude passing checks and resolved threats."""
        body = client.get("/api/findings/prioritised").json()
        assert "items" in body
        for item in body["items"]:
            assert item["source"] in {"posture", "recommendation", "threat"}
            assert item["severity"] in {"critical", "high", "medium", "low", "info"}
            assert item["why_first"]
        ranks = [i["priority_rank"] for i in body["items"]]
        assert ranks == sorted(ranks), "items must arrive already ranked"

    def test_prioritised_posture_findings_say_what_is_actually_wrong(self, client):
        """A posture title states the desired end state ("Default inbound
        action is Block"). In a list where every entry is a failure that
        reads as a claim the thing is fine, so each posture item has to
        carry the check's own `observed` text alongside it."""
        items = client.get("/api/findings/prioritised").json()["items"]
        posture_items = [i for i in items if i["source"] == "posture"]
        assert posture_items, "this machine should have at least one failing check"
        with_observed = [i for i in posture_items if i.get("observed")]
        assert with_observed, "posture findings must carry the observed state"
        for item in with_observed:
            assert item["observed"] != item["title"]

    def test_explain_covers_a_real_detector(self, client):
        body = client.get("/api/explain/detector/c2_beaconing").json()
        assert body["id"] == "c2_beaconing"
        assert body["plain"]
        assert body["what_would_make_it_wrong"]

    @pytest.mark.parametrize("path", [
        "/api/compliance/frameworks",
        "/api/alerts/config",
        "/api/alerts/history",
        "/api/baselines",
        "/api/capture/filter",
        "/api/sessions",
        "/api/reports",
    ])
    def test_pro_routes_are_reachable_after_late_mounting(self, client, path):
        assert client.get(path).status_code == 200

    @pytest.mark.parametrize("path", ["/api/compliance/frameworks", "/api/baselines", "/api/reports"])
    def test_pro_routes_inherit_auth(self, client, path):
        assert client.get(path, headers={"X-NetAudit-Token": ""}).status_code == 401

    def test_compliance_sees_real_posture_evidence(self, client):
        """Without the orchestrator's override, compliance's default provider
        reports no checks at all and every control comes back
        `not_assessed`. Seeing any other status proves the real posture
        service is actually reaching it."""
        frameworks = client.get("/api/compliance/frameworks").json()["frameworks"]
        assert frameworks, "at least one framework must ship"
        report = client.get(f"/api/compliance/{frameworks[0]['id']}").json()
        statuses = {c["status"] for c in report["controls"]}
        assert statuses - {"not_assessed"}, "compliance is not receiving posture evidence"

    def test_baseline_snapshot_captures_live_state(self, client):
        created = client.post("/api/baselines", json={"label": "wiring test"}).json()
        assert created["label"] == "wiring test"
        # A snapshot with zero checks means the posture provider override did
        # not take, which is the failure mode worth catching here.
        assert created["checks_count"] > 0
        assert created["listeners_count"] > 0
        assert 0 <= created["overall_score"] <= 100
        listed = client.get("/api/baselines").json()["baselines"]
        assert created["id"] in {b["id"] for b in listed}

    def test_report_is_built_from_live_data_not_the_static_fallback(self, client):
        """`export`'s default provider is a fixed sample. If the override is
        missing, the report still renders -- with someone else's numbers."""
        res = client.post("/api/reports", json={"format": "json", "window": "1h"})
        assert res.status_code == 200
        body = res.json()
        score = body["security_score"]
        live = client.get("/api/security/score").json()
        assert score["overall"] == live["overall"]

    def test_lan_scan_rejects_a_subnet_this_machine_is_not_on(self, client):
        """The interface override widens what may be scanned, so it has to
        stay narrow: a valid RFC1918 subnet the machine has no interface on
        must still be refused."""
        res = client.post("/api/devices/scan", json={"subnet": "10.99.99.0/24", "ports": [80]})
        assert res.status_code == 400

    def test_pcap_export_emits_a_real_libpcap_header(self, client):
        res = client.get("/api/capture/pcap?limit=10")
        assert res.status_code == 200
        # Little-endian magic + version 2.4, per the libpcap file format.
        assert res.content[:8] == b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00"

    def test_v1_routes_still_work_alongside_the_new_ones(self, client):
        assert client.get("/api/health").status_code == 200
        assert client.get("/api/traffic/log").status_code == 200


def _flow_row(flow_id, ts, **overrides):
    row = {
        "id": flow_id,
        "protocol": "tcp",
        "state": "established",
        "local_addr": "192.168.0.53",
        "local_port": 51422,
        "remote_addr": "93.184.216.34",
        "remote_port": 443,
        "remote_host": None,
        "remote_org": None,
        "direction": "outbound",
        "pid": 1,
        "process_name": "chrome.exe",
        "process_path": None,
        "bytes_in": 10,
        "bytes_out": 20,
        "ts_epoch": ts,
        "is_external": 1,
        "is_encrypted": 1,
        "risk": "low",
        "risk_reasons": "[]",
    }
    row.update(overrides)
    return row


class TestProAdapters:
    """The adapter classes `wire_pro` installs, exercised directly."""

    def test_interface_provider_skips_down_and_loopback_interfaces(self, monkeypatch):
        monkeypatch.setattr(
            integration.netinfo,
            "list_interfaces",
            lambda: [
                {"ipv4": "192.168.0.53", "netmask": "255.255.255.0", "is_up": True, "is_loopback": False},
                {"ipv4": "169.254.104.194", "netmask": "255.255.0.0", "is_up": False, "is_loopback": False},
                {"ipv4": "127.0.0.1", "netmask": "255.0.0.0", "is_up": True, "is_loopback": True},
                {"ipv4": None, "netmask": None, "is_up": True, "is_loopback": False},
            ],
        )
        assert integration.MachineInterfaceProvider().interfaces() == [
            {"address": "192.168.0.53", "prefixlen": 24}
        ]

    def test_peers_use_the_baseline_window_not_the_live_connections_window(self, db):
        """`query_connections` only sees the last 120 seconds. A baseline
        taken on a quiet minute would then record an empty peer set and make
        every ordinary destination look new on the next diff."""
        old = time.time() - 3600  # outside the live window, inside a day
        flowstore.upsert_flow(_flow_row("f1", old, remote_host="example.com"), db_path=db)

        provider = integration.StoreTrafficProvider(db)
        assert flowstore.query_connections(db_path=db) == []
        assert provider.peers() == ["example.com"]

    def test_peers_exclude_internal_flows(self, db):
        now = time.time()
        for flow_id, remote, external in (("a", "93.184.216.34", 1), ("b", "192.168.0.7", 0)):
            flowstore.upsert_flow(
                _flow_row(flow_id, now, remote_addr=remote, is_external=external), db_path=db
            )
        assert integration.StoreTrafficProvider(db).peers() == ["93.184.216.34"]

    def test_score_provider_reports_unmeasured_threats_as_none_not_zero(self):
        class _Score:
            overall = 62
            components = [type("C", (), {"id": "posture", "score": 70})()]

        class _Posture:
            def get_security_score(self):
                return _Score()

        result = integration.CompositeScoreProvider(_Posture()).security_score()
        assert result == {"posture": 70, "threats": None, "overall": 62}

    def test_adapters_degrade_to_empty_rather_than_raising(self):
        class _Broken:
            def get_report(self):
                raise RuntimeError("posture exploded")

            def get_security_score(self):
                raise RuntimeError("posture exploded")

        assert integration.PostureChecksAdapter(_Broken()).checks() == []
        assert integration.CompositeScoreProvider(_Broken()).security_score() == {
            "posture": 0, "threats": None, "overall": 0,
        }
        provider = integration.LiveReportDataProvider(_Broken(), None, Path("/nonexistent/x.db"))
        assert provider.security_score() == {}
        assert provider.posture_report() == {}
        assert provider.threats() == []


class _FakeAlertService:
    """Stands in for `alerts.AlertService` with no DB and no sending."""

    def __init__(self, enabled=True, min_severity="high", history=()):
        self._enabled = enabled
        self._min = min_severity
        self._order = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
        self.dispatched: list[tuple[str, str]] = []
        self._history = list(history)

    def get_config(self):
        return type("C", (), {"enabled": self._enabled})()

    def history(self, limit=200):
        alerts = [
            type("I", (), {"source": s, "source_id": sid})() for s, sid in self._history
        ]
        return type("H", (), {"alerts": alerts})()

    def dispatch(self, severity, source, source_id, title):
        if self._order.get(severity, 0) < self._order.get(self._min, 0):
            return None
        self.dispatched.append((source_id, severity))
        return object()


class TestThreatAlertDispatcher:
    """`alerts.dispatch()` documents itself as needing a caller. This is it,
    so the tests here are about not being annoying: no duplicates, no replay
    after restart, nothing swallowed while alerting was off."""

    def _threat(self, tid, severity="critical", status="open"):
        return {"id": tid, "severity": severity, "title": f"Threat {tid}", "status": status}

    def test_each_threat_alerts_once_across_repeated_passes(self):
        alerts = _FakeAlertService()
        d = integration.ThreatAlertDispatcher(alerts)
        batch = [self._threat("t1"), self._threat("t2")]

        assert d.dispatch_new(batch) == 2
        # run_once() returns every open threat every pass, not just new ones
        assert d.dispatch_new(batch) == 0
        assert d.dispatch_new(batch + [self._threat("t3")]) == 1
        assert [tid for tid, _ in alerts.dispatched] == ["t1", "t2", "t3"]

    def test_history_seeding_stops_a_restart_replaying_old_threats(self):
        alerts = _FakeAlertService(history=[("threat", "t1"), ("recommendation", "r9")])
        d = integration.ThreatAlertDispatcher(alerts)
        assert d.dispatch_new([self._threat("t1"), self._threat("t2")]) == 1
        assert [tid for tid, _ in alerts.dispatched] == ["t2"]

    def test_nothing_is_marked_alerted_while_alerting_is_disabled(self):
        """Turning alerting on must not silently swallow the threats that
        were already on screen when it was off."""
        alerts = _FakeAlertService(enabled=False)
        d = integration.ThreatAlertDispatcher(alerts)
        assert d.dispatch_new([self._threat("t1")]) == 0

        alerts._enabled = True
        assert d.dispatch_new([self._threat("t1")]) == 1

    def test_below_threshold_threats_stay_eligible_if_the_threshold_drops(self):
        alerts = _FakeAlertService(min_severity="critical")
        d = integration.ThreatAlertDispatcher(alerts)
        assert d.dispatch_new([self._threat("t1", severity="medium")]) == 0

        alerts._min = "low"
        assert d.dispatch_new([self._threat("t1", severity="medium")]) == 1

    def test_resolved_threats_do_not_alert(self):
        alerts = _FakeAlertService()
        d = integration.ThreatAlertDispatcher(alerts)
        assert d.dispatch_new([self._threat("t1", status="resolved")]) == 0

    def test_a_failing_alert_service_cannot_break_the_detection_loop(self):
        class _Exploding(_FakeAlertService):
            def dispatch(self, **kwargs):
                raise RuntimeError("webhook host is down")

        alerts = _Exploding()
        d = integration.ThreatAlertDispatcher(alerts)
        assert d.dispatch_new([self._threat("t1"), self._threat("t2")]) == 0

    def test_scheduler_forwards_detections_to_the_dispatcher(self):
        class _Engine:
            def run_once(self):
                return [{"id": "t1", "severity": "critical", "title": "T", "status": "open"}]

        alerts = _FakeAlertService()
        scheduler = integration.ThreatScheduler(_Engine())
        scheduler.alert_dispatcher = integration.ThreatAlertDispatcher(alerts)

        scheduler.run_once()
        assert scheduler.alerts_sent == 1
        scheduler.run_once()
        assert scheduler.alerts_sent == 1, "the same threat must not re-alert each pass"
