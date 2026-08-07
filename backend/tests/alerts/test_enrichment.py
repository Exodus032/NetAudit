"""IP reputation enrichment (AbuseIPDB / VirusTotal): config validation,
key hygiene, the public-IP filter, the lookup pipeline (cache, quota,
failure containment) and the auto-tag rules. No real DNS and no real
socket -- `socket.getaddrinfo` is monkeypatched and every request goes
through `FakeTransport`, exactly like the webhook/slack tests.
"""
from __future__ import annotations

import json

import pytest

from netaudit.alerts import webhook
from netaudit.alerts.enrichment import (
    EnrichmentConfigError,
    EnrichmentService,
    build_provider_request,
    enrichment_summary,
    extract_public_ips,
    parse_provider_response,
    tags_for,
)
from netaudit.alerts.models import EnrichmentConfigUpdate, EnrichmentProviderUpdate
from netaudit.alerts.service import AlertService
from netaudit.alerts.webhook import WebhookResult

from .conftest import FakeTransport, fake_getaddrinfo

ABUSE = "abuseipdb"
VT = "virustotal"


def _provider(provider_id, enabled=False, api_key=None, clear_key=False):
    return EnrichmentProviderUpdate(id=provider_id, enabled=enabled, api_key=api_key, clear_key=clear_key)


def _update(enabled=False, min_severity="medium", cache_ttl_hours=24, providers=None):
    return EnrichmentConfigUpdate(
        enabled=enabled, min_severity=min_severity, cache_ttl_hours=cache_ttl_hours,
        providers=providers or [_provider(ABUSE, enabled), _provider(VT, enabled)],
    )


def _enabled_with_keys(api_key="test-key-abuse", vt_key="test-key-vt"):
    return _update(
        enabled=True,
        min_severity="low",
        providers=[_provider(ABUSE, True, api_key), _provider(VT, True, vt_key)],
    )


def _fake_dns(monkeypatch):
    monkeypatch.setattr(
        webhook.socket, "getaddrinfo",
        fake_getaddrinfo({
            "api.abuseipdb.com": ["8.8.8.8"],
            "www.virustotal.com": ["8.8.8.8"],
            "hooks.example.com": ["8.8.8.8"],  # webhook/slack channels in dispatch tests
        }),
    )


# ---------------------------------------------------------------------------
# public-IP filter
# ---------------------------------------------------------------------------


def test_extract_public_ips_only_keeps_public_unicast():
    indicators = [
        {"type": "ip", "value": "8.8.8.8"},
        {"type": "ip", "value": "1.2.3.4"},
        {"type": "ip", "value": "10.0.0.1"},        # RFC1918
        {"type": "ip", "value": "192.168.1.50"},     # RFC1918
        {"type": "ip", "value": "172.16.5.5"},       # RFC1918
        {"type": "ip", "value": "127.0.0.1"},        # loopback
        {"type": "ip", "value": "169.254.1.1"},      # link-local
        {"type": "ip", "value": "100.64.0.1"},       # CGNAT
        {"type": "ip", "value": "224.0.0.1"},        # multicast
        {"type": "ip", "value": "0.0.0.0"},          # unspecified
        {"type": "ip", "value": "fe80::1"},          # IPv6 link-local
        {"type": "ip", "value": "fc00::1"},          # IPv6 ULA
        {"type": "ip", "value": "not-an-ip"},        # garbage
        {"type": "ip", "value": "8.8.8.8"},          # duplicate
        {"type": "domain", "value": "evil.example"},  # non-ip indicator
        {"type": "ip", "value": "2606:4700:4700::1111"},  # public IPv6
    ]
    assert extract_public_ips(indicators) == ["8.8.8.8", "1.2.3.4", "2606:4700:4700::1111"]


def test_extract_public_ips_empty_and_malformed():
    assert extract_public_ips([]) == []
    assert extract_public_ips(None) == []
    assert extract_public_ips([{"type": "ip"}, {"type": "port", "value": "443"}, "garbage"]) == []


# ---------------------------------------------------------------------------
# request building / response parsing / tags (pure functions)
# ---------------------------------------------------------------------------


def test_build_provider_request_puts_key_in_auth_header_not_url():
    url, headers = build_provider_request(ABUSE, "8.8.8.8", "k-abuse")
    assert "8.8.8.8" in url and "k-abuse" not in url
    assert headers == {"Key": "k-abuse"}

    url, headers = build_provider_request(VT, "8.8.8.8", "k-vt")
    assert url.endswith("/8.8.8.8") and "k-vt" not in url
    assert headers == {"x-apikey": "k-vt"}


def test_parse_provider_response_abuseipdb():
    payload = {
        "data": {
            "ipAddress": "8.8.8.8",
            "abuseConfidenceScore": 92,
            "isTor": True,
            "countryCode": "US",
            "usageType": "Data Center/Web Hosting/Transit",
            "numReports": 5,
            "lastReportedAt": "2024-01-01T00:00:00Z",
            "isp": "Example ISP",
        }
    }
    parsed = parse_provider_response(ABUSE, payload)
    assert parsed["abuse_confidence_score"] == 92
    assert parsed["is_tor"] is True
    assert parsed["country_code"] == "US"


def test_parse_provider_response_virustotal():
    payload = {
        "data": {
            "id": "8.8.8.8",
            "attributes": {
                "reputation": -2,
                "as_owner": "EXAMPLE",
                "country": "US",
                "last_analysis_stats": {"harmless": 90, "malicious": 3, "suspicious": 1, "undetected": 4},
            },
        }
    }
    parsed = parse_provider_response(VT, payload)
    assert parsed["last_analysis_stats"]["malicious"] == 3
    assert parsed["as_owner"] == "EXAMPLE"


def test_parse_provider_response_tolerates_missing_keys():
    parsed = parse_provider_response(ABUSE, {"data": {}})
    assert parsed["abuse_confidence_score"] is None
    parsed = parse_provider_response(VT, {})  # even no "data" at all
    assert parsed["last_analysis_stats"] == {}
    assert parsed["reputation"] is None


def test_tags_for_thresholds():
    assert tags_for(ABUSE, {"abuse_confidence_score": 92}) == ["abuseipdb-malicious"]
    assert tags_for(ABUSE, {"abuse_confidence_score": 60}) == ["abuseipdb-suspicious"]
    assert tags_for(ABUSE, {"abuse_confidence_score": 40}) == []
    assert tags_for(ABUSE, {"abuse_confidence_score": 90, "is_tor": True}) == ["abuseipdb-malicious", "tor-exit"]
    assert tags_for(VT, {"last_analysis_stats": {"malicious": 2, "suspicious": 1}}) == ["vt-malicious", "vt-suspicious"]
    assert tags_for(VT, {"last_analysis_stats": {"malicious": 0, "suspicious": 0}}) == []


def test_enrichment_summary_compact():
    enrichment = {
        "8.8.8.8": {
            ABUSE: {"abuse_confidence_score": 92, "is_tor": True},
            VT: {"last_analysis_stats": {"malicious": 2, "suspicious": 1}},
        }
    }
    summary = enrichment_summary(enrichment)
    assert "8.8.8.8" in summary
    assert "AbuseIPDB 92" in summary
    assert "VT 2 malicious/1 suspicious" in summary


# ---------------------------------------------------------------------------
# config validation + key hygiene
# ---------------------------------------------------------------------------


def test_default_config_is_disabled_with_no_keys(db_path):
    svc = EnrichmentService(db_path=db_path)
    cfg = svc.get_config()
    assert cfg.enabled is False
    assert cfg.cache_ttl_hours == 24
    assert [p.id for p in cfg.providers] == [ABUSE, VT]
    assert all(not p.enabled and not p.has_key for p in cfg.providers)


def test_enabled_provider_without_key_rejected(db_path):
    svc = EnrichmentService(db_path=db_path)
    with pytest.raises(EnrichmentConfigError) as exc:
        svc.update_config(_update(enabled=True, providers=[_provider(ABUSE, True)]))
    assert exc.value.code == "missing_key"


def test_unknown_provider_rejected(db_path):
    svc = EnrichmentService(db_path=db_path)
    with pytest.raises(EnrichmentConfigError) as exc:
        svc.update_config(_update(providers=[_provider("shodan", True, "k")]))
    assert exc.value.code == "unknown_provider"


def test_duplicate_provider_rejected(db_path):
    svc = EnrichmentService(db_path=db_path)
    with pytest.raises(EnrichmentConfigError) as exc:
        svc.update_config(EnrichmentConfigUpdate(providers=[_provider(ABUSE), _provider(ABUSE)]))
    assert exc.value.code == "duplicate_provider"


def test_bad_cache_ttl_rejected(db_path):
    svc = EnrichmentService(db_path=db_path)
    with pytest.raises(EnrichmentConfigError) as exc:
        svc.update_config(_update(cache_ttl_hours=0))
    assert exc.value.code == "bad_cache_ttl"


def test_keys_are_never_echoed_and_survive_saves(db_path):
    svc = EnrichmentService(db_path=db_path)
    cfg = svc.update_config(_enabled_with_keys(api_key="super-secret-abuse", vt_key="super-secret-vt"))
    assert all(p.has_key for p in cfg.providers)
    assert all("api_key" not in p.model_dump() for p in cfg.providers)  # response model has no api_key field at all

    # Re-saving with api_key=None keeps the stored keys (frontend sends
    # null for unchanged keys) -- the config still validates as enabled.
    kept = svc.update_config(_enabled_with_keys(api_key=None, vt_key=None))
    assert all(p.has_key for p in kept.providers)

    # clear_key drops a key, and an enabled provider without a key is then rejected.
    with pytest.raises(EnrichmentConfigError) as exc:
        svc.update_config(
            _update(enabled=True, providers=[_provider(ABUSE, True, clear_key=True), _provider(VT, True, None)])
        )
    assert exc.value.code == "missing_key"

    # After clearing, the provider reports no key.
    svc.update_config(_update(enabled=False, providers=[_provider(ABUSE, False, clear_key=True), _provider(VT, False)]))
    cfg = svc.get_config()
    assert next(p for p in cfg.providers if p.id == ABUSE).has_key is False


# ---------------------------------------------------------------------------
# the lookup pipeline
# ---------------------------------------------------------------------------


def test_enrich_sends_only_public_ips_and_parses(db_path, monkeypatch, fake_transport):
    _fake_dns(monkeypatch)
    svc = EnrichmentService(db_path=db_path)
    svc.update_config(_enabled_with_keys())
    # 8.8.8.8 is enriched; 10.0.0.1 must never produce a request.
    result = svc.enrich(
        [{"type": "ip", "value": "8.8.8.8"}, {"type": "ip", "value": "10.0.0.1"}],
        severity="high",
        transport=fake_transport,
    )
    assert set(result) == {"8.8.8.8"}
    assert set(result["8.8.8.8"]) == {ABUSE, VT}
    assert result["8.8.8.8"][ABUSE]["abuse_confidence_score"] is None  # default FakeTransport body "" -> {} -> absent fields

    calls = fake_transport.calls
    assert len(calls) == 2
    methods = {c["method"] for c in calls}
    assert methods == {"GET"}
    abuse_call = next(c for c in calls if c["host"] == "api.abuseipdb.com")
    assert "/api/v2/check?ipAddress=8.8.8.8" in abuse_call["path"]
    assert abuse_call["headers"]["Key"] == "test-key-abuse"
    vt_call = next(c for c in calls if c["host"] == "www.virustotal.com")
    assert vt_call["path"].endswith("/8.8.8.8")
    assert vt_call["headers"]["x-apikey"] == "test-key-vt"
    assert all(c["timeout"] <= 2.0 for c in calls)  # hard 2s per-provider timeout


def test_enrich_uses_cache_and_skips_repeat_queries(db_path, monkeypatch, fake_transport):
    _fake_dns(monkeypatch)
    svc = EnrichmentService(db_path=db_path)
    svc.update_config(_enabled_with_keys())

    svc.enrich([{"type": "ip", "value": "8.8.8.8"}], severity="high", transport=fake_transport)
    assert len(fake_transport.calls) == 2

    svc.enrich([{"type": "ip", "value": "8.8.8.8"}], severity="high", transport=fake_transport)
    assert len(fake_transport.calls) == 2  # cache hit -- no new requests


def test_enrich_respects_min_severity_and_disabled(db_path, monkeypatch, fake_transport):
    _fake_dns(monkeypatch)
    svc = EnrichmentService(db_path=db_path)
    svc.update_config(_update(enabled=True, min_severity="medium", providers=[_provider(ABUSE, True, "k")]))
    assert svc.enrich([{"type": "ip", "value": "8.8.8.8"}], severity="low", transport=fake_transport) == {}
    assert fake_transport.calls == []

    svc.update_config(_update(enabled=False, min_severity="low", providers=[_provider(ABUSE, True, "k")]))
    assert svc.enrich([{"type": "ip", "value": "8.8.8.8"}], severity="critical", transport=fake_transport) == {}
    assert fake_transport.calls == []


def test_enrich_never_raises_and_contains_failures(db_path, monkeypatch, fake_transport):
    _fake_dns(monkeypatch)
    svc = EnrichmentService(db_path=db_path)
    svc.update_config(_enabled_with_keys())

    fake_transport._responses = [
        WebhookResult(ok=False, status_code=500, detail="HTTP 500"),
        WebhookResult(ok=True, status_code=200, detail="HTTP 200"),
    ]
    result = svc.enrich([{"type": "ip", "value": "8.8.8.8"}], severity="high", transport=fake_transport)
    assert result["8.8.8.8"][ABUSE] == {"error": "http_500"}
    assert "error" not in result["8.8.8.8"][VT]

    # A transport that blows up entirely must be contained, not raised.
    class _Exploding:
        def send(self, **kwargs):
            raise RuntimeError("boom")

    result = svc.enrich([{"type": "ip", "value": "8.8.8.8"}], severity="high", transport=_Exploding())
    assert result == {}


def test_enrich_honors_daily_quota_budget(db_path, monkeypatch, fake_transport):
    _fake_dns(monkeypatch)
    svc = EnrichmentService(db_path=db_path)
    svc.update_config(_enabled_with_keys(api_key="k", vt_key="k"))
    # Burn the abuseipdb budget past the 90% soft limit (900 for the
    # 1000/day default) by recording usage directly.
    from netaudit.alerts import store as alerts_store
    from netaudit.alerts.enrichment import _today

    for _ in range(900):
        alerts_store.record_enrichment_usage(ABUSE, _today(), db_path)

    result = svc.enrich([{"type": "ip", "value": "8.8.8.8"}], severity="high", transport=fake_transport)
    assert result["8.8.8.8"][ABUSE] == {"error": "quota_exhausted"}
    assert "error" not in result["8.8.8.8"][VT]
    # Only the VirusTotal request was attempted.
    assert [c["host"] for c in fake_transport.calls] == ["www.virustotal.com"]


def test_enrich_records_usage_and_tags(db_path, monkeypatch, fake_transport):
    _fake_dns(monkeypatch)
    from netaudit.alerts import store as alerts_store
    from netaudit.alerts.enrichment import _today

    svc = EnrichmentService(db_path=db_path)
    svc.update_config(_enabled_with_keys())
    fake_transport._responses = [
        WebhookResult(ok=True, status_code=200, detail="HTTP 200", body=json.dumps(
            {"data": {"abuseConfidenceScore": 92, "isTor": True}})),
        WebhookResult(ok=True, status_code=200, detail="HTTP 200", body=json.dumps(
            {"data": {"attributes": {"last_analysis_stats": {"malicious": 2, "suspicious": 1}}}})),
    ]
    result = svc.enrich([{"type": "ip", "value": "8.8.8.8"}], severity="high", transport=fake_transport)
    assert svc.tags_for(result) == ["abuseipdb-malicious", "tor-exit", "vt-malicious", "vt-suspicious"]
    assert alerts_store.get_enrichment_usage(ABUSE, _today(), db_path) == 1
    assert alerts_store.get_enrichment_usage(VT, _today(), db_path) == 1


# ---------------------------------------------------------------------------
# threat-store persistence + dispatcher integration
# ---------------------------------------------------------------------------


def test_apply_to_threat_persists_tags_and_results(db_path, monkeypatch, fake_transport):
    _fake_dns(monkeypatch)
    from netaudit.threat.store import ThreatStore

    threat_store = ThreatStore(db_path)
    threat_store.upsert_threat({
        "id": "t1", "detector_id": "c2_beaconing", "title": "x", "severity": "high",
        "confidence": 0.8, "category": "command_and_control", "status": "active",
        "mitre": "[]", "summary": "s", "detail": "d", "evidence": "[]", "indicators": "[]",
        "metrics": "{}", "occurrences": 1, "related_connection_ids": "[]", "related_log_ids": "[]",
        "false_positive_notes": "", "recommended_actions": "[]",
        "first_seen_epoch": 1, "last_seen_epoch": 1, "acknowledged_note": None,
    })
    svc = EnrichmentService(db_path=db_path, threat_store=threat_store)
    enrichment = {"8.8.8.8": {ABUSE: {"abuse_confidence_score": 92}}}
    svc.apply_to_threat("t1", enrichment, ["abuseipdb-malicious"])

    row = threat_store.get_threat("t1")
    assert row["tags"] == ["abuseipdb-malicious"]
    assert row["enrichment"]["8.8.8.8"][ABUSE]["abuse_confidence_score"] == 92


def test_apply_to_threat_without_store_is_a_noop(db_path):
    svc = EnrichmentService(db_path=db_path, threat_store=None)
    svc.apply_to_threat("t1", {"8.8.8.8": {}}, [])  # must not raise


def test_dispatcher_enriches_and_passes_extra(db_path, monkeypatch):
    """ThreatAlertDispatcher with a fake enrichment service: enrichment
    runs before dispatch, tags are applied, and `extra` reaches the alert
    service -- while a failing enrichment still lets the alert through."""
    import netaudit.integration as integration
    from netaudit.alerts.models import AlertHistoryItem

    class _FakeAlerts:
        def __init__(self):
            self.dispatched = []
            self.config_enabled = True

        def get_config(self):
            return type("Cfg", (), {"enabled": self.config_enabled})()

        def history(self, limit=500):
            return type("H", (), {"alerts": []})()

        def dispatch(self, **kwargs):
            self.dispatched.append(kwargs)
            return AlertHistoryItem(id="a1", ts="2024-01-01T00:00:00Z", severity="high", source="threat", source_id=kwargs["source_id"], title=kwargs["title"])

    class _FakeEnrichment:
        def __init__(self):
            self.calls = 0

        def enrich(self, indicators, severity):
            self.calls += 1
            return {"8.8.8.8": {ABUSE: {"abuse_confidence_score": 92}}}

        def tags_for(self, enrichment):
            return ["abuseipdb-malicious"]

        def apply_to_threat(self, threat_id, enrichment, tags):
            self.applied = (threat_id, tags)

    alerts = _FakeAlerts()
    enrichment_svc = _FakeEnrichment()
    dispatcher = integration.ThreatAlertDispatcher(alerts, enrichment_service=enrichment_svc)
    threat = {
        "id": "t1", "severity": "high", "title": "beaconing",
        "status": "active", "indicators": [{"type": "ip", "value": "8.8.8.8"}],
    }
    assert dispatcher.dispatch_new([threat]) == 1
    assert enrichment_svc.calls == 1
    assert enrichment_svc.applied == ("t1", ["abuseipdb-malicious"])
    assert alerts.dispatched[0]["extra"] == {"enrichment": {"8.8.8.8": {ABUSE: {"abuse_confidence_score": 92}}}}  # extra is passed only because enrichment is non-empty

    # A failing enrichment must not stop the alert.
    class _ExplodingEnrichment(_FakeEnrichment):
        def enrich(self, indicators, severity):
            raise RuntimeError("provider down")

    alerts2 = _FakeAlerts()
    dispatcher2 = integration.ThreatAlertDispatcher(alerts2, enrichment_service=_ExplodingEnrichment())
    assert dispatcher2.dispatch_new([threat]) == 1
    assert "extra" not in alerts2.dispatched[0]  # empty enrichment -> the call shape is unchanged


# ---------------------------------------------------------------------------
# router: config + test endpoints
# ---------------------------------------------------------------------------


def test_router_enrichment_config_roundtrip(db_path, monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from netaudit.alerts.enrichment import get_enrichment_service
    from netaudit.alerts.providers import get_webhook_transport
    from netaudit.alerts.router import router

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_enrichment_service] = lambda: EnrichmentService(db_path=db_path)
    app.dependency_overrides[get_webhook_transport] = lambda: FakeTransport()
    client = TestClient(app)

    resp = client.get("/api/alerts/enrichment")
    assert resp.status_code == 200
    assert resp.json()["enabled"] is False
    assert {p["id"]: p for p in resp.json()["providers"]}[ABUSE]["has_key"] is False

    resp = client.put(
        "/api/alerts/enrichment",
        json={
            "enabled": True, "min_severity": "low", "cache_ttl_hours": 12,
            "providers": [
                {"id": ABUSE, "enabled": True, "api_key": "secret-abuse"},
                {"id": VT, "enabled": True, "api_key": "secret-vt"},
            ],
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "secret-abuse" not in json.dumps(body)  # key never echoed
    assert all(p["has_key"] for p in body["providers"])
    assert body["cache_ttl_hours"] == 12

    resp = client.put(
        "/api/alerts/enrichment",
        json={
            "enabled": True, "min_severity": "low", "cache_ttl_hours": 12,
            "providers": [{"id": ABUSE, "enabled": True}, {"id": VT, "enabled": True}],
        },
    )
    assert resp.status_code == 200  # null keys keep the stored ones

    resp = client.put(
        "/api/alerts/enrichment",
        json={
            "enabled": True, "min_severity": "low", "cache_ttl_hours": 12,
            "providers": [{"id": ABUSE, "enabled": True, "clear_key": True}, {"id": VT, "enabled": True}],
        },
    )
    assert resp.status_code == 400  # abuseipdb now enabled without a key


def test_router_enrichment_test_endpoint(db_path, monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from netaudit.alerts.enrichment import get_enrichment_service
    from netaudit.alerts.providers import get_webhook_transport
    from netaudit.alerts.router import router

    _fake_dns(monkeypatch)
    svc = EnrichmentService(db_path=db_path)
    svc.update_config(_update(enabled=False, providers=[_provider(ABUSE, False, "k")]))

    transport = FakeTransport()
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_enrichment_service] = lambda: svc
    app.dependency_overrides[get_webhook_transport] = lambda: transport
    client = TestClient(app)

    resp = client.post("/api/alerts/enrichment/test", json={"provider_id": ABUSE})
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "delivered"
    assert len(transport.calls) == 1
    assert "ipAddress=1.1.1.1" in transport.calls[0]["path"]  # benign test IP

    resp = client.post("/api/alerts/enrichment/test", json={"provider_id": VT})
    assert resp.status_code == 200
    assert resp.json()["status"] == "failed"  # no key stored for vt
    assert len(transport.calls) == 1  # nothing was sent


# ---------------------------------------------------------------------------
# dispatch payload carries enrichment (webhook + slack)
# ---------------------------------------------------------------------------


def test_dispatch_extra_lands_in_webhook_payload(db_path, monkeypatch):
    _fake_dns(monkeypatch)
    from netaudit.alerts.models import AlertChannel, AlertsConfigUpdate

    svc = AlertService(db_path=db_path)
    svc.update_config(AlertsConfigUpdate(
        enabled=True, min_severity="low",
        channels=[AlertChannel(id="w1", kind="webhook", enabled=True, url="https://hooks.example.com/hook")],
        rate_limit_per_hour=20,
    ))
    transport = FakeTransport()
    enrichment = {"8.8.8.8": {ABUSE: {"abuse_confidence_score": 92}}}
    svc.dispatch("high", "threat", "t1", "beaconing", transport=transport, extra={"enrichment": enrichment})
    body = json.loads(transport.calls[0]["body"])
    assert body["enrichment"] == enrichment
    assert body["title"] == "beaconing"


def test_dispatch_extra_lands_in_slack_attachment(db_path, monkeypatch):
    _fake_dns(monkeypatch)
    from netaudit.alerts.models import AlertChannel, AlertsConfigUpdate

    svc = AlertService(db_path=db_path)
    svc.update_config(AlertsConfigUpdate(
        enabled=True, min_severity="low",
        channels=[AlertChannel(id="s1", kind="slack", enabled=True, url="https://hooks.example.com/slack-hook")],
        rate_limit_per_hour=20,
    ))
    transport = FakeTransport()
    enrichment = {"8.8.8.8": {ABUSE: {"abuse_confidence_score": 92}}}
    svc.dispatch("high", "threat", "t1", "beaconing", transport=transport, extra={"enrichment": enrichment})
    body = json.loads(transport.calls[0]["body"])
    fields = body["attachments"][0]["fields"]
    enrichment_field = next(f for f in fields if f["title"] == "IP enrichment")
    assert "8.8.8.8" in enrichment_field["value"]
