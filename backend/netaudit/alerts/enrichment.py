"""IP reputation enrichment (AbuseIPDB / VirusTotal) for threat indicators.

Lives inside the alerts package on purpose: the no-stray-network AST test
(`tests/alerts/test_no_stray_network_calls.py`) scans this package, and
every outbound request goes through `webhook.send_request()` -- the same
validated, fresh-resolved, exactly-once path as alert webhooks -- so the
"single outbound path" invariant from docs/API_CONTRACT_V3.md rule 2 holds
for enrichment too.

Privacy contract (surfaced in the UI):
  - enrichment is off by default and only runs for providers the user
    enabled with their own API key;
  - only *public* IPs are ever sent (RFC1918, loopback, link-local,
    CGNAT, multicast, unspecified and site-local are filtered before any
    request is built);
  - provider hosts are code constants, not user URLs.

Operational contract:
  - `EnrichmentService.enrich()` NEVER raises; a provider failure or a
    bad response is recorded as an `{"error": ...}` entry per IP/provider
    and the alert pipeline proceeds unchanged;
  - results are cached per IP/provider (`cache_ttl_hours`, default 24h)
    so a beaconing C2 IP is queried once, not every detection;
  - per-provider daily request budgets (free-tier limits) are counted
    locally and lookup stops at 90% of the daily quota.
"""
from __future__ import annotations

import ipaddress
import json
import logging
from datetime import datetime, timezone
from typing import Optional

from ..timeutil import now_epoch, now_iso
from . import store
from .models import (
    EnrichmentConfig,
    EnrichmentConfigUpdate,
    EnrichmentProvider,
    EnrichmentTestResult,
    SEVERITY_ORDER,
)
from .webhook import Transport, WebhookRejected, _is_public_ip, send_request

logger = logging.getLogger(__name__)

ENRICHMENT_TIMEOUT_SECONDS = 2.0

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/ip_addresses/"
ABUSEIPDB_HEADER = "Key"
VIRUSTOTAL_HEADER = "x-apikey"

# Free-tier daily quotas; lookups stop at QUOTA_SOFT_LIMIT_RATIO of these
# so a busy network can't silently burn the user's budget.
ABUSEIPDB_DAILY_LIMIT = 1000
VIRUSTOTAL_DAILY_LIMIT = 500
QUOTA_SOFT_LIMIT_RATIO = 0.9

PROVIDER_DAILY_LIMITS = {"abuseipdb": ABUSEIPDB_DAILY_LIMIT, "virustotal": VIRUSTOTAL_DAILY_LIMIT}

_TEST_IP = "1.1.1.1"  # benign public address used by the "test key" endpoint


class EnrichmentConfigError(Exception):
    """Raised by `update_config()` for a config the enrichment rules
    reject (enabled provider without a key, unknown provider, bad cache
    TTL). The router maps this to a 400."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(message)


# ---------------------------------------------------------------------------
# pure helpers (unit-testable without any service/db)
# ---------------------------------------------------------------------------


def _is_public(ip_str: str) -> bool:
    """True only for a public unicast IP NetAudit is willing to send to a
    reputation provider. Reuses webhook's exhaustive public-address check
    and additionally excludes CGNAT (100.64/10)."""
    try:
        addr = ipaddress.ip_address(ip_str.split("%")[0])
    except ValueError:
        return False
    if addr in ipaddress.ip_network("100.64.0.0/10"):
        return False
    return _is_public_ip(str(addr))


def extract_public_ips(indicators: list) -> list[str]:
    """Pulls `type == "ip"` indicators, keeps only genuinely public
    addresses, dedupes, preserves order."""
    out: list[str] = []
    seen: set[str] = set()
    for ind in indicators or []:
        if not isinstance(ind, dict) or ind.get("type") != "ip":
            continue
        value = str(ind.get("value") or "")
        if not value or value in seen or not _is_public(value):
            continue
        seen.add(value)
        out.append(value)
    return out


def build_provider_request(provider_id: str, ip: str, api_key: str) -> tuple[str, dict]:
    """Returns (url, headers) for one lookup. The key rides in the
    provider's own auth header, never in the URL."""
    if provider_id == "abuseipdb":
        return f"{ABUSEIPDB_URL}?ipAddress={ip}&maxAgeInDays=90", {ABUSEIPDB_HEADER: api_key}
    return f"{VIRUSTOTAL_URL}{ip}", {VIRUSTOTAL_HEADER: api_key}


def parse_provider_response(provider_id: str, payload: dict) -> dict:
    """Reduces a provider response to the fields NetAudit uses (and that
    fit in the bounded response read). Never trusts the shape blindly --
    a missing key becomes None / {} rather than a crash."""
    data = payload.get("data") or {}
    if provider_id == "abuseipdb":
        return {
            "abuse_confidence_score": data.get("abuseConfidenceScore"),
            "is_tor": bool(data.get("isTor")),
            "country_code": data.get("countryCode"),
            "usage_type": data.get("usageType"),
            "num_reports": data.get("numReports"),
            "last_reported_at": data.get("lastReportedAt"),
            "isp": data.get("isp"),
        }
    attrs = data.get("attributes") or {}
    return {
        "reputation": attrs.get("reputation"),
        "as_owner": attrs.get("as_owner"),
        "country": attrs.get("country"),
        "network": attrs.get("network"),
        "last_analysis_stats": attrs.get("last_analysis_stats") or {},
        "last_analysis_date": attrs.get("last_analysis_date"),
    }


def tags_for(provider_id: str, parsed: dict) -> list[str]:
    """Auto-tag rules per provider. Thresholds are fixed in v1."""
    tags: list[str] = []
    if provider_id == "abuseipdb":
        score = parsed.get("abuse_confidence_score") or 0
        if score >= 80:
            tags.append("abuseipdb-malicious")
        elif score >= 50:
            tags.append("abuseipdb-suspicious")
        if parsed.get("is_tor"):
            tags.append("tor-exit")
    else:
        stats = parsed.get("last_analysis_stats") or {}
        if int(stats.get("malicious") or 0) > 0:
            tags.append("vt-malicious")
        if int(stats.get("suspicious") or 0) > 0:
            tags.append("vt-suspicious")
    return tags


def enrichment_summary(enrichment: dict) -> str:
    """One compact line per enriched IP, for Slack/webhook payloads."""
    lines: list[str] = []
    for ip, providers in sorted(enrichment.items()):
        bits: list[str] = []
        abuse = providers.get("abuseipdb") or {}
        score = abuse.get("abuse_confidence_score")
        if score is not None:
            bits.append(f"AbuseIPDB {score}")
        vt = providers.get("virustotal") or {}
        stats = vt.get("last_analysis_stats") or {}
        malicious = int(stats.get("malicious") or 0)
        suspicious = int(stats.get("suspicious") or 0)
        if malicious or suspicious:
            bits.append(f"VT {malicious} malicious/{suspicious} suspicious")
        if bits:
            lines.append(f"{ip}: " + ", ".join(bits))
    return "; ".join(lines)


def _today() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")


# ---------------------------------------------------------------------------
# service
# ---------------------------------------------------------------------------


class EnrichmentService:
    """Config persistence + validation for enrichment providers, the
    "test key" action, and the lookup pipeline used by the threat
    dispatcher.

    `threat_store` (optional) is the `ThreatStore` instance enrichment
    results/tags are written to; when absent (tests, minimal wiring) the
    pipeline still runs, it just doesn't persist onto threat rows."""

    def __init__(self, db_path=None, threat_store=None, timeout: float = ENRICHMENT_TIMEOUT_SECONDS) -> None:
        self._db_path = db_path
        self._threat_store = threat_store
        self._timeout = timeout

    # -- config -----------------------------------------------------------

    def get_config(self) -> EnrichmentConfig:
        row = store.get_enrichment_config_row(self._db_path)
        providers = [
            EnrichmentProvider(
                id=p["id"],
                enabled=bool(p["enabled"]),
                has_key=bool(p.get("api_key")),
                last_status=p.get("last_status"),
                last_attempt=p.get("last_attempt"),
            )
            for p in store.list_enrichment_providers(self._db_path)
        ]
        return EnrichmentConfig(
            enabled=bool(row["enabled"]),
            min_severity=row["min_severity"],
            cache_ttl_hours=row["cache_ttl_hours"],
            providers=providers,
        )

    def update_config(self, update: EnrichmentConfigUpdate) -> EnrichmentConfig:
        if update.cache_ttl_hours < 1:
            raise EnrichmentConfigError("bad_cache_ttl", "cache_ttl_hours must be at least 1")
        seen: set[str] = set()
        for p in update.providers:
            if p.id in seen:
                raise EnrichmentConfigError("duplicate_provider", f"duplicate provider id {p.id!r}")
            seen.add(p.id)
            if p.id not in PROVIDER_DAILY_LIMITS:
                raise EnrichmentConfigError("unknown_provider", f"unknown provider id {p.id!r}")
            if not p.enabled:
                continue
            existing = store.get_enrichment_provider(p.id, self._db_path) or {}
            has_key = bool(p.api_key) or (bool(existing.get("api_key")) and not p.clear_key)
            if not has_key:
                raise EnrichmentConfigError(
                    "missing_key",
                    f"{p.id} provider is enabled but has no API key (add one or disable it)",
                )

        store.set_enrichment_config_row(update.enabled, update.min_severity, update.cache_ttl_hours, self._db_path)
        for p in update.providers:
            store.set_enrichment_provider(p.id, enabled=p.enabled, api_key=p.api_key, clear_key=p.clear_key, db_path=self._db_path)
        return self.get_config()

    # -- test ---------------------------------------------------------------

    def test_provider(self, provider_id: str, transport: Optional[Transport] = None) -> EnrichmentTestResult:
        """One real lookup of a benign public IP to check the key works.
        Bypasses `enabled`/quotas on purpose: this is a deliberate,
        explicit, one-off user action."""
        attempted_at = now_iso()
        row = store.get_enrichment_provider(provider_id, self._db_path)
        if row is None:
            return EnrichmentTestResult(provider_id=provider_id, status="failed", detail="unknown provider id", attempted_at=attempted_at)
        key = row.get("api_key")
        if not key:
            return EnrichmentTestResult(provider_id=provider_id, status="failed", detail="no API key configured", attempted_at=attempted_at)
        url, headers = build_provider_request(provider_id, _TEST_IP, key)
        try:
            result = send_request(url, method="GET", headers=headers, timeout=self._timeout, transport=transport)
        except WebhookRejected as exc:
            store.update_enrichment_provider_status(provider_id, "failed", self._db_path)
            return EnrichmentTestResult(provider_id=provider_id, status="failed", detail=exc.message, attempted_at=attempted_at)
        status = "delivered" if result.ok else "failed"
        store.update_enrichment_provider_status(provider_id, status, self._db_path)
        return EnrichmentTestResult(provider_id=provider_id, status=status, detail=result.detail, attempted_at=attempted_at)

    # -- lookup pipeline ----------------------------------------------------

    def enrich(self, indicators: list, severity: str, transport: Optional[Transport] = None) -> dict:
        """Enrich the public IPs among `indicators` against every enabled,
        keyed provider. Never raises. Returns
        `{ip: {provider_id: parsed_response | {"error": ...}}}`.

        Honors `enabled`, `min_severity`, the per-IP cache TTL, and the
        per-provider daily quota; anything that would slow or fail the
        alert pipeline is recorded, not thrown."""
        try:
            config = self.get_config()
            if not config.enabled:
                return {}
            if SEVERITY_ORDER.get(severity, 0) < SEVERITY_ORDER.get(config.min_severity, 0):
                return {}
            ips = extract_public_ips(indicators)
            if not ips:
                return {}
            providers = {p.id: p for p in config.providers if p.enabled and p.has_key}
            if not providers:
                return {}
            cache_ttl_epochs = config.cache_ttl_hours * 3600
            now = now_epoch()
            today = _today()
            results: dict = {}
            for ip in ips:
                per_ip: dict = {}
                for provider_id in providers:
                    limit = PROVIDER_DAILY_LIMITS[provider_id]
                    if store.get_enrichment_usage(provider_id, today, self._db_path) >= int(limit * QUOTA_SOFT_LIMIT_RATIO):
                        per_ip[provider_id] = {"error": "quota_exhausted"}
                        continue
                    cached = store.get_enrichment_cache(ip, provider_id, self._db_path)
                    if cached and now - cached["fetched_epoch"] < cache_ttl_epochs:
                        per_ip[provider_id] = cached["response"]
                        continue
                    key = store.get_enrichment_provider(provider_id, self._db_path)["api_key"]
                    url, headers = build_provider_request(provider_id, ip, key)
                    try:
                        result = send_request(url, method="GET", headers=headers, timeout=self._timeout, transport=transport)
                    except WebhookRejected as exc:
                        per_ip[provider_id] = {"error": exc.code}
                        continue
                    if not result.ok:
                        per_ip[provider_id] = {"error": f"http_{result.status_code}"}
                        continue
                    try:
                        payload = json.loads(result.body or "{}")
                    except ValueError:
                        per_ip[provider_id] = {"error": "bad_response"}
                        continue
                    parsed = parse_provider_response(provider_id, payload)
                    store.set_enrichment_cache(ip, provider_id, parsed, now, self._db_path)
                    store.record_enrichment_usage(provider_id, today, self._db_path)
                    per_ip[provider_id] = parsed
                if per_ip:
                    results[ip] = per_ip
            return results
        except Exception:
            logger.exception("enrichment pipeline failed")
            return {}

    def tags_for(self, enrichment: dict) -> list[str]:
        """Aggregates auto-tags across every IP/provider, deduped, in a
        stable (sorted-by-IP) order."""
        tags: list[str] = []
        for ip in sorted(enrichment):
            providers = enrichment[ip] or {}
            for provider_id, parsed in providers.items():
                if isinstance(parsed, dict) and "error" not in parsed:
                    for tag in tags_for(provider_id, parsed):
                        if tag not in tags:
                            tags.append(tag)
        return tags

    def apply_to_threat(self, threat_id: str, enrichment: dict, tags: list[str]) -> None:
        """Persists tags + enrichment results onto the threat row (when a
        threat store is available). Never raises -- this must not be able
        to break the detection loop."""
        if self._threat_store is None:
            return
        try:
            self._threat_store.set_threat_enrichment(threat_id, tags=tags, enrichment=enrichment)
        except Exception:
            logger.debug("could not persist enrichment for threat %s", threat_id, exc_info=True)


_default_enrichment_service: Optional[EnrichmentService] = None


def get_enrichment_service() -> EnrichmentService:
    global _default_enrichment_service
    if _default_enrichment_service is None:
        _default_enrichment_service = EnrichmentService()
    return _default_enrichment_service
