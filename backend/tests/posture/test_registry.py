"""Check registration and category grouping against the Part A catalogue
table (API_CONTRACT_V2_SECURITY.md A4)."""
from __future__ import annotations

from netaudit.posture.registry import CATEGORY_LABELS, all_checks, checks_by_category

# The exact catalogue from API_CONTRACT_V2_SECURITY.md A4.
EXPECTED_CHECKS_BY_CATEGORY: dict[str, set[str]] = {
    "firewall": {"firewall_profiles_enabled", "firewall_inbound_default_block", "firewall_allow_rules_broad", "firewall_logging_enabled"},
    "smb": {"smb1_disabled", "smb_signing_required", "smb_guest_auth_disabled", "smb_shares_exposed"},
    "remote_access": {"rdp_disabled_or_nla", "winrm_exposure", "remote_registry_disabled", "psremoting_scope"},
    "name_resolution": {"llmnr_disabled", "netbios_disabled", "mdns_exposure", "wpad_disabled", "dns_over_https", "dns_servers_trusted"},
    "network_config": {"ipv6_state", "ip_forwarding_disabled", "promiscuous_adapters", "unused_adapters_enabled", "network_profile_public"},
    "wifi": {"wifi_encryption_strength", "wifi_open_networks_saved", "wifi_autoconnect_open"},
    "tls": {"tls10_11_disabled", "ssl3_disabled", "weak_ciphers_disabled", "certificate_store_anomalies"},
    "listening_services": {"listening_on_all_interfaces", "high_risk_ports_open", "unexpected_listeners", "upnp_disabled"},
    "updates_and_defense": {"defender_realtime_enabled", "defender_signatures_current", "windows_update_current", "uac_enabled", "bitlocker_status"},
    "accounts": {"guest_account_disabled", "local_admin_count", "blank_passwords", "autologon_disabled"},
}


def test_every_required_category_and_check_is_registered():
    grouped = checks_by_category()
    assert set(grouped.keys()) == set(CATEGORY_LABELS.keys()) == set(EXPECTED_CHECKS_BY_CATEGORY.keys())
    for category, expected_ids in EXPECTED_CHECKS_BY_CATEGORY.items():
        actual_ids = {c.id for c in grouped[category]}
        missing = expected_ids - actual_ids
        assert not missing, f"category {category!r} is missing required checks: {missing}"


def test_total_check_count_matches_the_catalogue():
    total_expected = sum(len(ids) for ids in EXPECTED_CHECKS_BY_CATEGORY.values())
    assert len(all_checks()) == total_expected


def test_no_duplicate_check_ids():
    ids = [c.id for c in all_checks()]
    assert len(ids) == len(set(ids)), "duplicate check ids found in the registry"


def test_every_check_declares_required_fields():
    for check in all_checks():
        assert check.id
        assert check.category in CATEGORY_LABELS
        assert check.title
        assert check.severity in {"critical", "high", "medium", "low", "info"}
        assert isinstance(check.score_weight, int) and check.score_weight > 0
        assert check.why_it_matters and len(check.why_it_matters) > 20, f"{check.id}: why_it_matters looks like a placeholder"
        assert check.remediation is not None
        assert check.remediation.summary
