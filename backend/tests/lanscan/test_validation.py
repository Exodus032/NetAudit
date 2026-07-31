from __future__ import annotations

import pytest

from netaudit.lanscan.validation import ScanValidationError, validate_scan_request

HOME_IFACES = [{"address": "192.168.1.10", "prefixlen": 24}]


def test_valid_request_on_matching_interface_accepted():
    network = validate_scan_request("192.168.1.0/24", [22, 80, 443], 50, HOME_IFACES)
    assert str(network) == "192.168.1.0/24"


def test_non_rfc1918_subnet_rejected_8_8_8_0_24():
    # From the definition-of-done verification step.
    with pytest.raises(ScanValidationError) as exc:
        validate_scan_request("8.8.8.0/24", [80], 10, HOME_IFACES)
    assert exc.value.code == "not_rfc1918"


def test_non_rfc1918_subnet_rejected_public_single_host():
    with pytest.raises(ScanValidationError) as exc:
        validate_scan_request("1.1.1.0/24", [80], 10, HOME_IFACES)
    assert exc.value.code == "not_rfc1918"


def test_subnet_larger_than_slash24_rejected_slash16():
    # From the definition-of-done verification step: a /16 is rejected.
    with pytest.raises(ScanValidationError) as exc:
        validate_scan_request("192.168.0.0/16", [80], 10, HOME_IFACES)
    assert exc.value.code == "subnet_too_large"


def test_subnet_larger_than_slash24_rejected_slash8():
    with pytest.raises(ScanValidationError) as exc:
        validate_scan_request("10.0.0.0/8", [80], 10, HOME_IFACES)
    assert exc.value.code == "subnet_too_large"


def test_slash25_is_allowed_smaller_than_slash24():
    network = validate_scan_request("192.168.1.0/25", [80], 10, HOME_IFACES)
    assert network.prefixlen == 25


def test_more_than_20_ports_rejected():
    with pytest.raises(ScanValidationError) as exc:
        validate_scan_request("192.168.1.0/24", list(range(1, 22)), 10, HOME_IFACES)
    assert exc.value.code == "too_many_ports"


def test_exactly_20_ports_allowed():
    validate_scan_request("192.168.1.0/24", list(range(1, 21)), 10, HOME_IFACES)


def test_no_ports_rejected():
    with pytest.raises(ScanValidationError) as exc:
        validate_scan_request("192.168.1.0/24", [], 10, HOME_IFACES)
    assert exc.value.code == "no_ports"


def test_invalid_port_number_rejected():
    with pytest.raises(ScanValidationError) as exc:
        validate_scan_request("192.168.1.0/24", [70000], 10, HOME_IFACES)
    assert exc.value.code == "invalid_port"


def test_duplicate_ports_rejected():
    with pytest.raises(ScanValidationError) as exc:
        validate_scan_request("192.168.1.0/24", [80, 80], 10, HOME_IFACES)
    assert exc.value.code == "duplicate_ports"


def test_rate_limit_over_100_rejected():
    with pytest.raises(ScanValidationError) as exc:
        validate_scan_request("192.168.1.0/24", [80], 101, HOME_IFACES)
    assert exc.value.code == "rate_limit_too_high"


def test_rate_limit_exactly_100_allowed():
    validate_scan_request("192.168.1.0/24", [80], 100, HOME_IFACES)


def test_rate_limit_zero_or_negative_rejected():
    with pytest.raises(ScanValidationError) as exc:
        validate_scan_request("192.168.1.0/24", [80], 0, HOME_IFACES)
    assert exc.value.code == "invalid_rate_limit"


def test_subnet_not_on_any_local_interface_rejected():
    # Private and /24 (both individually fine) but this machine has no
    # interface on 192.168.99.0/24.
    with pytest.raises(ScanValidationError) as exc:
        validate_scan_request("192.168.99.0/24", [80], 10, HOME_IFACES)
    assert exc.value.code == "no_matching_interface"


def test_no_interfaces_at_all_rejects_everything():
    with pytest.raises(ScanValidationError) as exc:
        validate_scan_request("192.168.1.0/24", [80], 10, [])
    assert exc.value.code == "no_matching_interface"


def test_smaller_subnet_within_the_interfaces_network_is_allowed():
    # /28 within the machine's /24 interface -- still a match.
    network = validate_scan_request("192.168.1.16/28", [80], 10, HOME_IFACES)
    assert network.prefixlen == 28


def test_invalid_cidr_string_rejected():
    with pytest.raises(ScanValidationError) as exc:
        validate_scan_request("not-a-subnet", [80], 10, HOME_IFACES)
    assert exc.value.code == "invalid_subnet"


def test_malformed_interface_entries_are_ignored_not_fatal():
    weird_ifaces = [{"bogus": "entry"}, {"address": "192.168.1.10", "prefixlen": 24}]
    validate_scan_request("192.168.1.0/24", [80], 10, weird_ifaces)
