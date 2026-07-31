"""Every constraint in Part E7 of docs/API_CONTRACT_V3.md, enforced here as
one function so `router.py` has a single place that turns a bad request
into 400, and `service.py` can't accidentally start a scan without going
through the same checks.
"""
from __future__ import annotations

import ipaddress
from typing import Iterable

MAX_PORTS = 20
MAX_RATE_LIMIT_PPS = 100
MIN_PREFIXLEN = 24  # "maximum /24 per request" -- a *smaller* network (bigger prefixlen) is fine

# The three RFC1918 private ranges, checked explicitly rather than trusting
# `ipaddress`'s broader `is_private` (which is also True for loopback,
# link-local, and the RFC5737 documentation ranges -- none of which should
# be scannable here).
_RFC1918_NETS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)


class ScanValidationError(Exception):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(message)


def _is_rfc1918(network: ipaddress.IPv4Network) -> bool:
    return any(network == rfc or network.subnet_of(rfc) for rfc in _RFC1918_NETS)


def _matches_local_interface(network: ipaddress.IPv4Network, interfaces: Iterable[dict]) -> bool:
    for iface in interfaces:
        try:
            address = iface["address"]
            prefixlen = int(iface["prefixlen"])
            iface_network = ipaddress.ip_network(f"{address}/{prefixlen}", strict=False)
        except (KeyError, ValueError, TypeError):
            continue
        if iface_network.version != 4:
            continue
        if network == iface_network or network.subnet_of(iface_network):
            return True
    return False


def validate_scan_request(subnet: str, ports: list[int], rate_limit_pps: int, interfaces: Iterable[dict]) -> ipaddress.IPv4Network:
    """Returns the parsed, validated network. Raises `ScanValidationError`
    (mapped to 400 by the router) for anything that fails any constraint.
    """
    try:
        network = ipaddress.ip_network(subnet, strict=True)
    except ValueError as exc:
        raise ScanValidationError("invalid_subnet", f"{subnet!r} is not a valid CIDR subnet: {exc}") from exc

    if network.version != 4:
        raise ScanValidationError("invalid_subnet", "only IPv4 subnets are supported")

    if not _is_rfc1918(network):
        raise ScanValidationError("not_rfc1918", f"{subnet} is not a private RFC1918 subnet (10/8, 172.16/12, 192.168/16 only) -- no scanning arbitrary internet ranges")

    if network.prefixlen < MIN_PREFIXLEN:
        raise ScanValidationError("subnet_too_large", f"{subnet} is larger than the maximum allowed /{MIN_PREFIXLEN} per request")

    if not ports:
        raise ScanValidationError("no_ports", "at least one port is required")
    if len(ports) > MAX_PORTS:
        raise ScanValidationError("too_many_ports", f"{len(ports)} ports requested, maximum is {MAX_PORTS}")
    for p in ports:
        if not isinstance(p, int) or isinstance(p, bool) or not (1 <= p <= 65535):
            raise ScanValidationError("invalid_port", f"{p!r} is not a valid port number (1-65535)")
    if len(set(ports)) != len(ports):
        raise ScanValidationError("duplicate_ports", "ports must not contain duplicates")

    if not isinstance(rate_limit_pps, int) or isinstance(rate_limit_pps, bool) or rate_limit_pps <= 0:
        raise ScanValidationError("invalid_rate_limit", "rate_limit_pps must be a positive integer")
    if rate_limit_pps > MAX_RATE_LIMIT_PPS:
        raise ScanValidationError("rate_limit_too_high", f"rate_limit_pps of {rate_limit_pps} exceeds the maximum of {MAX_RATE_LIMIT_PPS}")

    if not _matches_local_interface(network, interfaces):
        raise ScanValidationError(
            "no_matching_interface",
            f"{subnet} does not match any RFC1918 subnet this machine has an interface on -- refusing to scan a network this host isn't actually connected to",
        )

    return network
