"""Network interface enumeration for GET /api/interfaces."""
from __future__ import annotations

import socket

import psutil


def list_interfaces() -> list[dict]:
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    out = []
    for name, addr_list in addrs.items():
        ipv4 = ipv6 = mac = netmask = None
        for a in addr_list:
            if a.family == socket.AF_INET and ipv4 is None:
                ipv4 = a.address
                netmask = a.netmask
            elif a.family == socket.AF_INET6 and ipv6 is None:
                ipv6 = a.address.split("%")[0]
            elif getattr(socket, "AF_LINK", None) is not None and a.family == socket.AF_LINK and mac is None:
                mac = a.address
            elif a.family == psutil.AF_LINK and mac is None:
                mac = a.address

        if mac:
            mac = mac.replace("-", ":").upper()

        st = stats.get(name)
        is_up = bool(st.isup) if st else False
        speed = st.speed if st else 0
        is_loopback = "loopback" in name.lower() or (ipv4 or "").startswith("127.")

        out.append({
            "id": name,
            "name": name,
            "description": name,
            "ipv4": ipv4,
            "ipv6": ipv6,
            "mac": mac,
            "netmask": netmask,
            "is_up": is_up,
            "is_loopback": is_loopback,
            "speed_mbps": speed if speed and speed > 0 else None,
        })
    return out


def default_interface_id(interfaces: list[dict] | None = None) -> str | None:
    interfaces = interfaces if interfaces is not None else list_interfaces()
    candidates = [i for i in interfaces if i["is_up"] and not i["is_loopback"] and i["ipv4"]]
    if candidates:
        # Prefer whichever has an actual gateway-routable-looking IPv4 (i.e.
        # not link-local 169.254.x.x).
        non_apipa = [i for i in candidates if not i["ipv4"].startswith("169.254.")]
        chosen = non_apipa[0] if non_apipa else candidates[0]
        return chosen["id"]
    if interfaces:
        return interfaces[0]["id"]
    return None
