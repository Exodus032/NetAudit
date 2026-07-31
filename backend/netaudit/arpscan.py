"""Best-effort LAN device discovery via the OS ARP cache (`arp -a`). Needs
no privileges and no raw sockets -- just reads whatever Windows already
resolved from normal traffic."""
from __future__ import annotations

import re
import subprocess

_LINE_RE = re.compile(r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\s+(\w+)")


def read_arp_table() -> list[dict]:
    try:
        result = subprocess.run(
            ["arp", "-a"], capture_output=True, text=True, timeout=5,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        output = result.stdout
    except Exception:
        return []

    entries = []
    for line in output.splitlines():
        m = _LINE_RE.match(line)
        if not m:
            continue
        ip, mac_raw, kind = m.groups()
        entries.append({
            "ip": ip,
            "mac": mac_raw.replace("-", ":").upper(),
            "is_dynamic": kind.lower() == "dynamic",
        })
    return entries
