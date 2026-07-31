"""Shared, lightweight risk classification for log entries and flows.
Deliberately simple -- the rules engine (rules/builtin.py) is where the
real analysis happens. This just gives each row/flow a defensible label
without waiting for a rules-engine tick."""
from __future__ import annotations

_HIGH_RISK_PLAINTEXT_PORTS = {23}  # telnet: unauthenticated, unencrypted remote shell
_MEDIUM_RISK_PLAINTEXT_PORTS = {80, 21, 143, 110, 389}


def classify_risk(is_external: bool, is_encrypted: bool, remote_port: int | None) -> tuple[str, list[str]]:
    reasons: list[str] = []
    if remote_port in _HIGH_RISK_PLAINTEXT_PORTS:
        reasons.append("Telnet: unauthenticated, unencrypted remote access")
        return "high", reasons
    if is_external and not is_encrypted and remote_port in _MEDIUM_RISK_PLAINTEXT_PORTS:
        reasons.append("Unencrypted protocol to an external host")
        return "medium", reasons
    return "low", reasons
