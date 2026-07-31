"""Check registration and category grouping.

Each module under `checks/` decorates its `Check` subclasses with
`@register`. `all_checks()` / `checks_by_category()` trigger a one-time
lazy import of every `checks.*` module (deferred to dodge a circular import,
since `checks/*.py` imports `register` from this module) and then return
fresh `Check()` instances.
"""
from __future__ import annotations

from typing import Type

from .base import Check

CATEGORY_LABELS: dict[str, str] = {
    "firewall": "Firewall",
    "smb": "SMB",
    "remote_access": "Remote Access",
    "name_resolution": "Name Resolution",
    "network_config": "Network Configuration",
    "wifi": "Wi-Fi",
    "tls": "TLS",
    "listening_services": "Listening Services",
    "updates_and_defense": "Updates & Defense",
    "accounts": "Accounts",
}

_REGISTRY: list[Type[Check]] = []
_loaded = False


def register(cls: Type[Check]) -> Type[Check]:
    _REGISTRY.append(cls)
    return cls


def _ensure_loaded() -> None:
    global _loaded
    if _loaded:
        return
    from .checks import (  # noqa: F401  imported for @register side effects
        accounts,
        firewall,
        listening_services,
        name_resolution,
        network_config,
        remote_access,
        smb,
        tls,
        updates_and_defense,
        wifi,
    )

    _loaded = True


def all_checks() -> list[Check]:
    _ensure_loaded()
    return [cls() for cls in _REGISTRY]


def checks_by_category() -> dict[str, list[Check]]:
    grouped: dict[str, list[Check]] = {cat: [] for cat in CATEGORY_LABELS}
    for check in all_checks():
        grouped.setdefault(check.category, []).append(check)
    return grouped
