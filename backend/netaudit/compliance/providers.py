"""Decoupling: this package never imports `netaudit.posture`. Instead it
defines the narrow shape of posture data it actually needs as a `Protocol`,
resolved through a FastAPI dependency the orchestrator overrides with the
real posture service.
"""
from __future__ import annotations

from typing import Iterable, Optional, Protocol, runtime_checkable


@runtime_checkable
class PostureProvider(Protocol):
    """What this package needs from posture. `checks()` returns plain
    dicts (not posture's pydantic model) so this package has zero import
    dependency on `netaudit.posture` -- any object satisfying this shape
    works, real or fake.

    Each dict must carry at least `id` (str) and `status` (one of
    "pass"/"warn"/"fail"/"error"/"skipped"). Extra keys are ignored.
    """

    def checks(self) -> Iterable[dict]: ...


class StaticPostureProvider:
    """Trivial `PostureProvider` backed by a fixed list of `{id, status}`
    dicts, supplied at construction time. Used by tests and by the done-
    criteria verification run (feeding this machine's real posture
    results through the compliance service without importing posture)."""

    def __init__(self, checks: Optional[list[dict]] = None) -> None:
        self._checks = list(checks or [])

    def checks(self) -> list[dict]:
        return list(self._checks)


_default_provider: Optional[PostureProvider] = None


def get_posture_provider() -> PostureProvider:
    """FastAPI dependency `router.py` depends on. The orchestrator
    overrides this via `app.dependency_overrides[get_posture_provider] =
    lambda: real_service` to wire in the real posture data without this
    package importing `netaudit.posture` at all. Defaults to an empty
    static provider so the router still works (fully `not_assessed`) if
    nothing overrides it."""
    global _default_provider
    if _default_provider is None:
        _default_provider = StaticPostureProvider([])
    return _default_provider
