from __future__ import annotations

from netaudit.capture import selector
from netaudit.capture.polling import PollingBackend


def test_not_elevated_falls_back_to_polling(monkeypatch):
    monkeypatch.setattr(selector, "is_elevated", lambda: False)
    result = selector.select_tier()
    assert result.mode == "polling"
    assert isinstance(result.backend, PollingBackend)
    assert result.elevated is False
    assert "Administrator" in result.degraded_reason


def test_elevated_and_npcap_probe_succeeds_selects_npcap(monkeypatch):
    monkeypatch.setattr(selector, "is_elevated", lambda: True)
    result = selector.select_tier(prefer_npcap_probe=lambda: None)
    assert result.mode == "npcap"
    assert result.elevated is True
    assert result.degraded_reason is None


def test_elevated_npcap_fails_rawsocket_succeeds(monkeypatch):
    monkeypatch.setattr(selector, "is_elevated", lambda: True)

    def failing_npcap():
        raise RuntimeError("scapy is not importable")

    result = selector.select_tier(prefer_npcap_probe=failing_npcap, prefer_rawsocket_probe=lambda: None)
    assert result.mode == "rawsocket"
    assert result.elevated is True
    assert "Npcap" in result.degraded_reason


def test_elevated_both_probes_fail_falls_back_to_polling(monkeypatch):
    monkeypatch.setattr(selector, "is_elevated", lambda: True)

    def failing_npcap():
        raise RuntimeError("scapy is not importable")

    def failing_rawsocket():
        raise OSError("raw sockets require admin")

    result = selector.select_tier(prefer_npcap_probe=failing_npcap, prefer_rawsocket_probe=failing_rawsocket)
    assert result.mode == "polling"
    assert result.elevated is True
    assert isinstance(result.backend, PollingBackend)
    assert "Npcap" in result.degraded_reason and "raw sockets" in result.degraded_reason.lower()
